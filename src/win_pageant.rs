use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sshcast_proto::v1::PublicKey;
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::null_mut;
use std::time::Duration;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authentication::Identity::{GetUserNameExW, NameUserPrincipal};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectMemory, CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_CROSS_PROCESS,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenOwner, TokenUser, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;

use crate::local_agent::{request_identities_over_stream, sign_over_stream};

/// `SECURITY_IDENTIFICATION` (`0x00010000`) prevents a named-pipe server from impersonating
/// our client security context while still permitting identity inspection.
const SECURITY_IDENTIFICATION_QOS: u32 = 0x0001_0000;
const ERROR_PIPE_BUSY_CODE: i32 = 231;
const ERROR_FILE_NOT_FOUND_CODE: i32 = 2;

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalAllocGuard(PSECURITY_DESCRIPTOR);

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

/// Reproduces PuTTY's `capi_obfuscate_string(realname)` (`windows/utils/cryptoapi.c`):
/// 1. Pads `realname` + NUL terminator to a multiple of `CRYPTPROTECTMEMORY_BLOCK_SIZE` (16 bytes).
/// 2. Encrypts in-place via `CryptProtectMemory(..., CRYPTPROTECTMEMORY_CROSS_PROCESS)` so only
///    processes in the same user security context derive the same bytes.
/// 3. Hashes `[uint32_be(cryptlen) || encrypted_bytes]` with SHA-256 and formats as lowercase hex.
pub fn capi_obfuscate_string(realname: &str) -> Option<String> {
    let block_size = CRYPTPROTECTMEMORY_BLOCK_SIZE as usize;
    let raw = realname.as_bytes();
    let cryptlen = (raw.len() + 1 + block_size - 1) / block_size * block_size;
    let mut buf = vec![0u8; cryptlen];
    buf[..raw.len()].copy_from_slice(raw);

    let ok = unsafe {
        CryptProtectMemory(
            buf.as_mut_ptr() as *mut c_void,
            cryptlen as u32,
            CRYPTPROTECTMEMORY_CROSS_PROCESS,
        )
    };
    if ok == 0 {
        buf.fill(0);
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update((cryptlen as u32).to_be_bytes());
    hasher.update(&buf);
    buf.fill(0);

    Some(hex::encode(hasher.finalize()))
}

fn push_unique_username(out: &mut Vec<String>, raw: &str) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    // PuTTY's `agent_named_pipe_name` replaces spaces in the username with underscores.
    let sanitized: String = trimmed
        .chars()
        .map(|c| if c == ' ' { '_' } else { c })
        .collect();
    for candidate in [sanitized, trimmed.to_string()] {
        if !candidate.is_empty() && !out.iter().any(|u| u.eq_ignore_ascii_case(&candidate)) {
            out.push(candidate);
        }
    }
}

/// Collects candidate `<username>` values matching PuTTY's `get_username()` logic across
/// domain/Entra UPN accounts (`GetUserNameExW(NameUserPrincipal)`), SAM/local accounts
/// (`GetUserNameW`), and `$USERNAME`.
fn query_current_usernames() -> Vec<String> {
    let mut names = Vec::with_capacity(4);

    unsafe {
        let mut len: u32 = 0;
        let _ = GetUserNameExW(NameUserPrincipal, null_mut(), &mut len);
        if len > 0 {
            let mut buf = vec![0u16; len as usize];
            if GetUserNameExW(NameUserPrincipal, buf.as_mut_ptr(), &mut len) != 0 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(len as usize);
                let upn = String::from_utf16_lossy(&buf[..end]);
                let user_part = upn.split('@').next().unwrap_or(&upn);
                let user_part = user_part.rsplit('\\').next().unwrap_or(user_part);
                push_unique_username(&mut names, user_part);
            }
        }

        let mut sam_len: u32 = 257;
        let mut sam_buf = vec![0u16; sam_len as usize];
        if GetUserNameW(sam_buf.as_mut_ptr(), &mut sam_len) != 0 && sam_len > 0 {
            let end = sam_buf
                .iter()
                .position(|&c| c == 0)
                .unwrap_or((sam_len as usize).saturating_sub(1));
            let sam = String::from_utf16_lossy(&sam_buf[..end]);
            push_unique_username(&mut names, &sam);
        }
    }

    if let Ok(env_user) = std::env::var("USERNAME") {
        push_unique_username(&mut names, &env_user);
    }

    names
}

/// Computes deterministic PuTTY 0.75+ Pageant named pipe path(s):
/// `\\.\pipe\pageant.<username>.<capi_obfuscate_string("Pageant")>`.
pub fn deterministic_pageant_pipe_paths() -> (Option<String>, Vec<String>, Vec<String>) {
    let usernames = query_current_usernames();
    let suffix = capi_obfuscate_string("Pageant");
    let mut paths = Vec::new();
    if let Some(ref suf) = suffix {
        for user in &usernames {
            paths.push(format!(r"\\.\pipe\pageant.{user}.{suf}"));
        }
    }
    (suffix, usernames, paths)
}

/// Scans `\\.\pipe\` (NPFS) for `pageant.<username>.<hex>` named pipes if the direct deterministic
/// path was not found (e.g. Microsoft Account / Entra ID username mapping differences, or Pageant
/// builds using a per-instance random suffix). Every candidate is still verified via kernel
/// `GetSecurityInfo` (`EqualSid`) before any SSH agent traffic is sent.
fn scan_npfs_pageant_pipe_candidates(
    expected_suffix: Option<&str>,
    usernames: &[String],
    already_tried: &[String],
) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(r"\\.\pipe\") else {
        return Vec::new();
    };

    let mut tier1_suffix_match = Vec::new();
    let mut tier2_user_match = Vec::new();
    let mut tier3_other_pageant = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        if !lower.starts_with("pageant.") {
            continue;
        }
        let full_path = format!(r"\\.\pipe\{name}");
        if already_tried
            .iter()
            .any(|p| p.eq_ignore_ascii_case(&full_path))
        {
            continue;
        }

        if let Some(suf) = expected_suffix {
            if lower.ends_with(&format!(".{}", suf.to_ascii_lowercase())) {
                tier1_suffix_match.push(full_path);
                continue;
            }
        }

        if usernames.iter().any(|u| {
            let prefix = format!("pageant.{}.", u.to_ascii_lowercase());
            lower.starts_with(&prefix)
        }) {
            tier2_user_match.push(full_path);
        } else {
            tier3_other_pageant.push(full_path);
        }
    }

    tier1_suffix_match.extend(tier2_user_match);
    tier1_suffix_match.extend(tier3_other_pageant);
    tier1_suffix_match
}

fn query_token_info_buf(token: HANDLE, class: i32) -> Option<Vec<u8>> {
    unsafe {
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, class, null_mut(), 0, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            class,
            buf.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        ) == 0
        {
            return None;
        }
        Some(buf)
    }
}

/// Verifies that the connected named pipe's kernel object owner SID matches the current process's
/// `TokenUser` SID (set explicitly by Pageant's `make_private_security_descriptor`) or `TokenOwner`
/// SID (default kernel owner for elevated processes). Prevents local pipe-squatting attacks.
fn verify_pipe_owned_by_current_user(client: &NamedPipeClient) -> Result<()> {
    unsafe {
        let mut pipe_owner_sid: PSID = null_mut();
        let mut psd: PSECURITY_DESCRIPTOR = null_mut();
        let rc = GetSecurityInfo(
            client.as_raw_handle() as HANDLE,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut pipe_owner_sid,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut psd,
        );
        let _psd_guard = LocalAllocGuard(psd);
        if rc != ERROR_SUCCESS || pipe_owner_sid.is_null() {
            anyhow::bail!("GetSecurityInfo failed on Pageant named pipe (Win32 error {rc})");
        }

        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            anyhow::bail!("OpenProcessToken failed while verifying Pageant pipe owner");
        }
        let _tok_guard = HandleGuard(token);

        if let Some(user_buf) = query_token_info_buf(token, TokenUser) {
            let tu = &*(user_buf.as_ptr() as *const TOKEN_USER);
            if !tu.User.Sid.is_null() && EqualSid(pipe_owner_sid, tu.User.Sid) != 0 {
                return Ok(());
            }
        }

        if let Some(owner_buf) = query_token_info_buf(token, TokenOwner) {
            let to = &*(owner_buf.as_ptr() as *const TOKEN_OWNER);
            if !to.Owner.is_null() && EqualSid(pipe_owner_sid, to.Owner) != 0 {
                return Ok(());
            }
        }

        anyhow::bail!("refusing to use Pageant named pipe owned by a different Windows user")
    }
}

/// Normalizes OpenSSH forward-slash pipe syntax (`//./pipe/...` -> `\\.\pipe\...`) and, if given
/// a path to a `pageant.exe --openssh-config <file>` snippet on disk, extracts its `IdentityAgent`
/// pipe path.
pub fn normalize_pipe_or_openssh_config(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches('"');
    if let Some(rest) = trimmed.strip_prefix("//./pipe/") {
        return format!(r"\\.\pipe\{}", rest.replace('/', r"\"));
    }
    if !trimmed.starts_with(r"\\.\pipe\") {
        let p = Path::new(trimmed);
        if p.is_file() {
            if let Ok(contents) = std::fs::read_to_string(p) {
                if let Some(extracted) = parse_identity_agent_from_openssh_config(&contents) {
                    return extracted;
                }
            }
        }
    }
    trimmed.to_string()
}

pub fn parse_identity_agent_from_openssh_config(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_ascii_whitespace() || c == '=');
        let key = parts.next()?.trim();
        if !key.eq_ignore_ascii_case("IdentityAgent") {
            continue;
        }
        let val = parts.next()?.trim();
        let unquoted = if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
            // Pageant's `--openssh-config` escapes backslashes inside double quotes (`"\\\\.\\pipe\\..."`).
            val[1..val.len() - 1].replace(r"\\", r"\")
        } else {
            val.trim_matches('\'').to_string()
        };
        if let Some(rest) = unquoted.strip_prefix("//./pipe/") {
            return Some(format!(r"\\.\pipe\{}", rest.replace('/', r"\")));
        }
        if !unquoted.is_empty() {
            return Some(unquoted);
        }
    }
    None
}

async fn open_verified_pipe_path(pipe_path: &str) -> std::io::Result<NamedPipeClient> {
    let mut attempts = 0usize;
    loop {
        let open_res = ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION_QOS)
            .open(pipe_path);
        match open_res {
            Ok(client) => match verify_pipe_owned_by_current_user(&client) {
                Ok(()) => return Ok(client),
                Err(sec_err) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        sec_err.to_string(),
                    ));
                }
            },
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY_CODE) && attempts < 5 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Discovers and connects to a running PuTTY Pageant named pipe (`\\.\pipe\pageant.<user>.<hex>`),
/// verifying kernel pipe ownership before returning the `NamedPipeClient` and its resolved path.
pub async fn connect_pageant_pipe(
    pipe_override: Option<&str>,
) -> Result<(NamedPipeClient, String)> {
    if let Some(raw_override) = pipe_override {
        let resolved = normalize_pipe_or_openssh_config(raw_override);
        let client = open_verified_pipe_path(&resolved)
            .await
            .with_context(|| format!("failed to connect to Pageant named pipe {resolved}"))?;
        return Ok((client, resolved));
    }

    let (suffix, usernames, direct_paths) = deterministic_pageant_pipe_paths();
    let mut last_err: Option<std::io::Error> = None;

    // 1. Fast O(1) direct open of `\\.\pipe\pageant.<username>.<capi_obfuscate_string("Pageant")>`
    for path in &direct_paths {
        match open_verified_pipe_path(path).await {
            Ok(client) => return Ok((client, path.clone())),
            Err(e) => {
                if e.raw_os_error() != Some(ERROR_FILE_NOT_FOUND_CODE) {
                    tracing::debug!("Pageant direct pipe candidate {path} failed: {e}");
                }
                last_err = Some(e);
            }
        }
    }

    // 2. Fallback NPFS scan of `\\.\pipe\pageant.*` (handles Entra/MSA username mapping differences
    //    or random-suffix Pageant builds, still strictly verified by `EqualSid` owner check).
    let scanned_paths =
        scan_npfs_pageant_pipe_candidates(suffix.as_deref(), &usernames, &direct_paths);
    for path in scanned_paths {
        match open_verified_pipe_path(&path).await {
            Ok(client) => return Ok((client, path)),
            Err(e) => {
                tracing::debug!("Pageant scanned pipe candidate {path} failed: {e}");
                last_err = Some(e);
            }
        }
    }

    match last_err {
        Some(e) if e.raw_os_error() != Some(ERROR_FILE_NOT_FOUND_CODE) => {
            Err(e).context("failed to connect to PuTTY Pageant named pipe")
        }
        _ => anyhow::bail!("PuTTY Pageant named pipe is not running"),
    }
}

/// Queries `SSH2_AGENTC_REQUEST_IDENTITIES` from PuTTY Pageant over its Windows named pipe.
pub async fn request_identities_with_pipe(pipe_override: Option<&str>) -> Result<Vec<PublicKey>> {
    let (mut pipe, pipe_path) = connect_pageant_pipe(pipe_override).await?;
    request_identities_over_stream(&mut pipe)
        .await
        .with_context(|| format!("failed reading identities from Pageant pipe {pipe_path}"))
}

/// Sends `SSH2_AGENTC_SIGN_REQUEST` to PuTTY Pageant over its Windows named pipe.
pub async fn sign_with_pipe(
    pipe_override: Option<&str>,
    key_blob: &[u8],
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>> {
    let (mut pipe, pipe_path) = connect_pageant_pipe(pipe_override).await?;
    sign_over_stream(&mut pipe, key_blob, data, flags)
        .await
        .with_context(|| format!("Pageant signing failed over pipe {pipe_path}"))
}
