use anyhow::{Context, Result};
use sockcast_proto::ssh::{parse_public_key_blob, LoadedSshKey, SshKeyError};
use sockcast_proto::v1::PublicKey;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{expand_tilde_path, ClientConfig, KeyFilterConfig};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub const MAX_AGENT_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct LocalAgentConnector {
    socket_override: Option<String>,
    filter: KeyFilterConfig,
    disable_os_agent: bool,
    loaded_keys: Arc<RwLock<Vec<LoadedSshKey>>>,
}

impl LocalAgentConnector {
    pub fn new(socket_override: Option<String>, filter: KeyFilterConfig) -> Self {
        Self::with_options(socket_override, filter, false)
    }

    pub fn with_options(
        socket_override: Option<String>,
        filter: KeyFilterConfig,
        disable_os_agent: bool,
    ) -> Self {
        Self {
            socket_override,
            filter,
            disable_os_agent,
            loaded_keys: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Constructs a `LocalAgentConnector` from `ClientConfig`, loading any configured
    /// `ssh_key_files`, `ssh_keys_inline`, and `extra_key_files` into the built-in in-memory agent.
    pub fn from_client_config(
        cfg: &ClientConfig,
        extra_key_files: &[PathBuf],
        interactive_passphrase_prompt: bool,
    ) -> Result<Self> {
        let connector = Self::with_options(
            cfg.local_agent_socket.clone(),
            cfg.key_filter.clone(),
            cfg.disable_os_agent,
        );

        for (idx, inline_pem) in cfg.ssh_keys_inline.iter().enumerate() {
            let label = format!("client.toml ssh_keys_inline[{idx}]");
            let pk = connector.load_private_key_pem_with_prompt(
                inline_pem,
                &label,
                interactive_passphrase_prompt,
            )?;
            tracing::info!(
                "Loaded built-in inline SSH key: {} {} ({})",
                pk.key_type,
                pk.fingerprint_sha256,
                pk.comment
            );
        }

        let mut all_paths: Vec<PathBuf> = cfg
            .ssh_key_files
            .iter()
            .map(|s| expand_tilde_path(s))
            .collect();
        for extra in extra_key_files {
            if !all_paths.contains(extra) {
                all_paths.push(extra.clone());
            }
        }

        for path in &all_paths {
            let pk = connector
                .load_private_key_file_interactive(path, interactive_passphrase_prompt)?;
            tracing::info!(
                "Loaded built-in SSH key from {}: {} {} ({})",
                path.display(),
                pk.key_type,
                pk.fingerprint_sha256,
                pk.comment
            );
        }

        Ok(connector)
    }

    /// Adds an already-parsed `LoadedSshKey` into the built-in key ring, replacing any existing
    /// entry with the same public `key_blob`.
    pub fn add_loaded_key(&self, key: LoadedSshKey) -> PublicKey {
        let pk = key.public_key_proto();
        let mut guard = self.loaded_keys.write().expect("loaded_keys lock poisoned");
        if let Some(existing) = guard.iter_mut().find(|k| k.key_blob() == pk.key_blob) {
            *existing = key;
        } else {
            guard.push(key);
        }
        pk
    }

    /// Parses an OpenSSH PEM private key and loads it into the built-in in-memory agent.
    pub fn load_private_key_pem(
        &self,
        pem: &str,
        passphrase: Option<&str>,
    ) -> std::result::Result<PublicKey, SshKeyError> {
        let key = LoadedSshKey::parse_openssh_pem(pem, passphrase)?;
        Ok(self.add_loaded_key(key))
    }

    /// Loads an OpenSSH private key file from disk using an optional passphrase.
    pub fn load_private_key_file(
        &self,
        path: &Path,
        passphrase: Option<&str>,
    ) -> Result<PublicKey> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read SSH private key file {}", path.display()))?;
        self.load_private_key_pem(&pem, passphrase)
            .with_context(|| format!("failed to load SSH private key from {}", path.display()))
    }

    /// Loads an OpenSSH private key file from disk, checking `SOCKCAST_SSH_PASSPHRASE` or prompting
    /// interactively on the terminal if the key is passphrase-protected.
    pub fn load_private_key_file_interactive(
        &self,
        path: &Path,
        allow_prompt: bool,
    ) -> Result<PublicKey> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read SSH private key file {}", path.display()))?;
        let label = path.display().to_string();
        self.load_private_key_pem_with_prompt(&pem, &label, allow_prompt)
    }

    fn load_private_key_pem_with_prompt(
        &self,
        pem: &str,
        label: &str,
        allow_prompt: bool,
    ) -> Result<PublicKey> {
        match self.load_private_key_pem(pem, None) {
            Ok(pk) => Ok(pk),
            Err(SshKeyError::PassphraseRequired) => {
                if let Ok(env_pass) = std::env::var("SOCKCAST_SSH_PASSPHRASE") {
                    if !env_pass.is_empty() {
                        return self.load_private_key_pem(pem, Some(&env_pass)).with_context(
                            || {
                                format!(
                                    "failed to unlock SSH private key {label} with SOCKCAST_SSH_PASSPHRASE"
                                )
                            },
                        );
                    }
                }
                if !allow_prompt {
                    anyhow::bail!(
                        "SSH private key {label} is encrypted; set SOCKCAST_SSH_PASSPHRASE or unlock interactively"
                    );
                }
                let pass = prompt_key_passphrase(label)?;
                self.load_private_key_pem(pem, Some(&pass))
                    .with_context(|| format!("failed to unlock SSH private key {label}"))
            }
            Err(e) => Err(anyhow::Error::new(e))
                .with_context(|| format!("failed to parse SSH private key {label}")),
        }
    }

    /// Removes a key from the built-in key ring by SHA256 fingerprint or comment.
    pub fn remove_loaded_key(&self, fingerprint_or_comment: &str) -> bool {
        let target = fingerprint_or_comment.trim();
        let mut guard = self.loaded_keys.write().expect("loaded_keys lock poisoned");
        let before = guard.len();
        guard.retain(|k| k.fingerprint_sha256() != target && k.comment() != target);
        guard.len() != before
    }

    /// Lists all public keys currently loaded in the built-in in-memory agent.
    pub fn list_loaded_keys(&self) -> Vec<PublicKey> {
        let guard = self.loaded_keys.read().expect("loaded_keys lock poisoned");
        guard.iter().map(|k| k.public_key_proto()).collect()
    }

    pub fn loaded_key_count(&self) -> usize {
        self.loaded_keys
            .read()
            .expect("loaded_keys lock poisoned")
            .len()
    }

    pub fn is_loaded_key(&self, key_blob: &[u8]) -> bool {
        let guard = self.loaded_keys.read().expect("loaded_keys lock poisoned");
        guard.iter().any(|k| k.key_blob() == key_blob)
    }

    pub fn is_os_agent_disabled(&self) -> bool {
        self.disable_os_agent
    }

    pub fn filter_config(&self) -> &KeyFilterConfig {
        &self.filter
    }

    pub fn resolve_endpoint(&self) -> Result<String> {
        if let Some(s) = &self.socket_override {
            if !s.trim().is_empty() {
                return Ok(s.trim().to_string());
            }
        }
        #[cfg(windows)]
        {
            if let Ok(env_sock) = std::env::var("SSH_AUTH_SOCK") {
                if !env_sock.trim().is_empty() {
                    return Ok(env_sock);
                }
            }
            Ok(r"\\.\pipe\openssh-ssh-agent".to_string())
        }
        #[cfg(not(windows))]
        {
            let sock = std::env::var("SSH_AUTH_SOCK")
                .context("SSH_AUTH_SOCK is not set and local_agent_socket is not configured")?;
            if sock.trim().is_empty() {
                anyhow::bail!("SSH_AUTH_SOCK is empty");
            }
            Ok(sock)
        }
    }

    /// Queries the built-in key ring and (unless disabled) the local OS SSH agent,
    /// returning all keys matching the configured `KeyFilterConfig`.
    pub async fn list_filtered_keys(&self) -> Result<Vec<PublicKey>> {
        let all_keys = self.list_all_keys().await?;
        Ok(filter_keys(all_keys, &self.filter))
    }

    /// Queries only the external OS SSH agent (`SSH2_AGENTC_REQUEST_IDENTITIES`).
    pub async fn list_os_agent_keys(&self) -> Result<Vec<PublicKey>> {
        #[cfg(unix)]
        {
            let path = self.resolve_endpoint()?;
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .with_context(|| format!("failed to connect to local SSH agent at {path}"))?;
            request_identities_over_stream(&mut stream).await
        }
        #[cfg(windows)]
        {
            let pipe_name = self.resolve_endpoint()?;
            let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&pipe_name)
                .with_context(|| {
                    format!("failed to connect to Windows OpenSSH agent pipe {pipe_name}")
                })?;
            request_identities_over_stream(&mut client).await
        }
    }

    /// Returns all available SSH public keys, merging built-in in-memory keys with keys from
    /// the local OS SSH agent (when enabled and reachable).
    pub async fn list_all_keys(&self) -> Result<Vec<PublicKey>> {
        let mut keys = self.list_loaded_keys();
        if self.disable_os_agent {
            return Ok(keys);
        }

        match self.list_os_agent_keys().await {
            Ok(os_keys) => {
                for k in os_keys {
                    if !keys.iter().any(|existing| existing.key_blob == k.key_blob) {
                        keys.push(k);
                    }
                }
                Ok(keys)
            }
            Err(e) => {
                if !keys.is_empty() {
                    tracing::debug!(
                        "OS SSH agent unavailable ({:#}); using {} built-in SSH key(s)",
                        e,
                        keys.len()
                    );
                    Ok(keys)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Signs `data` with `key_blob`, first checking `KeyFilterConfig`.
    /// If `key_blob` is loaded in the built-in in-memory key ring, signs directly in-process;
    /// otherwise delegates to the local OS SSH agent (`SSH2_AGENTC_SIGN_REQUEST`).
    pub async fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        // 1. Check built-in in-memory keys first
        let maybe_loaded = {
            let guard = self.loaded_keys.read().expect("loaded_keys lock poisoned");
            guard.iter().find(|k| k.key_blob() == key_blob).cloned()
        };

        if let Some(loaded_key) = maybe_loaded {
            if is_filter_active(&self.filter)
                && !key_matches_filter(&loaded_key.public_key_proto(), &self.filter)
            {
                anyhow::bail!("requested SSH key is not permitted by client key_filter policy");
            }
            return loaded_key
                .sign_ssh_data(data, flags)
                .context("built-in SSH key signing failed");
        }

        if self.disable_os_agent {
            anyhow::bail!(
                "requested SSH key is not loaded in built-in agent and OS ssh-agent is disabled"
            );
        }

        // 2. Fall back to local OS SSH agent
        if is_filter_active(&self.filter) {
            let allowed = self.list_filtered_keys().await?;
            if !allowed.iter().any(|k| k.key_blob == key_blob) {
                anyhow::bail!("requested SSH key is not permitted by client key_filter policy");
            }
        }

        #[cfg(unix)]
        {
            let path = self.resolve_endpoint()?;
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .with_context(|| format!("failed to connect to local SSH agent at {path}"))?;
            sign_over_stream(&mut stream, key_blob, data, flags).await
        }
        #[cfg(windows)]
        {
            let pipe_name = self.resolve_endpoint()?;
            let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&pipe_name)
                .with_context(|| {
                    format!("failed to connect to Windows OpenSSH agent pipe {pipe_name}")
                })?;
            sign_over_stream(&mut client, key_blob, data, flags).await
        }
    }
}

fn prompt_key_passphrase(label: &str) -> Result<String> {
    eprint!("Enter passphrase for SSH key '{label}': ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read passphrase from stdin")?;
    let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
    Ok(trimmed)
}

pub fn is_filter_active(filter: &KeyFilterConfig) -> bool {
    !filter.allowed_fingerprints.is_empty()
        || !filter.allowed_comment_substrings.is_empty()
        || !filter.excluded_fingerprints.is_empty()
}

pub fn filter_keys(keys: Vec<PublicKey>, filter: &KeyFilterConfig) -> Vec<PublicKey> {
    keys.into_iter()
        .filter(|k| key_matches_filter(k, filter))
        .collect()
}

pub fn key_matches_filter(key: &PublicKey, filter: &KeyFilterConfig) -> bool {
    if filter
        .excluded_fingerprints
        .iter()
        .any(|fp| fp.trim() == key.fingerprint_sha256)
    {
        return false;
    }

    let has_fp_allow = !filter.allowed_fingerprints.is_empty();
    let has_comment_allow = !filter.allowed_comment_substrings.is_empty();

    if !has_fp_allow && !has_comment_allow {
        return true;
    }

    let fp_match = filter
        .allowed_fingerprints
        .iter()
        .any(|fp| fp.trim() == key.fingerprint_sha256);
    let comment_match = filter
        .allowed_comment_substrings
        .iter()
        .any(|sub| !sub.is_empty() && key.comment.contains(sub));

    fp_match || comment_match
}

pub async fn request_identities_over_stream<S>(stream: &mut S) -> Result<Vec<PublicKey>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(stream, &[SSH2_AGENTC_REQUEST_IDENTITIES]).await?;
    let resp = read_frame(stream).await?;
    let Some((&msg_type, mut cursor)) = resp.split_first() else {
        anyhow::bail!("empty response from local SSH agent");
    };
    if msg_type != SSH2_AGENT_IDENTITIES_ANSWER {
        anyhow::bail!("unexpected response type {msg_type} from local SSH agent");
    }
    let count = read_u32(&mut cursor).context("truncated identities answer count")? as usize;
    let mut keys = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let blob = read_ssh_bytes(&mut cursor)
            .context("truncated key blob")?
            .to_vec();
        let comment_bytes = read_ssh_bytes(&mut cursor).context("truncated key comment")?;
        let comment = String::from_utf8_lossy(comment_bytes).into_owned();
        keys.push(parse_public_key_blob(blob, comment));
    }
    Ok(keys)
}

pub async fn sign_over_stream<S>(
    stream: &mut S,
    key_blob: &[u8],
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = Vec::with_capacity(13 + key_blob.len() + data.len());
    req.push(SSH2_AGENTC_SIGN_REQUEST);
    write_ssh_bytes(&mut req, key_blob);
    write_ssh_bytes(&mut req, data);
    req.extend_from_slice(&flags.to_be_bytes());

    write_frame(stream, &req).await?;
    let resp = read_frame(stream).await?;
    let Some((&msg_type, mut cursor)) = resp.split_first() else {
        anyhow::bail!("empty sign response from local SSH agent");
    };
    if msg_type == SSH_AGENT_FAILURE {
        anyhow::bail!("local SSH agent refused to sign (SSH_AGENT_FAILURE)");
    }
    if msg_type != SSH2_AGENT_SIGN_RESPONSE {
        anyhow::bail!("unexpected sign response type {msg_type} from local SSH agent");
    }
    let sig_blob = read_ssh_bytes(&mut cursor)
        .context("truncated signature blob from local SSH agent")?
        .to_vec();
    Ok(sig_blob)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AGENT_FRAME_LEN {
        anyhow::bail!("invalid frame length {len} from local SSH agent");
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_u32<'a>(cursor: &mut &'a [u8]) -> Option<u32> {
    if cursor.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Some(val)
}

fn read_ssh_bytes<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return None;
    }
    let slice = &cursor[..len];
    *cursor = &cursor[len..];
    Some(slice)
}
