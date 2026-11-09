use anyhow::{Context, Result};
use sockcast_proto::ssh::{parse_public_key_blob, LoadedSshKey, SshKeyError};
use sockcast_proto::v1::PublicKey;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{expand_tilde_path, ClientConfig, ClientConfigFile, KeyFilterConfig};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub const MAX_AGENT_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
struct AgentConnectorOptions {
    socket_override: Option<String>,
    filter: KeyFilterConfig,
    disable_os_agent: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedKeyEntry {
    pub key: LoadedSshKey,
    /// Origin of this built-in key (e.g. `~/.ssh/id_ed25519`, `inline`, or `memory`)
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldKeyDisplayItem {
    /// `true` if held in the built-in in-memory agent; `false` if from the external OS `ssh-agent`
    pub is_builtin: bool,
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub comment: String,
    pub source: String,
    pub display_line: String,
}

#[derive(Debug, Clone)]
pub struct LocalAgentConnector {
    options: Arc<RwLock<AgentConnectorOptions>>,
    loaded_keys: Arc<RwLock<Vec<LoadedKeyEntry>>>,
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
            options: Arc::new(RwLock::new(AgentConnectorOptions {
                socket_override,
                filter,
                disable_os_agent,
            })),
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
                "inline",
                interactive_passphrase_prompt,
            )?;
            tracing::info!(
                "Loaded built-in inline SSH key: {} {} ({})",
                pk.key_type,
                pk.fingerprint_sha256,
                pk.comment
            );
        }

        let mut all_paths: Vec<(String, PathBuf)> = cfg
            .ssh_key_files
            .iter()
            .map(|s| (s.clone(), expand_tilde_path(s)))
            .collect();
        for extra in extra_key_files {
            let expanded = expand_tilde_path(&extra.to_string_lossy());
            if !all_paths.iter().any(|(_, p)| p == &expanded) {
                all_paths.push((extra.to_string_lossy().to_string(), expanded));
            }
        }

        for (raw_label, path) in &all_paths {
            let pk = connector.load_private_key_file_with_source_interactive(
                path,
                raw_label,
                interactive_passphrase_prompt,
            )?;
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

    /// Synchronizes connector options (`socket_override`, `filter`, `disable_os_agent`) and
    /// loads any newly configured keys from `ClientConfig` without wiping keys already unlocked
    /// in memory during the current session.
    pub fn sync_from_client_config(&self, cfg: &ClientConfig) {
        {
            let mut opts = self.options.write().expect("options lock poisoned");
            opts.socket_override = cfg.local_agent_socket.clone();
            opts.filter = cfg.key_filter.clone();
            opts.disable_os_agent = cfg.disable_os_agent;
        }

        for inline_pem in &cfg.ssh_keys_inline {
            if let Ok(key) = LoadedSshKey::parse_openssh_pem(inline_pem, None) {
                self.add_loaded_key_with_source(key, "inline");
            }
        }

        for raw_path in &cfg.ssh_key_files {
            let expanded = expand_tilde_path(raw_path);
            let already_loaded = {
                let guard = self.loaded_keys.read().expect("loaded_keys lock poisoned");
                guard.iter().any(|e| {
                    e.source == *raw_path || expand_tilde_path(&e.source) == expanded
                })
            };
            if !already_loaded {
                if let Ok(pem) = std::fs::read_to_string(&expanded) {
                    if let Ok(key) = LoadedSshKey::parse_openssh_pem(&pem, None) {
                        self.add_loaded_key_with_source(key, raw_path.clone());
                    }
                }
            }
        }
    }

    /// Adds an already-parsed `LoadedSshKey` into the built-in key ring, replacing any existing
    /// entry with the same public `key_blob`.
    pub fn add_loaded_key(&self, key: LoadedSshKey) -> PublicKey {
        self.add_loaded_key_with_source(key, "memory")
    }

    pub fn add_loaded_key_with_source(
        &self,
        key: LoadedSshKey,
        source: impl Into<String>,
    ) -> PublicKey {
        let pk = key.public_key_proto();
        let source_str = source.into();
        let mut guard = self.loaded_keys.write().expect("loaded_keys lock poisoned");
        if let Some(existing) = guard.iter_mut().find(|e| e.key.key_blob() == pk.key_blob) {
            existing.key = key;
            existing.source = source_str;
        } else {
            guard.push(LoadedKeyEntry {
                key,
                source: source_str,
            });
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
        Ok(self.add_loaded_key_with_source(key, "inline"))
    }

    /// Loads an OpenSSH private key file from disk using an optional passphrase.
    pub fn load_private_key_file(
        &self,
        path: &Path,
        passphrase: Option<&str>,
    ) -> Result<PublicKey> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read SSH private key file {}", path.display()))?;
        let key = LoadedSshKey::parse_openssh_pem(&pem, passphrase)
            .with_context(|| format!("failed to load SSH private key from {}", path.display()))?;
        Ok(self.add_loaded_key_with_source(key, path.display().to_string()))
    }

    /// Loads an OpenSSH private key file from disk, checking `SOCKCAST_SSH_PASSPHRASE` or prompting
    /// interactively on the terminal if the key is passphrase-protected.
    pub fn load_private_key_file_interactive(
        &self,
        path: &Path,
        allow_prompt: bool,
    ) -> Result<PublicKey> {
        let source = path.display().to_string();
        self.load_private_key_file_with_source_interactive(path, &source, allow_prompt)
    }

    fn load_private_key_file_with_source_interactive(
        &self,
        path: &Path,
        source: &str,
        allow_prompt: bool,
    ) -> Result<PublicKey> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read SSH private key file {}", path.display()))?;
        let label = path.display().to_string();
        self.load_private_key_pem_with_prompt(&pem, &label, source, allow_prompt)
    }

    fn load_private_key_pem_with_prompt(
        &self,
        pem: &str,
        label: &str,
        source: &str,
        allow_prompt: bool,
    ) -> Result<PublicKey> {
        match LoadedSshKey::parse_openssh_pem(pem, None) {
            Ok(key) => Ok(self.add_loaded_key_with_source(key, source)),
            Err(SshKeyError::PassphraseRequired) => {
                if let Ok(env_pass) = std::env::var("SOCKCAST_SSH_PASSPHRASE") {
                    if !env_pass.is_empty() {
                        let key = LoadedSshKey::parse_openssh_pem(pem, Some(&env_pass))
                            .with_context(|| {
                                format!(
                                    "failed to unlock SSH private key {label} with SOCKCAST_SSH_PASSPHRASE"
                                )
                            })?;
                        return Ok(self.add_loaded_key_with_source(key, source));
                    }
                }
                if !allow_prompt {
                    anyhow::bail!(
                        "SSH private key {label} is encrypted; set SOCKCAST_SSH_PASSPHRASE or unlock interactively"
                    );
                }
                let pass = prompt_key_passphrase(label)?;
                let key = LoadedSshKey::parse_openssh_pem(pem, Some(&pass))
                    .with_context(|| format!("failed to unlock SSH private key {label}"))?;
                Ok(self.add_loaded_key_with_source(key, source))
            }
            Err(e) => Err(anyhow::Error::new(e))
                .with_context(|| format!("failed to parse SSH private key {label}")),
        }
    }

    /// Removes a key from the built-in key ring by SHA256 fingerprint, comment, or source path.
    pub fn remove_loaded_key(&self, identifier: &str) -> bool {
        let target = identifier.trim();
        let mut guard = self.loaded_keys.write().expect("loaded_keys lock poisoned");
        let before = guard.len();
        guard.retain(|e| {
            e.key.fingerprint_sha256() != target
                && e.key.comment() != target
                && e.source != target
        });
        guard.len() != before
    }

    /// Lists all public keys currently loaded in the built-in in-memory agent.
    pub fn list_loaded_keys(&self) -> Vec<PublicKey> {
        let guard = self.loaded_keys.read().expect("loaded_keys lock poisoned");
        guard.iter().map(|e| e.key.public_key_proto()).collect()
    }

    pub fn list_loaded_key_entries(&self) -> Vec<LoadedKeyEntry> {
        self.loaded_keys
            .read()
            .expect("loaded_keys lock poisoned")
            .clone()
    }

    pub fn loaded_key_count(&self) -> usize {
        self.loaded_keys
            .read()
            .expect("loaded_keys lock poisoned")
            .len()
    }

    pub fn is_loaded_key(&self, key_blob: &[u8]) -> bool {
        let guard = self.loaded_keys.read().expect("loaded_keys lock poisoned");
        guard.iter().any(|e| e.key.key_blob() == key_blob)
    }

    pub fn is_os_agent_disabled(&self) -> bool {
        self.options
            .read()
            .expect("options lock poisoned")
            .disable_os_agent
    }

    pub fn set_disable_os_agent(&self, disable: bool) {
        self.options
            .write()
            .expect("options lock poisoned")
            .disable_os_agent = disable;
    }

    pub fn filter_config(&self) -> KeyFilterConfig {
        self.options
            .read()
            .expect("options lock poisoned")
            .filter
            .clone()
    }

    pub fn resolve_endpoint(&self) -> Result<String> {
        let socket_override = self
            .options
            .read()
            .expect("options lock poisoned")
            .socket_override
            .clone();
        if let Some(s) = &socket_override {
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
        let filter = self.filter_config();
        Ok(filter_keys(all_keys, &filter))
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
        if self.is_os_agent_disabled() {
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
        let filter = self.filter_config();

        // 1. Check built-in in-memory keys first
        let maybe_loaded = {
            let guard = self.loaded_keys.read().expect("loaded_keys lock poisoned");
            guard
                .iter()
                .find(|e| e.key.key_blob() == key_blob)
                .map(|e| e.key.clone())
        };

        if let Some(loaded_key) = maybe_loaded {
            if is_filter_active(&filter)
                && !key_matches_filter(&loaded_key.public_key_proto(), &filter)
            {
                anyhow::bail!("requested SSH key is not permitted by client key_filter policy");
            }
            return loaded_key
                .sign_ssh_data(data, flags)
                .context("built-in SSH key signing failed");
        }

        if self.is_os_agent_disabled() {
            anyhow::bail!(
                "requested SSH key is not loaded in built-in agent and OS ssh-agent is disabled"
            );
        }

        // 2. Fall back to local OS SSH agent
        if is_filter_active(&filter) {
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

    // ========================================================================
    // UI Helpers for System Tray / Menu Bar SSH Key Management Dialogs
    // ========================================================================

    /// Returns a snapshot of all held SSH keys (`[Built-in]` and `[OS Agent]`) formatted for
    /// display in the System Tray / Menu Bar SSH Keys management window.
    pub fn query_held_keys_for_ui(&self) -> Vec<HeldKeyDisplayItem> {
        let builtin_entries = self.list_loaded_key_entries();
        let mut items = Vec::new();
        let mut seen_blobs = Vec::new();

        for entry in builtin_entries {
            let pk = entry.key.public_key_proto();
            seen_blobs.push(pk.key_blob.clone());
            let comment_part = if pk.comment.is_empty() {
                "no comment".to_string()
            } else {
                pk.comment.clone()
            };
            let display_line = format!(
                "[Built-in] {} {} ({}) — {}",
                pk.key_type, pk.fingerprint_sha256, comment_part, entry.source
            );
            items.push(HeldKeyDisplayItem {
                is_builtin: true,
                key_type: pk.key_type,
                fingerprint_sha256: pk.fingerprint_sha256,
                comment: pk.comment,
                source: entry.source,
                display_line,
            });
        }

        if !self.is_os_agent_disabled() {
            let clone_self = self.clone();
            let os_keys = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?;
                rt.block_on(async move {
                    tokio::time::timeout(
                        Duration::from_millis(1200),
                        clone_self.list_os_agent_keys(),
                    )
                    .await
                    .ok()?
                    .ok()
                })
            })
            .join()
            .ok()
            .flatten()
            .unwrap_or_default();

            for pk in os_keys {
                if seen_blobs.iter().any(|b| b == &pk.key_blob) {
                    continue;
                }
                let comment_part = if pk.comment.is_empty() {
                    "no comment".to_string()
                } else {
                    pk.comment.clone()
                };
                let display_line = format!(
                    "[OS Agent] {} {} ({})",
                    pk.key_type, pk.fingerprint_sha256, comment_part
                );
                items.push(HeldKeyDisplayItem {
                    is_builtin: false,
                    key_type: pk.key_type,
                    fingerprint_sha256: pk.fingerprint_sha256,
                    comment: pk.comment,
                    source: "os-agent".to_string(),
                    display_line,
                });
            }
        }

        items
    }

    /// Loads an OpenSSH private key file into the built-in agent (unlocking with `passphrase` if needed)
    /// and persists the file path into `client.toml`'s `ssh_key_files`.
    pub fn ui_add_key_from_file(
        &self,
        raw_path: &str,
        passphrase: &str,
        cfg_path: Option<&Path>,
    ) -> Result<PublicKey> {
        let trimmed_path = raw_path.trim();
        if trimmed_path.is_empty() {
            anyhow::bail!("Please enter the path to an OpenSSH private key file (e.g. ~/.ssh/id_ed25519)");
        }
        let expanded = expand_tilde_path(trimmed_path);
        let pem = std::fs::read_to_string(&expanded).with_context(|| {
            format!(
                "Could not read SSH private key file '{}'",
                expanded.display()
            )
        })?;
        let pass_opt = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase)
        };
        let key = LoadedSshKey::parse_openssh_pem(&pem, pass_opt).map_err(|e| match e {
            SshKeyError::PassphraseRequired => anyhow::anyhow!(
                "This SSH private key is encrypted. Please enter its passphrase in the Passphrase field."
            ),
            SshKeyError::InvalidPassphrase => {
                anyhow::anyhow!("Incorrect passphrase for '{}'.", expanded.display())
            }
            other => anyhow::Error::new(other),
        })?;

        let pk = self.add_loaded_key_with_source(key, trimmed_path.to_string());

        if let Ok((resolved_cfg_path, mut cfg_file)) = ClientConfigFile::load(cfg_path) {
            if !cfg_file.ssh_key_files.iter().any(|p| p.trim() == trimmed_path) {
                cfg_file.ssh_key_files.push(trimmed_path.to_string());
                cfg_file.save(Some(&resolved_cfg_path))?;
            }
        }

        Ok(pk)
    }

    /// Loads an OpenSSH private key PEM string (e.g. pasted from clipboard) into the built-in agent
    /// and persists its unencrypted OpenSSH PEM representation in `client.toml`'s `ssh_keys_inline`.
    pub fn ui_add_key_from_pem(
        &self,
        pem: &str,
        passphrase: &str,
        cfg_path: Option<&Path>,
    ) -> Result<PublicKey> {
        let trimmed = pem.trim();
        if trimmed.is_empty() {
            anyhow::bail!("Clipboard does not contain an OpenSSH private key");
        }
        let pass_opt = if passphrase.is_empty() {
            None
        } else {
            Some(passphrase)
        };
        let key = LoadedSshKey::parse_openssh_pem(trimmed, pass_opt).map_err(|e| match e {
            SshKeyError::PassphraseRequired => anyhow::anyhow!(
                "The pasted SSH private key is encrypted. Please enter its passphrase in the Passphrase field first."
            ),
            SshKeyError::InvalidPassphrase => {
                anyhow::anyhow!("Incorrect passphrase for the pasted SSH private key.")
            }
            other => anyhow::Error::new(other),
        })?;

        let exported_pem = key.to_openssh_pem();
        let pk = self.add_loaded_key_with_source(key, "inline".to_string());

        if let Ok((resolved_cfg_path, mut cfg_file)) = ClientConfigFile::load(cfg_path) {
            let fp = pk.fingerprint_sha256.clone();
            let already_inline = cfg_file.ssh_keys_inline.iter().any(|existing| {
                LoadedSshKey::parse_openssh_pem(existing, None)
                    .map(|k| k.fingerprint_sha256() == fp)
                    .unwrap_or(false)
            });
            if !already_inline {
                cfg_file.ssh_keys_inline.push(exported_pem);
                cfg_file.save(Some(&resolved_cfg_path))?;
            }
        }

        Ok(pk)
    }

    /// Removes a built-in SSH key from memory and from `client.toml` (`ssh_key_files` and `ssh_keys_inline`).
    pub fn ui_remove_builtin_key(
        &self,
        item: &HeldKeyDisplayItem,
        cfg_path: Option<&Path>,
    ) -> Result<bool> {
        if !item.is_builtin {
            anyhow::bail!(
                "Selected key belongs to the external OS ssh-agent. Use `ssh-add -d` or check 'Use Built-in Keys Only'."
            );
        }
        let removed = self.remove_loaded_key(&item.fingerprint_sha256);
        if let Ok((resolved_cfg_path, mut cfg_file)) = ClientConfigFile::load(cfg_path) {
            let target_expanded = expand_tilde_path(&item.source);
            let before_files = cfg_file.ssh_key_files.len();
            cfg_file.ssh_key_files.retain(|p| {
                p.trim() != item.source && expand_tilde_path(p) != target_expanded
            });
            let before_inline = cfg_file.ssh_keys_inline.len();
            cfg_file.ssh_keys_inline.retain(|pem| {
                LoadedSshKey::parse_openssh_pem(pem, None)
                    .map(|k| k.fingerprint_sha256() != item.fingerprint_sha256)
                    .unwrap_or(true)
            });
            if cfg_file.ssh_key_files.len() != before_files
                || cfg_file.ssh_keys_inline.len() != before_inline
            {
                cfg_file.save(Some(&resolved_cfg_path))?;
            }
        }
        Ok(removed)
    }

    /// Updates `disable_os_agent` in memory and persists it to `client.toml`.
    pub fn ui_set_disable_os_agent(&self, disable: bool, cfg_path: Option<&Path>) -> Result<()> {
        self.set_disable_os_agent(disable);
        if let Ok((resolved_cfg_path, mut cfg_file)) = ClientConfigFile::load(cfg_path) {
            cfg_file.disable_os_agent = disable;
            cfg_file.save(Some(&resolved_cfg_path))?;
        }
        Ok(())
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
