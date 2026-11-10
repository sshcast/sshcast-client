use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use prost::Message;
use serde::{Deserialize, Serialize};
use sshcast_proto::bundle::EnrollmentBundle;
use sshcast_proto::v1::NodeGrant;
use std::path::{Path, PathBuf};

fn default_heartbeat_secs() -> u64 {
    25 // 25 seconds (keeps Cloudflare/Nginx HTTP/2 streams warm)
}

pub fn default_zellij_listen_port() -> u16 {
    18080
}

pub fn default_stun_servers() -> Vec<String> {
    sshcast_proto::p2p::DEFAULT_STUN_SERVERS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyFilterConfig {
    /// If non-empty, only export local SSH keys whose SHA256 fingerprint matches one of these values.
    #[serde(default)]
    pub allowed_fingerprints: Vec<String>,
    /// If non-empty, only export local SSH keys whose comment contains one of these substrings.
    #[serde(default)]
    pub allowed_comment_substrings: Vec<String>,
    /// Fingerprints explicitly excluded from export to remote relays.
    #[serde(default)]
    pub excluded_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeyFile {
    pub user_id: String,
    /// `sc_pub_<hex>` representation for `server.toml` `allowed_user_pubkeys`
    pub user_pubkey_token: String,
    /// Base64 URL-safe encoded 32-byte Ed25519 root private key seed
    pub user_privkey_seed_b64: String,
}

impl UserKeyFile {
    pub fn load(path: Option<&Path>) -> Result<(PathBuf, Self)> {
        let p = match path {
            Some(p) => p.to_path_buf(),
            None => default_user_key_path()?,
        };
        let raw = std::fs::read_to_string(&p)
            .with_context(|| format!("failed to read user root key {}", p.display()))?;
        let parsed: Self =
            toml::from_str(&raw).with_context(|| format!("failed to parse {}", p.display()))?;
        Ok((p, parsed))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigFile {
    /// Coordinator server URLs (e.g. ["https://coord1.example.com", "https://coord2.example.com"])
    pub servers: Vec<String>,
    /// Base64 URL-safe encoded 32-byte Ed25519 private key seed for this workstation node
    pub node_privkey_seed_b64: String,
    /// Base64 URL-safe encoded protobuf `NodeGrant` (`role = NODE_ROLE_CLIENT`)
    pub grant_proto_b64: String,
    /// Optional local SSH agent socket path override (defaults to `$SSH_AUTH_SOCK` on Unix or `\\.\pipe\openssh-ssh-agent` on Windows)
    #[serde(default)]
    pub local_agent_socket: Option<String>,
    /// Application heartbeat interval in seconds (default: 25s)
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_interval_secs: u64,
    /// Force this workstation to be treated as active regardless of idle time
    #[serde(default)]
    pub force_active: bool,
    /// Optional key filtering rules
    #[serde(default)]
    pub key_filter: KeyFilterConfig,
    /// Local loopback HTTP port for Zellij Web dashboard & tunneling (`http://localhost:18080/`; 0 = disabled)
    #[serde(default = "default_zellij_listen_port")]
    pub zellij_listen_port: u16,
    /// STUN servers used for direct P2P hole-punching to Zellij-enabled relays
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,
    /// Optional paths to OpenSSH private key files (e.g. `["~/.ssh/id_ed25519"]`) to load into the built-in SSH agent
    #[serde(default)]
    pub ssh_key_files: Vec<String>,
    /// Optional inline OpenSSH private keys (`-----BEGIN OPENSSH PRIVATE KEY-----...`) to load into the built-in SSH agent
    #[serde(default)]
    pub ssh_keys_inline: Vec<String>,
    /// Disable querying the external OS SSH agent (`$SSH_AUTH_SOCK` / Windows `openssh-ssh-agent`) and use only built-in keys
    #[serde(default)]
    pub disable_os_agent: bool,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub servers: Vec<String>,
    pub node_signing_key: SigningKey,
    pub grant: NodeGrant,
    pub local_agent_socket: Option<String>,
    pub heartbeat_interval_secs: u64,
    pub force_active: bool,
    pub key_filter: KeyFilterConfig,
    pub zellij_listen_port: u16,
    pub stun_servers: Vec<String>,
    pub ssh_key_files: Vec<String>,
    pub ssh_keys_inline: Vec<String>,
    pub disable_os_agent: bool,
}

impl ClientConfigFile {
    pub fn from_bundle(bundle: &EnrollmentBundle) -> Self {
        let mut grant_bytes = Vec::new();
        bundle
            .grant
            .encode(&mut grant_bytes)
            .expect("prost encode cannot fail on Vec");
        Self {
            servers: bundle.servers.clone(),
            node_privkey_seed_b64: URL_SAFE_NO_PAD.encode(bundle.node_signing_key.to_bytes()),
            grant_proto_b64: URL_SAFE_NO_PAD.encode(grant_bytes),
            local_agent_socket: None,
            heartbeat_interval_secs: default_heartbeat_secs(),
            force_active: false,
            key_filter: KeyFilterConfig::default(),
            zellij_listen_port: default_zellij_listen_port(),
            stun_servers: default_stun_servers(),
            ssh_key_files: Vec::new(),
            ssh_keys_inline: Vec::new(),
            disable_os_agent: false,
        }
    }

    pub fn load(path: Option<&Path>) -> Result<(PathBuf, Self)> {
        let cfg_path = match path {
            Some(p) => p.to_path_buf(),
            None => default_client_config_path()?,
        };
        let raw = std::fs::read_to_string(&cfg_path)
            .with_context(|| format!("failed to read client config {}", cfg_path.display()))?;
        let parsed: Self = toml::from_str(&raw).context("failed to parse client.toml")?;
        Ok((cfg_path, parsed))
    }

    pub fn save(&self, path: Option<&Path>) -> Result<PathBuf> {
        if self.servers.is_empty() {
            anyhow::bail!("client configuration must specify at least one coordinator server URL");
        }
        let cfg_path = match path {
            Some(p) => p.to_path_buf(),
            None => default_client_config_path()?,
        };
        if let Some(parent) = cfg_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        let toml_str = toml::to_string_pretty(self).context("failed to serialize client.toml")?;
        std::fs::write(&cfg_path, &toml_str)
            .with_context(|| format!("failed to write {}", cfg_path.display()))?;
        Ok(cfg_path)
    }
}

impl ClientConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let cfg_path = match path {
            Some(p) => p.to_path_buf(),
            None => default_client_config_path()?,
        };
        let raw = std::fs::read_to_string(&cfg_path)
            .with_context(|| format!("failed to read client config {}", cfg_path.display()))?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let file: ClientConfigFile =
            toml::from_str(raw).context("failed to parse client.toml")?;
        Self::from_config_file(file)
    }

    pub fn from_config_file(file: ClientConfigFile) -> Result<Self> {
        if file.servers.is_empty() {
            anyhow::bail!("client configuration must specify at least one coordinator server URL");
        }
        let seed_vec = URL_SAFE_NO_PAD
            .decode(file.node_privkey_seed_b64.trim())
            .context("invalid base64 in node_privkey_seed_b64")?;
        let seed: [u8; 32] = seed_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("node_privkey_seed_b64 must decode to 32 bytes"))?;
        let node_signing_key = SigningKey::from_bytes(&seed);

        let grant_bytes = URL_SAFE_NO_PAD
            .decode(file.grant_proto_b64.trim())
            .context("invalid base64 in grant_proto_b64")?;
        let grant = NodeGrant::decode(grant_bytes.as_slice())
            .context("failed to decode NodeGrant protobuf")?;

        Ok(Self {
            servers: file.servers,
            node_signing_key,
            grant,
            local_agent_socket: file.local_agent_socket,
            heartbeat_interval_secs: file.heartbeat_interval_secs.max(1),
            force_active: file.force_active,
            key_filter: file.key_filter,
            zellij_listen_port: file.zellij_listen_port,
            stun_servers: if file.stun_servers.is_empty() {
                default_stun_servers()
            } else {
                file.stun_servers
            },
            ssh_key_files: file.ssh_key_files,
            ssh_keys_inline: file.ssh_keys_inline,
            disable_os_agent: file.disable_os_agent,
        })
    }
}

pub fn expand_tilde_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix("~\\")) {
        if let Ok(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(trimmed)
}

pub fn home_dir() -> Result<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    if let Some(up) = std::env::var_os("USERPROFILE") {
        if !up.is_empty() {
            return Ok(PathBuf::from(up));
        }
    }
    anyhow::bail!("neither HOME nor USERPROFILE environment variable is set")
}

pub fn default_config_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg).join("sshcast"));
        }
    }
    Ok(home_dir()?.join(".config").join("sshcast"))
}

pub fn default_user_key_path() -> Result<PathBuf> {
    Ok(default_config_dir()?.join("user_key.toml"))
}

pub fn default_client_config_path() -> Result<PathBuf> {
    Ok(default_config_dir()?.join("client.toml"))
}
