use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::crypto::{derive_user_id, sign_node_grant, verify_node_grant};
use sockcast_proto::v1::{NodeGrant, NodeRole};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{
    default_client_config_path, default_user_key_path, ClientConfigFile, UserKeyFile,
};

#[derive(Debug, Clone)]
pub struct KeygenOutcome {
    pub key_path: PathBuf,
    pub user_id: String,
    pub user_pubkey_token: String,
}

/// Generates a new User Root Ed25519 keypair and saves it to `user_key.toml` with `0600` permissions.
pub fn run_keygen(output_path: Option<&Path>, force: bool) -> Result<KeygenOutcome> {
    let path = match output_path {
        Some(p) => p.to_path_buf(),
        None => default_user_key_path()?,
    };

    if path.exists() && !force {
        anyhow::bail!(
            "user root key already exists at {} (pass --force to overwrite)",
            path.display()
        );
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let user_id = derive_user_id(&pubkey_bytes);
    let user_pubkey_token = format!("sc_pub_{}", hex::encode(pubkey_bytes));

    let file = UserKeyFile {
        user_id: user_id.clone(),
        user_pubkey_token: user_pubkey_token.clone(),
        user_privkey_seed_b64: URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
    };

    let toml_str = toml::to_string_pretty(&file).context("failed to serialize user_key.toml")?;
    std::fs::write(&path, &toml_str)
        .with_context(|| format!("failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set 0600 permissions on {}", path.display()))?;
    }

    Ok(KeygenOutcome {
        key_path: path,
        user_id,
        user_pubkey_token,
    })
}

pub fn load_user_signing_key(key_path: Option<&Path>) -> Result<SigningKey> {
    let path = match key_path {
        Some(p) => p.to_path_buf(),
        None => default_user_key_path()?,
    };
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read user root key at {} (run `sockcast-client keygen` first)",
            path.display()
        )
    })?;
    let file: UserKeyFile =
        toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))?;
    let seed_vec = URL_SAFE_NO_PAD
        .decode(file.user_privkey_seed_b64.trim())
        .context("invalid base64 in user_privkey_seed_b64")?;
    let seed: [u8; 32] = seed_vec
        .try_into()
        .map_err(|_| anyhow::anyhow!("user_privkey_seed_b64 must decode to 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Mints a signed `NodeGrant` and returns an `EnrollmentBundle` (`sc1_<base64>`) for a target relay or workstation.
pub fn mint_enrollment_bundle(
    user_signing_key: &SigningKey,
    node_id: &str,
    role: NodeRole,
    servers: Vec<String>,
    expires_in_days: u64,
) -> Result<EnrollmentBundle> {
    if node_id.trim().is_empty() {
        anyhow::bail!("node_id cannot be empty");
    }
    if servers.is_empty() {
        anyhow::bail!("at least one --server URL is required");
    }

    let node_signing_key = SigningKey::generate(&mut OsRng);
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at_unix_sec = if expires_in_days == 0 {
        0
    } else {
        now_sec + expires_in_days * 86_400
    };

    let mut grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: node_id.trim().to_string(),
        role: role as i32,
        node_pubkey: node_signing_key.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec,
        expires_at_unix_sec,
        user_signature: Vec::new(),
    };
    sign_node_grant(&mut grant, user_signing_key);

    Ok(EnrollmentBundle::new(servers, node_signing_key, grant))
}

/// Writes `client.toml` from a client `EnrollmentBundle` (used by `grant-client` or `init --bundle`).
pub fn write_client_config_from_bundle(
    bundle: &EnrollmentBundle,
    config_path: Option<&Path>,
) -> Result<PathBuf> {
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    verify_node_grant(&bundle.grant, now_sec)
        .context("client bundle NodeGrant signature verification failed")?;

    if bundle.grant.role != NodeRole::Client as i32 {
        anyhow::bail!(
            "enrollment bundle role is not CLIENT (got {})",
            bundle.grant.role
        );
    }

    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => default_client_config_path()?,
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let cfg_file = ClientConfigFile::from_bundle(bundle);
    let toml_str = toml::to_string_pretty(&cfg_file).context("failed to serialize client.toml")?;
    std::fs::write(&path, &toml_str)
        .with_context(|| format!("failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set 0600 permissions on {}", path.display()))?;
    }

    Ok(path)
}
