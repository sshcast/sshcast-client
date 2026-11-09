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
    default_client_config_path, default_user_key_path, ClientConfig, ClientConfigFile, UserKeyFile,
};

pub const USER_KEY_TOKEN_PREFIX: &str = "scu1_";
pub const BUNDLE_ROOT_KEY_SUFFIX_SEP: &str = ".rk_";

#[derive(Debug, Clone)]
pub struct KeygenOutcome {
    pub key_path: PathBuf,
    pub user_id: String,
    pub user_pubkey_token: String,
}

/// Saves a User Root Ed25519 keypair to `user_key.toml` with `0600` permissions.
pub fn save_user_signing_key(
    signing_key: &SigningKey,
    output_path: Option<&Path>,
    force: bool,
) -> Result<KeygenOutcome> {
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

/// Generates a new User Root Ed25519 keypair and saves it to `user_key.toml` with `0600` permissions.
pub fn run_keygen(output_path: Option<&Path>, force: bool) -> Result<KeygenOutcome> {
    let signing_key = SigningKey::generate(&mut OsRng);
    save_user_signing_key(&signing_key, output_path, force)
}

/// Exports the local `user_key.toml` as a compact single-line `scu1_<base64>` token.
pub fn export_user_root_key(key_path: Option<&Path>) -> Result<String> {
    let sk = load_user_signing_key(key_path)?;
    Ok(format!(
        "{USER_KEY_TOKEN_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(sk.to_bytes())
    ))
}

/// Decodes a `scu1_<base64>` user root key token into an Ed25519 `SigningKey`.
pub fn decode_user_root_key_token(token: &str) -> Result<SigningKey> {
    let trimmed = token
        .split_whitespace()
        .find(|w| w.starts_with(USER_KEY_TOKEN_PREFIX))
        .unwrap_or(token.trim());
    let b64 = trimmed
        .strip_prefix(USER_KEY_TOKEN_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("user root key token must start with '{USER_KEY_TOKEN_PREFIX}'"))?;
    let seed_vec = URL_SAFE_NO_PAD
        .decode(b64.trim())
        .context("invalid base64 in scu1_ user root key token")?;
    let seed: [u8; 32] = seed_vec
        .try_into()
        .map_err(|_| anyhow::anyhow!("scu1_ user root key token must decode to 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Imports a `scu1_<base64>` user root key token, verifying it against `client.toml` if this
/// workstation is already enrolled, and writes `user_key.toml`.
pub fn import_user_root_key(
    token: &str,
    key_path: Option<&Path>,
    config_path: Option<&Path>,
    force: bool,
) -> Result<KeygenOutcome> {
    let signing_key = decode_user_root_key_token(token)?;
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let imported_user_id = derive_user_id(&pubkey_bytes);

    if let Ok(cfg) = ClientConfig::load(config_path) {
        if !cfg.grant.user_pubkey.is_empty()
            && cfg.grant.user_pubkey.as_slice() != pubkey_bytes.as_slice()
        {
            anyhow::bail!(
                "imported root key ({}) does not match this workstation's enrolled user ({}) in client.toml",
                imported_user_id,
                cfg.grant.user_id
            );
        }
    }

    save_user_signing_key(&signing_key, key_path, force)
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
    force: bool,
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

    if path.exists() && !force {
        anyhow::bail!(
            "client config already exists at {} (pass --bundle-only to mint a bundle for another machine, or --force to overwrite)",
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

/// Encodes an `EnrollmentBundle` into its `sc1_<base64>` token string.
/// If `bundle.grant.role == CLIENT` and `include_user_root_key` is `Some`, appends `.rk_<base64_seed>`
/// so the secondary workstation also receives `user_key.toml` upon initialization.
pub fn encode_enrollment_bundle_token(
    bundle: &EnrollmentBundle,
    include_user_root_key: Option<&SigningKey>,
) -> Result<String> {
    let base_token = bundle.encode().context("failed to encode enrollment bundle")?;
    if bundle.grant.role == NodeRole::Client as i32 {
        if let Some(user_sk) = include_user_root_key {
            let rk_b64 = URL_SAFE_NO_PAD.encode(user_sk.to_bytes());
            return Ok(format!("{base_token}{BUNDLE_ROOT_KEY_SUFFIX_SEP}{rk_b64}"));
        }
    }
    Ok(base_token)
}

/// Decodes an `sc1_<base64>` client bundle token, optionally extracting an embedded `.rk_<base64_seed>`
/// user root signing key and verifying that it matches `bundle.grant.user_pubkey`.
pub fn decode_enrollment_bundle_token(
    token: &str,
) -> Result<(EnrollmentBundle, Option<SigningKey>)> {
    let trimmed = token
        .split_whitespace()
        .find(|w| w.starts_with("sc1_"))
        .unwrap_or(token.trim());

    let (base_token, rk_part) = match trimmed.split_once(BUNDLE_ROOT_KEY_SUFFIX_SEP) {
        Some((b, r)) => (b, Some(r)),
        None => (trimmed, None),
    };

    let bundle = EnrollmentBundle::decode(base_token).context("failed to decode sc1_ bundle")?;

    let root_key = if let Some(rk_b64) = rk_part {
        let seed_vec = URL_SAFE_NO_PAD
            .decode(rk_b64.trim())
            .context("invalid base64 in embedded .rk_ root key suffix")?;
        let seed: [u8; 32] = seed_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("embedded .rk_ root key seed must decode to 32 bytes"))?;
        let sk = SigningKey::from_bytes(&seed);
        if sk.verifying_key().to_bytes().as_slice() != bundle.grant.user_pubkey.as_slice() {
            anyhow::bail!(
                "embedded .rk_ root key does not match the bundle's NodeGrant user_pubkey"
            );
        }
        Some(sk)
    } else {
        None
    };

    Ok((bundle, root_key))
}

/// Writes `client.toml` from a client `EnrollmentBundle` and, if an embedded user root `SigningKey`
/// is provided, also writes `user_key.toml`.
pub fn write_client_config_and_optional_root_key(
    bundle: &EnrollmentBundle,
    root_key: Option<&SigningKey>,
    config_path: Option<&Path>,
    key_path: Option<&Path>,
    force: bool,
) -> Result<(PathBuf, Option<PathBuf>)> {
    let cfg_out = write_client_config_from_bundle(bundle, config_path, force)?;
    let key_out = if let Some(sk) = root_key {
        let effective_key_path = key_path.map(Path::to_path_buf).or_else(|| {
            config_path.and_then(|c| c.parent().map(|p| p.join("user_key.toml")))
        });
        let out = save_user_signing_key(sk, effective_key_path.as_deref(), true)?;
        Some(out.key_path)
    } else {
        None
    };
    Ok((cfg_out, key_out))
}
