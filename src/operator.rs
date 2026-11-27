use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT};
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use prost::Message;
use rand::rngs::OsRng;
use rustls::pki_types::ServerName;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sshcast_proto::bundle::{decode_user_cert_token, EnrollmentBundle};
use sshcast_proto::crypto::{create_node_auth, derive_user_id, verify_user_cert};
use sshcast_proto::dns::{normalize_coordinator_url, resolve_swarm_discovery};
use sshcast_proto::v1::{NodeGrant, NodeRole, UserCert};
use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::pairing::{
    parse_user_pubkey_token, PairingHandoffEnvelope, RecoveryVaultBlob, RequesterPairingKeys,
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const ENROLL_POLL_INTERVAL: Duration = Duration::from_secs(2);
const ENROLL_POLL_TIMEOUT: Duration = Duration::from_secs(300);

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn tls_client_config() -> Arc<rustls::ClientConfig> {
    static TLS_CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(TLS_CFG.get_or_init(|| {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("valid default TLS protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();
        Arc::new(cfg)
    }))
}

/// Returns `true` if `cert` is present, has a non-zero expiration, and is expired or
/// within the renewal window (half of total TTL, floored at 3600s when TTL >= 7200s).
pub fn cert_needs_renewal(cert: Option<&UserCert>, now_sec: u64) -> bool {
    let Some(cert) = cert else {
        return false;
    };
    if cert.expires_at_unix_sec == 0 {
        return false;
    }
    if now_sec >= cert.expires_at_unix_sec {
        return true;
    }
    let remaining = cert.expires_at_unix_sec - now_sec;
    let total = cert
        .expires_at_unix_sec
        .saturating_sub(cert.issued_at_unix_sec);
    let half = total / 2;
    let threshold = if total >= 7200 { half.max(3600) } else { half };
    remaining <= threshold
}

/// Resolves an operator URL from an explicit override or `_sshcast.<domain>` DNS TXT discovery.
pub fn resolve_operator_url(explicit: Option<&str>, servers: &[String]) -> Option<String> {
    if let Some(raw) = explicit {
        if let Some(norm) = normalize_coordinator_url(raw) {
            return Some(norm);
        }
    }
    resolve_swarm_discovery(servers).operator_url
}

async fn send_http_json_with_timeout(
    method: Method,
    full_url: &str,
    bearer_token: Option<&str>,
    body_json: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, String)> {
    let parsed = Url::parse(full_url).with_context(|| format!("invalid URL {full_url}"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("unsupported URL scheme {scheme:?} in {full_url}");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host in {full_url}"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("missing port in {full_url}"))?;
    let host_header = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_string(),
    };

    tokio::time::timeout(timeout, async {
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("failed to connect to {host}:{port}"))?;

        let body_vec = body_json.map(|b| b.to_vec()).unwrap_or_default();
        let mut req_builder = Request::builder()
            .method(method)
            .uri(path_and_query)
            .header(HOST, &host_header)
            .header(USER_AGENT, concat!("sshcast-client/", env!("CARGO_PKG_VERSION")));
        if body_json.is_some() {
            req_builder = req_builder.header(CONTENT_TYPE, "application/json");
        }
        if let Some(tok) = bearer_token {
            req_builder = req_builder.header(AUTHORIZATION, format!("Bearer {tok}"));
        }
        let req = req_builder.body(Full::new(Cursor::new(body_vec)))?;

        if scheme == "https" {
            let connector = TlsConnector::from(tls_client_config());
            let sni = ServerName::try_from(host.clone())
                .with_context(|| format!("invalid TLS SNI hostname {host:?}"))?;
            let tls_stream = connector
                .connect(sni, tcp)
                .await
                .with_context(|| format!("TLS handshake failed for {host}:{port}"))?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let resp = sender.send_request(req).await?;
            let status = resp.status().as_u16();
            let collected = resp.into_body().collect().await?;
            let text = String::from_utf8_lossy(&collected.to_bytes()).into_owned();
            Ok((status, text))
        } else {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let resp = sender.send_request(req).await?;
            let status = resp.status().as_u16();
            let collected = resp.into_body().collect().await?;
            let text = String::from_utf8_lossy(&collected.to_bytes()).into_owned();
            Ok((status, text))
        }
    })
    .await
    .with_context(|| format!("HTTP request to {full_url} timed out after {timeout:?}"))?
}

async fn send_http_json(
    method: Method,
    full_url: &str,
    bearer_token: Option<&str>,
    body_json: Option<&[u8]>,
) -> Result<(u16, String)> {
    send_http_json_with_timeout(method, full_url, bearer_token, body_json, HTTP_TIMEOUT).await
}

/// Builds a base64-encoded `NodeAuth` with `user_cert = None` so operator endpoints can
/// authenticate requests even when a workstation's `UserCert` is missing or expired.
pub fn build_node_auth_b64(grant: &NodeGrant, node_signing_key: &SigningKey) -> Result<String> {
    let mut auth_grant = grant.clone();
    auth_grant.user_cert = None;
    let auth = create_node_auth(auth_grant, node_signing_key, now_unix_ms())?;
    Ok(STANDARD.encode(auth.encode_to_vec()))
}

#[derive(Debug, Deserialize)]
struct OperatorEnvelope<T> {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    status: String,
    #[serde(default)]
    error: String,
    #[serde(flatten)]
    data: T,
}

#[derive(Debug, Default, Deserialize)]
struct EmptyOperatorBody {}

#[derive(Debug, Deserialize)]
struct CertTokenBody {
    #[serde(default)]
    cert_token: String,
}

#[derive(Debug, Deserialize)]
struct PairingPollBody {
    #[serde(default)]
    requests: Vec<PendingDevicePairingRequest>,
}

#[derive(Debug, Deserialize)]
struct RecoveryVaultUploadBody {
    #[serde(default)]
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct RecoveryVaultStatusBody {
    #[serde(default)]
    configured: bool,
    #[serde(default)]
    updated_at: i64,
}

async fn post_operator_json_with_timeout<T: DeserializeOwned>(
    operator_url: &str,
    path: &str,
    bearer_token: Option<&str>,
    payload: &serde_json::Value,
    timeout: Duration,
    action_label: &str,
) -> Result<T> {
    let body = serde_json::to_vec(payload)?;
    let url = format!("{}{}", operator_url.trim_end_matches('/'), path);
    let (status, resp_text) =
        send_http_json_with_timeout(Method::POST, &url, bearer_token, Some(&body), timeout).await?;
    let parsed: OperatorEnvelope<T> = serde_json::from_str(&resp_text).with_context(|| {
        format!("unexpected non-JSON response from operator {url} (HTTP {status}): {resp_text}")
    })?;
    if status >= 400 || !parsed.ok {
        let detail = if !parsed.error.is_empty() {
            parsed.error
        } else if !parsed.status.is_empty() {
            format!("HTTP {status} (status={})", parsed.status)
        } else {
            format!("HTTP {status}")
        };
        anyhow::bail!("{action_label} rejected: {detail}");
    }
    Ok(parsed.data)
}

/// Requests a renewed `UserCert` from `<operator_url>/api/v1/renew` using `NodeAuth`
/// built over a cloned `NodeGrant` with `user_cert = None` so even expired certs can renew.
pub async fn renew_user_cert_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
) -> Result<UserCert> {
    let payload = json!({
        "node_auth_proto_b64": build_node_auth_b64(grant, node_signing_key)?,
    });
    let body: CertTokenBody = post_operator_json_with_timeout(
        operator_url,
        "/api/v1/renew",
        None,
        &payload,
        HTTP_TIMEOUT,
        "operator renewal",
    )
    .await?;

    let cert = decode_user_cert_token(&body.cert_token)
        .context("failed to decode sc_cert_ token from operator")?;
    verify_user_cert(&cert, &grant.user_pubkey, now_unix_sec())
        .context("operator returned invalid UserCert")?;
    Ok(cert)
}

#[derive(Debug, Deserialize)]
struct EnrollStartResponse {
    ok: bool,
    #[serde(default)]
    state: String,
    #[serde(default)]
    poll_token: String,
    #[serde(default)]
    auth_url: String,
    #[serde(default)]
    error: String,
}

#[derive(Debug, Deserialize)]
struct EnrollPollResponse {
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    cert_token: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    pairing_id: String,
    #[serde(default)]
    existing_user_pubkey: String,
    #[serde(default)]
    github_login: String,
    #[serde(default)]
    has_recovery_vault: bool,
    #[serde(default)]
    recovery_vault: Option<RecoveryVaultBlob>,
    #[serde(default)]
    approver_node_id: String,
    #[serde(default)]
    approver_eph_x25519_pub_b64: String,
    #[serde(default)]
    approver_signature_b64: String,
    #[serde(default)]
    handoff_nonce_b64: String,
    #[serde(default)]
    encrypted_handoff_b64: String,
}

/// Terminal error returned by [`poll_enrollment_once`] for non-recoverable rejections
/// (`banned`, `denied`, `canceled`, `expired`, or 4xx operator errors).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TerminalEnrollError(String);

/// Returns `true` if `err` represents a terminal enrollment rejection that should stop polling.
pub fn is_terminal_enroll_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|e| e.downcast_ref::<TerminalEnrollError>().is_some())
}

/// Active GitHub OAuth + pairing enrollment session initiated on this workstation.
pub struct StartedEnrollment {
    pub operator_url: String,
    pub servers: Vec<String>,
    pub state: String,
    pub poll_token: String,
    pub auth_url: String,
    pub node_name: String,
    pub key_path: PathBuf,
    pub config_path: PathBuf,
    existing_local_user_sk: Option<SigningKey>,
    candidate_user_sk: SigningKey,
    pairing_keys: Option<RequesterPairingKeys>,
    node_override_provided: bool,
    explicit_operator_url_provided: bool,
}

impl fmt::Debug for StartedEnrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartedEnrollment")
            .field("operator_url", &self.operator_url)
            .field("servers", &self.servers)
            .field("state", &self.state)
            .field("auth_url", &self.auth_url)
            .field("node_name", &self.node_name)
            .field("key_path", &self.key_path)
            .field("config_path", &self.config_path)
            .field("has_existing_local_user_sk", &self.existing_local_user_sk.is_some())
            .field("has_pairing_keys", &self.pairing_keys.is_some())
            .finish()
    }
}

/// Details surfaced when GitHub OAuth matches an existing Sshcast root key.
#[derive(Debug, Clone)]
pub struct PendingPairingInfo {
    pub pairing_id: String,
    pub existing_user_pubkey_token: String,
    pub existing_user_pubkey: [u8; 32],
    pub github_login: String,
    pub sas_code: String,
    pub has_recovery_vault: bool,
    pub recovery_vault: Option<RecoveryVaultBlob>,
}

/// Single poll result returned by [`poll_enrollment_once`].
#[derive(Debug, Clone)]
pub enum EnrollPollStep {
    Pending,
    AwaitingApproval,
    Approved { cert_token: String },
    PairingRequired(PendingPairingInfo),
    Paired {
        pairing_id: String,
        existing_user_pubkey: [u8; 32],
        approver_node_id: String,
        envelope: PairingHandoffEnvelope,
    },
    Denied(String),
}

/// Starts GitHub OAuth + pairing-capable enrollment against `sshcast-operator` without
/// writing `user_key.toml` until enrollment completes.
#[allow(clippy::too_many_arguments)]
pub async fn start_github_enrollment<F>(
    servers: &[String],
    explicit_operator_url: Option<&str>,
    node_override: Option<&str>,
    key_file: Option<&Path>,
    config_file: Option<&Path>,
    open_browser: bool,
    mut on_url: F,
) -> Result<StartedEnrollment>
where
    F: FnMut(&str),
{
    let effective_servers = if servers.is_empty() {
        vec!["sshcast.net".to_string()]
    } else {
        servers.to_vec()
    };

    let key_path = match key_file {
        Some(p) => p.to_path_buf(),
        None => crate::config::default_user_key_path()?,
    };
    let config_path = match config_file {
        Some(p) => p.to_path_buf(),
        None => crate::config::default_client_config_path()?,
    };

    let existing_local_user_sk = match crate::config::UserKeyFile::load(Some(&key_path)) {
        Ok(_) => Some(crate::enroll::load_user_signing_key(Some(&key_path))?),
        Err(_) if !key_path.exists() => None,
        Err(e) => return Err(e),
    };
    let candidate_user_sk = existing_local_user_sk
        .clone()
        .unwrap_or_else(|| SigningKey::generate(&mut OsRng));
    let user_pubkey_token = format!(
        "sc_pub_{}",
        hex::encode(candidate_user_sk.verifying_key().to_bytes())
    );

    let node_override_provided = node_override
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let node_name = node_override
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_workstation_hostname);

    let explicit_operator_url_provided = explicit_operator_url
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let explicit_opt = explicit_operator_url.map(|s| s.to_string());
    let servers_clone = effective_servers.clone();
    let op_url = tokio::task::spawn_blocking(move || {
        resolve_operator_url(explicit_opt.as_deref(), &servers_clone)
    })
    .await?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "could not discover operator URL via _sshcast DNS TXT for {:?}; pass --operator https://...",
            effective_servers
        )
    })?;

    let pairing_keys = RequesterPairingKeys::generate()?;
    let base = op_url.trim_end_matches('/');
    let start_url = format!("{base}/api/v1/enroll/start");
    let start_body = serde_json::to_vec(&json!({
        "user_pubkey": user_pubkey_token,
        "supports_pairing": true,
        "node_name": node_name,
        "os_name": crate::presence::current_os_name(),
        "node_pubkey_b64": pairing_keys.node_pubkey_b64(),
        "eph_x25519_pub_b64": pairing_keys.eph_x25519_pub_b64(),
    }))?;

    let (status, start_text) =
        send_http_json(Method::POST, &start_url, None, Some(&start_body)).await?;
    let start_resp: EnrollStartResponse = serde_json::from_str(&start_text).with_context(|| {
        format!("unexpected non-JSON response from {start_url} (HTTP {status}): {start_text}")
    })?;
    if status >= 400 || !start_resp.ok {
        anyhow::bail!(
            "failed to start GitHub enrollment: {}",
            if start_resp.error.is_empty() {
                format!("HTTP {status}")
            } else {
                start_resp.error
            }
        );
    }

    on_url(&start_resp.auth_url);
    if open_browser {
        if let Err(e) = webbrowser::open(&start_resp.auth_url) {
            tracing::debug!(
                "Could not automatically open browser ({}): user can open URL manually",
                e
            );
        }
    }

    Ok(StartedEnrollment {
        operator_url: op_url,
        servers: effective_servers,
        state: start_resp.state,
        poll_token: start_resp.poll_token,
        auth_url: start_resp.auth_url,
        node_name,
        key_path,
        config_path,
        existing_local_user_sk,
        candidate_user_sk,
        pairing_keys: Some(pairing_keys),
        node_override_provided,
        explicit_operator_url_provided,
    })
}

/// Polls `/api/v1/enroll/poll` once for an in-flight [`StartedEnrollment`].
pub async fn poll_enrollment_once(started: &StartedEnrollment) -> Result<EnrollPollStep> {
    let base = started.operator_url.trim_end_matches('/');
    let mut poll_url = Url::parse(&format!("{base}/api/v1/enroll/poll"))
        .with_context(|| format!("invalid operator URL {}", started.operator_url))?;
    poll_url.query_pairs_mut().append_pair("state", &started.state);

    let (poll_status, poll_text) = send_http_json(
        Method::GET,
        poll_url.as_str(),
        Some(&started.poll_token),
        None,
    )
    .await?;

    let parsed: EnrollPollResponse = match serde_json::from_str(&poll_text) {
        Ok(p) => p,
        Err(e) => {
            if (400..500).contains(&poll_status) {
                return Err(anyhow::Error::new(TerminalEnrollError(format!(
                    "enrollment failed (HTTP {poll_status}): {poll_text}"
                ))));
            }
            anyhow::bail!("enrollment poll returned non-JSON HTTP {poll_status}: {e}");
        }
    };

    if matches!(
        parsed.status.as_str(),
        "banned" | "denied" | "canceled" | "expired"
    ) {
        let detail = if parsed.error.is_empty() {
            parsed.status.clone()
        } else {
            format!("{}: {}", parsed.status, parsed.error)
        };
        return Err(anyhow::Error::new(TerminalEnrollError(format!(
            "enrollment rejected ({detail})"
        ))));
    }

    let ok_flag = parsed.ok.unwrap_or(poll_status < 400);
    if poll_status >= 400 || !ok_flag {
        let err_msg = if !parsed.error.is_empty() {
            parsed.error
        } else if !parsed.status.is_empty() {
            format!("HTTP {poll_status} (status={})", parsed.status)
        } else {
            format!("HTTP {poll_status}")
        };
        if poll_status >= 500 {
            anyhow::bail!("enrollment failed: {err_msg}");
        }
        return Err(anyhow::Error::new(TerminalEnrollError(format!(
            "enrollment failed: {err_msg}"
        ))));
    }

    match parsed.status.as_str() {
        "pending" | "" => Ok(EnrollPollStep::Pending),
        "awaiting_approval" => Ok(EnrollPollStep::AwaitingApproval),
        "approved" => {
            if parsed.cert_token.trim().is_empty() {
                anyhow::bail!("operator returned approved status without cert_token");
            }
            Ok(EnrollPollStep::Approved {
                cert_token: parsed.cert_token,
            })
        }
        "pairing_required" => {
            if parsed.pairing_id.trim().is_empty() {
                anyhow::bail!("operator returned pairing_required without pairing_id");
            }
            let existing_user_pubkey = parse_user_pubkey_token(&parsed.existing_user_pubkey)
                .context("operator returned invalid existing_user_pubkey in pairing_required")?;
            let pairing_keys = started
                .pairing_keys
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("pairing keys already consumed"))?;
            let sas_code = pairing_keys.sas_code(&existing_user_pubkey);
            Ok(EnrollPollStep::PairingRequired(PendingPairingInfo {
                pairing_id: parsed.pairing_id,
                existing_user_pubkey_token: parsed.existing_user_pubkey,
                existing_user_pubkey,
                github_login: parsed.github_login,
                sas_code,
                has_recovery_vault: parsed.has_recovery_vault,
                recovery_vault: parsed.recovery_vault,
            }))
        }
        "paired" => {
            if parsed.pairing_id.trim().is_empty() {
                anyhow::bail!("operator returned paired status without pairing_id");
            }
            let existing_user_pubkey = parse_user_pubkey_token(&parsed.existing_user_pubkey)
                .context("operator returned invalid existing_user_pubkey in paired response")?;
            let envelope = PairingHandoffEnvelope {
                approver_eph_x25519_pub_b64: parsed.approver_eph_x25519_pub_b64,
                approver_signature_b64: parsed.approver_signature_b64,
                handoff_nonce_b64: parsed.handoff_nonce_b64,
                encrypted_handoff_b64: parsed.encrypted_handoff_b64,
            };
            Ok(EnrollPollStep::Paired {
                pairing_id: parsed.pairing_id,
                existing_user_pubkey,
                approver_node_id: parsed.approver_node_id,
                envelope,
            })
        }
        other => {
            tracing::debug!("Ignoring unknown enrollment poll status {other:?}");
            Ok(EnrollPollStep::Pending)
        }
    }
}

fn finalize_with_user_signing_key(
    started: &StartedEnrollment,
    user_sk: &SigningKey,
    cert_token: &str,
    force_save_key: bool,
    force_rewrite_client_cfg: bool,
) -> Result<LoginOutcome> {
    let expected_pub = user_sk.verifying_key().to_bytes();
    let pre_cert = decode_user_cert_token(cert_token)
        .context("failed to decode sc_cert_ user certificate token")?;
    verify_user_cert(&pre_cert, &expected_pub, now_unix_sec())
        .context("operator certificate verification failed")?;

    if force_save_key || !started.key_path.exists() || started.existing_local_user_sk.is_none() {
        crate::enroll::save_user_signing_key(user_sk, Some(&started.key_path), force_save_key)?;
    }

    let mut enrolled_new_client = false;
    if !started.config_path.exists() || started.node_override_provided || force_rewrite_client_cfg
    {
        let bundle = crate::enroll::mint_enrollment_bundle_with_cert(
            user_sk,
            &started.node_name,
            NodeRole::Client,
            started.servers.clone(),
            0,
            Some(pre_cert),
        )?;
        let mut cfg_file = crate::config::ClientConfigFile::from_bundle(&bundle);
        cfg_file.operator_url = Some(started.operator_url.clone());
        cfg_file.save(Some(&started.config_path))?;
        enrolled_new_client = true;
    } else if let Ok((loaded_path, mut cfg_file)) =
        crate::config::ClientConfigFile::load(Some(&started.config_path))
    {
        if started.explicit_operator_url_provided || cfg_file.operator_url.is_none() {
            cfg_file.operator_url = Some(started.operator_url.clone());
            cfg_file.save(Some(&loaded_path))?;
        }
    }

    let (_, _, parsed_cert) = crate::enroll::import_user_cert(
        cert_token,
        Some(&started.key_path),
        Some(&started.config_path),
    )?;

    Ok(LoginOutcome {
        user_id: derive_user_id(&expected_pub),
        user_pubkey_token: format!("sc_pub_{}", hex::encode(expected_pub)),
        operator_url: started.operator_url.clone(),
        cert: parsed_cert,
        key_path: started.key_path.clone(),
        config_path: started.config_path.clone(),
        enrolled_new_client,
    })
}

/// Finalizes GitHub enrollment when the operator approves the workstation's candidate
/// (or existing local) root key directly.
pub fn finalize_new_or_same_key_enrollment(
    started: &StartedEnrollment,
    cert_token: &str,
) -> Result<LoginOutcome> {
    finalize_with_user_signing_key(started, &started.candidate_user_sk, cert_token, false, false)
}

/// Completes enrollment on Workstation B after an existing workstation approves pairing
/// and delivers the encrypted [`PairingHandoffEnvelope`].
pub async fn complete_paired_enrollment(
    mut started: StartedEnrollment,
    existing_user_pubkey: &[u8; 32],
    pairing_id: &str,
    envelope: &PairingHandoffEnvelope,
) -> Result<LoginOutcome> {
    let pairing_keys = started
        .pairing_keys
        .take()
        .ok_or_else(|| anyhow::anyhow!("pairing keys already consumed"))?;
    let verified =
        pairing_keys.decrypt_and_verify_handoff(pairing_id, existing_user_pubkey, envelope)?;

    let servers = if verified.servers.is_empty() {
        started.servers.clone()
    } else {
        verified.servers.clone()
    };
    let op_url = verified
        .operator_url
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| started.operator_url.clone());

    let mut grant = verified.grant;
    let now_sec = now_unix_sec();
    let cert =
        if grant.user_cert.is_none() || cert_needs_renewal(grant.user_cert.as_ref(), now_sec) {
            let renewed =
                renew_user_cert_http(&op_url, &grant, &verified.node_signing_key).await?;
            grant.user_cert = Some(renewed.clone());
            renewed
        } else {
            grant.user_cert.clone().expect("checked user_cert is_some")
        };

    let key_out = crate::enroll::save_user_signing_key(
        &verified.user_signing_key,
        Some(&started.key_path),
        true,
    )?;
    let bundle = EnrollmentBundle::new(servers, verified.node_signing_key, grant);
    let mut cfg_file = crate::config::ClientConfigFile::from_bundle(&bundle);
    cfg_file.operator_url = Some(op_url.clone());
    cfg_file.save(Some(&started.config_path))?;
    crate::enroll::persist_user_cert(&cert, Some(&started.key_path), Some(&started.config_path))?;

    Ok(LoginOutcome {
        user_id: key_out.user_id,
        user_pubkey_token: key_out.user_pubkey_token,
        operator_url: op_url,
        cert,
        key_path: started.key_path,
        config_path: started.config_path,
        enrolled_new_client: true,
    })
}

/// Unlocks the user's root signing key from `info.recovery_vault` using `passphrase`,
/// enrolls this workstation, fetches a fresh `UserCert`, and cancels the pending pairing session.
pub async fn unlock_with_recovery_passphrase(
    started: &StartedEnrollment,
    info: &PendingPairingInfo,
    passphrase: &str,
) -> Result<LoginOutcome> {
    let vault = info.recovery_vault.as_ref().ok_or_else(|| {
        anyhow::anyhow!("operator did not include an encrypted recovery vault blob")
    })?;
    let user_sk =
        crate::pairing::decrypt_recovery_vault(vault, &info.existing_user_pubkey, passphrase)?;

    let mut bundle = crate::enroll::mint_enrollment_bundle_with_cert(
        &user_sk,
        &started.node_name,
        NodeRole::Client,
        started.servers.clone(),
        0,
        None,
    )?;
    let cert =
        renew_user_cert_http(&started.operator_url, &bundle.grant, &bundle.node_signing_key)
            .await?;
    bundle.grant.user_cert = Some(cert.clone());

    let key_out =
        crate::enroll::save_user_signing_key(&user_sk, Some(&started.key_path), true)?;
    let mut cfg_file = crate::config::ClientConfigFile::from_bundle(&bundle);
    cfg_file.operator_url = Some(started.operator_url.clone());
    cfg_file.save(Some(&started.config_path))?;
    crate::enroll::persist_user_cert(&cert, Some(&started.key_path), Some(&started.config_path))?;

    let _ = cancel_enrollment_pairing(started).await;

    Ok(LoginOutcome {
        user_id: key_out.user_id,
        user_pubkey_token: key_out.user_pubkey_token,
        operator_url: started.operator_url.clone(),
        cert,
        key_path: started.key_path.clone(),
        config_path: started.config_path.clone(),
        enrolled_new_client: true,
    })
}

/// Confirms replacing a lost account root key on the operator (`POST /api/v1/enroll/replace`)
/// and writes the new `user_key.toml` + `client.toml`.
pub async fn confirm_replace_lost_root_key(started: &StartedEnrollment) -> Result<LoginOutcome> {
    let payload = json!({ "state": started.state });
    let body: CertTokenBody = post_operator_json_with_timeout(
        &started.operator_url,
        "/api/v1/enroll/replace",
        Some(&started.poll_token),
        &payload,
        HTTP_TIMEOUT,
        "root key replacement",
    )
    .await?;

    if body.cert_token.trim().is_empty() {
        anyhow::bail!("operator returned replace approval without cert_token");
    }

    finalize_with_user_signing_key(
        started,
        &started.candidate_user_sk,
        &body.cert_token,
        true,
        true,
    )
}

/// Cancels an in-flight enrollment/pairing session on the operator (`POST /api/v1/enroll/cancel`).
pub async fn cancel_enrollment_pairing(started: &StartedEnrollment) -> Result<()> {
    let payload = json!({ "state": started.state });
    let _: EmptyOperatorBody = post_operator_json_with_timeout(
        &started.operator_url,
        "/api/v1/enroll/cancel",
        Some(&started.poll_token),
        &payload,
        HTTP_TIMEOUT,
        "enrollment cancel",
    )
    .await?;
    Ok(())
}

/// Runs browser-based GitHub OAuth enrollment against `sshcast-operator` and returns the minted `sc_cert_...` token.
pub async fn enroll_with_github<F>(
    operator_url: &str,
    user_pubkey_token: &str,
    open_browser: bool,
    mut on_url: F,
) -> Result<String>
where
    F: FnMut(&str),
{
    let base = operator_url.trim_end_matches('/');
    let start_url = format!("{base}/api/v1/enroll/start");
    let start_body = serde_json::to_vec(&json!({
        "user_pubkey": user_pubkey_token,
    }))?;

    let (status, start_text) =
        send_http_json(Method::POST, &start_url, None, Some(&start_body)).await?;
    let start_resp: EnrollStartResponse = serde_json::from_str(&start_text).with_context(|| {
        format!("unexpected non-JSON response from {start_url} (HTTP {status}): {start_text}")
    })?;
    if status >= 400 || !start_resp.ok {
        anyhow::bail!(
            "failed to start GitHub enrollment: {}",
            if start_resp.error.is_empty() {
                format!("HTTP {status}")
            } else {
                start_resp.error
            }
        );
    }

    on_url(&start_resp.auth_url);
    if open_browser {
        if let Err(e) = webbrowser::open(&start_resp.auth_url) {
            tracing::debug!(
                "Could not automatically open browser ({}): user can open URL manually",
                e
            );
        }
    }

    let mut poll_url = Url::parse(&format!("{base}/api/v1/enroll/poll"))
        .with_context(|| format!("invalid operator URL {operator_url}"))?;
    poll_url
        .query_pairs_mut()
        .append_pair("state", &start_resp.state);
    let deadline = tokio::time::Instant::now() + ENROLL_POLL_TIMEOUT;
    let mut logged_awaiting = false;

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for GitHub OAuth enrollment completion");
        }
        tokio::time::sleep(ENROLL_POLL_INTERVAL).await;

        let (poll_status, poll_text) = match send_http_json(
            Method::GET,
            poll_url.as_str(),
            Some(&start_resp.poll_token),
            None,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("Enrollment poll transient error: {e:#}");
                continue;
            }
        };

        let parsed: EnrollPollResponse = match serde_json::from_str(&poll_text) {
            Ok(p) => p,
            Err(_) => {
                if poll_status >= 400 {
                    anyhow::bail!("enrollment poll returned HTTP {poll_status}: {poll_text}");
                }
                continue;
            }
        };

        if poll_status >= 400 || parsed.ok == Some(false) {
            let err_msg = if parsed.error.is_empty() {
                format!("HTTP {poll_status}")
            } else {
                parsed.error
            };
            anyhow::bail!("enrollment failed: {err_msg}");
        }

        match parsed.status.as_str() {
            "approved" => {
                if parsed.cert_token.trim().is_empty() {
                    anyhow::bail!("operator returned approved status without cert_token");
                }
                return Ok(parsed.cert_token);
            }
            "banned" | "denied" | "canceled" | "expired" => {
                let reason = if parsed.error.is_empty() {
                    parsed.status
                } else {
                    parsed.error
                };
                anyhow::bail!("enrollment rejected ({reason})");
            }
            "awaiting_approval" => {
                if !logged_awaiting {
                    logged_awaiting = true;
                    tracing::info!(
                        "GitHub sign-in completed; waiting for operator approval in /console/..."
                    );
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoginOutcome {
    pub user_id: String,
    pub user_pubkey_token: String,
    pub operator_url: String,
    pub cert: UserCert,
    pub key_path: PathBuf,
    pub config_path: PathBuf,
    pub enrolled_new_client: bool,
}

/// Returns a sanitized default workstation hostname for enrollment.
pub fn default_workstation_hostname() -> String {
    for key in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(val) = std::env::var(key) {
            let clean = val.trim().trim_end_matches(".local").to_ascii_lowercase();
            if !clean.is_empty() {
                return clean;
            }
        }
    }
    if let Ok(raw) = std::fs::read_to_string("/etc/hostname") {
        let clean = raw.trim().trim_end_matches(".local").to_ascii_lowercase();
        if !clean.is_empty() {
            return clean;
        }
    }
    if let Ok(out) = std::process::Command::new("hostname").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            let clean = s.trim().trim_end_matches(".local").to_ascii_lowercase();
            if !clean.is_empty() {
                return clean;
            }
        }
    }
    "workstation".to_string()
}

/// Shared GitHub OAuth login + UserCert import + initial client.toml enrollment workflow
/// used by non-interactive callers (such as the Windows/macOS tray dialogs).
#[allow(clippy::too_many_arguments)]
pub async fn login_and_enroll<F>(
    servers: &[String],
    explicit_operator_url: Option<&str>,
    node_override: Option<&str>,
    key_file: Option<&Path>,
    config_file: Option<&Path>,
    open_browser: bool,
    on_url: F,
) -> Result<LoginOutcome>
where
    F: FnMut(&str),
{
    let started = start_github_enrollment(
        servers,
        explicit_operator_url,
        node_override,
        key_file,
        config_file,
        open_browser,
        on_url,
    )
    .await?;

    let deadline = tokio::time::Instant::now() + ENROLL_POLL_TIMEOUT;
    let mut logged_awaiting = false;

    loop {
        if tokio::time::Instant::now() >= deadline {
            let _ = cancel_enrollment_pairing(&started).await;
            anyhow::bail!("timed out waiting for GitHub OAuth enrollment completion");
        }
        tokio::time::sleep(ENROLL_POLL_INTERVAL).await;

        let step = match poll_enrollment_once(&started).await {
            Ok(s) => s,
            Err(e) if is_terminal_enroll_error(&e) => return Err(e),
            Err(e) => {
                tracing::debug!("Enrollment poll transient error: {e:#}");
                continue;
            }
        };

        match step {
            EnrollPollStep::Pending => {}
            EnrollPollStep::AwaitingApproval => {
                if !logged_awaiting {
                    logged_awaiting = true;
                    tracing::info!(
                        "GitHub sign-in completed; waiting for operator approval in /console/..."
                    );
                }
            }
            EnrollPollStep::Approved { cert_token } => {
                return finalize_new_or_same_key_enrollment(&started, &cert_token);
            }
            EnrollPollStep::Paired {
                pairing_id,
                existing_user_pubkey,
                envelope,
                ..
            } => {
                return complete_paired_enrollment(
                    started,
                    &existing_user_pubkey,
                    &pairing_id,
                    &envelope,
                )
                .await;
            }
            EnrollPollStep::PairingRequired(info) => {
                let _ = cancel_enrollment_pairing(&started).await;
                anyhow::bail!(
                    "GitHub account @{} already has an existing Sshcast root key ({}). Run `sshcast-client login` in a terminal to approve device pairing (verification code {}) or unlock with your recovery passphrase.",
                    info.github_login,
                    info.existing_user_pubkey_token,
                    info.sas_code
                );
            }
            EnrollPollStep::Denied(reason) => {
                anyhow::bail!("enrollment rejected ({reason})");
            }
        }
    }
}

/// Pending pairing request returned by `POST /api/v1/pairing/poll` for an existing workstation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDevicePairingRequest {
    pub pairing_id: String,
    pub node_name: String,
    pub os_name: String,
    pub github_login: String,
    pub node_pubkey_b64: String,
    pub eph_x25519_pub_b64: String,
    pub expires_at: i64,
    pub created_at: i64,
}

/// Long-polls `POST <operator_url>/api/v1/pairing/poll` for pending pairing requests targeting
/// this user's account.
pub async fn poll_pending_pairing_requests_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
    timeout_secs: u64,
) -> Result<Vec<PendingDevicePairingRequest>> {
    let payload = json!({
        "node_auth_proto_b64": build_node_auth_b64(grant, node_signing_key)?,
        "timeout_secs": timeout_secs,
    });
    let body: PairingPollBody = post_operator_json_with_timeout(
        operator_url,
        "/api/v1/pairing/poll",
        None,
        &payload,
        Duration::from_secs(timeout_secs.saturating_add(10)),
        "pairing poll",
    )
    .await?;
    Ok(body.requests)
}

/// Approves or denies a pending pairing request on `POST <operator_url>/api/v1/pairing/respond`.
pub async fn respond_to_pairing_request_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
    pairing_id: &str,
    approved: bool,
    envelope: Option<&PairingHandoffEnvelope>,
) -> Result<()> {
    let node_auth_b64 = build_node_auth_b64(grant, node_signing_key)?;
    let payload = if approved {
        let env = envelope.ok_or_else(|| {
            anyhow::anyhow!("encrypted PairingHandoffEnvelope is required when approved is true")
        })?;
        json!({
            "node_auth_proto_b64": node_auth_b64,
            "pairing_id": pairing_id,
            "approved": true,
            "approver_eph_x25519_pub_b64": env.approver_eph_x25519_pub_b64,
            "approver_signature_b64": env.approver_signature_b64,
            "handoff_nonce_b64": env.handoff_nonce_b64,
            "encrypted_handoff_b64": env.encrypted_handoff_b64,
        })
    } else {
        json!({
            "node_auth_proto_b64": node_auth_b64,
            "pairing_id": pairing_id,
            "approved": false,
        })
    };

    let _: EmptyOperatorBody = post_operator_json_with_timeout(
        operator_url,
        "/api/v1/pairing/respond",
        None,
        &payload,
        HTTP_TIMEOUT,
        "pairing response",
    )
    .await?;
    Ok(())
}

/// Uploads a passphrase-encrypted [`RecoveryVaultBlob`] to `POST <operator_url>/api/v1/recovery-vault`.
pub async fn upload_recovery_vault_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
    vault: &RecoveryVaultBlob,
) -> Result<i64> {
    let payload = json!({
        "node_auth_proto_b64": build_node_auth_b64(grant, node_signing_key)?,
        "vault": vault,
    });
    let body: RecoveryVaultUploadBody = post_operator_json_with_timeout(
        operator_url,
        "/api/v1/recovery-vault",
        None,
        &payload,
        HTTP_TIMEOUT,
        "recovery vault upload",
    )
    .await?;
    Ok(body.updated_at)
}

/// Queries whether a recovery vault is configured on `POST <operator_url>/api/v1/recovery-vault/status`.
pub async fn get_recovery_vault_status_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
) -> Result<(bool, i64)> {
    let payload = json!({
        "node_auth_proto_b64": build_node_auth_b64(grant, node_signing_key)?,
    });
    let body: RecoveryVaultStatusBody = post_operator_json_with_timeout(
        operator_url,
        "/api/v1/recovery-vault/status",
        None,
        &payload,
        HTTP_TIMEOUT,
        "recovery vault status",
    )
    .await?;
    Ok((body.configured, body.updated_at))
}

/// Deletes any stored recovery vault from `POST <operator_url>/api/v1/recovery-vault/delete`.
pub async fn delete_recovery_vault_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
) -> Result<()> {
    let payload = json!({
        "node_auth_proto_b64": build_node_auth_b64(grant, node_signing_key)?,
    });
    let _: EmptyOperatorBody = post_operator_json_with_timeout(
        operator_url,
        "/api/v1/recovery-vault/delete",
        None,
        &payload,
        HTTP_TIMEOUT,
        "recovery vault deletion",
    )
    .await?;
    Ok(())
}
