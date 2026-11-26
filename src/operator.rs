use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT};
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use prost::Message;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde_json::json;
use sshcast_proto::bundle::decode_user_cert_token;
use sshcast_proto::crypto::{create_node_auth, verify_user_cert};
use sshcast_proto::dns::{normalize_coordinator_url, resolve_swarm_discovery};
use sshcast_proto::v1::{NodeGrant, NodeRole, UserCert};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

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

async fn send_http_json(
    method: Method,
    full_url: &str,
    bearer_token: Option<&str>,
    body_json: Option<&[u8]>,
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

    tokio::time::timeout(HTTP_TIMEOUT, async {
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
    .with_context(|| format!("HTTP request to {full_url} timed out after {HTTP_TIMEOUT:?}"))?
}

#[derive(Debug, Deserialize)]
struct RenewResponse {
    ok: bool,
    #[serde(default)]
    cert_token: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    error: String,
}

/// Requests a renewed `UserCert` from `<operator_url>/api/v1/renew` using `NodeAuth`
/// built over a cloned `NodeGrant` with `user_cert = None` so even expired certs can renew.
pub async fn renew_user_cert_http(
    operator_url: &str,
    grant: &NodeGrant,
    node_signing_key: &SigningKey,
) -> Result<UserCert> {
    let mut auth_grant = grant.clone();
    auth_grant.user_cert = None;

    let auth = create_node_auth(auth_grant, node_signing_key, now_unix_ms())?;
    let payload = json!({
        "node_auth_proto_b64": STANDARD.encode(auth.encode_to_vec()),
    });
    let body = serde_json::to_vec(&payload)?;
    let url = format!("{}/api/v1/renew", operator_url.trim_end_matches('/'));

    let (status, resp_text) = send_http_json(Method::POST, &url, None, Some(&body)).await?;
    let parsed: RenewResponse = serde_json::from_str(&resp_text).with_context(|| {
        format!("unexpected non-JSON response from operator {url} (HTTP {status}): {resp_text}")
    })?;
    if status >= 400 || !parsed.ok {
        let detail = if parsed.error.is_empty() {
            format!("HTTP {status} (status={})", parsed.status)
        } else {
            parsed.error
        };
        anyhow::bail!("operator renewal rejected: {detail}");
    }

    let cert = decode_user_cert_token(&parsed.cert_token)
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
    ok: bool,
    #[serde(default)]
    status: String,
    #[serde(default)]
    cert_token: String,
    #[serde(default)]
    error: String,
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
            tracing::debug!("Could not automatically open browser ({}): user can open URL manually", e);
        }
    }

    let poll_url = format!("{base}/api/v1/enroll/poll?state={}", start_resp.state);
    let deadline = tokio::time::Instant::now() + ENROLL_POLL_TIMEOUT;
    let mut logged_awaiting = false;

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for GitHub OAuth enrollment completion");
        }
        tokio::time::sleep(ENROLL_POLL_INTERVAL).await;

        let (poll_status, poll_text) = match send_http_json(
            Method::GET,
            &poll_url,
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

        if poll_status >= 400 || !parsed.ok {
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
            "banned" | "denied" => {
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
/// used by both CLI `sshcast-client login` and the Windows/macOS tray dialogs.
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
    let effective_servers = if servers.is_empty() {
        vec!["sshcast.net".to_string()]
    } else {
        servers.to_vec()
    };

    let (kp, uk) = match crate::config::UserKeyFile::load(key_file) {
        Ok(pair) => pair,
        Err(_) => {
            let out = crate::enroll::run_keygen(key_file, false)?;
            crate::config::UserKeyFile::load(Some(&out.key_path))?
        }
    };

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

    let cert_token =
        enroll_with_github(&op_url, &uk.user_pubkey_token, open_browser, on_url).await?;

    let (_, _, parsed_cert) =
        crate::enroll::import_user_cert(&cert_token, Some(&kp), config_file)?;

    let target_cfg_path = match config_file {
        Some(p) => p.to_path_buf(),
        None => crate::config::default_client_config_path()?,
    };

    let mut enrolled_new_client = false;
    if !target_cfg_path.exists() || node_override.is_some() {
        let node_name = node_override
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default_workstation_hostname);
        let user_sk = crate::enroll::load_user_signing_key(Some(&kp))?;
        let bundle = crate::enroll::mint_enrollment_bundle_with_cert(
            &user_sk,
            &node_name,
            NodeRole::Client,
            effective_servers,
            0,
            Some(parsed_cert.clone()),
        )?;
        let mut cfg_file = crate::config::ClientConfigFile::from_bundle(&bundle);
        cfg_file.operator_url = Some(op_url.clone());
        cfg_file.save(Some(&target_cfg_path))?;
        enrolled_new_client = true;
    } else if let Ok((loaded_path, mut cfg_file)) =
        crate::config::ClientConfigFile::load(Some(&target_cfg_path))
    {
        if explicit_operator_url.is_some() || cfg_file.operator_url.is_none() {
            cfg_file.operator_url = Some(op_url.clone());
            cfg_file.save(Some(&loaded_path))?;
        }
    }

    Ok(LoginOutcome {
        user_id: uk.user_id,
        user_pubkey_token: uk.user_pubkey_token,
        operator_url: op_url,
        cert: parsed_cert,
        key_path: kp,
        config_path: target_cfg_path,
        enrolled_new_client,
    })
}
