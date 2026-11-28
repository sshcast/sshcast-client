use crate::pairing::{
    compute_pairing_sas_code, create_encrypted_pairing_handoff_with_entropy,
    decrypt_recovery_vault, decrypt_recovery_vault_with_derived_key, derive_recovery_vault_key,
    encrypt_recovery_vault_with_derived_key, encrypt_recovery_vault_with_entropy,
    parse_user_pubkey_token, PairingHandoffEnvelope, RecoveryVaultBlob, RequesterPairingKeys,
    ScryptParams, VaultDecryptError,
};
use crate::prompt::PromptDetails;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::SigningKey;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sshcast_proto::bundle::{decode_user_cert_token, EnrollmentBundle, BUNDLE_PREFIX};
use sshcast_proto::crypto::{
    create_node_auth_with_nonce, derive_user_id, sign_node_grant, verify_node_grant,
    verify_sign_request, verify_user_cert, CryptoError,
};
use sshcast_proto::ssh::{parse_public_key_blob, parse_ssh_auth_context, LoadedSshKey};
use sshcast_proto::v1::{
    client_stream_message, server_stream_message, ClientStreamMessage, NodeGrant, NodeRole,
    PublicKey, ServerStreamMessage, SignAck, SignRequest, SignResponse, WorkstationStatus,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmHeldKeyInfo {
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub comment: String,
    pub authorized_key_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmAncestorInfo {
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSignRequestInfo {
    pub request_id: String,
    pub timestamp_unix_ms: u64,
    pub verified_node_id: String,
    pub hostname: String,
    pub uid: u32,
    pub pid: u32,
    pub comm: String,
    pub cmdline: String,
    pub cwd: String,
    pub primary_tool: String,
    pub primary_cmdline: String,
    pub ancestry_chain: String,
    pub key_summary: String,
    pub ancestors: Vec<WasmAncestorInfo>,
    pub is_userauth_request: bool,
    pub target_username: String,
    pub service_name: String,
    pub pubkey_algorithm: String,
    pub key_fingerprint: String,
    pub key_comment: String,
    pub has_matching_key: bool,
}

struct WasmPendingEnrollment {
    servers: Vec<String>,
    operator_url: String,
    node_name: String,
    candidate_user_sk: SigningKey,
    pairing_keys: Option<RequesterPairingKeys>,
}

#[derive(Default)]
pub struct WasmWorkstationEngine {
    bundle: Option<EnrollmentBundle>,
    user_signing_key: Option<SigningKey>,
    pending_enrollment: Option<WasmPendingEnrollment>,
    keys: Vec<LoadedSshKey>,
    pending_requests: HashMap<String, SignRequest>,
    nonce_counter: u64,
    last_result_bytes: Vec<u8>,
}

impl WasmWorkstationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    fn held_key_info(k: &LoadedSshKey) -> WasmHeldKeyInfo {
        let authorized_key_line = format!(
            "{} {} {}",
            k.key_type(),
            STANDARD.encode(k.key_blob()),
            k.comment()
        )
        .trim()
        .to_string();
        WasmHeldKeyInfo {
            key_type: k.key_type().to_string(),
            fingerprint_sha256: k.fingerprint_sha256().to_string(),
            comment: k.comment().to_string(),
            authorized_key_line,
        }
    }

    fn key_summaries(&self) -> Vec<WasmHeldKeyInfo> {
        self.keys.iter().map(Self::held_key_info).collect()
    }

    fn public_keys(&self) -> Vec<PublicKey> {
        self.keys
            .iter()
            .map(|k| k.public_key_proto())
            .collect()
    }

    fn decode_b64_bytes(raw: &str, field: &str) -> Result<Vec<u8>, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!("Missing required base64 field '{field}'"));
        }
        STANDARD
            .decode(trimmed)
            .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
            .or_else(|_| URL_SAFE.decode(trimmed))
            .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
            .map_err(|e| format!("Invalid base64 in '{field}': {e}"))
    }

    fn decode_b64_fixed<const N: usize>(req: &Value, field: &str) -> Result<[u8; N], String> {
        let raw = req.get(field).and_then(Value::as_str).unwrap_or("");
        let mut vec = Self::decode_b64_bytes(raw, field)?;
        if vec.len() != N {
            return Err(format!(
                "Field '{field}' must decode to {N} bytes (got {})",
                vec.len()
            ));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&vec);
        zeroize::Zeroize::zeroize(&mut vec);
        Ok(arr)
    }

    fn extract_optional_root_key_suffix(
        bundle_str: &str,
        expected_user_pubkey: &[u8],
    ) -> Result<Option<SigningKey>, String> {
        let candidate = bundle_str
            .split_whitespace()
            .find(|w| w.starts_with(BUNDLE_PREFIX))
            .unwrap_or(bundle_str.trim());
        let cleaned: String = candidate.chars().filter(|c| !c.is_whitespace()).collect();
        let Some((_, rk_part)) = cleaned.split_once(".rk_") else {
            return Ok(None);
        };
        let mut seed_vec = URL_SAFE_NO_PAD
            .decode(rk_part.trim().trim_end_matches('='))
            .map_err(|e| format!("Invalid base64 in embedded .rk_ root key suffix: {e}"))?;
        let seed_res: Result<[u8; 32], _> = seed_vec.clone().try_into();
        zeroize::Zeroize::zeroize(&mut seed_vec);
        let seed = Zeroizing::new(
            seed_res.map_err(|_| "Embedded .rk_ root key seed must decode to 32 bytes".to_string())?,
        );
        let sk = SigningKey::from_bytes(&seed);
        if sk.verifying_key().to_bytes().as_slice() != expected_user_pubkey {
            return Err(
                "Embedded .rk_ root key does not match the bundle's NodeGrant user_pubkey"
                    .to_string(),
            );
        }
        Ok(Some(sk))
    }

    fn user_pubkey_token_bytes(pk: &[u8]) -> String {
        format!("sc_pub_{}", hex::encode(pk))
    }

    fn build_bundle_summary_json(
        bundle: &EnrollmentBundle,
        user_cert_expired: bool,
        has_user_root_key: bool,
    ) -> Value {
        let coordinator_url = bundle.servers.first().cloned().unwrap_or_default();
        let ws_url = Self::derive_ws_url(&coordinator_url);
        let dns_domains: Vec<String> = bundle
            .servers
            .iter()
            .filter_map(|s| sshcast_proto::dns::is_dns_discovery_entry(s))
            .collect();
        let has_user_cert = bundle.grant.user_cert.is_some();
        let cert_issued_at_unix_sec = bundle
            .grant
            .user_cert
            .as_ref()
            .map(|c| c.issued_at_unix_sec)
            .unwrap_or(0);
        let cert_expires_at_unix_sec = bundle
            .grant
            .user_cert
            .as_ref()
            .map(|c| c.expires_at_unix_sec)
            .unwrap_or(0);
        json!({
            "ok": true,
            "bundle_str": bundle.encode().unwrap_or_default(),
            "coordinator_url": coordinator_url,
            "ws_url": ws_url,
            "servers": bundle.servers,
            "dns_domains": dns_domains,
            "has_user_cert": has_user_cert,
            "user_cert_expired": user_cert_expired,
            "cert_issued_at_unix_sec": cert_issued_at_unix_sec,
            "cert_expires_at_unix_sec": cert_expires_at_unix_sec,
            "user_id": bundle.grant.user_id,
            "user_pubkey_token": Self::user_pubkey_token_bytes(&bundle.grant.user_pubkey),
            "node_id": bundle.grant.node_id,
            "role": "CLIENT",
            "issued_at_unix_sec": bundle.grant.issued_at_unix_sec,
            "expires_at_unix_sec": bundle.grant.expires_at_unix_sec,
            "has_user_root_key": has_user_root_key,
        })
    }

    fn cert_needs_renewal_at(cert: Option<&sshcast_proto::v1::UserCert>, now_unix_sec: u64) -> bool {
        let Some(cert) = cert else {
            return true;
        };
        if cert.expires_at_unix_sec == 0 {
            return false;
        }
        if now_unix_sec >= cert.expires_at_unix_sec {
            return true;
        }
        let remaining = cert.expires_at_unix_sec - now_unix_sec;
        let total = cert
            .expires_at_unix_sec
            .saturating_sub(cert.issued_at_unix_sec);
        let half = total / 2;
        let threshold = if total >= 7200 { half.max(3600) } else { half };
        remaining <= threshold
    }

    fn build_operator_node_auth_b64(
        &mut self,
        now_unix_ms: u64,
        explicit_nonce_b64: Option<&str>,
    ) -> Result<String, String> {
        let Some(bundle) = &self.bundle else {
            return Err("No enrollment bundle configured in WASM engine".to_string());
        };
        let nonce = if let Some(raw_nonce) = explicit_nonce_b64.filter(|s| !s.trim().is_empty()) {
            Self::decode_b64_bytes(raw_nonce, "nonce_b64")?
        } else {
            self.nonce_counter = self.nonce_counter.wrapping_add(1);
            let mut h = Sha256::new();
            h.update(b"sshcast-wasm-renew-nonce-v1");
            h.update(now_unix_ms.to_be_bytes());
            h.update(self.nonce_counter.to_be_bytes());
            h.update(&bundle.grant.node_pubkey);
            h.finalize()[..16].to_vec()
        };

        let mut grant_no_cert = bundle.grant.clone();
        grant_no_cert.user_cert = None;
        let auth = create_node_auth_with_nonce(
            grant_no_cert,
            &bundle.node_signing_key,
            now_unix_ms,
            nonce,
        )
        .map_err(|e| e.to_string())?;
        Ok(STANDARD.encode(auth.encode_to_vec()))
    }

    fn derive_ws_url(server_url: &str) -> String {
        let trimmed = server_url.trim().trim_end_matches('/');
        if let Some(rest) = trimmed.strip_prefix("https://") {
            format!("wss://{rest}/ws/workstation")
        } else if let Some(rest) = trimmed.strip_prefix("http://") {
            format!("ws://{rest}/ws/workstation")
        } else if trimmed.starts_with("wss://") || trimmed.starts_with("ws://") {
            if trimmed.ends_with("/ws/workstation") {
                trimmed.to_string()
            } else {
                format!("{trimmed}/ws/workstation")
            }
        } else {
            format!("wss://{trimmed}/ws/workstation")
        }
    }

    pub fn call_value(&mut self, req: Value) -> Value {
        let op = req.get("op").and_then(Value::as_str).unwrap_or("");
        match op {
            "parse_bundle" | "set_bundle" => {
                let bundle_str = req
                    .get("bundle_str")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let bundle = match EnrollmentBundle::decode(bundle_str) {
                    Ok(b) => b,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Invalid enrollment bundle: {e}")
                        })
                    }
                };
                let mut user_cert_expired = false;
                if let Err(e) = verify_node_grant(&bundle.grant, now_unix_sec) {
                    if e == CryptoError::UserCertExpired {
                        let mut grant_no_cert = bundle.grant.clone();
                        grant_no_cert.user_cert = None;
                        if let Err(e2) = verify_node_grant(&grant_no_cert, now_unix_sec) {
                            return json!({
                                "ok": false,
                                "error": format!("Node grant verification failed: {e2}")
                            });
                        }
                        user_cert_expired = true;
                    } else {
                        return json!({
                            "ok": false,
                            "error": format!("Node grant verification failed: {e}")
                        });
                    }
                }
                if bundle.grant.role != NodeRole::Client as i32 {
                    return json!({
                        "ok": false,
                        "error": "Enrollment bundle has RELAY role; browser workstation requires a CLIENT bundle"
                    });
                }
                let rk_opt = match Self::extract_optional_root_key_suffix(
                    bundle_str,
                    &bundle.grant.user_pubkey,
                ) {
                    Ok(rk) => rk,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": e
                        })
                    }
                };
                let same_existing_rk = self
                    .user_signing_key
                    .as_ref()
                    .map(|sk| sk.verifying_key().to_bytes().as_slice() == bundle.grant.user_pubkey.as_slice())
                    .unwrap_or(false);
                let has_user_root_key = rk_opt.is_some() || same_existing_rk;
                let resp = Self::build_bundle_summary_json(
                    &bundle,
                    user_cert_expired,
                    has_user_root_key,
                );
                if op == "set_bundle" {
                    if let Some(sk) = rk_opt {
                        self.user_signing_key = Some(sk);
                    } else if !same_existing_rk {
                        self.user_signing_key = None;
                    }
                    self.bundle = Some(bundle);
                }
                resp
            }
            "get_identity_status" => {
                let has_user_root_key = self.user_signing_key.is_some();
                if let Some(b) = &self.bundle {
                    let cert = b.grant.user_cert.as_ref();
                    json!({
                        "ok": true,
                        "has_bundle": true,
                        "has_user_root_key": has_user_root_key,
                        "user_id": b.grant.user_id,
                        "user_pubkey_token": Self::user_pubkey_token_bytes(&b.grant.user_pubkey),
                        "node_id": b.grant.node_id,
                        "servers": b.servers,
                        "has_user_cert": cert.is_some(),
                        "cert_issued_at_unix_sec": cert.map(|c| c.issued_at_unix_sec).unwrap_or(0),
                        "cert_expires_at_unix_sec": cert.map(|c| c.expires_at_unix_sec).unwrap_or(0),
                    })
                } else if let Some(sk) = &self.user_signing_key {
                    let pk = sk.verifying_key().to_bytes();
                    json!({
                        "ok": true,
                        "has_bundle": false,
                        "has_user_root_key": true,
                        "user_id": derive_user_id(&pk),
                        "user_pubkey_token": Self::user_pubkey_token_bytes(&pk),
                        "node_id": "",
                        "servers": [],
                        "has_user_cert": false,
                        "cert_issued_at_unix_sec": 0,
                        "cert_expires_at_unix_sec": 0,
                    })
                } else {
                    json!({
                        "ok": true,
                        "has_bundle": false,
                        "has_user_root_key": false,
                        "user_id": "",
                        "user_pubkey_token": "",
                        "node_id": "",
                        "servers": [],
                        "has_user_cert": false,
                        "cert_issued_at_unix_sec": 0,
                        "cert_expires_at_unix_sec": 0,
                    })
                }
            }
            "import_user_root_key" => {
                let raw = req.get("token").and_then(Value::as_str).unwrap_or("");
                let trimmed = raw
                    .split_whitespace()
                    .find(|w| w.starts_with("scu1_"))
                    .unwrap_or_else(|| raw.trim());
                let Some(b64) = trimmed.strip_prefix("scu1_") else {
                    return json!({
                        "ok": false,
                        "error": "User root key token must start with 'scu1_'"
                    });
                };
                let mut seed_vec = match URL_SAFE_NO_PAD.decode(b64.trim().trim_end_matches('=')) {
                    Ok(v) => v,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Invalid base64 in scu1_ token: {e}")
                        })
                    }
                };
                let seed_res: Result<[u8; 32], _> = seed_vec.clone().try_into();
                zeroize::Zeroize::zeroize(&mut seed_vec);
                let Ok(seed_arr) = seed_res else {
                    return json!({
                        "ok": false,
                        "error": "scu1_ token must decode to 32 bytes"
                    });
                };
                let seed = Zeroizing::new(seed_arr);
                let sk = SigningKey::from_bytes(&seed);
                let pk = sk.verifying_key().to_bytes();
                let user_id = derive_user_id(&pk);
                if let Some(b) = &self.bundle {
                    if b.grant.user_pubkey.as_slice() != pk.as_slice() {
                        return json!({
                            "ok": false,
                            "error": format!(
                                "Imported root key ({user_id}) does not match loaded bundle user ({})",
                                b.grant.user_id
                            )
                        });
                    }
                }
                self.user_signing_key = Some(sk);
                json!({
                    "ok": true,
                    "user_id": user_id,
                    "user_pubkey_token": Self::user_pubkey_token_bytes(&pk),
                    "has_user_root_key": true,
                })
            }
            "export_user_root_key" => {
                let Some(sk) = &self.user_signing_key else {
                    return json!({
                        "ok": false,
                        "error": "No user root signing key is loaded in WASM memory"
                    });
                };
                let pk = sk.verifying_key().to_bytes();
                let seed = Zeroizing::new(sk.to_bytes());
                let token = format!("scu1_{}", URL_SAFE_NO_PAD.encode(&*seed));
                json!({
                    "ok": true,
                    "root_key_token": token,
                    "user_id": derive_user_id(&pk),
                    "user_pubkey_token": Self::user_pubkey_token_bytes(&pk),
                })
            }
            "clear_identity" => {
                self.bundle = None;
                self.user_signing_key = None;
                self.pending_enrollment = None;
                self.pending_requests.clear();
                json!({ "ok": true })
            }
            "build_renew_node_auth" | "build_operator_node_auth" => {
                let now_unix_ms = req
                    .get("now_unix_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let nonce_b64 = req.get("nonce_b64").and_then(Value::as_str);
                match self.build_operator_node_auth_b64(now_unix_ms, nonce_b64) {
                    Ok(node_auth_proto_b64) => json!({
                        "ok": true,
                        "node_auth_proto_b64": node_auth_proto_b64,
                    }),
                    Err(e) => json!({
                        "ok": false,
                        "error": e,
                    }),
                }
            }
            "begin_github_enrollment" => {
                let servers: Vec<String> = req
                    .get("servers")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty())
                    .unwrap_or_else(|| vec!["sshcast.net".to_string()]);
                let operator_url = req
                    .get("operator_url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('/')
                    .to_string();
                let node_name = req
                    .get("node_name")
                    .and_then(Value::as_str)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "browser-workstation".to_string());
                let reuse_existing = req
                    .get("reuse_existing_root_key")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                let candidate_user_sk = if reuse_existing {
                    if let Some(existing) = &self.user_signing_key {
                        existing.clone()
                    } else {
                        let seed = match Self::decode_b64_fixed::<32>(&req, "candidate_user_seed_b64")
                        {
                            Ok(s) => Zeroizing::new(s),
                            Err(e) => return json!({ "ok": false, "error": e }),
                        };
                        SigningKey::from_bytes(&seed)
                    }
                } else {
                    let seed = match Self::decode_b64_fixed::<32>(&req, "candidate_user_seed_b64") {
                        Ok(s) => Zeroizing::new(s),
                        Err(e) => return json!({ "ok": false, "error": e }),
                    };
                    SigningKey::from_bytes(&seed)
                };

                let node_seed = match Self::decode_b64_fixed::<32>(&req, "node_seed_b64") {
                    Ok(s) => Zeroizing::new(s),
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let eph_secret = match Self::decode_b64_fixed::<32>(&req, "eph_secret_b64") {
                    Ok(s) => Zeroizing::new(s),
                    Err(e) => return json!({ "ok": false, "error": e }),
                };

                let pairing_keys = RequesterPairingKeys::from_seeds(*node_seed, *eph_secret);
                let user_pubkey = Self::user_pubkey_token_bytes(
                    &candidate_user_sk.verifying_key().to_bytes(),
                );
                let start_body = json!({
                    "user_pubkey": user_pubkey,
                    "supports_pairing": true,
                    "node_name": node_name,
                    "os_name": "browser-wasm",
                    "node_pubkey_b64": pairing_keys.node_pubkey_b64(),
                    "eph_x25519_pub_b64": pairing_keys.eph_x25519_pub_b64(),
                });

                self.pending_enrollment = Some(WasmPendingEnrollment {
                    servers,
                    operator_url,
                    node_name,
                    candidate_user_sk,
                    pairing_keys: Some(pairing_keys),
                });

                json!({
                    "ok": true,
                    "start_body": start_body,
                })
            }
            "cancel_pending_enrollment" => {
                self.pending_enrollment = None;
                json!({ "ok": true })
            }
            "compute_pairing_sas" => {
                let Some(pending) = &self.pending_enrollment else {
                    return json!({
                        "ok": false,
                        "error": "No pending GitHub enrollment in WASM engine"
                    });
                };
                let Some(pk_keys) = &pending.pairing_keys else {
                    return json!({
                        "ok": false,
                        "error": "Pending pairing keys were already consumed"
                    });
                };
                let raw_pub = req
                    .get("existing_user_pubkey")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let existing_pk = match parse_user_pubkey_token(raw_pub) {
                    Ok(pk) => pk,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };
                json!({
                    "ok": true,
                    "sas_code": pk_keys.sas_code(&existing_pk),
                    "existing_user_id": derive_user_id(&existing_pk),
                })
            }
            "finalize_approved_enrollment" => {
                let cert_token = req
                    .get("cert_token")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let explicit_node_seed = req
                    .get("node_seed_b64")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(|_| Self::decode_b64_fixed::<32>(&req, "node_seed_b64"))
                    .transpose();
                let explicit_node_seed = match explicit_node_seed {
                    Ok(v) => v.map(Zeroizing::new),
                    Err(e) => return json!({ "ok": false, "error": e }),
                };

                let Some(pending) = &self.pending_enrollment else {
                    return json!({
                        "ok": false,
                        "error": "No pending GitHub enrollment in WASM engine"
                    });
                };
                let cert = match decode_user_cert_token(cert_token) {
                    Ok(c) => c,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Invalid user certificate token: {e}")
                        })
                    }
                };
                let expected_user_pk = pending.candidate_user_sk.verifying_key().to_bytes();
                if let Err(e) = verify_user_cert(&cert, &expected_user_pk, now_unix_sec) {
                    return json!({
                        "ok": false,
                        "error": format!("Operator certificate verification failed: {e}")
                    });
                }
                let node_sk = if let Some(seed) = explicit_node_seed {
                    SigningKey::from_bytes(&seed)
                } else if let Some(pk) = &pending.pairing_keys {
                    pk.node_signing_key().clone()
                } else {
                    return json!({
                        "ok": false,
                        "error": "Missing workstation node signing key for enrollment"
                    });
                };

                let pending = self.pending_enrollment.take().expect("checked above");
                let mut grant = NodeGrant {
                    user_id: String::new(),
                    user_pubkey: Vec::new(),
                    node_id: pending.node_name,
                    role: NodeRole::Client as i32,
                    node_pubkey: node_sk.verifying_key().to_bytes().to_vec(),
                    issued_at_unix_sec: now_unix_sec,
                    expires_at_unix_sec: 0,
                    user_signature: Vec::new(),
                    user_cert: Some(cert),
                };
                sign_node_grant(&mut grant, &pending.candidate_user_sk);
                let bundle = EnrollmentBundle::new(pending.servers, node_sk, grant);
                let mut resp = Self::build_bundle_summary_json(&bundle, false, true);
                if let Value::Object(ref mut map) = resp {
                    map.insert("operator_url".to_string(), Value::String(pending.operator_url));
                }
                self.user_signing_key = Some(pending.candidate_user_sk);
                self.bundle = Some(bundle);
                resp
            }
            "complete_paired_enrollment" => {
                let pairing_id = req
                    .get("pairing_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let raw_pub = req
                    .get("existing_user_pubkey")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let existing_user_pubkey = match parse_user_pubkey_token(raw_pub) {
                    Ok(pk) => pk,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let envelope = PairingHandoffEnvelope {
                    approver_eph_x25519_pub_b64: req
                        .get("approver_eph_x25519_pub_b64")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    approver_signature_b64: req
                        .get("approver_signature_b64")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    handoff_nonce_b64: req
                        .get("handoff_nonce_b64")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    encrypted_handoff_b64: req
                        .get("encrypted_handoff_b64")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                };

                let Some(pending) = self.pending_enrollment.take() else {
                    return json!({
                        "ok": false,
                        "error": "No pending GitHub enrollment in WASM engine"
                    });
                };
                let Some(pairing_keys) = pending.pairing_keys else {
                    return json!({
                        "ok": false,
                        "error": "Pairing keys were already consumed"
                    });
                };
                let verified = match pairing_keys.decrypt_and_verify_handoff_at(
                    pairing_id,
                    &existing_user_pubkey,
                    &envelope,
                    now_unix_sec,
                ) {
                    Ok(v) => v,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };

                let servers = if verified.servers.is_empty() {
                    pending.servers
                } else {
                    verified.servers
                };
                let op_url = verified
                    .operator_url
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(pending.operator_url);
                let needs_cert_renewal =
                    Self::cert_needs_renewal_at(verified.grant.user_cert.as_ref(), now_unix_sec);
                let bundle =
                    EnrollmentBundle::new(servers, verified.node_signing_key, verified.grant);
                let mut resp = Self::build_bundle_summary_json(&bundle, false, true);
                if let Value::Object(ref mut map) = resp {
                    map.insert("operator_url".to_string(), Value::String(op_url));
                    map.insert(
                        "needs_cert_renewal".to_string(),
                        Value::Bool(needs_cert_renewal),
                    );
                }
                self.user_signing_key = Some(verified.user_signing_key);
                self.bundle = Some(bundle);
                resp
            }
            "derive_scrypt_key" => {
                let passphrase = req.get("passphrase").and_then(Value::as_str).unwrap_or("");
                if passphrase.is_empty() {
                    return json!({
                        "ok": false,
                        "wrong_passphrase": true,
                        "error": "Recovery passphrase cannot be empty"
                    });
                }
                let salt_raw = req.get("salt_b64").and_then(Value::as_str).unwrap_or("");
                let salt = match Self::decode_b64_bytes(salt_raw, "salt_b64") {
                    Ok(s) => s,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let defaults = ScryptParams::default();
                let params = ScryptParams {
                    log_n: req
                        .get("log_n")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok())
                        .unwrap_or(defaults.log_n),
                    r: req
                        .get("r")
                        .and_then(Value::as_u64)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(defaults.r),
                    p: req
                        .get("p")
                        .and_then(Value::as_u64)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(defaults.p),
                };
                match derive_recovery_vault_key(passphrase, &salt, params) {
                    Ok(dk) => json!({
                        "ok": true,
                        "derived_key_b64": STANDARD.encode(&*dk),
                    }),
                    Err(e) => json!({
                        "ok": false,
                        "error": e.to_string(),
                    }),
                }
            }
            "unlock_recovery_vault" => {
                let raw_pub = req
                    .get("existing_user_pubkey")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let existing_pk = match parse_user_pubkey_token(raw_pub) {
                    Ok(pk) => pk,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };
                let vault_val = req.get("vault").cloned().unwrap_or(Value::Null);
                let vault: RecoveryVaultBlob = match serde_json::from_value(vault_val) {
                    Ok(v) => v,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Invalid recovery_vault payload: {e}")
                        })
                    }
                };
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let now_unix_ms = req
                    .get("now_unix_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or_else(|| now_unix_sec.saturating_mul(1000));

                let unlock_res = if let Some(dk_b64) = req
                    .get("derived_key_b64")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                {
                    let _ = dk_b64;
                    let dk = match Self::decode_b64_fixed::<32>(&req, "derived_key_b64") {
                        Ok(k) => Zeroizing::new(k),
                        Err(e) => return json!({ "ok": false, "error": e }),
                    };
                    decrypt_recovery_vault_with_derived_key(&vault, &existing_pk, &dk)
                } else {
                    let passphrase = req.get("passphrase").and_then(Value::as_str).unwrap_or("");
                    decrypt_recovery_vault(&vault, &existing_pk, passphrase)
                };

                let user_sk = match unlock_res {
                    Ok(sk) => sk,
                    Err(VaultDecryptError::WrongPassphrase) => {
                        return json!({
                            "ok": false,
                            "wrong_passphrase": true,
                            "error": "Incorrect recovery passphrase"
                        })
                    }
                    Err(VaultDecryptError::InvalidFormat(msg)) => {
                        return json!({
                            "ok": false,
                            "wrong_passphrase": false,
                            "error": msg
                        })
                    }
                };

                let explicit_node_seed = req
                    .get("node_seed_b64")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .map(|_| Self::decode_b64_fixed::<32>(&req, "node_seed_b64"))
                    .transpose();
                let explicit_node_seed = match explicit_node_seed {
                    Ok(v) => v.map(Zeroizing::new),
                    Err(e) => return json!({ "ok": false, "error": e }),
                };

                let pending_opt = self.pending_enrollment.take();
                let (servers, node_name, op_url, pending_pk) = match pending_opt {
                    Some(p) => (p.servers, p.node_name, p.operator_url, p.pairing_keys),
                    None => {
                        let servers: Vec<String> = req
                            .get("servers")
                            .and_then(Value::as_array)
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(Value::as_str)
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect()
                            })
                            .filter(|v: &Vec<String>| !v.is_empty())
                            .unwrap_or_else(|| vec!["sshcast.net".to_string()]);
                        let node_name = req
                            .get("node_name")
                            .and_then(Value::as_str)
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| "browser-workstation".to_string());
                        let op_url = req
                            .get("operator_url")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim()
                            .trim_end_matches('/')
                            .to_string();
                        (servers, node_name, op_url, None)
                    }
                };

                let node_sk = if let Some(seed) = explicit_node_seed {
                    SigningKey::from_bytes(&seed)
                } else if let Some(pk) = pending_pk {
                    pk.node_signing_key().clone()
                } else {
                    return json!({
                        "ok": false,
                        "error": "Missing node_seed_b64 or pending enrollment node key"
                    });
                };

                let mut grant = NodeGrant {
                    user_id: String::new(),
                    user_pubkey: Vec::new(),
                    node_id: node_name,
                    role: NodeRole::Client as i32,
                    node_pubkey: node_sk.verifying_key().to_bytes().to_vec(),
                    issued_at_unix_sec: now_unix_sec,
                    expires_at_unix_sec: 0,
                    user_signature: Vec::new(),
                    user_cert: None,
                };
                sign_node_grant(&mut grant, &user_sk);
                let bundle = EnrollmentBundle::new(servers, node_sk, grant);
                self.user_signing_key = Some(user_sk);
                self.bundle = Some(bundle);

                let auth_nonce_b64 = req.get("auth_nonce_b64").and_then(Value::as_str);
                let renew_auth = match self.build_operator_node_auth_b64(now_unix_ms, auth_nonce_b64)
                {
                    Ok(a) => a,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };

                let mut resp = Self::build_bundle_summary_json(
                    self.bundle.as_ref().expect("just set"),
                    false,
                    true,
                );
                if let Value::Object(ref mut map) = resp {
                    map.insert("operator_url".to_string(), Value::String(op_url));
                    map.insert(
                        "renew_node_auth_proto_b64".to_string(),
                        Value::String(renew_auth),
                    );
                }
                resp
            }
            "encrypt_recovery_vault" => {
                let Some(user_sk) = self.user_signing_key.clone() else {
                    return json!({
                        "ok": false,
                        "error": "No user root signing key is loaded in WASM memory"
                    });
                };
                if self.bundle.is_none() {
                    return json!({
                        "ok": false,
                        "error": "No enrollment bundle configured in WASM engine"
                    });
                }
                let salt = match Self::decode_b64_fixed::<16>(&req, "salt_b64") {
                    Ok(s) => s,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let nonce = match Self::decode_b64_fixed::<12>(&req, "nonce_b64") {
                    Ok(n) => n,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let defaults = ScryptParams::default();
                let params = ScryptParams {
                    log_n: req
                        .get("log_n")
                        .and_then(Value::as_u64)
                        .and_then(|v| u8::try_from(v).ok())
                        .unwrap_or(defaults.log_n),
                    r: req
                        .get("r")
                        .and_then(Value::as_u64)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(defaults.r),
                    p: req
                        .get("p")
                        .and_then(Value::as_u64)
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(defaults.p),
                };

                let vault_res = if let Some(_) = req
                    .get("derived_key_b64")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                {
                    let dk = match Self::decode_b64_fixed::<32>(&req, "derived_key_b64") {
                        Ok(k) => Zeroizing::new(k),
                        Err(e) => return json!({ "ok": false, "error": e }),
                    };
                    encrypt_recovery_vault_with_derived_key(&user_sk, &dk, params, salt, nonce)
                } else {
                    let passphrase = req.get("passphrase").and_then(Value::as_str).unwrap_or("");
                    encrypt_recovery_vault_with_entropy(&user_sk, passphrase, params, salt, nonce)
                };

                let vault = match vault_res {
                    Ok(v) => v,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };
                let now_unix_ms = req
                    .get("now_unix_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let auth_nonce_b64 = req.get("auth_nonce_b64").and_then(Value::as_str);
                let node_auth = match self.build_operator_node_auth_b64(now_unix_ms, auth_nonce_b64)
                {
                    Ok(a) => a,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                json!({
                    "ok": true,
                    "vault": vault,
                    "node_auth_proto_b64": node_auth,
                })
            }
            "compute_incoming_pairing_sas" => {
                let Some(user_sk) = &self.user_signing_key else {
                    return json!({
                        "ok": false,
                        "error": "No user root signing key is loaded in WASM memory"
                    });
                };
                let req_eph_pk = match Self::decode_b64_fixed::<32>(&req, "eph_x25519_pub_b64") {
                    Ok(pk) => pk,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let user_pk = user_sk.verifying_key().to_bytes();
                json!({
                    "ok": true,
                    "sas_code": compute_pairing_sas_code(&user_pk, &req_eph_pk),
                })
            }
            "approve_pairing_request" => {
                let Some(user_sk) = self.user_signing_key.clone() else {
                    return json!({
                        "ok": false,
                        "error": "No user root signing key is loaded in WASM memory"
                    });
                };
                let Some(bundle) = self.bundle.clone() else {
                    return json!({
                        "ok": false,
                        "error": "No enrollment bundle configured in WASM engine"
                    });
                };
                let pairing_id = req
                    .get("pairing_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let node_name = req
                    .get("node_name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let operator_url = req
                    .get("operator_url")
                    .and_then(Value::as_str)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let now_unix_ms = req
                    .get("now_unix_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or_else(|| now_unix_sec.saturating_mul(1000));

                let req_node_pk = match Self::decode_b64_fixed::<32>(&req, "node_pubkey_b64") {
                    Ok(pk) => pk,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let req_eph_pk = match Self::decode_b64_fixed::<32>(&req, "eph_x25519_pub_b64") {
                    Ok(pk) => pk,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let approver_eph_secret =
                    match Self::decode_b64_fixed::<32>(&req, "approver_eph_secret_b64") {
                        Ok(s) => Zeroizing::new(s),
                        Err(e) => return json!({ "ok": false, "error": e }),
                    };
                let handoff_nonce = match Self::decode_b64_fixed::<12>(&req, "handoff_nonce_b64") {
                    Ok(n) => n,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };

                let envelope = match create_encrypted_pairing_handoff_with_entropy(
                    &user_sk,
                    bundle.grant.user_cert,
                    pairing_id,
                    node_name,
                    &req_node_pk,
                    &req_eph_pk,
                    bundle.servers,
                    operator_url,
                    now_unix_sec,
                    *approver_eph_secret,
                    handoff_nonce,
                ) {
                    Ok(env) => env,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };

                let auth_nonce_b64 = req.get("auth_nonce_b64").and_then(Value::as_str);
                let node_auth = match self.build_operator_node_auth_b64(now_unix_ms, auth_nonce_b64)
                {
                    Ok(a) => a,
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                json!({
                    "ok": true,
                    "node_auth_proto_b64": node_auth,
                    "envelope": envelope,
                })
            }
            "mint_enrollment_bundle" => {
                let Some(user_sk) = &self.user_signing_key else {
                    return json!({
                        "ok": false,
                        "error": "No user root signing key is loaded in WASM memory"
                    });
                };
                let node_id = req
                    .get("node_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if node_id.is_empty() {
                    return json!({
                        "ok": false,
                        "error": "node_id cannot be empty"
                    });
                }
                let role_str = req
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("RELAY")
                    .trim()
                    .to_ascii_uppercase();
                let role = match role_str.as_str() {
                    "RELAY" => NodeRole::Relay,
                    "CLIENT" => NodeRole::Client,
                    other => {
                        return json!({
                            "ok": false,
                            "error": format!("Unsupported bundle role {other:?} (expected RELAY or CLIENT)")
                        })
                    }
                };
                let servers: Vec<String> = req
                    .get("servers")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .filter(|v: &Vec<String>| !v.is_empty())
                    .or_else(|| self.bundle.as_ref().map(|b| b.servers.clone()))
                    .unwrap_or_default();
                if servers.is_empty() {
                    return json!({
                        "ok": false,
                        "error": "At least one coordinator server or domain is required"
                    });
                }
                let expires_days = req
                    .get("expires_days")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let include_root_key = req
                    .get("include_root_key")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let node_seed = match Self::decode_b64_fixed::<32>(&req, "node_seed_b64") {
                    Ok(s) => Zeroizing::new(s),
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let node_sk = SigningKey::from_bytes(&node_seed);

                let user_pk = user_sk.verifying_key().to_bytes();
                let verified_cert = self
                    .bundle
                    .as_ref()
                    .and_then(|b| b.grant.user_cert.clone())
                    .filter(|c| c.user_pubkey.as_slice() == user_pk.as_slice());

                let expires_at_unix_sec = if expires_days == 0 {
                    0
                } else {
                    now_unix_sec.saturating_add(expires_days.saturating_mul(86_400))
                };

                let mut grant = NodeGrant {
                    user_id: String::new(),
                    user_pubkey: Vec::new(),
                    node_id: node_id.clone(),
                    role: role as i32,
                    node_pubkey: node_sk.verifying_key().to_bytes().to_vec(),
                    issued_at_unix_sec: now_unix_sec,
                    expires_at_unix_sec,
                    user_signature: Vec::new(),
                    user_cert: verified_cert,
                };
                sign_node_grant(&mut grant, user_sk);
                let minted = EnrollmentBundle::new(servers, node_sk, grant);
                let base_token = match minted.encode() {
                    Ok(t) => t,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };
                let bundle_str = if role == NodeRole::Client && include_root_key {
                    let rk_seed = Zeroizing::new(user_sk.to_bytes());
                    format!("{base_token}.rk_{}", URL_SAFE_NO_PAD.encode(&*rk_seed))
                } else {
                    base_token
                };
                let command_hint = match role {
                    NodeRole::Relay => format!("sshcast-relay init --bundle {bundle_str}"),
                    NodeRole::Client => format!("sshcast-client init --bundle {bundle_str}"),
                    NodeRole::Unspecified => String::new(),
                };
                json!({
                    "ok": true,
                    "bundle_str": bundle_str,
                    "node_id": node_id,
                    "role": role_str,
                    "command_hint": command_hint,
                })
            }
            "generate_ssh_key" => {
                let seed = match Self::decode_b64_fixed::<32>(&req, "seed_b64") {
                    Ok(s) => Zeroizing::new(s),
                    Err(e) => return json!({ "ok": false, "error": e }),
                };
                let comment = req
                    .get("comment")
                    .and_then(Value::as_str)
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("ephemeral@browser-wasm");
                let key = LoadedSshKey::from_ed25519_signing_key(
                    SigningKey::from_bytes(&seed),
                    comment,
                );
                let added = Self::held_key_info(&key);
                if let Some(existing) = self
                    .keys
                    .iter_mut()
                    .find(|k| k.key_blob() == key.key_blob())
                {
                    *existing = key;
                } else {
                    self.keys.push(key);
                }
                json!({
                    "ok": true,
                    "added_key": added,
                    "keys": self.key_summaries(),
                })
            }
            "update_user_cert" => {
                let Some(bundle) = &mut self.bundle else {
                    return json!({
                        "ok": false,
                        "error": "No enrollment bundle configured in WASM engine"
                    });
                };
                let cert_token = req
                    .get("cert_token")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let cert = match decode_user_cert_token(cert_token) {
                    Ok(c) => c,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Invalid user certificate token: {e}")
                        })
                    }
                };
                if let Err(e) = verify_user_cert(&cert, &bundle.grant.user_pubkey, now_unix_sec) {
                    return json!({
                        "ok": false,
                        "error": format!("User certificate verification failed: {e}")
                    });
                }
                let cert_issued_at_unix_sec = cert.issued_at_unix_sec;
                let cert_expires_at_unix_sec = cert.expires_at_unix_sec;
                bundle.grant.user_cert = Some(cert);
                let updated_bundle_str = bundle.encode().unwrap_or_default();
                json!({
                    "ok": true,
                    "has_user_cert": true,
                    "user_cert_expired": false,
                    "cert_issued_at_unix_sec": cert_issued_at_unix_sec,
                    "cert_expires_at_unix_sec": cert_expires_at_unix_sec,
                    "updated_bundle_str": updated_bundle_str,
                })
            }
            "parse_txt_records" => {
                let raw_records: Vec<String> = req
                    .get("txt_records")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default();
                let coordinators =
                    sshcast_proto::dns::parse_txt_coordinator_records(&raw_records);
                let ws_urls: Vec<String> = coordinators
                    .iter()
                    .map(|u| Self::derive_ws_url(u))
                    .collect();
                json!({
                    "ok": true,
                    "coordinators": coordinators,
                    "ws_urls": ws_urls,
                })
            }
            "add_ssh_key" => {
                let pem = req.get("pem").and_then(Value::as_str).unwrap_or("");
                let passphrase = req
                    .get("passphrase")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                let key = match LoadedSshKey::parse_openssh_pem(pem, passphrase) {
                    Ok(k) => k,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": e.to_string(),
                            "needs_passphrase": matches!(e, sshcast_proto::ssh::SshKeyError::PassphraseRequired)
                        })
                    }
                };
                let added = Self::held_key_info(&key);
                if let Some(existing) = self
                    .keys
                    .iter_mut()
                    .find(|k| k.key_blob() == key.key_blob())
                {
                    *existing = key;
                } else {
                    self.keys.push(key);
                }
                json!({
                    "ok": true,
                    "added_key": added,
                    "keys": self.key_summaries(),
                })
            }
            "remove_ssh_key" => {
                let fp = req
                    .get("fingerprint_sha256")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let before = self.keys.len();
                self.keys.retain(|k| k.fingerprint_sha256() != fp);
                json!({
                    "ok": true,
                    "removed": self.keys.len() < before,
                    "keys": self.key_summaries(),
                })
            }
            "list_ssh_keys" => {
                json!({
                    "ok": true,
                    "keys": self.key_summaries(),
                })
            }
            "build_auth_handshake_frame" => {
                let Some(bundle) = &self.bundle else {
                    return json!({
                        "ok": false,
                        "error": "No enrollment bundle configured in WASM engine"
                    });
                };
                let now_unix_ms = req
                    .get("now_unix_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                self.nonce_counter = self.nonce_counter.wrapping_add(1);
                let nonce = if let Some(hex_str) = req.get("nonce_hex").and_then(Value::as_str) {
                    hex::decode(hex_str).unwrap_or_else(|_| vec![1, 2, 3, 4, 5, 6, 7, 8])
                } else {
                    let mut h = Sha256::new();
                    h.update(b"sshcast-wasm-nonce-v1");
                    h.update(now_unix_ms.to_be_bytes());
                    h.update(self.nonce_counter.to_be_bytes());
                    h.update(&bundle.grant.node_pubkey);
                    h.finalize()[..16].to_vec()
                };
                let auth = match create_node_auth_with_nonce(
                    bundle.grant.clone(),
                    &bundle.node_signing_key,
                    now_unix_ms,
                    nonce,
                ) {
                    Ok(a) => a,
                    Err(e) => return json!({ "ok": false, "error": e.to_string() }),
                };
                let msg = ClientStreamMessage {
                    payload: Some(client_stream_message::Payload::AuthHandshake(auth)),
                };
                json!({
                    "ok": true,
                    "frame_b64": STANDARD.encode(msg.encode_to_vec()),
                })
            }
            "build_status_frame" => {
                let last_input_epoch_ms = req
                    .get("last_input_epoch_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let force_active = req
                    .get("force_active")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let os = req
                    .get("os")
                    .and_then(Value::as_str)
                    .unwrap_or("browser-wasm")
                    .to_string();
                let status = WorkstationStatus {
                    last_input_epoch_ms,
                    keys: self.public_keys(),
                    os,
                    force_active,
                };
                let msg = ClientStreamMessage {
                    payload: Some(client_stream_message::Payload::Status(status)),
                };
                json!({
                    "ok": true,
                    "frame_b64": STANDARD.encode(msg.encode_to_vec()),
                })
            }
            "build_request_zellij_hosts_frame" => {
                let refresh = req
                    .get("refresh")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let msg = ClientStreamMessage {
                    payload: Some(client_stream_message::Payload::RequestZellijHosts(refresh)),
                };
                json!({
                    "ok": true,
                    "frame_b64": STANDARD.encode(msg.encode_to_vec()),
                })
            }
            "decode_server_frame" => {
                let frame_b64 = req.get("frame_b64").and_then(Value::as_str).unwrap_or("");
                let now_unix_sec = req
                    .get("now_unix_sec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let bytes = match STANDARD.decode(frame_b64) {
                    Ok(b) => b,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Invalid base64 server frame: {e}")
                        })
                    }
                };
                let srv_msg = match ServerStreamMessage::decode(bytes.as_slice()) {
                    Ok(m) => m,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Invalid ServerStreamMessage protobuf: {e}")
                        })
                    }
                };
                match srv_msg.payload {
                    Some(server_stream_message::Payload::ServerHeartbeatEpochMs(ms)) => {
                        json!({
                            "ok": true,
                            "frame_type": "heartbeat",
                            "server_heartbeat_epoch_ms": ms,
                        })
                    }
                    Some(server_stream_message::Payload::CancelSignRequest(cancel)) => {
                        self.pending_requests.remove(&cancel.request_id);
                        json!({
                            "ok": true,
                            "frame_type": "cancel_sign_request",
                            "request_id": cancel.request_id,
                        })
                    }
                    Some(server_stream_message::Payload::ZellijHostList(list)) => {
                        let hosts: Vec<Value> = list
                            .hosts
                            .into_iter()
                            .map(|h| {
                                let sessions: Vec<Value> = h
                                    .sessions
                                    .into_iter()
                                    .map(|s| {
                                        json!({
                                            "name": s.name,
                                            "created_info": s.created_info,
                                            "exited": s.exited,
                                        })
                                    })
                                    .collect();
                                json!({
                                    "node_id": h.node_id,
                                    "zellij_enabled": h.zellij_enabled,
                                    "sessions": sessions,
                                })
                            })
                            .collect();
                        json!({
                            "ok": true,
                            "frame_type": "zellij_host_list",
                            "hosts": hosts,
                        })
                    }
                    Some(server_stream_message::Payload::ZellijFrame(zf)) => {
                        json!({
                            "ok": true,
                            "frame_type": "zellij_frame",
                            "tunnel_id": zf.tunnel_id,
                            "relay_node_id": zf.relay_node_id,
                            "client_node_id": zf.client_node_id,
                            "zf_type": zf.frame_type,
                            "payload_b64": STANDARD.encode(&zf.payload),
                        })
                    }
                    Some(server_stream_message::Payload::SignRequest(sign_req)) => {
                        let ack_msg = ClientStreamMessage {
                            payload: Some(client_stream_message::Payload::SignAck(SignAck {
                                request_id: sign_req.request_id.clone(),
                            })),
                        };
                        let ack_frame_b64 = STANDARD.encode(ack_msg.encode_to_vec());

                        // Verify end-to-end relay grant + signature + user pubkey match
                        if let Err(e) = verify_sign_request(&sign_req, now_unix_sec) {
                            let deny = ClientStreamMessage {
                                payload: Some(client_stream_message::Payload::SignResponse(
                                    SignResponse {
                                        request_id: sign_req.request_id.clone(),
                                        approved: false,
                                        signature_blob: Vec::new(),
                                        error_message: format!("End-to-end verification failed: {e}"),
                                        handled_by_node_id: self
                                            .bundle
                                            .as_ref()
                                            .map(|b| b.grant.node_id.clone())
                                            .unwrap_or_default(),
                                    },
                                )),
                            };
                            return json!({
                                "ok": true,
                                "frame_type": "sign_request_invalid",
                                "request_id": sign_req.request_id,
                                "error": e.to_string(),
                                "ack_frame_b64": ack_frame_b64,
                                "deny_frame_b64": STANDARD.encode(deny.encode_to_vec()),
                            });
                        }

                        if let Some(bundle) = &self.bundle {
                            let relay_user_pk = sign_req
                                .relay_grant
                                .as_ref()
                                .map(|g| g.user_pubkey.as_slice())
                                .unwrap_or(&[]);
                            if relay_user_pk != bundle.grant.user_pubkey.as_slice() {
                                let deny = ClientStreamMessage {
                                    payload: Some(client_stream_message::Payload::SignResponse(
                                        SignResponse {
                                            request_id: sign_req.request_id.clone(),
                                            approved: false,
                                            signature_blob: Vec::new(),
                                            error_message: "Relay user_pubkey mismatch".to_string(),
                                            handled_by_node_id: bundle.grant.node_id.clone(),
                                        },
                                    )),
                                };
                                return json!({
                                    "ok": true,
                                    "frame_type": "sign_request_invalid",
                                    "request_id": sign_req.request_id,
                                    "error": "Relay user_pubkey does not match client bundle user_pubkey",
                                    "ack_frame_b64": ack_frame_b64,
                                    "deny_frame_b64": STANDARD.encode(deny.encode_to_vec()),
                                });
                            }
                        }

                        // Reuse the exact native `PromptDetails::from_request` and `policy.rs` logic!
                        let known_pks = self.public_keys();
                        let prompt_details = PromptDetails::from_request(&sign_req, &known_pks);

                        let pc = sign_req.process_context.as_ref();
                        let ancestors: Vec<WasmAncestorInfo> = pc
                            .map(|p| {
                                p.ancestors
                                    .iter()
                                    .map(|a| WasmAncestorInfo {
                                        pid: a.pid,
                                        comm: a.comm.clone(),
                                        cmdline: a.cmdline.clone(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        let parsed_ssh = sign_req
                            .ssh_auth_context
                            .clone()
                            .unwrap_or_else(|| parse_ssh_auth_context(&sign_req.data));
                        let pk_info = parse_public_key_blob(sign_req.key_blob.clone(), "");
                        let key_fingerprint = pk_info.fingerprint_sha256;
                        let matching_key = self
                            .keys
                            .iter()
                            .find(|k| k.key_blob() == sign_req.key_blob.as_slice());

                        let info = WasmSignRequestInfo {
                            request_id: prompt_details.request_id,
                            timestamp_unix_ms: sign_req.timestamp_unix_ms,
                            verified_node_id: prompt_details.verified_host.clone(),
                            hostname: pc
                                .map(|p| p.hostname.clone())
                                .filter(|h| !h.is_empty())
                                .unwrap_or(prompt_details.verified_host),
                            uid: pc.map(|p| p.uid).unwrap_or(0),
                            pid: pc.map(|p| p.pid).unwrap_or(0),
                            comm: pc.map(|p| p.comm.clone()).unwrap_or_default(),
                            cmdline: pc.map(|p| p.cmdline.clone()).unwrap_or_default(),
                            cwd: prompt_details.cwd,
                            primary_tool: prompt_details.primary_tool,
                            primary_cmdline: prompt_details.primary_command,
                            ancestry_chain: prompt_details.ancestry_chain,
                            key_summary: prompt_details.key_summary,
                            ancestors,
                            is_userauth_request: parsed_ssh.is_userauth_request,
                            target_username: parsed_ssh.target_username,
                            service_name: parsed_ssh.service_name,
                            pubkey_algorithm: parsed_ssh.pubkey_algorithm,
                            key_fingerprint,
                            key_comment: matching_key
                                .map(|k| k.comment().to_string())
                                .unwrap_or_default(),
                            has_matching_key: matching_key.is_some(),
                        };

                        self.pending_requests
                            .insert(sign_req.request_id.clone(), sign_req);

                        json!({
                            "ok": true,
                            "frame_type": "sign_request",
                            "ack_frame_b64": ack_frame_b64,
                            "request": info,
                        })
                    }
                    None => json!({
                        "ok": true,
                        "frame_type": "empty",
                    }),
                }
            }
            "decide_sign_request" => {
                let request_id = req
                    .get("request_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let approved = req
                    .get("approved")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let Some(sign_req) = self.pending_requests.remove(&request_id) else {
                    return json!({
                        "ok": false,
                        "error": format!("SignRequest {request_id:?} is no longer pending")
                    });
                };
                let handled_by_node_id = self
                    .bundle
                    .as_ref()
                    .map(|b| b.grant.node_id.clone())
                    .unwrap_or_default();

                if !approved {
                    let resp_msg = ClientStreamMessage {
                        payload: Some(client_stream_message::Payload::SignResponse(SignResponse {
                            request_id,
                            approved: false,
                            signature_blob: Vec::new(),
                            error_message: "Denied by user in browser workstation".to_string(),
                            handled_by_node_id,
                        })),
                    };
                    return json!({
                        "ok": true,
                        "approved": false,
                        "frame_b64": STANDARD.encode(resp_msg.encode_to_vec()),
                    });
                }

                let Some(key) = self
                    .keys
                    .iter()
                    .find(|k| k.key_blob() == sign_req.key_blob.as_slice())
                else {
                    let resp_msg = ClientStreamMessage {
                        payload: Some(client_stream_message::Payload::SignResponse(SignResponse {
                            request_id,
                            approved: false,
                            signature_blob: Vec::new(),
                            error_message: "Requested SSH key is not loaded in browser workstation"
                                .to_string(),
                            handled_by_node_id,
                        })),
                    };
                    return json!({
                        "ok": false,
                        "error": "Requested SSH key is not loaded in browser workstation",
                        "frame_b64": STANDARD.encode(resp_msg.encode_to_vec()),
                    });
                };

                let signature_blob = match key.sign_ssh_data(&sign_req.data, sign_req.flags) {
                    Ok(sig) => sig,
                    Err(e) => {
                        return json!({
                            "ok": false,
                            "error": format!("Signing failed: {e}")
                        })
                    }
                };
                let resp_msg = ClientStreamMessage {
                    payload: Some(client_stream_message::Payload::SignResponse(SignResponse {
                        request_id,
                        approved: true,
                        signature_blob: signature_blob.clone(),
                        error_message: String::new(),
                        handled_by_node_id,
                    })),
                };
                json!({
                    "ok": true,
                    "approved": true,
                    "signature_b64": STANDARD.encode(&signature_blob),
                    "frame_b64": STANDARD.encode(resp_msg.encode_to_vec()),
                })
            }
            other => json!({
                "ok": false,
                "error": format!("Unknown WASM operation: {other:?}")
            }),
        }
    }

    pub fn call_json(&mut self, request_json: &str) -> String {
        let parsed: Value = match serde_json::from_str(request_json) {
            Ok(v) => v,
            Err(e) => {
                return serde_json::to_string(&json!({
                    "ok": false,
                    "error": format!("Invalid JSON request: {e}")
                }))
                .unwrap_or_default()
            }
        };
        let resp = self.call_value(parsed);
        serde_json::to_string(&resp).unwrap_or_default()
    }
}

static GLOBAL_ENGINE: OnceLock<Mutex<WasmWorkstationEngine>> = OnceLock::new();

fn global_engine() -> &'static Mutex<WasmWorkstationEngine> {
    GLOBAL_ENGINE.get_or_init(|| Mutex::new(WasmWorkstationEngine::new()))
}

pub fn wasm_call_json(request_json: &str) -> String {
    let mut guard = global_engine()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.call_json(request_json)
}

#[no_mangle]
pub extern "C" fn sshcast_wasm_alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `size` must have been allocated via `sshcast_wasm_alloc(size)`.
#[no_mangle]
pub unsafe extern "C" fn sshcast_wasm_free(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}

/// Executes a JSON command stored at `req_ptr..req_ptr+req_len` and stores the UTF-8 JSON response
/// inside the engine buffer. Returns the byte length of the response (retrieve pointer with
/// `sshcast_wasm_result_ptr`).
///
/// # Safety
/// `req_ptr` must point to `req_len` valid bytes in WASM linear memory.
#[no_mangle]
pub unsafe extern "C" fn sshcast_wasm_call(req_ptr: *const u8, req_len: usize) -> usize {
    let slice = if req_ptr.is_null() || req_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(req_ptr, req_len)
    };
    let req_str = std::str::from_utf8(slice).unwrap_or("{}");
    let mut guard = global_engine()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let resp_str = guard.call_json(req_str);
    guard.last_result_bytes = resp_str.into_bytes();
    guard.last_result_bytes.len()
}

#[no_mangle]
pub extern "C" fn sshcast_wasm_result_ptr() -> *const u8 {
    let guard = global_engine()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.last_result_bytes.as_ptr()
}

#[no_mangle]
pub extern "C" fn sshcast_wasm_result_len() -> usize {
    let guard = global_engine()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.last_result_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sshcast_proto::crypto::{
        derive_user_id, sign_node_grant, sign_sign_request, verify_node_auth,
        DEFAULT_MAX_CLOCK_SKEW_MS,
    };
    use sshcast_proto::v1::{NodeGrant, ProcessAncestor, ProcessContext};

    #[test]
    fn test_wasm_workstation_engine_shares_native_prompt_and_policy() {
        let user_sk = SigningKey::from_bytes(&[0x51; 32]);
        let client_sk = SigningKey::from_bytes(&[0x52; 32]);
        let relay_sk = SigningKey::from_bytes(&[0x53; 32]);
        let ssh_key = LoadedSshKey::from_ed25519_signing_key(
            SigningKey::from_bytes(&[0x66; 32]),
            "browser@chrome",
        );

        let mut client_grant = NodeGrant {
            user_id: derive_user_id(&user_sk.verifying_key().to_bytes()),
            user_pubkey: user_sk.verifying_key().to_bytes().to_vec(),
            node_id: "chrome-workstation".to_string(),
            role: NodeRole::Client as i32,
            node_pubkey: client_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
            user_cert: None,
        };
        sign_node_grant(&mut client_grant, &user_sk);

        let bundle = EnrollmentBundle::new(
            vec!["https://coord.example.com:8443".to_string()],
            client_sk,
            client_grant,
        );
        let bundle_token = format!(
            "{}.rk_{}",
            bundle.encode().unwrap(),
            URL_SAFE_NO_PAD.encode(user_sk.to_bytes())
        );

        let mut engine = WasmWorkstationEngine::new();

        let r1 = engine.call_value(json!({
            "op": "set_bundle",
            "bundle_str": bundle_token,
            "now_unix_sec": 1_750_000_000u64,
        }));
        assert_eq!(r1["ok"], Value::Bool(true));
        assert_eq!(r1["ws_url"], "wss://coord.example.com:8443/ws/workstation");
        assert_eq!(r1["has_user_root_key"], Value::Bool(true));
        assert!(!r1["bundle_str"].as_str().unwrap().contains(".rk_"));

        let r2 = engine.call_value(json!({
            "op": "add_ssh_key",
            "pem": ssh_key.to_openssh_pem(),
        }));
        assert_eq!(r2["ok"], Value::Bool(true));

        let r3 = engine.call_value(json!({
            "op": "build_auth_handshake_frame",
            "now_unix_ms": 1_750_000_000_000u64,
        }));
        assert_eq!(r3["ok"], Value::Bool(true));
        let hs_bytes = STANDARD.decode(r3["frame_b64"].as_str().unwrap()).unwrap();
        let hs_msg = ClientStreamMessage::decode(hs_bytes.as_slice()).unwrap();
        let Some(client_stream_message::Payload::AuthHandshake(node_auth)) = hs_msg.payload else {
            panic!("expected AuthHandshake payload");
        };
        verify_node_auth(
            &node_auth,
            Some(NodeRole::Client),
            1_750_000_000_500,
            DEFAULT_MAX_CLOCK_SKEW_MS,
        )
        .unwrap();

        let mut relay_grant = NodeGrant {
            user_id: derive_user_id(&user_sk.verifying_key().to_bytes()),
            user_pubkey: user_sk.verifying_key().to_bytes().to_vec(),
            node_id: "bastion.infra.local".to_string(),
            role: NodeRole::Relay as i32,
            node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
            user_cert: None,
        };
        sign_node_grant(&mut relay_grant, &user_sk);

        // Verify ssh inside bash + sshd-session keeps primary_tool="ssh" and primary_cmdline="ssh target.internal"
        let challenge = b"browser-wasm-sign-challenge";
        let mut sign_req = SignRequest {
            request_id: "req-wasm-1".to_string(),
            timestamp_unix_ms: 1_750_000_000_000,
            key_blob: ssh_key.key_blob().to_vec(),
            data: challenge.to_vec(),
            flags: 0,
            process_context: Some(ProcessContext {
                hostname: "bastion.infra.local".to_string(),
                uid: 1000,
                pid: 9001,
                comm: "ssh".to_string(),
                cmdline: "ssh target.internal".to_string(),
                cwd: "/home/pavel".to_string(),
                ancestors: vec![
                    ProcessAncestor {
                        pid: 9000,
                        comm: "bash".to_string(),
                        cmdline: "-bash".to_string(),
                    },
                    ProcessAncestor {
                        pid: 8999,
                        comm: "sshd-session".to_string(),
                        cmdline: "sshd-session: pavel@pts/0".to_string(),
                    },
                ],
            }),
            ssh_auth_context: None,
            relay_grant: Some(relay_grant),
            relay_signature: Vec::new(),
            auth: None,
        };
        sign_sign_request(&mut sign_req, &relay_sk).unwrap();

        let srv_frame = ServerStreamMessage {
            payload: Some(server_stream_message::Payload::SignRequest(sign_req)),
        };
        let r5 = engine.call_value(json!({
            "op": "decode_server_frame",
            "frame_b64": STANDARD.encode(srv_frame.encode_to_vec()),
            "now_unix_sec": 1_750_000_000u64,
        }));
        assert_eq!(r5["ok"], Value::Bool(true));
        assert_eq!(r5["frame_type"], "sign_request");
        assert_eq!(r5["request"]["primary_tool"], "ssh");
        assert_eq!(r5["request"]["primary_cmdline"], "ssh target.internal");
        assert_eq!(r5["request"]["has_matching_key"], Value::Bool(true));

        let r6 = engine.call_value(json!({
            "op": "decide_sign_request",
            "request_id": "req-wasm-1",
            "approved": true,
        }));
        assert_eq!(r6["ok"], Value::Bool(true));
        let resp_bytes = STANDARD.decode(r6["frame_b64"].as_str().unwrap()).unwrap();
        let resp_msg = ClientStreamMessage::decode(resp_bytes.as_slice()).unwrap();
        let Some(client_stream_message::Payload::SignResponse(sr)) = resp_msg.payload else {
            panic!("expected SignResponse payload");
        };
        assert!(sr.approved);
        ssh_key
            .verify_ssh_signature_blob(challenge, &sr.signature_blob)
            .unwrap();
    }

    #[test]
    fn test_wasm_expired_user_cert_renewal_roundtrip() {
        use sshcast_proto::bundle::encode_user_cert_token;
        use sshcast_proto::crypto::{derive_user_id, sign_user_cert, verify_node_auth};
        use sshcast_proto::v1::{NodeGrant, UserCert};

        let op_sk = SigningKey::from_bytes(&[0x71; 32]);
        let user_sk = SigningKey::from_bytes(&[0x72; 32]);
        let client_sk = SigningKey::from_bytes(&[0x73; 32]);
        let user_pk = user_sk.verifying_key().to_bytes().to_vec();

        let mut expired_cert = UserCert {
            user_id: derive_user_id(&user_pk),
            user_pubkey: user_pk.clone(),
            operator_pubkey: Vec::new(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 1_700_604_800,
            operator_signature: Vec::new(),
        };
        sign_user_cert(&mut expired_cert, &op_sk);

        let mut grant = NodeGrant {
            user_id: derive_user_id(&user_pk),
            user_pubkey: user_pk.clone(),
            node_id: "browser-laptop".to_string(),
            role: NodeRole::Client as i32,
            node_pubkey: client_sk.verifying_key().to_bytes().to_vec(),
            issued_at_unix_sec: 1_700_000_000,
            expires_at_unix_sec: 0,
            user_signature: Vec::new(),
            user_cert: Some(expired_cert),
        };
        sign_node_grant(&mut grant, &user_sk);

        let bundle = EnrollmentBundle::new(vec!["sshcast.net".to_string()], client_sk, grant);
        let bundle_str = bundle.encode().unwrap();

        let mut engine = WasmWorkstationEngine::new();
        let now_sec = 1_701_000_000u64; // past expired_cert.expires_at_unix_sec
        let res = engine.call_value(json!({
            "op": "set_bundle",
            "bundle_str": bundle_str,
            "now_unix_sec": now_sec,
        }));
        assert_eq!(res["ok"], Value::Bool(true));
        assert_eq!(res["has_user_cert"], Value::Bool(true));
        assert_eq!(res["user_cert_expired"], Value::Bool(true));

        let renew_auth = engine.call_value(json!({
            "op": "build_renew_node_auth",
            "now_unix_ms": now_sec * 1000,
        }));
        assert_eq!(renew_auth["ok"], Value::Bool(true));
        let auth_bytes = STANDARD
            .decode(renew_auth["node_auth_proto_b64"].as_str().unwrap())
            .unwrap();
        let auth_msg = sshcast_proto::v1::NodeAuth::decode(auth_bytes.as_slice()).unwrap();
        assert!(auth_msg.grant.as_ref().unwrap().user_cert.is_none());
        verify_node_auth(
            &auth_msg,
            Some(NodeRole::Client),
            now_sec * 1000,
            DEFAULT_MAX_CLOCK_SKEW_MS,
        )
        .unwrap();

        let mut fresh_cert = UserCert {
            user_id: derive_user_id(&user_pk),
            user_pubkey: user_pk,
            operator_pubkey: Vec::new(),
            issued_at_unix_sec: now_sec,
            expires_at_unix_sec: now_sec + 7 * 86_400,
            operator_signature: Vec::new(),
        };
        sign_user_cert(&mut fresh_cert, &op_sk);
        let fresh_tok = encode_user_cert_token(&fresh_cert);

        let updated = engine.call_value(json!({
            "op": "update_user_cert",
            "cert_token": fresh_tok,
            "now_unix_sec": now_sec,
        }));
        assert_eq!(updated["ok"], Value::Bool(true));
        assert_eq!(updated["user_cert_expired"], Value::Bool(false));
        assert_eq!(
            updated["cert_expires_at_unix_sec"],
            Value::from(now_sec + 7 * 86_400)
        );
        let updated_bundle_str = updated["updated_bundle_str"].as_str().unwrap();
        let rechecked = engine.call_value(json!({
            "op": "set_bundle",
            "bundle_str": updated_bundle_str,
            "now_unix_sec": now_sec + 10,
        }));
        assert_eq!(rechecked["ok"], Value::Bool(true));
        assert_eq!(rechecked["user_cert_expired"], Value::Bool(false));
    }

    #[test]
    fn test_wasm_github_signup_pairing_and_bundle_minting() {
        use sshcast_proto::bundle::encode_user_cert_token;
        use sshcast_proto::crypto::{derive_user_id, sign_user_cert};
        use sshcast_proto::v1::UserCert;

        let op_sk = SigningKey::from_bytes(&[0x81; 32]);
        let mut engine_a = WasmWorkstationEngine::new();
        let now_sec = 1_750_000_000u64;

        // 1. Fresh GitHub signup -> begin_github_enrollment + finalize_approved_enrollment
        let begin_a = engine_a.call_value(json!({
            "op": "begin_github_enrollment",
            "servers": ["sshcast.net"],
            "operator_url": "https://op.sshcast.net",
            "node_name": "browser-a",
            "candidate_user_seed_b64": STANDARD.encode([0x11u8; 32]),
            "node_seed_b64": STANDARD.encode([0x22u8; 32]),
            "eph_secret_b64": STANDARD.encode([0x33u8; 32]),
        }));
        assert_eq!(begin_a["ok"], Value::Bool(true));
        assert_eq!(begin_a["start_body"]["supports_pairing"], Value::Bool(true));
        assert_eq!(begin_a["start_body"]["os_name"], "browser-wasm");
        let user_pub_tok = begin_a["start_body"]["user_pubkey"].as_str().unwrap().to_string();
        let user_pk = parse_user_pubkey_token(&user_pub_tok).unwrap();

        let mut cert_a = UserCert {
            user_id: derive_user_id(&user_pk),
            user_pubkey: user_pk.to_vec(),
            operator_pubkey: Vec::new(),
            issued_at_unix_sec: now_sec - 10,
            expires_at_unix_sec: now_sec + 7 * 86_400,
            operator_signature: Vec::new(),
        };
        sign_user_cert(&mut cert_a, &op_sk);
        let cert_tok_a = encode_user_cert_token(&cert_a);

        let fin_a = engine_a.call_value(json!({
            "op": "finalize_approved_enrollment",
            "cert_token": cert_tok_a,
            "now_unix_sec": now_sec,
        }));
        assert_eq!(fin_a["ok"], Value::Bool(true));
        assert_eq!(fin_a["has_user_root_key"], Value::Bool(true));
        assert_eq!(fin_a["node_id"], "browser-a");
        assert!(!fin_a["bundle_str"].as_str().unwrap().contains(".rk_"));

        // 2. Export/import scu1_ + mint RELAY and CLIENT bundles
        let exp = engine_a.call_value(json!({ "op": "export_user_root_key" }));
        assert_eq!(exp["ok"], Value::Bool(true));
        let scu1_tok = exp["root_key_token"].as_str().unwrap().to_string();
        assert!(scu1_tok.starts_with("scu1_"));

        let mint_relay = engine_a.call_value(json!({
            "op": "mint_enrollment_bundle",
            "node_id": "relay-1",
            "role": "RELAY",
            "include_root_key": true, // must never include .rk_ for RELAY
            "now_unix_sec": now_sec,
            "node_seed_b64": STANDARD.encode([0x44u8; 32]),
        }));
        assert_eq!(mint_relay["ok"], Value::Bool(true));
        assert!(!mint_relay["bundle_str"].as_str().unwrap().contains(".rk_"));
        assert!(mint_relay["command_hint"]
            .as_str()
            .unwrap()
            .starts_with("sshcast-relay init --bundle sc1_"));

        let mint_client = engine_a.call_value(json!({
            "op": "mint_enrollment_bundle",
            "node_id": "laptop-b",
            "role": "CLIENT",
            "include_root_key": true,
            "now_unix_sec": now_sec,
            "node_seed_b64": STANDARD.encode([0x45u8; 32]),
        }));
        assert_eq!(mint_client["ok"], Value::Bool(true));
        assert!(mint_client["bundle_str"].as_str().unwrap().contains(".rk_"));

        // Loading bundle without .rk_ strips root key if different user, or clears when cleared
        let mut engine_c = WasmWorkstationEngine::new();
        let node_only = engine_c.call_value(json!({
            "op": "set_bundle",
            "bundle_str": fin_a["bundle_str"],
            "now_unix_sec": now_sec,
        }));
        assert_eq!(node_only["ok"], Value::Bool(true));
        assert_eq!(node_only["has_user_root_key"], Value::Bool(false));
        let imp = engine_c.call_value(json!({
            "op": "import_user_root_key",
            "token": scu1_tok,
        }));
        assert_eq!(imp["ok"], Value::Bool(true));
        assert_eq!(imp["has_user_root_key"], Value::Bool(true));

        // 3. Pairing between engine_b (requester) and engine_a (approver)
        let mut engine_b = WasmWorkstationEngine::new();
        let begin_b = engine_b.call_value(json!({
            "op": "begin_github_enrollment",
            "servers": ["sshcast.net"],
            "operator_url": "https://op.sshcast.net",
            "node_name": "browser-b",
            "candidate_user_seed_b64": STANDARD.encode([0x55u8; 32]),
            "node_seed_b64": STANDARD.encode([0x66u8; 32]),
            "eph_secret_b64": STANDARD.encode([0x77u8; 32]),
        }));
        assert_eq!(begin_b["ok"], Value::Bool(true));
        let req_node_pub_b64 = begin_b["start_body"]["node_pubkey_b64"].as_str().unwrap();
        let req_eph_pub_b64 = begin_b["start_body"]["eph_x25519_pub_b64"].as_str().unwrap();

        let sas_b = engine_b.call_value(json!({
            "op": "compute_pairing_sas",
            "existing_user_pubkey": user_pub_tok,
        }));
        let sas_a = engine_a.call_value(json!({
            "op": "compute_incoming_pairing_sas",
            "eph_x25519_pub_b64": req_eph_pub_b64,
        }));
        assert_eq!(sas_b["sas_code"], sas_a["sas_code"]);

        let approved = engine_a.call_value(json!({
            "op": "approve_pairing_request",
            "pairing_id": "pair_test_1",
            "node_name": "browser-b",
            "node_pubkey_b64": req_node_pub_b64,
            "eph_x25519_pub_b64": req_eph_pub_b64,
            "operator_url": "https://op.sshcast.net",
            "now_unix_sec": now_sec,
            "now_unix_ms": now_sec * 1000,
            "approver_eph_secret_b64": STANDARD.encode([0x88u8; 32]),
            "handoff_nonce_b64": STANDARD.encode([0x99u8; 12]),
            "auth_nonce_b64": STANDARD.encode([0xaau8; 16]),
        }));
        assert_eq!(approved["ok"], Value::Bool(true));
        assert!(approved["node_auth_proto_b64"].as_str().is_some());

        let env = &approved["envelope"];
        let paired = engine_b.call_value(json!({
            "op": "complete_paired_enrollment",
            "pairing_id": "pair_test_1",
            "existing_user_pubkey": user_pub_tok,
            "approver_eph_x25519_pub_b64": env["approver_eph_x25519_pub_b64"],
            "approver_signature_b64": env["approver_signature_b64"],
            "handoff_nonce_b64": env["handoff_nonce_b64"],
            "encrypted_handoff_b64": env["encrypted_handoff_b64"],
            "now_unix_sec": now_sec,
        }));
        assert_eq!(paired["ok"], Value::Bool(true));
        assert_eq!(paired["has_user_root_key"], Value::Bool(true));
        assert_eq!(paired["user_pubkey_token"], user_pub_tok);
        assert_eq!(paired["node_id"], "browser-b");
        assert_eq!(paired["needs_cert_renewal"], Value::Bool(false));
    }

    #[test]
    fn test_wasm_recovery_vault_worker_flow_and_ephemeral_ssh_key() {
        use sshcast_proto::bundle::encode_user_cert_token;
        use sshcast_proto::crypto::{derive_user_id, sign_user_cert};
        use sshcast_proto::v1::UserCert;

        let op_sk = SigningKey::from_bytes(&[0x91; 32]);
        let mut engine_a = WasmWorkstationEngine::new();
        let now_sec = 1_750_000_000u64;

        let begin_a = engine_a.call_value(json!({
            "op": "begin_github_enrollment",
            "servers": ["sshcast.net"],
            "operator_url": "https://op.sshcast.net",
            "node_name": "browser-a",
            "candidate_user_seed_b64": STANDARD.encode([0x12u8; 32]),
            "node_seed_b64": STANDARD.encode([0x23u8; 32]),
            "eph_secret_b64": STANDARD.encode([0x34u8; 32]),
        }));
        let user_pub_tok = begin_a["start_body"]["user_pubkey"].as_str().unwrap().to_string();
        let user_pk = parse_user_pubkey_token(&user_pub_tok).unwrap();

        let mut cert_a = UserCert {
            user_id: derive_user_id(&user_pk),
            user_pubkey: user_pk.to_vec(),
            operator_pubkey: Vec::new(),
            issued_at_unix_sec: now_sec - 10,
            expires_at_unix_sec: now_sec + 7 * 86_400,
            operator_signature: Vec::new(),
        };
        sign_user_cert(&mut cert_a, &op_sk);
        engine_a.call_value(json!({
            "op": "finalize_approved_enrollment",
            "cert_token": encode_user_cert_token(&cert_a),
            "now_unix_sec": now_sec,
        }));

        // Worker-split scrypt key derivation (log_n = 10 for fast test)
        let salt_b64 = STANDARD.encode([0x55u8; 16]);
        let dk_set = engine_a.call_value(json!({
            "op": "derive_scrypt_key",
            "passphrase": "correct-battery-horse-staple",
            "salt_b64": salt_b64,
            "log_n": 10,
            "r": 8,
            "p": 1,
        }));
        assert_eq!(dk_set["ok"], Value::Bool(true));

        let enc = engine_a.call_value(json!({
            "op": "encrypt_recovery_vault",
            "derived_key_b64": dk_set["derived_key_b64"],
            "salt_b64": salt_b64,
            "nonce_b64": STANDARD.encode([0x66u8; 12]),
            "log_n": 10,
            "r": 8,
            "p": 1,
            "now_unix_ms": now_sec * 1000,
        }));
        assert_eq!(enc["ok"], Value::Bool(true));
        let vault = &enc["vault"];

        // Device B unlocks with wrong passphrase -> wrong_passphrase: true
        let mut engine_b = WasmWorkstationEngine::new();
        engine_b.call_value(json!({
            "op": "begin_github_enrollment",
            "servers": ["sshcast.net"],
            "operator_url": "https://op.sshcast.net",
            "node_name": "browser-recovered",
            "candidate_user_seed_b64": STANDARD.encode([0x77u8; 32]),
            "node_seed_b64": STANDARD.encode([0x88u8; 32]),
            "eph_secret_b64": STANDARD.encode([0x99u8; 32]),
        }));

        let wrong_dk = engine_b.call_value(json!({
            "op": "derive_scrypt_key",
            "passphrase": "wrong-passphrase",
            "salt_b64": vault["salt_b64"],
            "log_n": vault["kdf_params"]["log_n"],
            "r": vault["kdf_params"]["r"],
            "p": vault["kdf_params"]["p"],
        }));
        let bad_unlock = engine_b.call_value(json!({
            "op": "unlock_recovery_vault",
            "vault": vault,
            "existing_user_pubkey": user_pub_tok,
            "derived_key_b64": wrong_dk["derived_key_b64"],
            "now_unix_sec": now_sec,
            "now_unix_ms": now_sec * 1000,
        }));
        assert_eq!(bad_unlock["ok"], Value::Bool(false));
        assert_eq!(bad_unlock["wrong_passphrase"], Value::Bool(true));

        // Retry with correct passphrase -> succeeds and yields renew_node_auth_proto_b64
        let good_dk = engine_b.call_value(json!({
            "op": "derive_scrypt_key",
            "passphrase": "correct-battery-horse-staple",
            "salt_b64": vault["salt_b64"],
            "log_n": vault["kdf_params"]["log_n"],
            "r": vault["kdf_params"]["r"],
            "p": vault["kdf_params"]["p"],
        }));
        let good_unlock = engine_b.call_value(json!({
            "op": "unlock_recovery_vault",
            "vault": vault,
            "existing_user_pubkey": user_pub_tok,
            "derived_key_b64": good_dk["derived_key_b64"],
            "now_unix_sec": now_sec,
            "now_unix_ms": now_sec * 1000,
        }));
        assert_eq!(good_unlock["ok"], Value::Bool(true));
        assert_eq!(good_unlock["user_pubkey_token"], user_pub_tok);
        assert_eq!(good_unlock["has_user_root_key"], Value::Bool(true));
        assert!(good_unlock["renew_node_auth_proto_b64"].as_str().is_some());

        // Ephemeral SSH keygen returns authorized_key_line and can sign challenges
        let gen_key = engine_b.call_value(json!({
            "op": "generate_ssh_key",
            "seed_b64": STANDARD.encode([0xabu8; 32]),
            "comment": "trip-laptop",
        }));
        assert_eq!(gen_key["ok"], Value::Bool(true));
        let auth_line = gen_key["added_key"]["authorized_key_line"].as_str().unwrap();
        assert!(auth_line.starts_with("ssh-ed25519 "));
        assert!(auth_line.ends_with(" trip-laptop"));
    }
}
