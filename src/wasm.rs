use crate::prompt::PromptDetails;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::crypto::{
    create_node_auth_with_nonce, verify_node_grant, verify_sign_request,
};
use sockcast_proto::ssh::{parse_public_key_blob, parse_ssh_auth_context, LoadedSshKey};
use sockcast_proto::v1::{
    client_stream_message, server_stream_message, ClientStreamMessage, NodeRole, PublicKey,
    ServerStreamMessage, SignAck, SignRequest, SignResponse, WorkstationStatus,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmHeldKeyInfo {
    pub key_type: String,
    pub fingerprint_sha256: String,
    pub comment: String,
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

#[derive(Default)]
pub struct WasmWorkstationEngine {
    bundle: Option<EnrollmentBundle>,
    keys: Vec<LoadedSshKey>,
    pending_requests: HashMap<String, SignRequest>,
    nonce_counter: u64,
    last_result_bytes: Vec<u8>,
}

impl WasmWorkstationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    fn key_summaries(&self) -> Vec<WasmHeldKeyInfo> {
        self.keys
            .iter()
            .map(|k| WasmHeldKeyInfo {
                key_type: k.key_type().to_string(),
                fingerprint_sha256: k.fingerprint_sha256().to_string(),
                comment: k.comment().to_string(),
            })
            .collect()
    }

    fn public_keys(&self) -> Vec<PublicKey> {
        self.keys
            .iter()
            .map(|k| k.public_key_proto())
            .collect()
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
                if let Err(e) = verify_node_grant(&bundle.grant, now_unix_sec) {
                    return json!({
                        "ok": false,
                        "error": format!("Node grant verification failed: {e}")
                    });
                }
                if bundle.grant.role != NodeRole::Client as i32 {
                    return json!({
                        "ok": false,
                        "error": "Enrollment bundle has RELAY role; browser workstation requires a CLIENT bundle"
                    });
                }
                let coordinator_url = bundle.servers.first().cloned().unwrap_or_default();
                let ws_url = Self::derive_ws_url(&coordinator_url);
                let resp = json!({
                    "ok": true,
                    "coordinator_url": coordinator_url,
                    "ws_url": ws_url,
                    "servers": bundle.servers,
                    "user_id": bundle.grant.user_id,
                    "node_id": bundle.grant.node_id,
                    "role": "CLIENT",
                    "issued_at_unix_sec": bundle.grant.issued_at_unix_sec,
                    "expires_at_unix_sec": bundle.grant.expires_at_unix_sec,
                });
                if op == "set_bundle" {
                    self.bundle = Some(bundle);
                }
                resp
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
                            "needs_passphrase": matches!(e, sockcast_proto::ssh::SshKeyError::PassphraseRequired)
                        })
                    }
                };
                let added = WasmHeldKeyInfo {
                    key_type: key.key_type().to_string(),
                    fingerprint_sha256: key.fingerprint_sha256().to_string(),
                    comment: key.comment().to_string(),
                };
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
                    h.update(b"sockcast-wasm-nonce-v1");
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
pub extern "C" fn sockcast_wasm_alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `size` must have been allocated via `sockcast_wasm_alloc(size)`.
#[no_mangle]
pub unsafe extern "C" fn sockcast_wasm_free(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}

/// Executes a JSON command stored at `req_ptr..req_ptr+req_len` and stores the UTF-8 JSON response
/// inside the engine buffer. Returns the byte length of the response (retrieve pointer with
/// `sockcast_wasm_result_ptr`).
///
/// # Safety
/// `req_ptr` must point to `req_len` valid bytes in WASM linear memory.
#[no_mangle]
pub unsafe extern "C" fn sockcast_wasm_call(req_ptr: *const u8, req_len: usize) -> usize {
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
pub extern "C" fn sockcast_wasm_result_ptr() -> *const u8 {
    let guard = global_engine()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.last_result_bytes.as_ptr()
}

#[no_mangle]
pub extern "C" fn sockcast_wasm_result_len() -> usize {
    let guard = global_engine()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.last_result_bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sockcast_proto::crypto::{
        derive_user_id, sign_node_grant, sign_sign_request, verify_node_auth,
        DEFAULT_MAX_CLOCK_SKEW_MS,
    };
    use sockcast_proto::v1::{NodeGrant, ProcessAncestor, ProcessContext};

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
        };
        sign_node_grant(&mut client_grant, &user_sk);

        let bundle = EnrollmentBundle::new(
            vec!["https://coord.example.com:8443".to_string()],
            client_sk,
            client_grant,
        );
        let bundle_token = format!("{}.rk_dGVzdC1yb290LWtleS1zdWZmaXg", bundle.encode().unwrap());

        let mut engine = WasmWorkstationEngine::new();

        let r1 = engine.call_value(json!({
            "op": "set_bundle",
            "bundle_str": bundle_token,
            "now_unix_sec": 1_750_000_000u64,
        }));
        assert_eq!(r1["ok"], Value::Bool(true));
        assert_eq!(r1["ws_url"], "wss://coord.example.com:8443/ws/workstation");

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
}
