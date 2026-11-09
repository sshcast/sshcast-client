use ed25519_dalek::SigningKey;
use sockcast_client::config::{ClientConfig, KeyFilterConfig};
use sockcast_client::coordinator::{handle_incoming_sign_request, WorkstationManager};
use sockcast_client::enroll::{
    decode_enrollment_bundle_token, encode_enrollment_bundle_token, export_user_root_key,
    import_user_root_key, load_user_signing_key, mint_enrollment_bundle, run_keygen,
    write_client_config_and_optional_root_key, write_client_config_from_bundle,
};
use sockcast_client::local_agent::{
    filter_keys, LocalAgentConnector, SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST,
    SSH2_AGENT_IDENTITIES_ANSWER, SSH2_AGENT_SIGN_RESPONSE,
};
use sockcast_client::policy::{ApprovalDecision, PolicyEngine};
use sockcast_client::prompt::{ApprovalPrompter, PromptDetails, StaticPrompter};
use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::crypto::{
    sign_node_grant, sign_sign_request, verify_node_auth, DEFAULT_MAX_CLOCK_SKEW_MS,
};
use sockcast_proto::ssh::parse_public_key_blob;
use sockcast_proto::v1::client_stream_message::Payload as ClientPayload;
use sockcast_proto::v1::server_stream_message::Payload as ServerPayload;
use sockcast_proto::v1::sockcast_service_server::{SockcastService, SockcastServiceServer};
use sockcast_proto::v1::{
    ClientStreamMessage, GetIdentitiesRequest, GetIdentitiesResponse, NodeGrant, NodeRole,
    ProcessAncestor, ProcessContext, ServerStreamMessage, SignAck, SignRequest, SignResponse,
    SshAuthContext, WorkstationStatus,
};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch, Mutex};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status, Streaming};

fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

async fn handle_mock_agent_stream<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).await.is_err() {
            break;
        }
        let msg_type = body[0];
        let mut reply = Vec::new();
        if msg_type == SSH2_AGENTC_REQUEST_IDENTITIES {
            reply.push(SSH2_AGENT_IDENTITIES_ANSWER);
            reply.extend_from_slice(&2u32.to_be_bytes());

            // Key 1: work key
            let mut k1 = Vec::new();
            write_ssh_bytes(&mut k1, b"ssh-ed25519");
            write_ssh_bytes(&mut k1, &[0x11; 32]);
            write_ssh_bytes(&mut reply, &k1);
            write_ssh_bytes(&mut reply, b"pavel@workstation");

            // Key 2: personal key (to test filtering)
            let mut k2 = Vec::new();
            write_ssh_bytes(&mut k2, b"ssh-ed25519");
            write_ssh_bytes(&mut k2, &[0x22; 32]);
            write_ssh_bytes(&mut reply, &k2);
            write_ssh_bytes(&mut reply, b"personal@github");
        } else if msg_type == SSH2_AGENTC_SIGN_REQUEST {
            reply.push(SSH2_AGENT_SIGN_RESPONSE);
            write_ssh_bytes(&mut reply, b"local-os-agent-ed25519-sig");
        } else {
            reply.push(5); // SSH_AGENT_FAILURE
        }

        let out_len = (reply.len() as u32).to_be_bytes();
        let _ = stream.write_all(&out_len).await;
        let _ = stream.write_all(&reply).await;
        let _ = stream.flush().await;
    }
}

/// Spawns a mock local OS SSH agent on a Unix socket (Unix) or Named Pipe (Windows).
#[cfg(unix)]
async fn spawn_mock_local_ssh_agent(tmp: &TempDir) -> String {
    let sock_path = tmp.path().join("mock-agent.sock");
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_mock_agent_stream(stream));
        }
    });
    sock_path.to_string_lossy().into_owned()
}

#[cfg(windows)]
async fn spawn_mock_local_ssh_agent(_tmp: &TempDir) -> String {
    use tokio::net::windows::named_pipe::ServerOptions;
    let pipe_name = format!(r"\\.\pipe\sockcast-mock-agent-{}", std::process::id());
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)
        .unwrap();
    let pipe_name_clone = pipe_name.clone();
    tokio::spawn(async move {
        while server.connect().await.is_ok() {
            let connected = server;
            server = match ServerOptions::new().create(&pipe_name_clone) {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(handle_mock_agent_stream(connected));
        }
    });
    pipe_name
}

#[test]
fn test_keygen_and_grant_relay_and_client_bundles() {
    let tmp = TempDir::new().unwrap();
    let user_key_path = tmp.path().join("user_key.toml");
    let client_cfg_path = tmp.path().join("client.toml");

    let kg = run_keygen(Some(&user_key_path), false).unwrap();
    assert!(kg.user_id.starts_with("sc_u_"));
    assert!(kg.user_pubkey_token.starts_with("sc_pub_"));

    let user_sk = load_user_signing_key(Some(&user_key_path)).unwrap();

    // 1. Mint relay bundle and verify decoding
    let relay_bundle = mint_enrollment_bundle(
        &user_sk,
        "server-x.infra.local",
        NodeRole::Relay,
        vec!["https://coord.example.com".to_string()],
        30,
    )
    .unwrap();
    let relay_token = relay_bundle.encode().unwrap();
    let decoded_relay = EnrollmentBundle::decode(&relay_token).unwrap();
    assert_eq!(decoded_relay.grant.node_id, "server-x.infra.local");
    assert_eq!(decoded_relay.grant.role, NodeRole::Relay as i32);

    // 2. Mint client bundle and write client.toml
    let client_bundle = mint_enrollment_bundle(
        &user_sk,
        "macbook-pro",
        NodeRole::Client,
        vec!["https://coord.example.com".to_string()],
        0,
    )
    .unwrap();
    write_client_config_from_bundle(&client_bundle, Some(&client_cfg_path), false).unwrap();
    // Second write without --force must fail instead of silently overwriting client.toml
    assert!(write_client_config_from_bundle(&client_bundle, Some(&client_cfg_path), false).is_err());
    // Overwrite succeeds with force = true
    write_client_config_from_bundle(&client_bundle, Some(&client_cfg_path), true).unwrap();

    let loaded_client = ClientConfig::load(Some(&client_cfg_path)).unwrap();
    assert_eq!(loaded_client.grant.node_id, "macbook-pro");
    assert_eq!(loaded_client.grant.role, NodeRole::Client as i32);

    // 3. Client bundle with embedded root key (.rk_<seed>) writes both client.toml and user_key.toml
    let secondary_dir = tmp.path().join("secondary");
    let sec_cfg_path = secondary_dir.join("client.toml");
    let sec_key_path = secondary_dir.join("user_key.toml");
    let client_token_with_rk =
        encode_enrollment_bundle_token(&client_bundle, Some(&user_sk)).unwrap();
    assert!(client_token_with_rk.contains(".rk_"));

    // Relay bundle never embeds .rk_ even if passed Some(&user_sk)
    let relay_token_checked =
        encode_enrollment_bundle_token(&relay_bundle, Some(&user_sk)).unwrap();
    assert!(!relay_token_checked.contains(".rk_"));

    let (decoded_sec, maybe_rk) = decode_enrollment_bundle_token(&client_token_with_rk).unwrap();
    assert!(maybe_rk.is_some());
    let (written_cfg, written_key) = write_client_config_and_optional_root_key(
        &decoded_sec,
        maybe_rk.as_ref(),
        Some(&sec_cfg_path),
        Some(&sec_key_path),
        false,
    )
    .unwrap();
    assert_eq!(written_cfg, sec_cfg_path);
    assert_eq!(written_key.as_deref(), Some(sec_key_path.as_path()));
    let sec_loaded_sk = load_user_signing_key(Some(&sec_key_path)).unwrap();
    assert_eq!(sec_loaded_sk.to_bytes(), user_sk.to_bytes());

    // 4. Export / Import user root key (scu1_<base64>) for an already-enrolled secondary workstation
    let exported_scu = export_user_root_key(Some(&user_key_path)).unwrap();
    assert!(exported_scu.starts_with("scu1_"));
    let imported_key_path = tmp.path().join("imported_user_key.toml");
    let imported_out = import_user_root_key(
        &exported_scu,
        Some(&imported_key_path),
        Some(&client_cfg_path),
        false,
    )
    .unwrap();
    assert_eq!(imported_out.user_id, kg.user_id);

    // Importing a DIFFERENT user's root key onto an enrolled workstation must be rejected
    let other_key_path = tmp.path().join("other_user_key.toml");
    run_keygen(Some(&other_key_path), false).unwrap();
    let other_scu = export_user_root_key(Some(&other_key_path)).unwrap();
    assert!(import_user_root_key(
        &other_scu,
        Some(&imported_key_path),
        Some(&client_cfg_path),
        true,
    )
    .is_err());
}

#[test]
fn test_key_filtering_and_15m_policy_engine() {
    let mut k1_blob = Vec::new();
    write_ssh_bytes(&mut k1_blob, b"ssh-ed25519");
    write_ssh_bytes(&mut k1_blob, &[0x11; 32]);
    let k1 = parse_public_key_blob(k1_blob.clone(), "pavel@workstation");

    let mut k2_blob = Vec::new();
    write_ssh_bytes(&mut k2_blob, b"ssh-ed25519");
    write_ssh_bytes(&mut k2_blob, &[0x22; 32]);
    let k2 = parse_public_key_blob(k2_blob.clone(), "personal@github");

    let filter = KeyFilterConfig {
        allowed_fingerprints: Vec::new(),
        allowed_comment_substrings: vec!["workstation".to_string()],
        excluded_fingerprints: Vec::new(),
    };
    let filtered = filter_keys(vec![k1.clone(), k2.clone()], &filter);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].comment, "pavel@workstation");

    // Test 15-minute PolicyEngine scoping:
    // Approving `scp` on `server-x` for 15m must auto-approve subsequent `scp` calls on `server-x`
    // for the same key and target user, but MUST NOT auto-approve `git` or direct `ssh` on `server-x`!
    let policy = PolicyEngine::new(Duration::from_secs(900));
    let t0 = Instant::now();

    let scp_req = SignRequest {
        request_id: "req-1".to_string(),
        timestamp_unix_ms: 1000,
        key_blob: k1_blob.clone(),
        data: Vec::new(),
        flags: 0,
        process_context: Some(ProcessContext {
            hostname: "server-x.local".to_string(),
            uid: 1000,
            pid: 500,
            comm: "ssh".to_string(),
            cmdline: "ssh server-y scp -t /tmp".to_string(),
            cwd: "/home/pavel".to_string(),
            ancestors: vec![ProcessAncestor {
                pid: 499,
                comm: "scp".to_string(),
                cmdline: "scp pkg.rpm server-y:/tmp".to_string(),
            }],
        }),
        ssh_auth_context: Some(SshAuthContext {
            is_userauth_request: true,
            target_username: "pavel".to_string(),
            service_name: "ssh-connection".to_string(),
            pubkey_algorithm: "ssh-ed25519".to_string(),
            session_id: vec![1, 2, 3],
        }),
        relay_grant: None,
        relay_signature: Vec::new(),
        auth: None,
    };

    assert!(!policy.check_auto_approved_at(&scp_req, t0));
    policy.record_decision_at(&scp_req, ApprovalDecision::ApproveToolOnHost15m, t0);
    assert!(policy.check_auto_approved_at(&scp_req, t0 + Duration::from_secs(60)));

    // Direct `ssh` without `scp` parent must NOT match the `scp` tool rule
    let mut direct_ssh_req = scp_req.clone();
    direct_ssh_req.process_context.as_mut().unwrap().ancestors.clear();
    assert!(!policy.check_auto_approved_at(&direct_ssh_req, t0 + Duration::from_secs(60)));

    // Different target SSH user (`root`) must NOT match the `pavel` rule
    let mut root_scp_req = scp_req.clone();
    root_scp_req
        .ssh_auth_context
        .as_mut()
        .unwrap()
        .target_username = "root".to_string();
    assert!(!policy.check_auto_approved_at(&root_scp_req, t0 + Duration::from_secs(60)));

    // Expired after 15m + 1s
    assert!(!policy.check_auto_approved_at(&scp_req, t0 + Duration::from_secs(901)));
}

struct CountingPrompter {
    calls: AtomicUsize,
    decision: ApprovalDecision,
}

#[tonic::async_trait]
impl ApprovalPrompter for CountingPrompter {
    async fn prompt_user(
        &self,
        _details: PromptDetails,
        _cancel_rx: watch::Receiver<Option<String>>,
    ) -> ApprovalDecision {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.decision
    }
}

struct MockCoordinatorStreamServer {
    sign_req_to_push: SignRequest,
    ack_tx: Mutex<Option<mpsc::Sender<SignAck>>>,
    resp_tx: Mutex<Option<mpsc::Sender<SignResponse>>>,
    status_tx: Mutex<Option<mpsc::Sender<WorkstationStatus>>>,
}

#[tonic::async_trait]
impl SockcastService for MockCoordinatorStreamServer {
    async fn get_identities(
        &self,
        _request: Request<GetIdentitiesRequest>,
    ) -> Result<Response<GetIdentitiesResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn sign(&self, _request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }

    type ConnectWorkstationStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ServerStreamMessage, Status>> + Send>>;

    async fn connect_workstation(
        &self,
        request: Request<Streaming<ClientStreamMessage>>,
    ) -> Result<Response<Self::ConnectWorkstationStream>, Status> {
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::unauthenticated("missing handshake"))?;
        let Some(ClientPayload::AuthHandshake(auth)) = first.payload else {
            return Err(Status::unauthenticated("expected AuthHandshake first"));
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        verify_node_auth(
            &auth,
            Some(NodeRole::Client),
            now_ms,
            DEFAULT_MAX_CLOCK_SKEW_MS,
        )
        .map_err(|e| Status::unauthenticated(e.to_string()))?;

        let (tx, rx) = mpsc::channel(16);
        let sign_req = self.sign_req_to_push.clone();
        let ack_tx = self.ack_tx.lock().await.take();
        let resp_tx = self.resp_tx.lock().await.take();
        let status_tx = self.status_tx.lock().await.take();

        tokio::spawn(async move {
            // Send initial server heartbeat
            let _ = tx
                .send(Ok(ServerStreamMessage {
                    payload: Some(ServerPayload::ServerHeartbeatEpochMs(now_ms)),
                }))
                .await;

            let mut pushed_sign = false;
            while let Ok(Some(msg)) = inbound.message().await {
                match msg.payload {
                    Some(ClientPayload::Status(st)) => {
                        if let Some(ref s_tx) = status_tx {
                            let _ = s_tx.send(st).await;
                        }
                        if !pushed_sign {
                            pushed_sign = true;
                            let _ = tx
                                .send(Ok(ServerStreamMessage {
                                    payload: Some(ServerPayload::SignRequest(sign_req.clone())),
                                }))
                                .await;
                        }
                    }
                    Some(ClientPayload::SignAck(ack)) => {
                        if let Some(ref a_tx) = ack_tx {
                            let _ = a_tx.send(ack).await;
                        }
                    }
                    Some(ClientPayload::SignResponse(resp)) => {
                        if let Some(ref r_tx) = resp_tx {
                            let _ = r_tx.send(resp).await;
                        }
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

#[tokio::test]
async fn test_workstation_stream_end_to_end_verification_sign_ack_and_local_agent_bridge() {
    let tmp = TempDir::new().unwrap();
    let agent_endpoint = spawn_mock_local_ssh_agent(&tmp).await;

    let user_sk = SigningKey::from_bytes(&[0x10; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x20; 32]);
    let client_sk = SigningKey::from_bytes(&[0x30; 32]);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ms = now_sec * 1000;

    let mut relay_grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "server-x.infra.local".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
    };
    sign_node_grant(&mut relay_grant, &user_sk);

    let mut client_grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "workstation-1".to_string(),
        role: NodeRole::Client as i32,
        node_pubkey: client_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
    };
    sign_node_grant(&mut client_grant, &user_sk);

    let mut k1_blob = Vec::new();
    write_ssh_bytes(&mut k1_blob, b"ssh-ed25519");
    write_ssh_bytes(&mut k1_blob, &[0x11; 32]);

    let mut valid_sign_req = SignRequest {
        request_id: "req-e2e-100".to_string(),
        timestamp_unix_ms: now_ms,
        key_blob: k1_blob.clone(),
        data: b"ssh-challenge-data".to_vec(),
        flags: 0,
        process_context: Some(ProcessContext {
            hostname: "server-x.infra.local".to_string(),
            uid: 1000,
            pid: 9001,
            comm: "ssh".to_string(),
            cmdline: "ssh server-y".to_string(),
            cwd: "/home/pavel".to_string(),
            ancestors: Vec::new(),
        }),
        ssh_auth_context: Some(SshAuthContext {
            is_userauth_request: true,
            target_username: "pavel".to_string(),
            service_name: "ssh-connection".to_string(),
            pubkey_algorithm: "ssh-ed25519".to_string(),
            session_id: vec![0xaa, 0xbb],
        }),
        relay_grant: Some(relay_grant),
        relay_signature: Vec::new(),
        auth: None,
    };
    sign_sign_request(&mut valid_sign_req, &relay_sk).unwrap();

    // 1. Verify that tampering with the challenge data or hostname is caught by handle_incoming_sign_request!
    let mut tampered_req = valid_sign_req.clone();
    tampered_req.data = b"attacker-tampered-challenge".to_vec();

    let connector = Arc::new(LocalAgentConnector::new(
        Some(agent_endpoint.clone()),
        KeyFilterConfig {
            allowed_fingerprints: Vec::new(),
            allowed_comment_substrings: vec!["workstation".to_string()],
            excluded_fingerprints: Vec::new(),
        },
    ));
    let policy = Arc::new(PolicyEngine::default());
    let static_prompter: Arc<dyn ApprovalPrompter> =
        Arc::new(StaticPrompter::new(ApprovalDecision::ApproveOnce));

    let dummy_cfg = ClientConfig {
        servers: vec!["http://127.0.0.1:1".to_string()],
        node_signing_key: client_sk.clone(),
        grant: client_grant.clone(),
        local_agent_socket: Some(agent_endpoint.clone()),
        heartbeat_interval_secs: 25,
        force_active: true,
        key_filter: KeyFilterConfig::default(),
    };

    let (_c_tx, c_rx) = watch::channel(None);
    let tampered_resp = handle_incoming_sign_request(
        tampered_req,
        &dummy_cfg,
        &connector,
        &policy,
        &static_prompter,
        c_rx,
    )
    .await;
    assert!(!tampered_resp.approved);
    assert!(tampered_resp
        .error_message
        .contains("end-to-end cryptographic verification failed"));

    // 2. Now test full bidirectional ConnectWorkstation stream against MockCoordinatorStreamServer
    let (ack_tx, mut ack_rx) = mpsc::channel(4);
    let (resp_tx, mut resp_rx) = mpsc::channel(4);
    let (status_tx, mut status_rx) = mpsc::channel(4);

    let mock_server = MockCoordinatorStreamServer {
        sign_req_to_push: valid_sign_req,
        ack_tx: Mutex::new(Some(ack_tx)),
        resp_tx: Mutex::new(Some(resp_tx)),
        status_tx: Mutex::new(Some(status_tx)),
    };

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(SockcastServiceServer::new(mock_server))
            .serve_with_incoming(TcpListenerStream::new(tcp_listener))
            .await;
    });

    let cfg = ClientConfig {
        servers: vec![format!("http://{}", addr)],
        node_signing_key: client_sk,
        grant: client_grant,
        local_agent_socket: Some(agent_endpoint),
        heartbeat_interval_secs: 25,
        force_active: true,
        key_filter: KeyFilterConfig {
            allowed_fingerprints: Vec::new(),
            allowed_comment_substrings: vec!["workstation".to_string()],
            excluded_fingerprints: Vec::new(),
        },
    };

    let counting_prompter = Arc::new(CountingPrompter {
        calls: AtomicUsize::new(0),
        decision: ApprovalDecision::ApproveToolOnHost15m,
    });
    let prompter_trait: Arc<dyn ApprovalPrompter> = counting_prompter.clone();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let manager = WorkstationManager::new(cfg, connector, policy, prompter_trait);
    let manager_handle = tokio::spawn(async move { manager.run(shutdown_rx).await });

    // Verify WorkstationStatus reported only the 1 filtered key ("pavel@workstation")
    let status = tokio::time::timeout(Duration::from_secs(3), status_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(status.force_active);
    assert_eq!(status.keys.len(), 1);
    assert_eq!(status.keys[0].comment, "pavel@workstation");

    // Verify immediate SignAck arrived
    let ack = tokio::time::timeout(Duration::from_secs(3), ack_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack.request_id, "req-e2e-100");

    // Verify approved SignResponse arrived with the signature from the local OS SSH agent
    let resp = tokio::time::timeout(Duration::from_secs(3), resp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.request_id, "req-e2e-100");
    assert!(resp.approved);
    assert_eq!(resp.signature_blob, b"local-os-agent-ed25519-sig");
    assert_eq!(resp.handled_by_node_id, "workstation-1");
    assert_eq!(counting_prompter.calls.load(Ordering::SeqCst), 1);

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), manager_handle).await;
}
