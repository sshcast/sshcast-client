use ed25519_dalek::SigningKey;
use sshcast_client::config::{ClientConfig, KeyFilterConfig};
use sshcast_client::coordinator::{handle_incoming_sign_request, WorkstationManager};
use sshcast_client::enroll::{
    decode_enrollment_bundle_token, encode_enrollment_bundle_token, export_user_root_key,
    import_user_root_key, load_user_signing_key, mint_enrollment_bundle, run_keygen,
    write_client_config_and_optional_root_key, write_client_config_from_bundle,
};
use sshcast_client::local_agent::{
    filter_keys, LocalAgentConnector, SSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENTC_SIGN_REQUEST,
    SSH2_AGENT_IDENTITIES_ANSWER, SSH2_AGENT_SIGN_RESPONSE,
};
use sshcast_client::policy::{ApprovalDecision, PolicyEngine};
use sshcast_client::prompt::{ApprovalPrompter, PromptDetails, StaticPrompter};
use sshcast_client::zellij_proxy::{
    extract_relay_target_from_host_header, parse_http_host_and_path,
    serve_zellij_proxy_with_listener, ZellijProxyHub,
};
use sshcast_proto::bundle::EnrollmentBundle;
use sshcast_proto::crypto::{
    sign_node_grant, sign_sign_request, verify_node_auth, verify_zellij_tunnel_frame,
    DEFAULT_MAX_CLOCK_SKEW_MS,
};
use sshcast_proto::ssh::parse_public_key_blob;
use sshcast_proto::v1::client_stream_message::Payload as ClientPayload;
use sshcast_proto::v1::server_stream_message::Payload as ServerPayload;
use sshcast_proto::v1::sshcast_service_server::{SshcastService, SshcastServiceServer};
use sshcast_proto::v1::{
    ClientStreamMessage, GetIdentitiesRequest, GetIdentitiesResponse, NodeGrant, NodeRole,
    ProcessAncestor, ProcessContext, RelayStreamMessage, RelayZellijStatus, ServerStreamMessage,
    ServerToRelayMessage, SignAck, SignRequest, SignResponse, SshAuthContext, WorkstationStatus,
    ZellijFrameType, ZellijHostList, ZellijSessionInfo, ZellijTunnelFrame,
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::windows::named_pipe::ServerOptions;
    static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(1);
    let seq = NEXT_PIPE_ID.fetch_add(1, Ordering::Relaxed);
    let pipe_name = format!(
        r"\\.\pipe\sshcast-mock-agent-{}-{}",
        std::process::id(),
        seq
    );
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
impl SshcastService for MockCoordinatorStreamServer {
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

    type ConnectRelayStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ServerToRelayMessage, Status>> + Send>>;

    async fn connect_relay(
        &self,
        _request: Request<Streaming<RelayStreamMessage>>,
    ) -> Result<Response<Self::ConnectRelayStream>, Status> {
        Err(Status::unimplemented("not used"))
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
        user_cert: None,
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
        user_cert: None,
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
        zellij_listen_port: 0,
        stun_servers: Vec::new(),
        ssh_key_files: Vec::new(),
        ssh_keys_inline: Vec::new(),
        disable_os_agent: false,
        operator_url: None,
        config_path: None,
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
            .add_service(SshcastServiceServer::new(mock_server))
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
        zellij_listen_port: 0,
        stun_servers: Vec::new(),
        ssh_key_files: Vec::new(),
        ssh_keys_inline: Vec::new(),
        disable_os_agent: false,
        operator_url: None,
        config_path: None,
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

#[tokio::test]
async fn test_zellij_local_proxy_dashboard_redirect_and_tunnel() {
    assert_eq!(
        extract_relay_target_from_host_header("sunduk.localhost:18080").as_deref(),
        Some("sunduk")
    );
    assert_eq!(extract_relay_target_from_host_header("localhost:18080"), None);

    let (method, path, host) = parse_http_host_and_path(
        b"GET /sunduk/work HTTP/1.1\r\nHost: localhost:18080\r\n\r\n",
    )
    .unwrap();
    assert_eq!(method, "GET");
    assert_eq!(path, "/sunduk/work");
    assert_eq!(host, "localhost:18080");

    let user_sk = SigningKey::from_bytes(&[0x60; 32]);
    let client_sk = SigningKey::from_bytes(&[0x61; 32]);
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut client_grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "workstation-1".to_string(),
        role: NodeRole::Client as i32,
        node_pubkey: client_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: None,
    };
    sign_node_grant(&mut client_grant, &user_sk);

    let cfg = ClientConfig {
        servers: vec!["http://127.0.0.1:1".to_string()],
        node_signing_key: client_sk,
        grant: client_grant.clone(),
        local_agent_socket: None,
        heartbeat_interval_secs: 25,
        force_active: true,
        key_filter: KeyFilterConfig::default(),
        zellij_listen_port: 18080,
        stun_servers: Vec::new(),
        ssh_key_files: Vec::new(),
        ssh_keys_inline: Vec::new(),
        disable_os_agent: false,
        operator_url: None,
        config_path: None,
    };

    let hub = Arc::new(ZellijProxyHub::new(cfg));
    let (coord_tx, mut coord_rx) = mpsc::channel(32);
    hub.register_coordinator_sender(coord_tx).await;
    hub.update_host_list(ZellijHostList {
        hosts: vec![RelayZellijStatus {
            node_id: "sunduk.infra.local".to_string(),
            zellij_enabled: true,
            sessions: vec![ZellijSessionInfo {
                name: "dev-session".to_string(),
                created_info: "Created 5m ago".to_string(),
                exited: false,
            }],
            updated_at_unix_ms: now_sec * 1000,
        }],
    })
    .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let hub_for_srv = Arc::clone(&hub);
    tokio::spawn(async move {
        let _ = serve_zellij_proxy_with_listener(listener, hub_for_srv, shutdown_rx).await;
    });

    // 1. GET http://localhost:<port>/ -> 200 OK Dashboard containing sunduk.infra.local and dev-session
    let mut s1 = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    s1.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            proxy_addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut r1 = Vec::new();
    s1.read_to_end(&mut r1).await.unwrap();
    let r1_str = String::from_utf8_lossy(&r1);
    assert!(r1_str.starts_with("HTTP/1.1 200 OK"));
    assert!(r1_str.contains("sunduk.infra.local"));
    assert!(r1_str.contains("dev-session"));

    // 2. GET http://localhost:<port>/sunduk/dev-session -> 302 Redirect to http://sunduk.localhost:<port>/dev-session
    let mut s2 = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    s2.write_all(
        format!(
            "GET /sunduk/dev-session HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            proxy_addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut r2 = Vec::new();
    s2.read_to_end(&mut r2).await.unwrap();
    let r2_str = String::from_utf8_lossy(&r2);
    assert!(r2_str.starts_with("HTTP/1.1 302 Found"));
    assert!(r2_str.contains(&format!(
        "Location: http://sunduk.localhost:{}/dev-session",
        proxy_addr.port()
    )));

    // 3. GET http://sunduk.localhost:<port>/dev-session -> Tunnels via signed ZellijTunnelFrame (OPEN -> DATA -> CLOSE)
    let hub_for_reply = Arc::clone(&hub);
    let user_pubkey = client_grant.user_pubkey.clone();
    tokio::spawn(async move {
        while let Some(msg) = coord_rx.recv().await {
            if let Some(ClientPayload::ZellijFrame(frame)) = msg.payload {
                if frame.frame_type == ZellijFrameType::Open as i32 {
                    verify_zellij_tunnel_frame(&frame, NodeRole::Client, &user_pubkey, now_sec)
                        .unwrap();
                    assert_eq!(frame.relay_node_id, "sunduk.infra.local");
                    hub_for_reply
                        .handle_incoming_frame(ZellijTunnelFrame {
                            tunnel_id: frame.tunnel_id.clone(),
                            relay_node_id: "sunduk.infra.local".to_string(),
                            client_node_id: "workstation-1".to_string(),
                            frame_type: ZellijFrameType::Data as i32,
                            payload: b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nZELLIJ_WEB_OK!".to_vec(),
                            error_message: String::new(),
                            sender_grant: None,
                            sender_signature: Vec::new(),
                        })
                        .await;
                    hub_for_reply
                        .handle_incoming_frame(ZellijTunnelFrame {
                            tunnel_id: frame.tunnel_id,
                            relay_node_id: "sunduk.infra.local".to_string(),
                            client_node_id: "workstation-1".to_string(),
                            frame_type: ZellijFrameType::Close as i32,
                            payload: Vec::new(),
                            error_message: String::new(),
                            sender_grant: None,
                            sender_signature: Vec::new(),
                        })
                        .await;
                    break;
                }
            }
        }
    });

    let mut s3 = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    s3.write_all(
        format!(
            "GET /dev-session HTTP/1.1\r\nHost: sunduk.localhost:{}\r\nConnection: close\r\n\r\n",
            proxy_addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut r3 = Vec::new();
    s3.read_to_end(&mut r3).await.unwrap();
    let r3_str = String::from_utf8_lossy(&r3);
    assert!(r3_str.ends_with("ZELLIJ_WEB_OK!"));

    // 4. GET /__sshcast/SymbolsNerdFontMono-Regular.ttf -> served locally by sshcast-client
    let mut s4 = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    s4.write_all(
        format!(
            "GET /__sshcast/SymbolsNerdFontMono-Regular.ttf HTTP/1.1\r\nHost: sunduk.localhost:{}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
            proxy_addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut r4 = Vec::new();
    s4.read_to_end(&mut r4).await.unwrap();
    let r4_hdr_end = r4.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let r4_hdr = std::str::from_utf8(&r4[..r4_hdr_end]).unwrap();
    assert!(r4_hdr.starts_with("HTTP/1.1 200 OK"));
    assert!(r4_hdr.contains("Content-Type: font/ttf"));
    assert!(r4_hdr.contains("Content-Encoding: gzip"));
    assert_eq!(&r4[r4_hdr_end + 4..r4_hdr_end + 6], &[0x1f, 0x8b]);

    let _ = shutdown_tx.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_builtin_ssh_agent_keys_without_os_agent() {
    use sshcast_proto::ssh::LoadedSshKey;

    let tmp = TempDir::new().unwrap();
    let key_file_path = tmp.path().join("id_ed25519_builtin");

    // Generate a real OpenSSH private key and save to disk
    let builtin_key = LoadedSshKey::generate_ed25519("builtin@browser-ready");
    std::fs::write(&key_file_path, builtin_key.to_openssh_pem()).unwrap();

    let user_sk = SigningKey::from_bytes(&[0x70; 32]);
    let relay_sk = SigningKey::from_bytes(&[0x71; 32]);
    let client_sk = SigningKey::from_bytes(&[0x72; 32]);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ms = now_sec * 1000;

    let mut relay_grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "relay-restrictive.local".to_string(),
        role: NodeRole::Relay as i32,
        node_pubkey: relay_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: None,
    };
    sign_node_grant(&mut relay_grant, &user_sk);

    let mut client_grant = NodeGrant {
        user_id: String::new(),
        user_pubkey: Vec::new(),
        node_id: "standalone-client".to_string(),
        role: NodeRole::Client as i32,
        node_pubkey: client_sk.verifying_key().to_bytes().to_vec(),
        issued_at_unix_sec: now_sec - 60,
        expires_at_unix_sec: 0,
        user_signature: Vec::new(),
        user_cert: None,
    };
    sign_node_grant(&mut client_grant, &user_sk);

    let challenge_data = b"builtin-agent-ssh-auth-challenge".to_vec();
    let mut sign_req = SignRequest {
        request_id: "req-builtin-1".to_string(),
        timestamp_unix_ms: now_ms,
        key_blob: builtin_key.key_blob().to_vec(),
        data: challenge_data.clone(),
        flags: 0,
        process_context: Some(ProcessContext {
            hostname: "relay-restrictive.local".to_string(),
            uid: 1000,
            pid: 4242,
            comm: "ssh".to_string(),
            cmdline: "ssh prod-box".to_string(),
            cwd: "/home/stingray".to_string(),
            ancestors: Vec::new(),
        }),
        ssh_auth_context: Some(SshAuthContext {
            is_userauth_request: true,
            target_username: "stingray".to_string(),
            service_name: "ssh-connection".to_string(),
            pubkey_algorithm: "ssh-ed25519".to_string(),
            session_id: vec![0x01, 0x02, 0x03, 0x04],
        }),
        relay_grant: Some(relay_grant),
        relay_signature: Vec::new(),
        auth: None,
    };
    sign_sign_request(&mut sign_req, &relay_sk).unwrap();

    let (ack_tx, mut ack_rx) = mpsc::channel(4);
    let (resp_tx, mut resp_rx) = mpsc::channel(4);
    let (status_tx, mut status_rx) = mpsc::channel(4);

    let mock_server = MockCoordinatorStreamServer {
        sign_req_to_push: sign_req,
        ack_tx: Mutex::new(Some(ack_tx)),
        resp_tx: Mutex::new(Some(resp_tx)),
        status_tx: Mutex::new(Some(status_tx)),
    };

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(SshcastServiceServer::new(mock_server))
            .serve_with_incoming(TcpListenerStream::new(tcp_listener))
            .await;
    });

    // Configure client with NO OS agent (pointing to a non-existent socket AND disable_os_agent = true)
    let cfg = ClientConfig {
        servers: vec![format!("http://{}", addr)],
        node_signing_key: client_sk,
        grant: client_grant,
        local_agent_socket: Some("/nonexistent/ssh-agent.sock".to_string()),
        heartbeat_interval_secs: 25,
        force_active: true,
        key_filter: KeyFilterConfig::default(),
        zellij_listen_port: 0,
        stun_servers: Vec::new(),
        ssh_key_files: vec![key_file_path.to_string_lossy().to_string()],
        ssh_keys_inline: Vec::new(),
        disable_os_agent: true,
        operator_url: None,
        config_path: None,
    };

    let connector = Arc::new(LocalAgentConnector::from_client_config(&cfg, &[], false).unwrap());
    assert_eq!(connector.loaded_key_count(), 1);

    let policy = Arc::new(PolicyEngine::default());
    let prompter: Arc<dyn ApprovalPrompter> =
        Arc::new(StaticPrompter::new(ApprovalDecision::ApproveOnce));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let manager = WorkstationManager::new(cfg, connector, policy, prompter);
    let manager_handle = tokio::spawn(async move { manager.run(shutdown_rx).await });

    let status = tokio::time::timeout(Duration::from_secs(3), status_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.keys.len(), 1);
    assert_eq!(status.keys[0].comment, "builtin@browser-ready");
    assert_eq!(
        status.keys[0].fingerprint_sha256,
        builtin_key.fingerprint_sha256()
    );

    let ack = tokio::time::timeout(Duration::from_secs(3), ack_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack.request_id, "req-builtin-1");

    let resp = tokio::time::timeout(Duration::from_secs(3), resp_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.request_id, "req-builtin-1");
    assert!(resp.approved);
    assert_eq!(resp.handled_by_node_id, "standalone-client");

    // Cryptographically verify the returned RFC 4253 signature blob against the challenge!
    builtin_key
        .verify_ssh_signature_blob(&challenge_data, &resp.signature_blob)
        .unwrap();

    // Also test the Tray UI key-management helpers (add from file, paste PEM, list held keys, remove, toggle OS agent)
    let ui_cfg_path = tmp.path().join("tray_client.toml");
    let user_sk = SigningKey::from_bytes(&[0x80; 32]);
    let bundle = mint_enrollment_bundle(
        &user_sk,
        "tray-workstation",
        NodeRole::Client,
        vec!["https://coord.example.com".to_string()],
        0,
    )
    .unwrap();
    write_client_config_from_bundle(&bundle, Some(&ui_cfg_path), true).unwrap();

    let tray_agent = LocalAgentConnector::with_options(
        Some(spawn_mock_local_ssh_agent(&tmp).await),
        KeyFilterConfig::default(),
        false,
    );

    // 1. Initially shows the 2 OS agent keys from the mock agent
    let held_initial = tray_agent.query_held_keys_for_ui();
    assert_eq!(held_initial.len(), 2);
    assert!(held_initial.iter().all(|i| !i.is_builtin));

    // 2. Add key from file via UI helper -> appears as [Built-in] and persists in client.toml
    let pk_added = tray_agent
        .ui_add_key_from_file(
            &key_file_path.to_string_lossy(),
            "",
            Some(&ui_cfg_path),
        )
        .unwrap();
    assert_eq!(pk_added.comment, "builtin@browser-ready");

    // 3. Paste inline PEM key via UI helper -> appears as [Built-in] and persists in client.toml
    let inline_key = LoadedSshKey::generate_ed25519("pasted@clipboard");
    let pk_inline = tray_agent
        .ui_add_key_from_pem(&inline_key.to_openssh_pem(), "", Some(&ui_cfg_path))
        .unwrap();
    assert_eq!(pk_inline.comment, "pasted@clipboard");

    let held_after_add = tray_agent.query_held_keys_for_ui();
    assert_eq!(held_after_add.len(), 4); // 2 built-in + 2 OS agent
    assert_eq!(held_after_add.iter().filter(|i| i.is_builtin).count(), 2);

    // 4. Toggle "Built-in Keys Only" (disable OS agent) via UI helper
    tray_agent
        .ui_set_disable_os_agent(true, Some(&ui_cfg_path))
        .unwrap();
    let held_builtin_only = tray_agent.query_held_keys_for_ui();
    assert_eq!(held_builtin_only.len(), 2);
    assert!(held_builtin_only.iter().all(|i| i.is_builtin));

    // 5. Remove the first built-in key via UI helper and verify client.toml was updated
    let removed = tray_agent
        .ui_remove_builtin_key(&held_builtin_only[0], Some(&ui_cfg_path))
        .unwrap();
    assert!(removed);
    let held_after_remove = tray_agent.query_held_keys_for_ui();
    assert_eq!(held_after_remove.len(), 1);
    assert_eq!(held_after_remove[0].comment, "pasted@clipboard");

    let reloaded_cfg = ClientConfig::load(Some(&ui_cfg_path)).unwrap();
    assert!(reloaded_cfg.disable_os_agent);
    assert!(reloaded_cfg.ssh_key_files.is_empty());
    assert_eq!(reloaded_cfg.ssh_keys_inline.len(), 1);

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), manager_handle).await;
}

#[tokio::test]
async fn test_operator_renewal_and_github_login_roundtrip() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use prost::Message;
    use sshcast_client::config::ClientConfigFile;
    use sshcast_client::operator::{cert_needs_renewal, login_and_enroll, renew_user_cert_http};
    use sshcast_proto::bundle::encode_user_cert_token;
    use sshcast_proto::crypto::{derive_user_id, sign_user_cert};
    use sshcast_proto::v1::{NodeAuth, UserCert};

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 1. Unit assertions for cert_needs_renewal
    assert!(!cert_needs_renewal(None, now_sec));
    let infinite = UserCert {
        expires_at_unix_sec: 0,
        ..Default::default()
    };
    assert!(!cert_needs_renewal(Some(&infinite), now_sec));
    let fresh = UserCert {
        issued_at_unix_sec: now_sec - 100,
        expires_at_unix_sec: now_sec + 7 * 86_400 - 100,
        ..Default::default()
    };
    assert!(!cert_needs_renewal(Some(&fresh), now_sec));
    let expiring = UserCert {
        issued_at_unix_sec: now_sec - 4 * 86_400,
        expires_at_unix_sec: now_sec + 3 * 86_400,
        ..Default::default()
    };
    assert!(cert_needs_renewal(Some(&expiring), now_sec));
    let expired = UserCert {
        issued_at_unix_sec: now_sec - 10_000,
        expires_at_unix_sec: now_sec - 10,
        ..Default::default()
    };
    assert!(cert_needs_renewal(Some(&expired), now_sec));

    // 2. Mock Operator HTTP server handling /api/v1/enroll/start, /api/v1/enroll/poll, and /api/v1/renew
    let op_sk = SigningKey::from_bytes(&[0x91; 32]);
    let op_sk_srv = op_sk.clone();
    let seen_stripped_cert = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_stripped_srv = Arc::clone(&seen_stripped_cert);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let base_url_srv = base_url.clone();

    let srv_handle = tokio::spawn(async move {
        let mut issued_cert_token = String::new();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut buf = vec![0u8; 16384];
            let mut total = 0usize;
            loop {
                let n = stream.read(&mut buf[total..]).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                total += n;
                let text = String::from_utf8_lossy(&buf[..total]);
                if let Some(hdr_end) = text.find("\r\n\r\n") {
                    let hdrs = &text[..hdr_end];
                    let content_len: usize = hdrs
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    if total >= hdr_end + 4 + content_len {
                        break;
                    }
                }
            }
            let req_text = String::from_utf8_lossy(&buf[..total]);
            let first_line = req_text.lines().next().unwrap_or("");
            let path = first_line.split_whitespace().nth(1).unwrap_or("");
            let body = req_text
                .split_once("\r\n\r\n")
                .map(|(_, b)| b)
                .unwrap_or("");

            let resp_body = if path == "/api/v1/enroll/start" {
                let val: serde_json::Value = serde_json::from_str(body).unwrap();
                let pub_hex = val["user_pubkey"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("sc_pub_")
                    .unwrap();
                let user_pk = hex::decode(pub_hex).unwrap();
                let mut cert = UserCert {
                    user_id: derive_user_id(&user_pk),
                    user_pubkey: user_pk,
                    operator_pubkey: Vec::new(),
                    issued_at_unix_sec: now_sec,
                    expires_at_unix_sec: now_sec + 7 * 86_400,
                    operator_signature: Vec::new(),
                };
                sign_user_cert(&mut cert, &op_sk_srv);
                issued_cert_token = encode_user_cert_token(&cert);
                serde_json::json!({
                    "ok": true,
                    "state": "state123",
                    "poll_token": "poll123",
                    "auth_url": format!("{base_url_srv}/auth/github/start?state=state123")
                })
                .to_string()
            } else if path.starts_with("/api/v1/enroll/poll") {
                serde_json::json!({
                    "ok": true,
                    "status": "approved",
                    "cert_token": issued_cert_token
                })
                .to_string()
            } else if path == "/api/v1/renew" {
                let val: serde_json::Value = serde_json::from_str(body).unwrap();
                let auth_b64 = val["node_auth_proto_b64"].as_str().unwrap();
                let auth_raw = STANDARD.decode(auth_b64).unwrap();
                let node_auth = NodeAuth::decode(auth_raw.as_slice()).unwrap();
                let grant = node_auth.grant.as_ref().unwrap();
                if grant.user_cert.is_none() {
                    seen_stripped_srv.store(true, Ordering::SeqCst);
                }
                verify_node_auth(
                    &node_auth,
                    Some(NodeRole::Client),
                    now_sec * 1000,
                    DEFAULT_MAX_CLOCK_SKEW_MS,
                )
                .unwrap();

                let mut fresh_cert = UserCert {
                    user_id: derive_user_id(&grant.user_pubkey),
                    user_pubkey: grant.user_pubkey.clone(),
                    operator_pubkey: Vec::new(),
                    issued_at_unix_sec: now_sec + 10,
                    expires_at_unix_sec: now_sec + 14 * 86_400,
                    operator_signature: Vec::new(),
                };
                sign_user_cert(&mut fresh_cert, &op_sk_srv);
                let renewed_tok = encode_user_cert_token(&fresh_cert);
                serde_json::json!({
                    "ok": true,
                    "cert_token": renewed_tok
                })
                .to_string()
            } else {
                serde_json::json!({ "ok": false, "error": "not found" }).to_string()
            };

            let http_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            let _ = stream.write_all(http_resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    let tmp = TempDir::new().unwrap();
    let key_path = tmp.path().join("user_key.toml");
    let cfg_path = tmp.path().join("client.toml");

    let mut seen_url = String::new();
    let outcome = login_and_enroll(
        &[base_url.clone()],
        Some(&base_url),
        Some("laptop-login"),
        Some(&key_path),
        Some(&cfg_path),
        false,
        |url| seen_url = url.to_string(),
    )
    .await
    .unwrap();
    assert!(seen_url.contains("state123"));
    assert!(outcome.enrolled_new_client);

    let (_, loaded_file) = ClientConfigFile::load(Some(&cfg_path)).unwrap();
    assert_eq!(loaded_file.operator_url.as_deref(), Some(base_url.as_str()));
    let loaded_cfg = ClientConfig::load(Some(&cfg_path)).unwrap();
    assert_eq!(loaded_cfg.grant.node_id, "laptop-login");
    assert!(loaded_cfg.grant.user_cert.is_some());

    // Now simulate an expired cert on that client grant and test renewal!
    let mut expired_grant = loaded_cfg.grant.clone();
    if let Some(ref mut c) = expired_grant.user_cert {
        c.expires_at_unix_sec = now_sec - 100;
    }
    let renewed = renew_user_cert_http(&base_url, &expired_grant, &loaded_cfg.node_signing_key)
        .await
        .unwrap();
    assert!(seen_stripped_cert.load(Ordering::SeqCst));
    assert_eq!(renewed.expires_at_unix_sec, now_sec + 14 * 86_400);

    srv_handle.abort();
}

struct MockOperatorEnrollSession {
    poll_token: String,
    candidate_user_pubkey: String,
    node_name: String,
    os_name: String,
    node_pubkey_b64: String,
    eph_x25519_pub_b64: String,
    status: String,
    pairing_id: String,
    cert_token: String,
    approver_node_id: String,
    approver_eph_x25519_pub_b64: String,
    approver_signature_b64: String,
    handoff_nonce_b64: String,
    encrypted_handoff_b64: String,
}

struct MockOperatorState {
    op_sk: SigningKey,
    github_login: String,
    existing_user_pubkey: String,
    recovery_vault: Option<(sshcast_client::pairing::RecoveryVaultBlob, i64)>,
    sessions: std::collections::HashMap<String, MockOperatorEnrollSession>,
    next_seq: u64,
    cancel_calls: usize,
    replace_calls: usize,
    renew_calls: usize,
}

async fn read_http_request_parts(
    stream: &mut tokio::net::TcpStream,
) -> Option<(String, String, Vec<(String, String)>, String)> {
    let mut buf = vec![0u8; 32768];
    let mut total = 0usize;
    loop {
        let n = stream.read(&mut buf[total..]).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        total += n;
        let text = String::from_utf8_lossy(&buf[..total]);
        if let Some(hdr_end) = text.find("\r\n\r\n") {
            let hdrs = &text[..hdr_end];
            let content_len: usize = hdrs
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        v.trim().parse().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if total >= hdr_end + 4 + content_len {
                break;
            }
        }
    }
    if total == 0 {
        return None;
    }
    let req_text = String::from_utf8_lossy(&buf[..total]);
    let (hdr_block, body) = req_text.split_once("\r\n\r\n").unwrap_or((&req_text, ""));
    let mut lines = hdr_block.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let headers = lines
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect();
    Some((method, path, headers, body.to_string()))
}

fn verify_mock_operator_node_auth(
    val: &serde_json::Value,
    expected_user_pubkey_token: &str,
    now_sec: u64,
) -> NodeGrant {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use prost::Message;
    use sshcast_proto::v1::NodeAuth;

    let auth_b64 = val["node_auth_proto_b64"].as_str().unwrap();
    let auth_raw = STANDARD.decode(auth_b64).unwrap();
    let node_auth = NodeAuth::decode(auth_raw.as_slice()).unwrap();
    verify_node_auth(
        &node_auth,
        Some(NodeRole::Client),
        now_sec * 1000,
        DEFAULT_MAX_CLOCK_SKEW_MS,
    )
    .unwrap();
    let grant = node_auth.grant.unwrap();
    let got_tok = format!("sc_pub_{}", hex::encode(&grant.user_pubkey));
    assert_eq!(got_tok, expected_user_pubkey_token);
    grant
}

fn sign_mock_user_cert(op_sk: &SigningKey, user_pubkey: &[u8], now_sec: u64) -> String {
    use sshcast_proto::bundle::encode_user_cert_token;
    use sshcast_proto::crypto::{derive_user_id, sign_user_cert};
    use sshcast_proto::v1::UserCert;

    let mut cert = UserCert {
        user_id: derive_user_id(user_pubkey),
        user_pubkey: user_pubkey.to_vec(),
        operator_pubkey: Vec::new(),
        issued_at_unix_sec: now_sec,
        expires_at_unix_sec: now_sec + 7 * 86_400,
        operator_signature: Vec::new(),
    };
    sign_user_cert(&mut cert, op_sk);
    encode_user_cert_token(&cert)
}

async fn spawn_mock_operator(
    existing_user_sk: &SigningKey,
    github_login: &str,
) -> (
    String,
    Arc<tokio::sync::Mutex<MockOperatorState>>,
    tokio::task::JoinHandle<()>,
) {
    let existing_user_pubkey = format!(
        "sc_pub_{}",
        hex::encode(existing_user_sk.verifying_key().to_bytes())
    );
    let state = Arc::new(tokio::sync::Mutex::new(MockOperatorState {
        op_sk: SigningKey::from_bytes(&[0x92; 32]),
        github_login: github_login.to_string(),
        existing_user_pubkey,
        recovery_vault: None,
        sessions: std::collections::HashMap::new(),
        next_seq: 1,
        cancel_calls: 0,
        replace_calls: 0,
        renew_calls: 0,
    }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let base_url_srv = base_url.clone();
    let state_srv = Arc::clone(&state);

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let Some((_method, path, headers, body)) = read_http_request_parts(&mut stream).await
            else {
                continue;
            };
            let now_sec = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let bearer = headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .and_then(|(_, v)| v.strip_prefix("Bearer "))
                .map(str::to_string);

            let (http_status, resp_body) = {
                let mut st = state_srv.lock().await;
                if path == "/api/v1/enroll/start" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let candidate_user_pubkey =
                        val["user_pubkey"].as_str().unwrap().to_string();
                    let supports_pairing =
                        val["supports_pairing"].as_bool().unwrap_or(false);
                    assert!(supports_pairing);
                    st.next_seq += 1;
                    let seq = st.next_seq;
                    let state_id = format!("state_{seq}");
                    let poll_token = format!("poll_tok_{seq}");
                    let pairing_id = format!("pair_{seq}");

                    let (status, cert_token) =
                        if candidate_user_pubkey == st.existing_user_pubkey {
                            let pub_raw = hex::decode(
                                candidate_user_pubkey.strip_prefix("sc_pub_").unwrap(),
                            )
                            .unwrap();
                            (
                                "approved".to_string(),
                                sign_mock_user_cert(&st.op_sk, &pub_raw, now_sec),
                            )
                        } else {
                            ("pairing_required".to_string(), String::new())
                        };

                    st.sessions.insert(
                        state_id.clone(),
                        MockOperatorEnrollSession {
                            poll_token: poll_token.clone(),
                            candidate_user_pubkey,
                            node_name: val["node_name"].as_str().unwrap_or("").to_string(),
                            os_name: val["os_name"].as_str().unwrap_or("").to_string(),
                            node_pubkey_b64: val["node_pubkey_b64"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            eph_x25519_pub_b64: val["eph_x25519_pub_b64"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            status,
                            pairing_id,
                            cert_token,
                            approver_node_id: String::new(),
                            approver_eph_x25519_pub_b64: String::new(),
                            approver_signature_b64: String::new(),
                            handoff_nonce_b64: String::new(),
                            encrypted_handoff_b64: String::new(),
                        },
                    );

                    (
                        200u16,
                        serde_json::json!({
                            "ok": true,
                            "state": state_id,
                            "poll_token": poll_token,
                            "auth_url": format!("{base_url_srv}/auth/github/start?state=state_{seq}"),
                        })
                        .to_string(),
                    )
                } else if path.starts_with("/api/v1/enroll/poll") {
                    let state_id = path.split("state=").nth(1).unwrap_or("");
                    let existing_pk = st.existing_user_pubkey.clone();
                    let login = st.github_login.clone();
                    let vault_opt = st.recovery_vault.as_ref().map(|(v, _)| v.clone());
                    if let Some(sess) = st.sessions.get(state_id) {
                        assert_eq!(bearer.as_deref(), Some(sess.poll_token.as_str()));
                        match sess.status.as_str() {
                            "approved" => (
                                200,
                                serde_json::json!({
                                    "ok": true,
                                    "status": "approved",
                                    "cert_token": sess.cert_token,
                                })
                                .to_string(),
                            ),
                            "pairing_required" => (
                                200,
                                serde_json::json!({
                                    "ok": true,
                                    "status": "pairing_required",
                                    "pairing_id": sess.pairing_id,
                                    "existing_user_pubkey": existing_pk,
                                    "github_login": login,
                                    "has_recovery_vault": vault_opt.is_some(),
                                    "recovery_vault": vault_opt,
                                })
                                .to_string(),
                            ),
                            "paired" => (
                                200,
                                serde_json::json!({
                                    "ok": true,
                                    "status": "paired",
                                    "pairing_id": sess.pairing_id,
                                    "existing_user_pubkey": existing_pk,
                                    "approver_node_id": sess.approver_node_id,
                                    "approver_eph_x25519_pub_b64": sess.approver_eph_x25519_pub_b64,
                                    "approver_signature_b64": sess.approver_signature_b64,
                                    "handoff_nonce_b64": sess.handoff_nonce_b64,
                                    "encrypted_handoff_b64": sess.encrypted_handoff_b64,
                                })
                                .to_string(),
                            ),
                            "denied" | "banned" => (
                                403,
                                serde_json::json!({
                                    "ok": false,
                                    "status": sess.status,
                                    "error": "denied by user",
                                })
                                .to_string(),
                            ),
                            "canceled" => (
                                409,
                                serde_json::json!({
                                    "ok": false,
                                    "status": "canceled",
                                    "error": "canceled",
                                })
                                .to_string(),
                            ),
                            "expired" => (
                                410,
                                serde_json::json!({
                                    "ok": false,
                                    "status": "expired",
                                    "error": "expired",
                                })
                                .to_string(),
                            ),
                            other => (
                                200,
                                serde_json::json!({
                                    "ok": true,
                                    "status": other,
                                })
                                .to_string(),
                            ),
                        }
                    } else {
                        (
                            404,
                            serde_json::json!({ "ok": false, "error": "unknown state" })
                                .to_string(),
                        )
                    }
                } else if path == "/api/v1/enroll/cancel" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let state_id = val["state"].as_str().unwrap();
                    if let Some(sess) = st.sessions.get_mut(state_id) {
                        assert_eq!(bearer.as_deref(), Some(sess.poll_token.as_str()));
                        sess.status = "canceled".to_string();
                        st.cancel_calls += 1;
                        (200, serde_json::json!({ "ok": true }).to_string())
                    } else {
                        (
                            404,
                            serde_json::json!({ "ok": false, "error": "unknown state" })
                                .to_string(),
                        )
                    }
                } else if path == "/api/v1/enroll/replace" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let state_id = val["state"].as_str().unwrap().to_string();
                    let op_sk_clone = st.op_sk.clone();
                    if let Some(sess) = st.sessions.get_mut(&state_id) {
                        assert_eq!(bearer.as_deref(), Some(sess.poll_token.as_str()));
                        let new_pub_hex = sess
                            .candidate_user_pubkey
                            .strip_prefix("sc_pub_")
                            .unwrap()
                            .to_string();
                        let new_pub_raw = hex::decode(&new_pub_hex).unwrap();
                        let cert_tok = sign_mock_user_cert(&op_sk_clone, &new_pub_raw, now_sec);
                        sess.status = "approved".to_string();
                        sess.cert_token = cert_tok.clone();
                        let new_pub_tok = sess.candidate_user_pubkey.clone();
                        st.existing_user_pubkey = new_pub_tok;
                        st.replace_calls += 1;
                        (
                            200,
                            serde_json::json!({
                                "ok": true,
                                "status": "approved",
                                "cert_token": cert_tok,
                            })
                            .to_string(),
                        )
                    } else {
                        (
                            404,
                            serde_json::json!({ "ok": false, "error": "unknown state" })
                                .to_string(),
                        )
                    }
                } else if path == "/api/v1/pairing/poll" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    verify_mock_operator_node_auth(&val, &st.existing_user_pubkey, now_sec);
                    let reqs: Vec<serde_json::Value> = st
                        .sessions
                        .values()
                        .filter(|s| s.status == "pairing_required")
                        .map(|s| {
                            serde_json::json!({
                                "pairing_id": s.pairing_id,
                                "node_name": s.node_name,
                                "os_name": s.os_name,
                                "github_login": st.github_login,
                                "node_pubkey_b64": s.node_pubkey_b64,
                                "eph_x25519_pub_b64": s.eph_x25519_pub_b64,
                                "expires_at": (now_sec + 300) as i64,
                                "created_at": now_sec as i64,
                            })
                        })
                        .collect();
                    (
                        200,
                        serde_json::json!({ "ok": true, "requests": reqs }).to_string(),
                    )
                } else if path == "/api/v1/pairing/respond" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let grant =
                        verify_mock_operator_node_auth(&val, &st.existing_user_pubkey, now_sec);
                    let pairing_id = val["pairing_id"].as_str().unwrap();
                    let approved = val["approved"].as_bool().unwrap();
                    if let Some(sess) = st
                        .sessions
                        .values_mut()
                        .find(|s| s.pairing_id == pairing_id)
                    {
                        if approved {
                            sess.status = "paired".to_string();
                            sess.approver_node_id = grant.node_id;
                            sess.approver_eph_x25519_pub_b64 = val["approver_eph_x25519_pub_b64"]
                                .as_str()
                                .unwrap()
                                .to_string();
                            sess.approver_signature_b64 =
                                val["approver_signature_b64"].as_str().unwrap().to_string();
                            sess.handoff_nonce_b64 =
                                val["handoff_nonce_b64"].as_str().unwrap().to_string();
                            sess.encrypted_handoff_b64 =
                                val["encrypted_handoff_b64"].as_str().unwrap().to_string();
                        } else {
                            sess.status = "denied".to_string();
                        }
                        (200, serde_json::json!({ "ok": true }).to_string())
                    } else {
                        (
                            404,
                            serde_json::json!({ "ok": false, "error": "unknown pairing_id" })
                                .to_string(),
                        )
                    }
                } else if path == "/api/v1/recovery-vault" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    verify_mock_operator_node_auth(&val, &st.existing_user_pubkey, now_sec);
                    let vault: sshcast_client::pairing::RecoveryVaultBlob =
                        serde_json::from_value(val["vault"].clone()).unwrap();
                    let updated_at = now_sec as i64;
                    st.recovery_vault = Some((vault, updated_at));
                    (
                        200,
                        serde_json::json!({ "ok": true, "updated_at": updated_at }).to_string(),
                    )
                } else if path == "/api/v1/recovery-vault/status" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    verify_mock_operator_node_auth(&val, &st.existing_user_pubkey, now_sec);
                    let (configured, updated_at) = match &st.recovery_vault {
                        Some((_, ts)) => (true, *ts),
                        None => (false, 0),
                    };
                    (
                        200,
                        serde_json::json!({
                            "ok": true,
                            "configured": configured,
                            "updated_at": updated_at,
                        })
                        .to_string(),
                    )
                } else if path == "/api/v1/recovery-vault/delete" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    verify_mock_operator_node_auth(&val, &st.existing_user_pubkey, now_sec);
                    st.recovery_vault = None;
                    (
                        200,
                        serde_json::json!({ "ok": true, "deleted": true }).to_string(),
                    )
                } else if path == "/api/v1/renew" {
                    let val: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let grant =
                        verify_mock_operator_node_auth(&val, &st.existing_user_pubkey, now_sec);
                    st.renew_calls += 1;
                    let cert_tok = sign_mock_user_cert(&st.op_sk, &grant.user_pubkey, now_sec);
                    (
                        200,
                        serde_json::json!({
                            "ok": true,
                            "cert_token": cert_tok,
                        })
                        .to_string(),
                    )
                } else {
                    (
                        404,
                        serde_json::json!({ "ok": false, "error": "not found" }).to_string(),
                    )
                }
            };

            let status_reason = match http_status {
                200 => "200 OK",
                403 => "403 Forbidden",
                404 => "404 Not Found",
                409 => "409 Conflict",
                410 => "410 Gone",
                _ => "500 Internal Server Error",
            };
            let http_resp = format!(
                "HTTP/1.1 {status_reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            let _ = stream.write_all(http_resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    (base_url, state, handle)
}

#[tokio::test]
async fn test_device_pairing_handoff_end_to_end() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use sshcast_client::config::{ClientConfigFile, UserKeyFile};
    use sshcast_client::operator::{
        cancel_enrollment_pairing, complete_paired_enrollment, is_terminal_enroll_error,
        poll_enrollment_once, poll_pending_pairing_requests_http, respond_to_pairing_request_http,
        start_github_enrollment, EnrollPollStep,
    };
    use sshcast_client::pairing::{compute_pairing_sas_code, create_encrypted_pairing_handoff};

    let user_sk_a = SigningKey::from_bytes(&[0xA1; 32]);
    let user_pk_a = user_sk_a.verifying_key().to_bytes();
    let user_pub_token_a = format!("sc_pub_{}", hex::encode(user_pk_a));
    let coord_url = "https://coord.example.com".to_string();

    let bundle_a = mint_enrollment_bundle(
        &user_sk_a,
        "workstation-a",
        NodeRole::Client,
        vec![coord_url.clone()],
        0,
    )
    .unwrap();

    let (op_url, op_state, srv_handle) = spawn_mock_operator(&user_sk_a, "octocat").await;

    let tmp_b = TempDir::new().unwrap();
    let key_path_b = tmp_b.path().join("user_key.toml");
    let cfg_path_b = tmp_b.path().join("client.toml");

    // Workstation B starts enrollment without an existing user_key.toml; nothing is written yet.
    let mut seen_auth_url = String::new();
    let started = start_github_enrollment(
        std::slice::from_ref(&coord_url),
        Some(&op_url),
        Some("workstation-b"),
        Some(&key_path_b),
        Some(&cfg_path_b),
        false,
        |u| seen_auth_url = u.to_string(),
    )
    .await
    .unwrap();
    assert!(seen_auth_url.contains("/auth/github/start"));
    assert!(!key_path_b.exists());
    assert!(!cfg_path_b.exists());

    // Operator tells B that @octocat already exists with user_sk_a.
    let info = match poll_enrollment_once(&started).await.unwrap() {
        EnrollPollStep::PairingRequired(info) => info,
        other => panic!("expected PairingRequired, got {other:?}"),
    };
    assert_eq!(info.github_login, "octocat");
    assert_eq!(info.existing_user_pubkey_token, user_pub_token_a);
    assert_eq!(info.existing_user_pubkey, user_pk_a);
    assert!(!info.has_recovery_vault);

    // Workstation A polls pending requests, verifies SAS code matches B's display, and approves.
    let pending = poll_pending_pairing_requests_http(
        &op_url,
        &bundle_a.grant,
        &bundle_a.node_signing_key,
        5,
    )
    .await
    .unwrap();
    assert_eq!(pending.len(), 1);
    let req = &pending[0];
    assert_eq!(req.pairing_id, info.pairing_id);
    assert_eq!(req.node_name, "workstation-b");
    assert_eq!(req.github_login, "octocat");

    let req_node_pub: [u8; 32] = STANDARD
        .decode(&req.node_pubkey_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let req_eph_pub: [u8; 32] = STANDARD
        .decode(&req.eph_x25519_pub_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let sas_a = compute_pairing_sas_code(&user_pk_a, &req_eph_pub);
    assert_eq!(sas_a, info.sas_code);

    let envelope = create_encrypted_pairing_handoff(
        &user_sk_a,
        None,
        &req.pairing_id,
        &req.node_name,
        &req_node_pub,
        &req_eph_pub,
        vec![coord_url.clone()],
        Some(op_url.clone()),
    )
    .unwrap();
    respond_to_pairing_request_http(
        &op_url,
        &bundle_a.grant,
        &bundle_a.node_signing_key,
        &req.pairing_id,
        true,
        Some(&envelope),
    )
    .await
    .unwrap();

    // Workstation B polls once more -> receives Paired -> completes enrollment and renews cert!
    let (pairing_id, existing_pk, approver_node, rx_env) =
        match poll_enrollment_once(&started).await.unwrap() {
            EnrollPollStep::Paired {
                pairing_id,
                existing_user_pubkey,
                approver_node_id,
                envelope,
            } => (pairing_id, existing_user_pubkey, approver_node_id, envelope),
            other => panic!("expected Paired, got {other:?}"),
        };
    assert_eq!(approver_node, "workstation-a");

    let outcome =
        complete_paired_enrollment(started, &existing_pk, &pairing_id, &rx_env)
            .await
            .unwrap();
    assert!(outcome.enrolled_new_client);
    assert_eq!(outcome.user_pubkey_token, user_pub_token_a);
    assert!(key_path_b.exists());
    assert!(cfg_path_b.exists());

    let loaded_sk_b = load_user_signing_key(Some(&key_path_b)).unwrap();
    assert_eq!(loaded_sk_b.to_bytes(), user_sk_a.to_bytes());

    let (_, uk_b) = UserKeyFile::load(Some(&key_path_b)).unwrap();
    assert!(uk_b.user_cert_token.is_some());

    let cfg_b = ClientConfig::load(Some(&cfg_path_b)).unwrap();
    assert_eq!(cfg_b.grant.node_id, "workstation-b");
    assert_eq!(cfg_b.grant.user_pubkey, user_pk_a);
    assert!(cfg_b.grant.user_cert.is_some());
    assert_eq!(cfg_b.operator_url.as_deref(), Some(op_url.as_str()));
    let (_, cfg_file_b) = ClientConfigFile::load(Some(&cfg_path_b)).unwrap();
    assert_eq!(cfg_file_b.servers, vec![coord_url.clone()]);
    assert_eq!(op_state.lock().await.renew_calls, 1);

    // Also verify terminal rejections (canceled -> 409) return a terminal Err from poll_enrollment_once.
    let tmp_cancel = TempDir::new().unwrap();
    let started_cancel = start_github_enrollment(
        std::slice::from_ref(&coord_url),
        Some(&op_url),
        Some("workstation-c"),
        Some(&tmp_cancel.path().join("user_key.toml")),
        Some(&tmp_cancel.path().join("client.toml")),
        false,
        |_| {},
    )
    .await
    .unwrap();
    cancel_enrollment_pairing(&started_cancel).await.unwrap();
    let cancel_err = poll_enrollment_once(&started_cancel).await.unwrap_err();
    assert!(is_terminal_enroll_error(&cancel_err));

    // Also verify denied (403) and expired (410) return terminal errors.
    for (status_str, node) in [("denied", "workstation-d"), ("expired", "workstation-e")] {
        let tmp_term = TempDir::new().unwrap();
        let started_term = start_github_enrollment(
            &[coord_url.clone()],
            Some(&op_url),
            Some(node),
            Some(&tmp_term.path().join("user_key.toml")),
            Some(&tmp_term.path().join("client.toml")),
            false,
            |_| {},
        )
        .await
        .unwrap();
        op_state
            .lock()
            .await
            .sessions
            .get_mut(&started_term.state)
            .unwrap()
            .status = status_str.to_string();
        let term_err = poll_enrollment_once(&started_term).await.unwrap_err();
        assert!(is_terminal_enroll_error(&term_err));
    }

    srv_handle.abort();
}

#[tokio::test]
async fn test_recovery_vault_upload_status_unlock_and_delete() {
    use sshcast_client::config::UserKeyFile;
    use sshcast_client::operator::{
        delete_recovery_vault_http, get_recovery_vault_status_http, poll_enrollment_once,
        start_github_enrollment, unlock_with_recovery_passphrase, upload_recovery_vault_http,
        EnrollPollStep,
    };
    use sshcast_client::pairing::{encrypt_recovery_vault, ScryptParams, VaultDecryptError};

    let user_sk_a = SigningKey::from_bytes(&[0xB2; 32]);
    let user_pk_a = user_sk_a.verifying_key().to_bytes();
    let user_pub_token_a = format!("sc_pub_{}", hex::encode(user_pk_a));
    let coord_url = "https://coord.example.com".to_string();

    let bundle_a = mint_enrollment_bundle(
        &user_sk_a,
        "workstation-a",
        NodeRole::Client,
        vec![coord_url.clone()],
        0,
    )
    .unwrap();

    let (op_url, op_state, srv_handle) = spawn_mock_operator(&user_sk_a, "octocat").await;

    let (configured_before, _) =
        get_recovery_vault_status_http(&op_url, &bundle_a.grant, &bundle_a.node_signing_key)
            .await
            .unwrap();
    assert!(!configured_before);

    let passphrase = "correct-horse-battery-staple";
    let vault = encrypt_recovery_vault(
        &user_sk_a,
        passphrase,
        ScryptParams {
            log_n: 10,
            r: 8,
            p: 1,
        },
    )
    .unwrap();
    let uploaded_at = upload_recovery_vault_http(
        &op_url,
        &bundle_a.grant,
        &bundle_a.node_signing_key,
        &vault,
    )
    .await
    .unwrap();
    let (configured_after, status_ts) =
        get_recovery_vault_status_http(&op_url, &bundle_a.grant, &bundle_a.node_signing_key)
            .await
            .unwrap();
    assert!(configured_after);
    assert_eq!(status_ts, uploaded_at);

    // Workstation B enrolls offline using the recovery passphrase.
    let tmp_b = TempDir::new().unwrap();
    let key_path_b = tmp_b.path().join("user_key.toml");
    let cfg_path_b = tmp_b.path().join("client.toml");

    let started = start_github_enrollment(
        &[coord_url],
        Some(&op_url),
        Some("workstation-recovery"),
        Some(&key_path_b),
        Some(&cfg_path_b),
        false,
        |_| {},
    )
    .await
    .unwrap();

    let info = match poll_enrollment_once(&started).await.unwrap() {
        EnrollPollStep::PairingRequired(info) => info,
        other => panic!("expected PairingRequired, got {other:?}"),
    };
    assert!(info.has_recovery_vault);
    assert!(info.recovery_vault.is_some());

    // Wrong passphrase fails with VaultDecryptError::WrongPassphrase and leaves disk untouched.
    let wrong_err = unlock_with_recovery_passphrase(&started, &info, "wrong-passphrase")
        .await
        .unwrap_err();
    assert!(matches!(
        wrong_err.downcast_ref::<VaultDecryptError>(),
        Some(VaultDecryptError::WrongPassphrase)
    ));
    assert!(!key_path_b.exists());
    assert!(!cfg_path_b.exists());

    // Right passphrase succeeds, writes user_key.toml + client.toml + renewed cert, and cancels pairing.
    let outcome = unlock_with_recovery_passphrase(&started, &info, passphrase)
        .await
        .unwrap();
    assert!(outcome.enrolled_new_client);
    assert_eq!(outcome.user_pubkey_token, user_pub_token_a);
    assert!(key_path_b.exists());
    assert!(cfg_path_b.exists());

    let loaded_sk_b = load_user_signing_key(Some(&key_path_b)).unwrap();
    assert_eq!(loaded_sk_b.to_bytes(), user_sk_a.to_bytes());
    let (_, uk_b) = UserKeyFile::load(Some(&key_path_b)).unwrap();
    assert!(uk_b.user_cert_token.is_some());

    let cfg_b = ClientConfig::load(Some(&cfg_path_b)).unwrap();
    assert_eq!(cfg_b.grant.node_id, "workstation-recovery");
    assert_eq!(cfg_b.grant.user_pubkey, user_pk_a);
    assert!(cfg_b.grant.user_cert.is_some());
    assert_eq!(cfg_b.operator_url.as_deref(), Some(op_url.as_str()));
    assert_eq!(op_state.lock().await.cancel_calls, 1);

    // Delete recovery vault and verify status returns false.
    delete_recovery_vault_http(&op_url, &bundle_a.grant, &bundle_a.node_signing_key)
        .await
        .unwrap();
    let (configured_deleted, _) =
        get_recovery_vault_status_http(&op_url, &bundle_a.grant, &bundle_a.node_signing_key)
            .await
            .unwrap();
    assert!(!configured_deleted);

    srv_handle.abort();
}

#[tokio::test]
async fn test_confirm_replace_lost_root_key_flow() {
    use sshcast_client::config::UserKeyFile;
    use sshcast_client::operator::{
        confirm_replace_lost_root_key, poll_enrollment_once, start_github_enrollment,
        EnrollPollStep,
    };

    let lost_user_sk = SigningKey::from_bytes(&[0xC3; 32]);
    let lost_user_pk = lost_user_sk.verifying_key().to_bytes();
    let coord_url = "https://coord.example.com".to_string();

    let (op_url, op_state, srv_handle) = spawn_mock_operator(&lost_user_sk, "octocat").await;

    // Pre-seed a stale key/config on Workstation B to verify replacement overwrites cleanly.
    let tmp_b = TempDir::new().unwrap();
    let key_path_b = tmp_b.path().join("user_key.toml");
    let cfg_path_b = tmp_b.path().join("client.toml");
    let stale_out = run_keygen(Some(&key_path_b), false).unwrap();
    let stale_sk = load_user_signing_key(Some(&key_path_b)).unwrap();
    let stale_bundle = mint_enrollment_bundle(
        &stale_sk,
        "old-node",
        NodeRole::Client,
        vec![coord_url.clone()],
        0,
    )
    .unwrap();
    write_client_config_from_bundle(&stale_bundle, Some(&cfg_path_b), false).unwrap();

    let started = start_github_enrollment(
        &[coord_url],
        Some(&op_url),
        Some("workstation-reset"),
        Some(&key_path_b),
        Some(&cfg_path_b),
        false,
        |_| {},
    )
    .await
    .unwrap();

    let info = match poll_enrollment_once(&started).await.unwrap() {
        EnrollPollStep::PairingRequired(info) => info,
        other => panic!("expected PairingRequired, got {other:?}"),
    };
    assert_eq!(info.existing_user_pubkey, lost_user_pk);

    let outcome = confirm_replace_lost_root_key(&started).await.unwrap();
    assert!(outcome.enrolled_new_client);
    assert_eq!(outcome.user_pubkey_token, stale_out.user_pubkey_token);
    assert_ne!(
        outcome.user_pubkey_token,
        format!("sc_pub_{}", hex::encode(lost_user_pk))
    );

    let (_, uk_b) = UserKeyFile::load(Some(&key_path_b)).unwrap();
    assert!(uk_b.user_cert_token.is_some());

    let cfg_b = ClientConfig::load(Some(&cfg_path_b)).unwrap();
    assert_eq!(cfg_b.grant.node_id, "workstation-reset");
    assert_eq!(
        cfg_b.grant.user_pubkey,
        stale_sk.verifying_key().to_bytes().to_vec()
    );
    assert!(cfg_b.grant.user_cert.is_some());
    assert_eq!(cfg_b.operator_url.as_deref(), Some(op_url.as_str()));
    assert_eq!(op_state.lock().await.replace_calls, 1);

    // Also test fresh workstation (no pre-existing user_key.toml / client.toml) replacing lost key.
    let tmp_fresh = TempDir::new().unwrap();
    let fresh_key = tmp_fresh.path().join("user_key.toml");
    let fresh_cfg = tmp_fresh.path().join("client.toml");
    // Reset operator's existing key back to lost_user_sk for this second check.
    op_state.lock().await.existing_user_pubkey =
        format!("sc_pub_{}", hex::encode(lost_user_pk));

    let started_fresh = start_github_enrollment(
        &["https://coord.example.com".to_string()],
        Some(&op_url),
        Some("workstation-fresh-reset"),
        Some(&fresh_key),
        Some(&fresh_cfg),
        false,
        |_| {},
    )
    .await
    .unwrap();
    assert!(!fresh_key.exists());
    assert!(!fresh_cfg.exists());

    let fresh_info = match poll_enrollment_once(&started_fresh).await.unwrap() {
        EnrollPollStep::PairingRequired(info) => info,
        other => panic!("expected PairingRequired, got {other:?}"),
    };
    assert_eq!(fresh_info.existing_user_pubkey, lost_user_pk);

    let fresh_outcome = confirm_replace_lost_root_key(&started_fresh)
        .await
        .unwrap();
    assert!(fresh_outcome.enrolled_new_client);
    assert!(fresh_key.exists());
    assert!(fresh_cfg.exists());
    let loaded_fresh_cfg = ClientConfig::load(Some(&fresh_cfg)).unwrap();
    assert_eq!(loaded_fresh_cfg.grant.node_id, "workstation-fresh-reset");
    assert!(loaded_fresh_cfg.grant.user_cert.is_some());
    assert_ne!(
        loaded_fresh_cfg.grant.user_pubkey.as_slice(),
        lost_user_pk.as_slice()
    );

    srv_handle.abort();
}

#[tokio::test]
async fn test_cli_recovery_and_interactive_login_subprocesses() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let user_sk_a = SigningKey::from_bytes(&[0xD4; 32]);
    let user_pk_a = user_sk_a.verifying_key().to_bytes();
    let coord_url = "https://coord.example.com".to_string();

    let (op_url, _op_state, srv_handle) = spawn_mock_operator(&user_sk_a, "octocat").await;

    let tmp_a = TempDir::new().unwrap();
    let key_a = tmp_a.path().join("user_key.toml");
    let cfg_a = tmp_a.path().join("client.toml");
    sshcast_client::enroll::save_user_signing_key(&user_sk_a, Some(&key_a), false).unwrap();
    let bundle_a = mint_enrollment_bundle(
        &user_sk_a,
        "workstation-a",
        NodeRole::Client,
        vec![coord_url.clone()],
        0,
    )
    .unwrap();
    write_client_config_from_bundle(&bundle_a, Some(&cfg_a), false).unwrap();

    let bin = env!("CARGO_BIN_EXE_sshcast-client");
    let passphrase = "super-secret-passphrase-123";

    // 1. `sshcast-client recovery set --passphrase-stdin`
    let mut set_child = Command::new(bin)
        .args([
            "recovery",
            "set",
            "--config",
            cfg_a.to_str().unwrap(),
            "--key-file",
            key_a.to_str().unwrap(),
            "--operator",
            &op_url,
            "--passphrase-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    set_child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{passphrase}\n").as_bytes())
        .unwrap();
    let set_out = tokio::task::spawn_blocking(move || set_child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        set_out.status.success(),
        "recovery set failed: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );
    assert!(String::from_utf8_lossy(&set_out.stdout).contains("Recovery vault uploaded"));

    // 2. `sshcast-client recovery status`
    let op_url_s = op_url.clone();
    let cfg_a_s = cfg_a.clone();
    let status_out = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args([
                "recovery",
                "status",
                "--config",
                cfg_a_s.to_str().unwrap(),
                "--operator",
                &op_url_s,
            ])
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(status_out.status.success());
    assert!(String::from_utf8_lossy(&status_out.stdout).contains("Recovery vault: configured"));

    // 3. `sshcast-client login` on Workstation B -> PairingRequired -> 'p' -> wrong passphrase -> retry 'p' -> right passphrase!
    let tmp_b = TempDir::new().unwrap();
    let key_b = tmp_b.path().join("user_key.toml");
    let cfg_b = tmp_b.path().join("client.toml");
    let mut login_child = Command::new(bin)
        .args([
            "login",
            "--domain",
            &coord_url,
            "--operator",
            &op_url,
            "--node",
            "workstation-b-cli",
            "--key-file",
            key_b.to_str().unwrap(),
            "--config",
            cfg_b.to_str().unwrap(),
            "--no-browser",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    login_child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("p\nwrong-pass\np\n{passphrase}\n").as_bytes())
        .unwrap();
    let login_out = tokio::task::spawn_blocking(move || login_child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let login_stdout = String::from_utf8_lossy(&login_out.stdout);
    let login_stderr = String::from_utf8_lossy(&login_out.stderr);
    assert!(
        login_out.status.success(),
        "cli login failed:\nstdout: {login_stdout}\nstderr: {login_stderr}"
    );
    assert!(login_stdout.contains("Existing account @octocat detected"));
    assert!(login_stdout.contains("Verification Code:"));
    assert!(login_stderr.contains("Incorrect recovery passphrase"));
    assert!(!login_stdout.contains("sshcast-client recovery set"));

    let loaded_sk_b = load_user_signing_key(Some(&key_b)).unwrap();
    assert_eq!(loaded_sk_b.to_bytes(), user_sk_a.to_bytes());
    let loaded_cfg_b = ClientConfig::load(Some(&cfg_b)).unwrap();
    assert_eq!(loaded_cfg_b.grant.node_id, "workstation-b-cli");
    assert_eq!(loaded_cfg_b.grant.user_pubkey, user_pk_a);
    assert!(loaded_cfg_b.grant.user_cert.is_some());

    // 4. `sshcast-client recovery remove`
    let op_url_r = op_url.clone();
    let cfg_a_r = cfg_a.clone();
    let rm_out = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args([
                "recovery",
                "remove",
                "--config",
                cfg_a_r.to_str().unwrap(),
                "--operator",
                &op_url_r,
            ])
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    assert!(rm_out.status.success());
    assert!(String::from_utf8_lossy(&rm_out.stdout).contains("Removed recovery vault"));

    srv_handle.abort();
}

#[tokio::test]
async fn test_workstation_manager_background_pairing_listener_approves_peer() {
    use sshcast_client::config::UserKeyFile;
    use sshcast_client::operator::{
        complete_paired_enrollment, poll_enrollment_once, start_github_enrollment, EnrollPollStep,
    };
    use sshcast_client::prompt::PairingPromptDetails;
    use sshcast_proto::crypto::derive_user_id;

    struct PairingCapturePrompter {
        prompt_tx: mpsc::Sender<PairingPromptDetails>,
        approve_gate: Arc<tokio::sync::Notify>,
        approve: bool,
    }

    #[tonic::async_trait]
    impl ApprovalPrompter for PairingCapturePrompter {
        async fn prompt_user(
            &self,
            _details: PromptDetails,
            _cancel_rx: watch::Receiver<Option<String>>,
        ) -> ApprovalDecision {
            ApprovalDecision::Deny
        }

        async fn prompt_pairing(
            &self,
            details: PairingPromptDetails,
            mut cancel_rx: watch::Receiver<Option<String>>,
        ) -> bool {
            let _ = self.prompt_tx.send(details).await;
            tokio::select! {
                _ = self.approve_gate.notified() => self.approve,
                _ = cancel_rx.changed() => false,
            }
        }
    }

    let user_sk_a = SigningKey::from_bytes(&[0xE5; 32]);
    let user_pk_a = user_sk_a.verifying_key().to_bytes();
    let user_id_a = derive_user_id(&user_pk_a);
    let user_pub_token_a = format!("sc_pub_{}", hex::encode(user_pk_a));
    let coord_url = "http://127.0.0.1:1".to_string();

    let (op_url, _op_state, srv_handle) = spawn_mock_operator(&user_sk_a, "octocat").await;

    // Set up Workstation A on disk in tmp_a with matching user_key.toml + client.toml
    let tmp_a = TempDir::new().unwrap();
    let key_path_a = tmp_a.path().join("user_key.toml");
    let cfg_path_a = tmp_a.path().join("client.toml");
    sshcast_client::enroll::save_user_signing_key(&user_sk_a, Some(&key_path_a), false).unwrap();

    let bundle_a = mint_enrollment_bundle(
        &user_sk_a,
        "workstation-a",
        NodeRole::Client,
        vec![coord_url.clone()],
        0,
    )
    .unwrap();
    write_client_config_from_bundle(&bundle_a, Some(&cfg_path_a), false).unwrap();
    {
        let (_, mut cfg_file_a) =
            sshcast_client::config::ClientConfigFile::load(Some(&cfg_path_a)).unwrap();
        cfg_file_a.operator_url = Some(op_url.clone());
        cfg_file_a.zellij_listen_port = 0;
        cfg_file_a.save(Some(&cfg_path_a)).unwrap();
    }
    let cfg_a = ClientConfig::load(Some(&cfg_path_a)).unwrap();

    let (prompt_tx, mut prompt_rx) = mpsc::channel(4);
    let approve_gate = Arc::new(tokio::sync::Notify::new());
    let prompter_a: Arc<dyn ApprovalPrompter> = Arc::new(PairingCapturePrompter {
        prompt_tx,
        approve_gate: Arc::clone(&approve_gate),
        approve: true,
    });
    let connector_a = Arc::new(LocalAgentConnector::with_options(
        None,
        KeyFilterConfig::default(),
        true,
    ));
    let policy_a = Arc::new(PolicyEngine::default());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let manager_a = WorkstationManager::new(cfg_a, connector_a, policy_a, prompter_a);
    let manager_handle = tokio::spawn(async move { manager_a.run(shutdown_rx).await });

    // Workstation B starts GitHub enrollment and hits PairingRequired
    let tmp_b = TempDir::new().unwrap();
    let key_path_b = tmp_b.path().join("user_key.toml");
    let cfg_path_b = tmp_b.path().join("client.toml");
    let started_b = start_github_enrollment(
        std::slice::from_ref(&coord_url),
        Some(&op_url),
        Some("workstation-b"),
        Some(&key_path_b),
        Some(&cfg_path_b),
        false,
        |_| {},
    )
    .await
    .unwrap();

    let info = match poll_enrollment_once(&started_b).await.unwrap() {
        EnrollPollStep::PairingRequired(info) => info,
        other => panic!("expected PairingRequired, got {other:?}"),
    };

    // Workstation A's background pairing listener receives the request and invokes prompt_pairing
    let captured = tokio::time::timeout(Duration::from_secs(10), prompt_rx.recv())
        .await
        .expect("timed out waiting for Workstation A pairing prompt")
        .expect("pairing prompt channel closed");
    assert_eq!(captured.pairing_id, info.pairing_id);
    assert_eq!(captured.node_name, "workstation-b");
    assert_eq!(captured.github_login, "octocat");
    assert_eq!(captured.sas_code, info.sas_code);
    assert_eq!(captured.existing_user_id, user_id_a);
    assert!(!captured.os_name.is_empty());

    // Release Workstation A to approve the pairing request now that B observed PairingRequired.
    approve_gate.notify_one();

    // Workstation B polls until it receives EnrollPollStep::Paired
    let paired_step = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match poll_enrollment_once(&started_b).await.unwrap() {
                step @ EnrollPollStep::Paired { .. } => break step,
                EnrollPollStep::PairingRequired(_) | EnrollPollStep::Pending => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                other => panic!("unexpected enrollment poll step: {other:?}"),
            }
        }
    })
    .await
    .expect("timed out waiting for Workstation B to receive Paired response");

    let (pairing_id, existing_pk, approver_node, envelope) = match paired_step {
        EnrollPollStep::Paired {
            pairing_id,
            existing_user_pubkey,
            approver_node_id,
            envelope,
        } => (pairing_id, existing_user_pubkey, approver_node_id, envelope),
        _ => unreachable!(),
    };
    assert_eq!(approver_node, "workstation-a");

    let outcome_b = complete_paired_enrollment(started_b, &existing_pk, &pairing_id, &envelope)
        .await
        .unwrap();
    assert!(outcome_b.enrolled_new_client);
    assert_eq!(outcome_b.user_pubkey_token, user_pub_token_a);
    assert!(key_path_b.exists());
    assert!(cfg_path_b.exists());

    let loaded_sk_b = load_user_signing_key(Some(&key_path_b)).unwrap();
    assert_eq!(loaded_sk_b.to_bytes(), user_sk_a.to_bytes());
    let (_, uk_b) = UserKeyFile::load(Some(&key_path_b)).unwrap();
    assert!(uk_b.user_cert_token.is_some());

    let cfg_b = ClientConfig::load(Some(&cfg_path_b)).unwrap();
    assert_eq!(cfg_b.grant.node_id, "workstation-b");
    assert_eq!(cfg_b.grant.user_pubkey, user_pk_a);
    assert!(cfg_b.grant.user_cert.is_some());

    let _ = shutdown_tx.send(true);
    let run_res = tokio::time::timeout(Duration::from_secs(5), manager_handle)
        .await
        .expect("WorkstationManager shutdown timed out")
        .unwrap();
    run_res.unwrap();

    srv_handle.abort();
}

#[tokio::test]
async fn test_workstation_manager_pairing_listener_skips_without_root_key_and_dismisses_canceled_prompt(
) {
    use sshcast_client::operator::{
        cancel_enrollment_pairing, poll_enrollment_once, start_github_enrollment, EnrollPollStep,
    };
    use sshcast_client::prompt::PairingPromptDetails;

    struct BlockingUntilCanceledPrompter {
        opened_tx: mpsc::Sender<PairingPromptDetails>,
        canceled_tx: mpsc::Sender<Option<String>>,
    }

    #[tonic::async_trait]
    impl ApprovalPrompter for BlockingUntilCanceledPrompter {
        async fn prompt_user(
            &self,
            _details: PromptDetails,
            _cancel_rx: watch::Receiver<Option<String>>,
        ) -> ApprovalDecision {
            ApprovalDecision::Deny
        }

        async fn prompt_pairing(
            &self,
            details: PairingPromptDetails,
            mut cancel_rx: watch::Receiver<Option<String>>,
        ) -> bool {
            let _ = self.opened_tx.send(details).await;
            let _ = cancel_rx.changed().await;
            let reason = cancel_rx.borrow().clone();
            let _ = self.canceled_tx.send(reason).await;
            false
        }
    }

    let user_sk_a = SigningKey::from_bytes(&[0xF6; 32]);
    let coord_url = "http://127.0.0.1:1".to_string();
    let (op_url, _op_state, srv_handle) = spawn_mock_operator(&user_sk_a, "octocat").await;

    // 1. Secondary workstation WITHOUT user_key.toml must NOT invoke prompt_pairing
    let tmp_no_key = TempDir::new().unwrap();
    let cfg_path_no_key = tmp_no_key.path().join("client.toml");
    let bundle_no_key = mint_enrollment_bundle(
        &user_sk_a,
        "secondary-no-key",
        NodeRole::Client,
        vec![coord_url.clone()],
        0,
    )
    .unwrap();
    write_client_config_from_bundle(&bundle_no_key, Some(&cfg_path_no_key), false).unwrap();
    {
        let (_, mut f) =
            sshcast_client::config::ClientConfigFile::load(Some(&cfg_path_no_key)).unwrap();
        f.operator_url = Some(op_url.clone());
        f.zellij_listen_port = 0;
        f.save(Some(&cfg_path_no_key)).unwrap();
    }
    let cfg_no_key = ClientConfig::load(Some(&cfg_path_no_key)).unwrap();

    let tmp_b = TempDir::new().unwrap();
    let started_b = start_github_enrollment(
        std::slice::from_ref(&coord_url),
        Some(&op_url),
        Some("workstation-b-cancel"),
        Some(&tmp_b.path().join("user_key.toml")),
        Some(&tmp_b.path().join("client.toml")),
        false,
        |_| {},
    )
    .await
    .unwrap();
    assert!(matches!(
        poll_enrollment_once(&started_b).await.unwrap(),
        EnrollPollStep::PairingRequired(_)
    ));

    let (no_key_opened_tx, mut no_key_opened_rx) = mpsc::channel(2);
    let (no_key_canceled_tx, _) = mpsc::channel(2);
    let (shutdown_no_key_tx, shutdown_no_key_rx) = watch::channel(false);
    let mgr_no_key = WorkstationManager::new(
        cfg_no_key,
        Arc::new(LocalAgentConnector::with_options(
            None,
            KeyFilterConfig::default(),
            true,
        )),
        Arc::new(PolicyEngine::default()),
        Arc::new(BlockingUntilCanceledPrompter {
            opened_tx: no_key_opened_tx,
            canceled_tx: no_key_canceled_tx,
        }),
    );
    let no_key_handle = tokio::spawn(async move { mgr_no_key.run(shutdown_no_key_rx).await });

    assert!(
        tokio::time::timeout(Duration::from_millis(400), no_key_opened_rx.recv())
            .await
            .is_err(),
        "workstation without local user_key.toml should not prompt for pairing"
    );
    let _ = shutdown_no_key_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), no_key_handle)
        .await
        .unwrap();

    // 2. Primary workstation WITH user_key.toml opens prompt, and 3s monitor auto-dismisses when canceled externally
    let tmp_a = TempDir::new().unwrap();
    let key_path_a = tmp_a.path().join("user_key.toml");
    let cfg_path_a = tmp_a.path().join("client.toml");
    sshcast_client::enroll::save_user_signing_key(&user_sk_a, Some(&key_path_a), false).unwrap();
    let bundle_a = mint_enrollment_bundle(
        &user_sk_a,
        "workstation-a-monitor",
        NodeRole::Client,
        vec![coord_url],
        0,
    )
    .unwrap();
    write_client_config_from_bundle(&bundle_a, Some(&cfg_path_a), false).unwrap();
    {
        let (_, mut f) =
            sshcast_client::config::ClientConfigFile::load(Some(&cfg_path_a)).unwrap();
        f.operator_url = Some(op_url.clone());
        f.zellij_listen_port = 0;
        f.save(Some(&cfg_path_a)).unwrap();
    }
    let cfg_a = ClientConfig::load(Some(&cfg_path_a)).unwrap();

    let (opened_tx, mut opened_rx) = mpsc::channel(2);
    let (canceled_tx, mut canceled_rx) = mpsc::channel(2);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mgr_a = WorkstationManager::new(
        cfg_a,
        Arc::new(LocalAgentConnector::with_options(
            None,
            KeyFilterConfig::default(),
            true,
        )),
        Arc::new(PolicyEngine::default()),
        Arc::new(BlockingUntilCanceledPrompter {
            opened_tx,
            canceled_tx,
        }),
    );
    let mgr_a_handle = tokio::spawn(async move { mgr_a.run(shutdown_rx).await });

    let opened_details = tokio::time::timeout(Duration::from_secs(10), opened_rx.recv())
        .await
        .expect("timed out waiting for pairing prompt to open")
        .unwrap();
    assert_eq!(opened_details.node_name, "workstation-b-cancel");

    // Cancel enrollment externally while the prompt is open; the 3s monitor should dismiss it!
    cancel_enrollment_pairing(&started_b).await.unwrap();
    let cancel_reason = tokio::time::timeout(Duration::from_secs(10), canceled_rx.recv())
        .await
        .expect("timed out waiting for 3s pairing monitor to cancel prompt")
        .unwrap();
    assert_eq!(cancel_reason.as_deref(), Some("Handled or canceled"));

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(5), mgr_a_handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    srv_handle.abort();
}
