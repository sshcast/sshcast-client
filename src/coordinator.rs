use anyhow::{Context, Result};
use sockcast_proto::crypto::{create_node_auth, verify_sign_request};
use sockcast_proto::v1::client_stream_message::Payload as ClientPayload;
use sockcast_proto::v1::server_stream_message::Payload as ServerPayload;
use sockcast_proto::v1::sockcast_service_client::SockcastServiceClient;
use sockcast_proto::v1::{
    ClientStreamMessage, SignAck, SignRequest, SignResponse, WorkstationStatus,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;

use crate::config::ClientConfig;
use crate::local_agent::LocalAgentConnector;
use crate::policy::{ApprovalDecision, PolicyEngine};
use crate::presence::{current_os_name, now_unix_ms, query_last_input_epoch_ms};
use crate::prompt::{ApprovalPrompter, PromptDetails};
use crate::zellij_proxy::{serve_zellij_proxy_with_listener, ZellijProxyHub};

pub struct WorkstationManager {
    cfg: ClientConfig,
    local_agent: Arc<LocalAgentConnector>,
    policy: Arc<PolicyEngine>,
    prompter: Arc<dyn ApprovalPrompter>,
    cancellations: Arc<Mutex<HashMap<String, watch::Sender<Option<String>>>>>,
    force_active_flag: Arc<AtomicBool>,
    connected_count: Arc<AtomicUsize>,
    zellij_hub: Arc<ZellijProxyHub>,
}

impl WorkstationManager {
    pub fn new(
        cfg: ClientConfig,
        local_agent: Arc<LocalAgentConnector>,
        policy: Arc<PolicyEngine>,
        prompter: Arc<dyn ApprovalPrompter>,
    ) -> Self {
        let force_active_flag = Arc::new(AtomicBool::new(cfg.force_active));
        let connected_count = Arc::new(AtomicUsize::new(0));
        Self::with_shared_state(
            cfg,
            local_agent,
            policy,
            prompter,
            force_active_flag,
            connected_count,
        )
    }

    pub fn with_shared_state(
        cfg: ClientConfig,
        local_agent: Arc<LocalAgentConnector>,
        policy: Arc<PolicyEngine>,
        prompter: Arc<dyn ApprovalPrompter>,
        force_active_flag: Arc<AtomicBool>,
        connected_count: Arc<AtomicUsize>,
    ) -> Self {
        connected_count.store(0, Ordering::Relaxed);
        let zellij_hub = Arc::new(ZellijProxyHub::new(cfg.clone()));
        Self {
            cfg,
            local_agent,
            policy,
            prompter,
            cancellations: Arc::new(Mutex::new(HashMap::new())),
            force_active_flag,
            connected_count,
            zellij_hub,
        }
    }

    pub fn zellij_hub(&self) -> Arc<ZellijProxyHub> {
        Arc::clone(&self.zellij_hub)
    }

    pub fn force_active_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.force_active_flag)
    }

    pub fn connected_count(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.connected_count)
    }

    /// Maintains persistent bidirectional `ConnectWorkstation` gRPC streams to all configured
    /// `sockcast-server` instances concurrently until `shutdown_rx` signals true.
    pub async fn run(&self, shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut handles = Vec::with_capacity(self.cfg.servers.len() + 1);
        if self.cfg.zellij_listen_port > 0 {
            let bind_addr = format!("127.0.0.1:{}", self.cfg.zellij_listen_port);
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    let hub = Arc::clone(&self.zellij_hub);
                    let shutdown = shutdown_rx.clone();
                    handles.push(tokio::spawn(async move {
                        let _ = serve_zellij_proxy_with_listener(listener, hub, shutdown).await;
                    }));
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not bind Zellij Web local proxy on {} ({}); continuing without local Zellij HTTP listener",
                        bind_addr,
                        e
                    );
                }
            }
        }
        for server_url in &self.cfg.servers {
            let url = server_url.clone();
            let cfg = self.cfg.clone();
            let local_agent = Arc::clone(&self.local_agent);
            let policy = Arc::clone(&self.policy);
            let prompter = Arc::clone(&self.prompter);
            let cancellations = Arc::clone(&self.cancellations);
            let force_active_flag = Arc::clone(&self.force_active_flag);
            let connected_count = Arc::clone(&self.connected_count);
            let zellij_hub = Arc::clone(&self.zellij_hub);
            let mut shutdown = shutdown_rx.clone();

            handles.push(tokio::spawn(async move {
                let mut backoff = Duration::from_millis(500);
                let max_backoff = Duration::from_secs(30);

                loop {
                    if *shutdown.borrow() {
                        break;
                    }

                    let conn_res = run_single_coordinator_stream(
                        &url,
                        &cfg,
                        &local_agent,
                        &policy,
                        &prompter,
                        &cancellations,
                        &force_active_flag,
                        &connected_count,
                        &zellij_hub,
                        shutdown.clone(),
                    )
                    .await;

                    if *shutdown.borrow() {
                        break;
                    }

                    match conn_res {
                        Ok(()) => {
                            backoff = Duration::from_millis(500);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Coordinator stream {} disconnected ({:#}); reconnecting in {:?}",
                                url,
                                e,
                                backoff
                            );
                        }
                    }

                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(max_backoff);
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }
        Ok(())
    }
}

struct ConnectedGuard<'a>(&'a AtomicUsize);

impl<'a> ConnectedGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ConnectedGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_single_coordinator_stream(
    server_url: &str,
    cfg: &ClientConfig,
    local_agent: &Arc<LocalAgentConnector>,
    policy: &Arc<PolicyEngine>,
    prompter: &Arc<dyn ApprovalPrompter>,
    cancellations: &Arc<Mutex<HashMap<String, watch::Sender<Option<String>>>>>,
    force_active_flag: &Arc<AtomicBool>,
    connected_count: &Arc<AtomicUsize>,
    zellij_hub: &Arc<ZellijProxyHub>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let endpoint = Endpoint::new(server_url.to_string())
        .with_context(|| format!("invalid coordinator URL {server_url}"))?
        .connect_timeout(Duration::from_secs(5))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Duration::from_secs(25))
        .keep_alive_timeout(Duration::from_secs(10));

    let channel = endpoint.connect().await?;
    let mut client = SockcastServiceClient::new(channel);

    let (tx, rx) = mpsc::channel::<ClientStreamMessage>(256);
    zellij_hub.register_coordinator_sender(tx.clone()).await;

    // 1. First message on ConnectWorkstation stream MUST be AuthHandshake
    let handshake = create_node_auth(cfg.grant.clone(), &cfg.node_signing_key, now_unix_ms())?;
    tx.send(ClientStreamMessage {
        payload: Some(ClientPayload::AuthHandshake(handshake)),
    })
    .await?;

    // 2. Immediately push initial WorkstationStatus (including local filtered public keys)
    let initial_status =
        build_workstation_status(local_agent, force_active_flag.load(Ordering::Relaxed)).await;
    tx.send(ClientStreamMessage {
        payload: Some(ClientPayload::Status(initial_status)),
    })
    .await?;

    let response = client
        .connect_workstation(ReceiverStream::new(rx))
        .await
        .with_context(|| format!("ConnectWorkstation RPC failed on {server_url}"))?;
    let mut inbound = response.into_inner();

    let _conn_guard = ConnectedGuard::new(connected_count);

    tracing::info!(
        "Connected workstation '{}' to coordinator {}",
        cfg.grant.node_id,
        server_url
    );

    let mut heartbeat_ticker =
        tokio::time::interval(Duration::from_secs(cfg.heartbeat_interval_secs.max(1)));
    heartbeat_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick since we already queued initial_status above
    heartbeat_ticker.tick().await;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            _ = heartbeat_ticker.tick() => {
                let status = build_workstation_status(
                    local_agent,
                    force_active_flag.load(Ordering::Relaxed),
                )
                .await;
                if tx.send(ClientStreamMessage {
                    payload: Some(ClientPayload::Status(status)),
                }).await.is_err() {
                    anyhow::bail!("outbound stream closed");
                }
            }
            frame_res = inbound.message() => {
                let Some(frame) = frame_res? else {
                    return Ok(());
                };
                match frame.payload {
                    Some(ServerPayload::ServerHeartbeatEpochMs(_ts)) => {
                        tracing::debug!("Received server heartbeat from {}", server_url);
                    }
                    Some(ServerPayload::CancelSignRequest(cancel)) => {
                        tracing::info!(
                            "Received CancelSignRequest for {} (reason: {})",
                            cancel.request_id,
                            cancel.reason
                        );
                        if let Some(cancel_tx) = cancellations.lock().await.remove(&cancel.request_id) {
                            let _ = cancel_tx.send(Some(cancel.reason));
                        }
                    }
                    Some(ServerPayload::SignRequest(sign_req)) => {
                        let req_id = sign_req.request_id.clone();

                        // Two-Phase Delivery Step 1: Immediately reply with SignAck (<1.5s)
                        if tx.send(ClientStreamMessage {
                            payload: Some(ClientPayload::SignAck(SignAck {
                                request_id: req_id.clone(),
                            })),
                        }).await.is_err() {
                            anyhow::bail!("outbound stream closed while sending SignAck");
                        }

                        // Spawn async task to verify end-to-end signature, evaluate policy/prompt, and sign
                        let tx_clone = tx.clone();
                        let cfg_clone = cfg.clone();
                        let agent_clone = Arc::clone(local_agent);
                        let policy_clone = Arc::clone(policy);
                        let prompter_clone = Arc::clone(prompter);
                        let cancels_clone = Arc::clone(cancellations);

                        tokio::spawn(async move {
                            let (cancel_tx, cancel_rx) = watch::channel(None);
                            cancels_clone.lock().await.insert(req_id.clone(), cancel_tx);

                            let sign_resp = handle_incoming_sign_request(
                                sign_req,
                                &cfg_clone,
                                &agent_clone,
                                &policy_clone,
                                &prompter_clone,
                                cancel_rx,
                            )
                            .await;

                            cancels_clone.lock().await.remove(&req_id);

                            let _ = tx_clone
                                .send(ClientStreamMessage {
                                    payload: Some(ClientPayload::SignResponse(sign_resp)),
                                })
                                .await;
                        });
                    }
                    Some(ServerPayload::ZellijHostList(list)) => {
                        zellij_hub.update_host_list(list).await;
                    }
                    Some(ServerPayload::ZellijFrame(z_frame)) => {
                        let hub = Arc::clone(zellij_hub);
                        tokio::spawn(async move {
                            hub.handle_incoming_frame(z_frame).await;
                        });
                    }
                    None => {}
                }
            }
        }
    }
}

async fn build_workstation_status(
    local_agent: &LocalAgentConnector,
    force_active: bool,
) -> WorkstationStatus {
    let keys = local_agent.list_filtered_keys().await.unwrap_or_default();
    WorkstationStatus {
        last_input_epoch_ms: query_last_input_epoch_ms(),
        force_active,
        os: current_os_name().to_string(),
        keys,
    }
}

/// Verifies `SignRequest` end-to-end against the user's root public key, evaluates 15m session trust rules
/// or invokes the user prompter, and bridges approved requests to the local OS SSH agent.
pub async fn handle_incoming_sign_request(
    req: SignRequest,
    cfg: &ClientConfig,
    local_agent: &Arc<LocalAgentConnector>,
    policy: &Arc<PolicyEngine>,
    prompter: &Arc<dyn ApprovalPrompter>,
    cancel_rx: watch::Receiver<Option<String>>,
) -> SignResponse {
    let request_id = req.request_id.clone();
    let handled_by_node_id = cfg.grant.node_id.clone();

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1. Cryptographic End-to-End Verification:
    //    a) Verify relay_grant signature and expiration
    //    b) Verify ProcessContext.hostname == relay_grant.node_id
    //    c) Verify relay_signature over canonical request fields
    if let Err(e) = verify_sign_request(&req, now_sec) {
        tracing::error!(
            "SECURITY ALERT: Rejecting SignRequest {} due to failed end-to-end verification: {}",
            request_id,
            e
        );
        return SignResponse {
            request_id,
            approved: false,
            signature_blob: Vec::new(),
            error_message: format!("end-to-end cryptographic verification failed: {e}"),
            handled_by_node_id,
        };
    }

    //    d) Verify that relay_grant.user_pubkey matches THIS workstation's user_pubkey!
    let relay_user_pk = req
        .relay_grant
        .as_ref()
        .map(|g| g.user_pubkey.as_slice())
        .unwrap_or(&[]);
    if relay_user_pk != cfg.grant.user_pubkey.as_slice() {
        tracing::error!(
            "SECURITY ALERT: SignRequest {} relay_grant.user_pubkey does not match workstation user_pubkey!",
            request_id
        );
        return SignResponse {
            request_id,
            approved: false,
            signature_blob: Vec::new(),
            error_message: "relay_grant user_pubkey mismatch".to_string(),
            handled_by_node_id,
        };
    }

    // 2. Evaluate 15-minute session trust rules or prompt the user
    let approved = if policy.check_auto_approved(&req) {
        tracing::info!(
            "Auto-approved SignRequest {} via active 15m session trust rule",
            request_id
        );
        true
    } else {
        let known_keys = local_agent.list_filtered_keys().await.unwrap_or_default();
        let details = PromptDetails::from_request(&req, &known_keys);
        let decision = prompter.prompt_user(details, cancel_rx.clone()).await;

        if cancel_rx.borrow().is_some() {
            return SignResponse {
                request_id,
                approved: false,
                signature_blob: Vec::new(),
                error_message: "request canceled".to_string(),
                handled_by_node_id,
            };
        }

        policy.record_decision(&req, decision);
        decision != ApprovalDecision::Deny
    };

    if !approved {
        return SignResponse {
            request_id,
            approved: false,
            signature_blob: Vec::new(),
            error_message: "request denied by user".to_string(),
            handled_by_node_id,
        };
    }

    // 3. Bridge approved request to local OS SSH agent
    match local_agent.sign(&req.key_blob, &req.data, req.flags).await {
        Ok(signature_blob) => SignResponse {
            request_id,
            approved: true,
            signature_blob,
            error_message: String::new(),
            handled_by_node_id,
        },
        Err(e) => {
            tracing::warn!("Local SSH agent signing failed for {}: {}", request_id, e);
            SignResponse {
                request_id,
                approved: false,
                signature_blob: Vec::new(),
                error_message: format!("local SSH agent error: {e}"),
                handled_by_node_id,
            }
        }
    }
}
