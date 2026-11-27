use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use sshcast_proto::crypto::{create_node_auth, derive_user_id, verify_sign_request};
use sshcast_proto::v1::client_stream_message::Payload as ClientPayload;
use sshcast_proto::v1::server_stream_message::Payload as ServerPayload;
use sshcast_proto::v1::sshcast_service_client::SshcastServiceClient;
use sshcast_proto::v1::{
    ClientStreamMessage, NodeGrant, SignAck, SignRequest, SignResponse, WorkstationStatus,
};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{ClientTlsConfig, Endpoint};

use crate::config::{ClientConfig, UserKeyFile};
use crate::enroll::load_user_signing_key;
use crate::local_agent::LocalAgentConnector;
use crate::operator::{
    cert_needs_renewal, poll_pending_pairing_requests_http, renew_user_cert_http,
    resolve_operator_url, respond_to_pairing_request_http,
};
use crate::pairing::{
    compute_pairing_sas_code, create_encrypted_pairing_handoff, parse_user_pubkey_token,
};
use crate::policy::{ApprovalDecision, PolicyEngine};
use crate::presence::{current_os_name, now_unix_ms, query_last_input_epoch_ms};
use crate::prompt::{ApprovalPrompter, PairingPromptDetails, PromptDetails};
use crate::zellij_proxy::{serve_zellij_proxy_with_listener, ZellijProxyHub};

const RECENT_CANCEL_TTL: Duration = Duration::from_secs(120);
const MAX_RECENT_CANCELS: usize = 256;
const PROMPT_SAFETY_TIMEOUT: Duration = Duration::from_secs(90);

struct InFlightSignRequest {
    generation: u64,
    cancel_tx: watch::Sender<Option<String>>,
    responders: HashMap<u64, mpsc::Sender<ClientStreamMessage>>,
}

enum RegisterRequestOutcome {
    AlreadyCanceled,
    AttachedExisting,
    Registered {
        generation: u64,
        cancel_rx: watch::Receiver<Option<String>>,
    },
}

#[derive(Default)]
struct ActiveSignRequests {
    next_generation: u64,
    in_flight: HashMap<String, InFlightSignRequest>,
    recently_canceled: VecDeque<(String, Instant)>,
}

impl ActiveSignRequests {
    fn prune_expired_cancels(&mut self, now: Instant) {
        while let Some((_, ts)) = self.recently_canceled.front() {
            if now.duration_since(*ts) > RECENT_CANCEL_TTL {
                self.recently_canceled.pop_front();
            } else {
                break;
            }
        }
    }

    fn is_recently_canceled(&mut self, request_id: &str) -> bool {
        let now = Instant::now();
        self.prune_expired_cancels(now);
        self.recently_canceled
            .iter()
            .any(|(id, _)| id == request_id)
    }

    fn cancel_request(&mut self, request_id: &str, reason: String) {
        let now = Instant::now();
        self.prune_expired_cancels(now);
        if !self
            .recently_canceled
            .iter()
            .any(|(id, _)| id == request_id)
        {
            if self.recently_canceled.len() >= MAX_RECENT_CANCELS {
                self.recently_canceled.pop_front();
            }
            self.recently_canceled
                .push_back((request_id.to_string(), now));
        }
        if let Some(entry) = self.in_flight.remove(request_id) {
            let _ = entry.cancel_tx.send(Some(reason));
        }
    }

    fn timeout_request(&mut self, request_id: &str, generation: u64) {
        if self
            .in_flight
            .get(request_id)
            .map(|e| e.generation == generation)
            .unwrap_or(false)
        {
            if let Some(entry) = self.in_flight.remove(request_id) {
                let _ = entry
                    .cancel_tx
                    .send(Some("Approval prompt timed out".to_string()));
            }
        }
    }

    fn register_or_attach(
        &mut self,
        request_id: &str,
        stream_id: u64,
        tx: mpsc::Sender<ClientStreamMessage>,
    ) -> RegisterRequestOutcome {
        if self.is_recently_canceled(request_id) {
            return RegisterRequestOutcome::AlreadyCanceled;
        }
        if let Some(existing) = self.in_flight.get_mut(request_id) {
            existing.responders.insert(stream_id, tx);
            return RegisterRequestOutcome::AttachedExisting;
        }
        self.next_generation = self.next_generation.wrapping_add(1);
        let generation = self.next_generation;
        let (cancel_tx, cancel_rx) = watch::channel(None);
        let mut responders = HashMap::new();
        responders.insert(stream_id, tx);
        self.in_flight.insert(
            request_id.to_string(),
            InFlightSignRequest {
                generation,
                cancel_tx,
                responders,
            },
        );
        RegisterRequestOutcome::Registered {
            generation,
            cancel_rx,
        }
    }

    fn complete_request(
        &mut self,
        request_id: &str,
        generation: u64,
    ) -> Vec<mpsc::Sender<ClientStreamMessage>> {
        if self
            .in_flight
            .get(request_id)
            .map(|e| e.generation == generation)
            .unwrap_or(false)
        {
            if let Some(entry) = self.in_flight.remove(request_id) {
                return entry.responders.into_values().collect();
            }
        }
        Vec::new()
    }

    fn detach_stream(&mut self, stream_id: u64) {
        let mut to_cancel = Vec::new();
        self.in_flight.retain(|_req_id, entry| {
            entry.responders.remove(&stream_id);
            if entry.responders.is_empty() {
                to_cancel.push(entry.cancel_tx.clone());
                false
            } else {
                true
            }
        });
        for cancel_tx in to_cancel {
            let _ = cancel_tx.send(Some("Coordinator stream disconnected".to_string()));
        }
    }
}

pub struct WorkstationManager {
    cfg: ClientConfig,
    grant: Arc<RwLock<NodeGrant>>,
    renew_lock: Arc<Mutex<()>>,
    resolved_operator_url: Arc<RwLock<Option<String>>>,
    local_agent: Arc<LocalAgentConnector>,
    policy: Arc<PolicyEngine>,
    prompter: Arc<dyn ApprovalPrompter>,
    active_requests: Arc<Mutex<ActiveSignRequests>>,
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
        let grant = Arc::new(RwLock::new(cfg.grant.clone()));
        let resolved_operator_url = Arc::new(RwLock::new(cfg.operator_url.clone()));
        Self {
            cfg,
            grant,
            renew_lock: Arc::new(Mutex::new(())),
            resolved_operator_url,
            local_agent,
            policy,
            prompter,
            active_requests: Arc::new(Mutex::new(ActiveSignRequests::default())),
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
    /// `sshcast-server` instances (including dynamic discovery via `_sshcast.<domain>` DNS TXT records)
    /// concurrently until `shutdown_rx` signals true.
    pub async fn run(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let mut zellij_handle = None;
        if self.cfg.zellij_listen_port > 0 {
            let bind_addr = format!("127.0.0.1:{}", self.cfg.zellij_listen_port);
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    let hub = Arc::clone(&self.zellij_hub);
                    let shutdown = shutdown_rx.clone();
                    zellij_handle = Some(tokio::spawn(async move {
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

        let configured_entries = self.cfg.servers.clone();
        let has_dns_entries = configured_entries
            .iter()
            .any(|s| sshcast_proto::dns::is_dns_discovery_entry(s).is_some());

        let discovery = tokio::task::spawn_blocking({
            let entries = configured_entries.clone();
            move || sshcast_proto::dns::resolve_swarm_discovery(&entries)
        })
        .await
        .unwrap_or_default();

        if self.cfg.operator_url.is_none() {
            if let Some(op_url) = discovery.operator_url {
                *self.resolved_operator_url.write().await = Some(op_url);
            }
        }

        let initial_urls = if discovery.servers.is_empty() {
            configured_entries.clone()
        } else {
            discovery.servers
        };

        let _ = sync_cert_if_needed(
            &self.cfg,
            &self.grant,
            &self.renew_lock,
            &self.resolved_operator_url,
            false,
        )
        .await;

        let pairing_handle = self.spawn_pairing_listener(shutdown_rx.clone());

        let mut active_streams: HashMap<String, (watch::Sender<bool>, tokio::task::JoinHandle<()>)> =
            HashMap::new();

        for server_url in initial_urls {
            let (stop_tx, handle) = self.spawn_coordinator_worker(server_url.clone(), shutdown_rx.clone());
            active_streams.insert(server_url, (stop_tx, handle));
        }

        let mut renew_ticker = tokio::time::interval(Duration::from_secs(1800));
        renew_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        renew_ticker.tick().await;

        if has_dns_entries {
            let mut dns_ticker = tokio::time::interval(Duration::from_secs(60));
            dns_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            dns_ticker.tick().await;

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = renew_ticker.tick() => {
                        let _ = sync_cert_if_needed(
                            &self.cfg,
                            &self.grant,
                            &self.renew_lock,
                            &self.resolved_operator_url,
                            false,
                        ).await;
                    }
                    _ = dns_ticker.tick() => {
                        let entries = configured_entries.clone();
                        if let Ok(disc) = tokio::task::spawn_blocking(move || {
                            sshcast_proto::dns::resolve_swarm_discovery(&entries)
                        }).await {
                            if self.cfg.operator_url.is_none() {
                                if let Some(op_url) = disc.operator_url {
                                    *self.resolved_operator_url.write().await = Some(op_url);
                                }
                            }
                            let resolved = disc.servers;
                            if !resolved.is_empty() {
                                for url in &resolved {
                                    if !active_streams.contains_key(url) {
                                        tracing::info!(
                                            "Discovered new coordinator via _sshcast DNS TXT: {}",
                                            url
                                        );
                                        let (stop_tx, handle) = self.spawn_coordinator_worker(
                                            url.clone(),
                                            shutdown_rx.clone(),
                                        );
                                        active_streams.insert(url.clone(), (stop_tx, handle));
                                    }
                                }
                                let to_remove: Vec<String> = active_streams
                                    .keys()
                                    .filter(|k| !resolved.contains(k))
                                    .cloned()
                                    .collect();
                                for old_url in to_remove {
                                    tracing::info!(
                                        "Coordinator removed from _sshcast DNS TXT: {}; disconnecting",
                                        old_url
                                    );
                                    if let Some((stop_tx, _handle)) = active_streams.remove(&old_url) {
                                        let _ = stop_tx.send(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::select! {
                    res = shutdown_rx.changed() => {
                        if res.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    _ = renew_ticker.tick() => {
                        let _ = sync_cert_if_needed(
                            &self.cfg,
                            &self.grant,
                            &self.renew_lock,
                            &self.resolved_operator_url,
                            false,
                        ).await;
                    }
                }
            }
        }

        for (_, (stop_tx, handle)) in active_streams {
            let _ = stop_tx.send(true);
            let _ = handle.await;
        }
        let _ = pairing_handle.await;
        if let Some(zh) = zellij_handle {
            let _ = zh.await;
        }
        Ok(())
    }

    fn spawn_pairing_listener(
        &self,
        shutdown_rx: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let cfg = self.cfg.clone();
        let grant_lock = Arc::clone(&self.grant);
        let resolved_operator_url = Arc::clone(&self.resolved_operator_url);
        let prompter = Arc::clone(&self.prompter);
        tokio::spawn(async move {
            run_pairing_listener(cfg, grant_lock, resolved_operator_url, prompter, shutdown_rx)
                .await;
        })
    }

    fn spawn_coordinator_worker(
        &self,
        url: String,
        mut global_shutdown: watch::Receiver<bool>,
    ) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let cfg = self.cfg.clone();
        let grant_lock = Arc::clone(&self.grant);
        let renew_lock = Arc::clone(&self.renew_lock);
        let resolved_operator_url = Arc::clone(&self.resolved_operator_url);
        let local_agent = Arc::clone(&self.local_agent);
        let policy = Arc::clone(&self.policy);
        let prompter = Arc::clone(&self.prompter);
        let active_requests = Arc::clone(&self.active_requests);
        let force_active_flag = Arc::clone(&self.force_active_flag);
        let connected_count = Arc::clone(&self.connected_count);
        let zellij_hub = Arc::clone(&self.zellij_hub);

        let handle = tokio::spawn(async move {
            let (combined_tx, combined_rx) = watch::channel(false);
            let mut gs_clone = global_shutdown.clone();
            let mut sr_clone = stop_rx.clone();
            let c_tx = combined_tx.clone();
            tokio::spawn(async move {
                loop {
                    if *gs_clone.borrow() || *sr_clone.borrow() {
                        let _ = c_tx.send(true);
                        break;
                    }
                    tokio::select! {
                        res = gs_clone.changed() => {
                            if res.is_err() || *gs_clone.borrow() {
                                let _ = c_tx.send(true);
                                break;
                            }
                        }
                        res = sr_clone.changed() => {
                            if res.is_err() || *sr_clone.borrow() {
                                let _ = c_tx.send(true);
                                break;
                            }
                        }
                    }
                }
            });

            let mut backoff = Duration::from_millis(500);
            let max_backoff = Duration::from_secs(30);

            loop {
                if *global_shutdown.borrow() || *stop_rx.borrow() {
                    break;
                }

                let conn_res = run_single_coordinator_stream(
                    &url,
                    &cfg,
                    &grant_lock,
                    &local_agent,
                    &policy,
                    &prompter,
                    &active_requests,
                    &force_active_flag,
                    &connected_count,
                    &zellij_hub,
                    combined_rx.clone(),
                )
                .await;

                if *global_shutdown.borrow() || *stop_rx.borrow() {
                    break;
                }

                let mut renewed_after_auth_err = false;
                match conn_res {
                    Ok(()) => {
                        backoff = Duration::from_millis(500);
                    }
                    Err(e) => {
                        let is_auth_err = e.chain().any(|cause| {
                            cause
                                .downcast_ref::<tonic::Status>()
                                .map(|st| {
                                    matches!(
                                        st.code(),
                                        tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
                                    )
                                })
                                .unwrap_or(false)
                        });
                        tracing::warn!(
                            "Coordinator stream {} disconnected ({:#}); reconnecting in {:?}",
                            url,
                            e,
                            backoff
                        );
                        if is_auth_err {
                            renewed_after_auth_err = sync_cert_if_needed(
                                &cfg,
                                &grant_lock,
                                &renew_lock,
                                &resolved_operator_url,
                                true,
                            )
                            .await;
                        }
                    }
                }

                if renewed_after_auth_err {
                    backoff = Duration::from_millis(500);
                }

                tokio::select! {
                    _ = global_shutdown.changed() => {
                        if *global_shutdown.borrow() {
                            break;
                        }
                    }
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(max_backoff);
            }
        });

        (stop_tx, handle)
    }
}

async fn resolve_or_cache_operator_url(
    cfg: &ClientConfig,
    resolved_operator_url: &Arc<RwLock<Option<String>>>,
) -> Option<String> {
    if let Some(cached) = resolved_operator_url.read().await.clone() {
        return Some(cached);
    }
    let explicit = cfg.operator_url.clone();
    let servers = cfg.servers.clone();
    let discovered = tokio::task::spawn_blocking(move || {
        resolve_operator_url(explicit.as_deref(), &servers)
    })
    .await
    .ok()
    .flatten();
    if let Some(ref op_url) = discovered {
        *resolved_operator_url.write().await = Some(op_url.clone());
    }
    discovered
}

async fn sleep_or_shutdown(duration: Duration, shutdown_rx: &mut watch::Receiver<bool>) -> bool {
    if *shutdown_rx.borrow() {
        return true;
    }
    tokio::select! {
        res = shutdown_rx.changed() => res.is_err() || *shutdown_rx.borrow(),
        _ = tokio::time::sleep(duration) => false,
    }
}

fn find_matching_local_user_key(cfg: &ClientConfig) -> Option<(Option<PathBuf>, [u8; 32])> {
    let candidate_path = cfg
        .config_path
        .as_ref()
        .and_then(|cp| cp.parent())
        .map(|parent| parent.join("user_key.toml"))
        .filter(|p| p.exists());

    let (_, key_file) = UserKeyFile::load(candidate_path.as_deref()).ok()?;
    let user_pk = parse_user_pubkey_token(&key_file.user_pubkey_token).ok()?;
    if user_pk.as_slice() != cfg.grant.user_pubkey.as_slice() {
        return None;
    }
    Some((candidate_path, user_pk))
}

fn decode_b64_32(raw: &str, label: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    let bytes = STANDARD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .with_context(|| format!("invalid base64 in {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must decode to 32 bytes"))
}

const PAIRING_POLL_TIMEOUT_SECS: u64 = 25;
const PAIRING_RECHECK_INTERVAL: Duration = Duration::from_secs(30);
const PAIRING_MONITOR_INTERVAL: Duration = Duration::from_secs(3);
const PAIRING_SEEN_TTL: Duration = Duration::from_secs(600);

async fn run_pairing_listener(
    cfg: ClientConfig,
    grant_lock: Arc<RwLock<NodeGrant>>,
    resolved_operator_url: Arc<RwLock<Option<String>>>,
    prompter: Arc<dyn ApprovalPrompter>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_secs(2);
    let max_backoff = Duration::from_secs(30);
    let mut recently_handled: HashMap<String, Instant> = HashMap::new();

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let cfg_for_key = cfg.clone();
        let matching_key =
            tokio::task::spawn_blocking(move || find_matching_local_user_key(&cfg_for_key))
                .await
                .ok()
                .flatten();

        let Some((local_key_path, user_pk_arr)) = matching_key else {
            if sleep_or_shutdown(PAIRING_RECHECK_INTERVAL, &mut shutdown_rx).await {
                break;
            }
            continue;
        };

        let Some(op_url) = resolve_or_cache_operator_url(&cfg, &resolved_operator_url).await else {
            if sleep_or_shutdown(PAIRING_RECHECK_INTERVAL, &mut shutdown_rx).await {
                break;
            }
            continue;
        };

        if *shutdown_rx.borrow() {
            break;
        }

        let current_grant = grant_lock.read().await.clone();
        let poll_started = Instant::now();
        let poll_res = tokio::select! {
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
            res = poll_pending_pairing_requests_http(
                &op_url,
                &current_grant,
                &cfg.node_signing_key,
                PAIRING_POLL_TIMEOUT_SECS,
            ) => res,
        };

        let requests = match poll_res {
            Ok(reqs) => {
                backoff = Duration::from_secs(2);
                reqs
            }
            Err(e) => {
                tracing::debug!("Pairing poll transient error from {}: {:#}", op_url, e);
                if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                    break;
                }
                backoff = (backoff * 2).min(max_backoff);
                continue;
            }
        };

        let now = Instant::now();
        recently_handled.retain(|_, ts| now.duration_since(*ts) < PAIRING_SEEN_TTL);

        let mut handled_any = false;
        for req in requests {
            if *shutdown_rx.borrow() {
                break;
            }
            if recently_handled.contains_key(&req.pairing_id) {
                continue;
            }
            recently_handled.insert(req.pairing_id.clone(), Instant::now());
            handled_any = true;

            let req_node_pk = match decode_b64_32(&req.node_pubkey_b64, "node_pubkey_b64") {
                Ok(pk) => {
                    if let Err(e) = VerifyingKey::from_bytes(&pk) {
                        tracing::warn!(
                            "Ignoring pairing request {} with invalid Ed25519 node_pubkey_b64: {}",
                            req.pairing_id,
                            e
                        );
                        continue;
                    }
                    pk
                }
                Err(e) => {
                    tracing::warn!(
                        "Ignoring pairing request {} with invalid node_pubkey_b64: {:#}",
                        req.pairing_id,
                        e
                    );
                    continue;
                }
            };
            let req_eph_pk = match decode_b64_32(&req.eph_x25519_pub_b64, "eph_x25519_pub_b64") {
                Ok(pk) => pk,
                Err(e) => {
                    tracing::warn!(
                        "Ignoring pairing request {} with invalid eph_x25519_pub_b64: {:#}",
                        req.pairing_id,
                        e
                    );
                    continue;
                }
            };

            let sas_code = compute_pairing_sas_code(&user_pk_arr, &req_eph_pk);
            let existing_user_id = if !current_grant.user_id.is_empty() {
                current_grant.user_id.clone()
            } else {
                derive_user_id(&user_pk_arr)
            };
            let details = PairingPromptDetails {
                pairing_id: req.pairing_id.clone(),
                node_name: req.node_name.clone(),
                os_name: req.os_name.clone(),
                github_login: req.github_login.clone(),
                sas_code,
                existing_user_id,
            };

            let (cancel_tx, cancel_rx) = watch::channel(None);
            let monitor_handle = tokio::spawn({
                let monitor_op_url = op_url.clone();
                let monitor_grant = Arc::clone(&grant_lock);
                let monitor_node_sk = cfg.node_signing_key.clone();
                let monitor_pairing_id = req.pairing_id.clone();
                let monitor_cancel_tx = cancel_tx.clone();
                let mut monitor_shutdown = shutdown_rx.clone();
                async move {
                    if *monitor_shutdown.borrow() {
                        let _ = monitor_cancel_tx
                            .send(Some("Workstation manager shutting down".to_string()));
                        return;
                    }
                    let mut ticker = tokio::time::interval(PAIRING_MONITOR_INTERVAL);
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    ticker.tick().await;
                    loop {
                        tokio::select! {
                            res = monitor_shutdown.changed() => {
                                if res.is_err() || *monitor_shutdown.borrow() {
                                    let _ = monitor_cancel_tx.send(Some(
                                        "Workstation manager shutting down".to_string(),
                                    ));
                                    break;
                                }
                            }
                            _ = ticker.tick() => {
                                let g = monitor_grant.read().await.clone();
                                if let Ok(pending) = poll_pending_pairing_requests_http(
                                    &monitor_op_url,
                                    &g,
                                    &monitor_node_sk,
                                    0,
                                )
                                .await
                                {
                                    if !pending.iter().any(|p| p.pairing_id == monitor_pairing_id) {
                                        let _ = monitor_cancel_tx
                                            .send(Some("Handled or canceled".to_string()));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            });

            let approved = prompter.prompt_pairing(details, cancel_rx.clone()).await;
            monitor_handle.abort();

            if *shutdown_rx.borrow() {
                break;
            }
            if cancel_rx.borrow().is_some() {
                tracing::info!(
                    "Pairing prompt for {} ({}) dismissed before response",
                    req.node_name,
                    req.pairing_id
                );
                continue;
            }

            if approved {
                let kp_for_load = local_key_path.clone();
                let user_sk = match tokio::task::spawn_blocking(move || {
                    load_user_signing_key(kp_for_load.as_deref())
                })
                .await
                {
                    Ok(Ok(sk)) => sk,
                    Ok(Err(e)) => {
                        tracing::warn!(
                            "Failed to load user root key while approving pairing {}: {:#}",
                            req.pairing_id,
                            e
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "User key load task panicked while approving pairing {}: {}",
                            req.pairing_id,
                            e
                        );
                        continue;
                    }
                };
                if user_sk.verifying_key().to_bytes() != user_pk_arr {
                    tracing::warn!(
                        "Refusing pairing approval for {}: local user_key.toml changed and no longer matches workstation user_pubkey",
                        req.pairing_id
                    );
                    continue;
                }

                let latest_grant = grant_lock.read().await.clone();
                match create_encrypted_pairing_handoff(
                    &user_sk,
                    latest_grant.user_cert.clone(),
                    &req.pairing_id,
                    &req.node_name,
                    &req_node_pk,
                    &req_eph_pk,
                    cfg.servers.clone(),
                    Some(op_url.clone()),
                ) {
                    Ok(envelope) => {
                        if let Err(e) = respond_to_pairing_request_http(
                            &op_url,
                            &latest_grant,
                            &cfg.node_signing_key,
                            &req.pairing_id,
                            true,
                            Some(&envelope),
                        )
                        .await
                        {
                            tracing::warn!(
                                "Failed to submit pairing approval for {}: {:#}",
                                req.pairing_id,
                                e
                            );
                        } else {
                            tracing::info!(
                                "Approved pairing request {} for workstation '{}'",
                                req.pairing_id,
                                req.node_name
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to build encrypted pairing handoff for {}: {:#}",
                            req.pairing_id,
                            e
                        );
                    }
                }
            } else {
                let latest_grant = grant_lock.read().await.clone();
                if let Err(e) = respond_to_pairing_request_http(
                    &op_url,
                    &latest_grant,
                    &cfg.node_signing_key,
                    &req.pairing_id,
                    false,
                    None,
                )
                .await
                {
                    tracing::warn!(
                        "Failed to submit pairing denial for {}: {:#}",
                        req.pairing_id,
                        e
                    );
                } else {
                    tracing::info!(
                        "Denied pairing request {} for workstation '{}'",
                        req.pairing_id,
                        req.node_name
                    );
                }
            }
        }

        if !handled_any && poll_started.elapsed() < Duration::from_millis(500) {
            if sleep_or_shutdown(Duration::from_millis(500), &mut shutdown_rx).await {
                break;
            }
        }
    }
}

async fn sync_cert_if_needed(
    cfg: &ClientConfig,
    grant_lock: &Arc<RwLock<NodeGrant>>,
    renew_lock: &Arc<Mutex<()>>,
    resolved_operator_url: &Arc<RwLock<Option<String>>>,
    force: bool,
) -> bool {
    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    {
        let grant_guard = grant_lock.read().await;
        if !force && !cert_needs_renewal(grant_guard.user_cert.as_ref(), now_sec) {
            return false;
        }
    }

    let _guard = renew_lock.lock().await;
    let current_grant = {
        let grant_guard = grant_lock.read().await;
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !force && !cert_needs_renewal(grant_guard.user_cert.as_ref(), now_sec) {
            return false;
        }
        grant_guard.clone()
    };

    let Some(op_url) = resolve_or_cache_operator_url(cfg, resolved_operator_url).await else {
        return false;
    };

    if current_grant.user_cert.is_none() && !force {
        return false;
    }

    match renew_user_cert_http(&op_url, &current_grant, &cfg.node_signing_key).await {
        Ok(new_cert) => {
            tracing::info!(
                "Renewed operator UserCert from {} (expires_at={})",
                op_url,
                new_cert.expires_at_unix_sec
            );
            grant_lock.write().await.user_cert = Some(new_cert.clone());
            if let Some(ref cfg_path) = cfg.config_path {
                let cp = cfg_path.clone();
                let cert_clone = new_cert;
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = crate::enroll::persist_user_cert(&cert_clone, None, Some(&cp));
                })
                .await;
            }
            true
        }
        Err(e) => {
            tracing::warn!("Failed to renew UserCert from {}: {:#}", op_url, e);
            false
        }
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
    grant_lock: &Arc<RwLock<NodeGrant>>,
    local_agent: &Arc<LocalAgentConnector>,
    policy: &Arc<PolicyEngine>,
    prompter: &Arc<dyn ApprovalPrompter>,
    active_requests: &Arc<Mutex<ActiveSignRequests>>,
    force_active_flag: &Arc<AtomicBool>,
    connected_count: &Arc<AtomicUsize>,
    zellij_hub: &Arc<ZellijProxyHub>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut endpoint = Endpoint::new(server_url.to_string())
        .with_context(|| format!("invalid coordinator URL {server_url}"))?
        .connect_timeout(Duration::from_secs(5))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Duration::from_secs(25))
        .keep_alive_timeout(Duration::from_secs(10));

    if server_url.trim().starts_with("https://") {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_enabled_roots())
            .with_context(|| format!("failed to configure TLS roots for {server_url}"))?;
    }

    let channel = endpoint.connect().await?;
    let mut client = SshcastServiceClient::new(channel);

    let (tx, rx) = mpsc::channel::<ClientStreamMessage>(1024);
    let sender_reg_id = zellij_hub.register_coordinator_sender(tx.clone()).await;
    struct SenderRegGuard {
        hub: Arc<ZellijProxyHub>,
        active_requests: Arc<Mutex<ActiveSignRequests>>,
        id: u64,
    }
    impl Drop for SenderRegGuard {
        fn drop(&mut self) {
            let hub = Arc::clone(&self.hub);
            let active_requests = Arc::clone(&self.active_requests);
            let id = self.id;
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    hub.unregister_coordinator_sender(id).await;
                    active_requests.lock().await.detach_stream(id);
                });
            }
        }
    }
    let _sender_guard = SenderRegGuard {
        hub: Arc::clone(zellij_hub),
        active_requests: Arc::clone(active_requests),
        id: sender_reg_id,
    };

    // 1. First message on ConnectWorkstation stream MUST be AuthHandshake
    let current_grant = grant_lock.read().await.clone();
    let handshake = create_node_auth(current_grant.clone(), &cfg.node_signing_key, now_unix_ms())?;
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
        current_grant.node_id,
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
                        active_requests
                            .lock()
                            .await
                            .cancel_request(&cancel.request_id, cancel.reason);
                    }
                    Some(ServerPayload::SignRequest(sign_req)) => {
                        let req_id = sign_req.request_id.clone();

                        if let Ok(local_keys) = local_agent.list_filtered_keys().await {
                            if !local_keys.iter().any(|k| k.key_blob == sign_req.key_blob) {
                                tracing::info!(
                                    "Ignoring SignRequest {} because requested key is not loaded on this workstation",
                                    req_id
                                );
                                continue;
                            }
                        }

                        let reg_outcome = active_requests
                            .lock()
                            .await
                            .register_or_attach(&req_id, sender_reg_id, tx.clone());

                        let (generation, cancel_rx) = match reg_outcome {
                            RegisterRequestOutcome::AlreadyCanceled => {
                                tracing::info!(
                                    "Ignoring SignRequest {} because it was already canceled",
                                    req_id
                                );
                                continue;
                            }
                            RegisterRequestOutcome::AttachedExisting => {
                                // Two-Phase Delivery Step 1: Reply with SignAck (<1.5s) without spawning a duplicate prompt
                                if tx.send(ClientStreamMessage {
                                    payload: Some(ClientPayload::SignAck(SignAck {
                                        request_id: req_id.clone(),
                                    })),
                                }).await.is_err() {
                                    anyhow::bail!("outbound stream closed while sending SignAck");
                                }
                                tracing::info!(
                                    "SignRequest {} is already prompting on this workstation; attached stream",
                                    req_id
                                );
                                continue;
                            }
                            RegisterRequestOutcome::Registered {
                                generation,
                                cancel_rx,
                            } => (generation, cancel_rx),
                        };

                        // Two-Phase Delivery Step 1: Immediately reply with SignAck (<1.5s)
                        if tx.send(ClientStreamMessage {
                            payload: Some(ClientPayload::SignAck(SignAck {
                                request_id: req_id.clone(),
                            })),
                        }).await.is_err() {
                            active_requests
                                .lock()
                                .await
                                .complete_request(&req_id, generation);
                            anyhow::bail!("outbound stream closed while sending SignAck");
                        }

                        // Spawn async task to verify end-to-end signature, evaluate policy/prompt, and sign
                        let cfg_clone = cfg.clone();
                        let agent_clone = Arc::clone(local_agent);
                        let policy_clone = Arc::clone(policy);
                        let prompter_clone = Arc::clone(prompter);
                        let active_clone = Arc::clone(active_requests);

                        tokio::spawn(async move {
                            let timeout_active = Arc::clone(&active_clone);
                            let timeout_req_id = req_id.clone();
                            let timeout_handle = tokio::spawn(async move {
                                tokio::time::sleep(PROMPT_SAFETY_TIMEOUT).await;
                                tracing::info!(
                                    "Auto-dismissing unanswered SignRequest {} after {:?}",
                                    timeout_req_id,
                                    PROMPT_SAFETY_TIMEOUT
                                );
                                timeout_active
                                    .lock()
                                    .await
                                    .timeout_request(&timeout_req_id, generation);
                            });

                            let sign_resp = handle_incoming_sign_request(
                                sign_req,
                                &cfg_clone,
                                &agent_clone,
                                &policy_clone,
                                &prompter_clone,
                                cancel_rx.clone(),
                            )
                            .await;

                            timeout_handle.abort();

                            let responders = active_clone
                                .lock()
                                .await
                                .complete_request(&req_id, generation);

                            if cancel_rx.borrow().is_none() {
                                for resp_tx in responders {
                                    let _ = resp_tx
                                        .send(ClientStreamMessage {
                                            payload: Some(ClientPayload::SignResponse(
                                                sign_resp.clone(),
                                            )),
                                        })
                                        .await;
                                }
                            }
                        });
                    }
                    Some(ServerPayload::ZellijHostList(list)) => {
                        zellij_hub.update_host_list(list).await;
                    }
                    Some(ServerPayload::ZellijFrame(z_frame)) => {
                        zellij_hub.handle_incoming_frame(z_frame).await;
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
    let last_input_epoch_ms = match tokio::time::timeout(
        Duration::from_millis(800),
        tokio::task::spawn_blocking(query_last_input_epoch_ms),
    )
    .await
    {
        Ok(Ok(ts)) => ts,
        _ => now_unix_ms(),
    };
    WorkstationStatus {
        last_input_epoch_ms,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_active_sign_requests_dedup_escalation_and_cancel() {
        let mut active = ActiveSignRequests::default();
        let (tx1, _rx1) = mpsc::channel(4);
        let (tx2, _rx2) = mpsc::channel(4);

        let (gen1, mut cancel_rx) = match active.register_or_attach("req-1", 10, tx1) {
            RegisterRequestOutcome::Registered {
                generation,
                cancel_rx,
            } => (generation, cancel_rx),
            _ => panic!("expected initial registration"),
        };

        // Re-delivery (broadcast escalation or second coordinator) attaches without dropping cancel_tx
        assert!(matches!(
            active.register_or_attach("req-1", 20, tx2),
            RegisterRequestOutcome::AttachedExisting
        ));
        assert!(cancel_rx.borrow().is_none());

        // Canceling after approval on another client immediately notifies the open prompt
        active.cancel_request("req-1", "Handled by another workstation".to_string());
        cancel_rx.changed().await.unwrap();
        assert_eq!(
            cancel_rx.borrow().as_deref(),
            Some("Handled by another workstation")
        );
        assert!(active.complete_request("req-1", gen1).is_empty());

        // Late SignRequest arriving after CancelSignRequest is suppressed
        let (tx3, _rx3) = mpsc::channel(4);
        assert!(matches!(
            active.register_or_attach("req-1", 30, tx3),
            RegisterRequestOutcome::AlreadyCanceled
        ));
    }

    #[tokio::test]
    async fn test_active_sign_requests_stream_disconnect_cancels_only_when_orphaned() {
        let mut active = ActiveSignRequests::default();
        let (tx1, _rx1) = mpsc::channel(4);
        let (tx2, _rx2) = mpsc::channel(4);

        let mut cancel_rx = match active.register_or_attach("req-2", 1, tx1) {
            RegisterRequestOutcome::Registered { cancel_rx, .. } => cancel_rx,
            _ => panic!("expected registration"),
        };
        assert!(matches!(
            active.register_or_attach("req-2", 2, tx2),
            RegisterRequestOutcome::AttachedExisting
        ));

        // Disconnecting stream 1 leaves stream 2 attached; prompt stays open
        active.detach_stream(1);
        assert!(cancel_rx.borrow().is_none());

        // Disconnecting stream 2 orphans the request; prompt is automatically canceled
        active.detach_stream(2);
        cancel_rx.changed().await.unwrap();
        assert_eq!(
            cancel_rx.borrow().as_deref(),
            Some("Coordinator stream disconnected")
        );
    }
}
