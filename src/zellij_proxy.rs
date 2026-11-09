use anyhow::{Context, Result};
use sockcast_proto::crypto::{sign_zellij_tunnel_frame, verify_zellij_tunnel_frame};
use sockcast_proto::p2p::{
    build_stun_binding_request, derive_p2p_session_keys, parse_stun_binding_response,
    P2pEndpointHandshake, P2pStreamCipher,
};
use sockcast_proto::v1::client_stream_message::Payload as ClientPayload;
use sockcast_proto::v1::{
    ClientStreamMessage, NodeRole, RelayZellijStatus, ZellijFrameType, ZellijHostList,
    ZellijTunnelFrame,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch, Mutex, RwLock};

use crate::config::ClientConfig;

#[derive(Debug, Clone)]
pub struct DirectP2pPeer {
    pub addr: SocketAddr,
    pub client_auth_token: [u8; 32],
    pub relay_auth_token: [u8; 32],
    pub cipher_key: [u8; 32],
}

fn now_unix_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn short_host_label(s: &str) -> &str {
    let trimmed = s.trim();
    match trimmed.find('.') {
        Some(idx) if idx > 0 => &trimmed[..idx],
        _ => trimmed,
    }
}

/// If `host_header` is `<target>.localhost` or `<target>.localhost:<port>`, returns `Some(<target>)`.
/// Returns `None` for bare `localhost` or `127.0.0.1`.
pub fn extract_relay_target_from_host_header(host_header: &str) -> Option<String> {
    let host_only = host_header
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let target = host_only.strip_suffix(".localhost")?;
    if target.is_empty() {
        return None;
    }
    Some(target.to_string())
}

/// Parses `(method, path, host_header)` from an HTTP/1.1 request buffer.
pub fn parse_http_host_and_path(buf: &[u8]) -> Option<(String, String, String)> {
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_str = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next()?;
    let mut req_parts = req_line.split_whitespace();
    let method = req_parts.next()?.to_string();
    let path = req_parts.next()?.to_string();

    let mut host = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                host = v.trim().to_string();
                break;
            }
        }
    }
    Some((method, path, host))
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub struct ZellijProxyHub {
    cfg: ClientConfig,
    hosts: RwLock<Vec<RelayZellijStatus>>,
    senders: Mutex<Vec<(u64, mpsc::Sender<ClientStreamMessage>)>>,
    active_tunnels: Mutex<HashMap<String, mpsc::Sender<ZellijTunnelFrame>>>,
    pending_p2p: Mutex<HashMap<String, oneshot::Sender<ZellijTunnelFrame>>>,
    direct_peers: RwLock<HashMap<String, DirectP2pPeer>>,
    p2p_in_flight: Mutex<HashSet<String>>,
    next_id: AtomicU64,
}

impl ZellijProxyHub {
    pub fn new(cfg: ClientConfig) -> Self {
        Self {
            cfg,
            hosts: RwLock::new(Vec::new()),
            senders: Mutex::new(Vec::new()),
            active_tunnels: Mutex::new(HashMap::new()),
            pending_p2p: Mutex::new(HashMap::new()),
            direct_peers: RwLock::new(HashMap::new()),
            p2p_in_flight: Mutex::new(HashSet::new()),
            next_id: AtomicU64::new(1),
        }
    }

    fn next_tunnel_id(&self, prefix: &str) -> String {
        let seq = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}-{}", prefix, self.cfg.grant.node_id, seq)
    }

    pub async fn register_coordinator_sender(&self, tx: mpsc::Sender<ClientStreamMessage>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.senders.lock().await;
        guard.retain(|(_, s)| !s.is_closed());
        guard.push((id, tx));
        id
    }

    pub async fn unregister_coordinator_sender(&self, id: u64) {
        let mut guard = self.senders.lock().await;
        guard.retain(|(entry_id, s)| *entry_id != id && !s.is_closed());
    }

    async fn send_to_coordinator(&self, msg: ClientStreamMessage) -> Result<()> {
        let candidates: Vec<mpsc::Sender<ClientStreamMessage>> = {
            let mut guard = self.senders.lock().await;
            guard.retain(|(_, s)| !s.is_closed());
            guard.iter().rev().map(|(_, s)| s.clone()).collect()
        };
        for tx in candidates {
            if tokio::time::timeout(Duration::from_secs(2), tx.send(msg.clone()))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        anyhow::bail!("no connected coordinator stream available")
    }

    pub async fn update_host_list(&self, list: ZellijHostList) {
        let mut guard = self.hosts.write().await;
        *guard = list.hosts;
    }

    pub async fn list_hosts(&self) -> Vec<RelayZellijStatus> {
        self.hosts.read().await.clone()
    }

    pub async fn resolve_relay_node_id(&self, target: &str) -> String {
        let target_lower = target.trim().to_ascii_lowercase();
        let target_short = short_host_label(&target_lower);
        let guard = self.hosts.read().await;
        for h in guard.iter() {
            if h.node_id.eq_ignore_ascii_case(&target_lower) {
                return h.node_id.clone();
            }
        }
        for h in guard.iter() {
            if short_host_label(&h.node_id).eq_ignore_ascii_case(target_short) {
                return h.node_id.clone();
            }
        }
        target.trim().to_string()
    }

    pub async fn handle_incoming_frame(&self, frame: ZellijTunnelFrame) {
        match ZellijFrameType::try_from(frame.frame_type).unwrap_or(ZellijFrameType::Unspecified) {
            ZellijFrameType::P2pAnswer => {
                if let Some(tx) = self.pending_p2p.lock().await.remove(&frame.tunnel_id) {
                    let _ = tx.send(frame);
                }
            }
            ZellijFrameType::Data | ZellijFrameType::Close => {
                let is_close = frame.frame_type == ZellijFrameType::Close as i32;
                let tx_opt = if is_close {
                    self.active_tunnels.lock().await.remove(&frame.tunnel_id)
                } else {
                    self.active_tunnels.lock().await.get(&frame.tunnel_id).cloned()
                };
                if let Some(tx) = tx_opt {
                    let _ = tx.send(frame).await;
                }
            }
            _ => {}
        }
    }

    async fn maybe_spawn_p2p_negotiation(self: &Arc<Self>, relay_node_id: String) {
        if self.direct_peers.read().await.contains_key(&relay_node_id) {
            return;
        }
        {
            let mut in_flight = self.p2p_in_flight.lock().await;
            if !in_flight.insert(relay_node_id.clone()) {
                return;
            }
        }
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            let res = hub.negotiate_direct_p2p(&relay_node_id).await;
            if let Err(e) = res {
                tracing::debug!(
                    "Direct P2P negotiation with {} did not establish direct path ({}); using coordinator stream",
                    relay_node_id,
                    e
                );
            }
            hub.p2p_in_flight.lock().await.remove(&relay_node_id);
        });
    }

    async fn negotiate_direct_p2p(&self, relay_node_id: &str) -> Result<()> {
        let mut udp_candidates = Vec::new();
        let udp_sock = UdpSocket::bind("0.0.0.0:0").await?;

        let (stun_req, tx_id) = build_stun_binding_request();
        for srv in &self.cfg.stun_servers {
            if tokio::time::timeout(
                Duration::from_millis(250),
                udp_sock.send_to(&stun_req, srv.as_str()),
            )
            .await
            .is_ok()
            {
                let mut buf = [0u8; 512];
                if let Ok(Ok((n, _))) =
                    tokio::time::timeout(Duration::from_millis(350), udp_sock.recv_from(&mut buf))
                        .await
                {
                    if let Some(mapped) = parse_stun_binding_response(&buf[..n], &tx_id) {
                        udp_candidates.push(mapped.to_string());
                        break;
                    }
                }
            }
        }

        let offer = P2pEndpointHandshake::new(Vec::new(), udp_candidates);
        let tunnel_id = self.next_tunnel_id("p2p");
        let mut offer_frame = ZellijTunnelFrame {
            tunnel_id: tunnel_id.clone(),
            relay_node_id: relay_node_id.to_string(),
            client_node_id: self.cfg.grant.node_id.clone(),
            frame_type: ZellijFrameType::P2pOffer as i32,
            payload: offer.to_bytes(),
            error_message: String::new(),
            sender_grant: Some(self.cfg.grant.clone()),
            sender_signature: Vec::new(),
        };
        sign_zellij_tunnel_frame(&mut offer_frame, &self.cfg.node_signing_key)?;
        let offer_sig = offer_frame.sender_signature.clone();

        let (ans_tx, ans_rx) = oneshot::channel();
        self.pending_p2p.lock().await.insert(tunnel_id.clone(), ans_tx);

        if let Err(e) = self
            .send_to_coordinator(ClientStreamMessage {
                payload: Some(ClientPayload::ZellijFrame(offer_frame)),
            })
            .await
        {
            self.pending_p2p.lock().await.remove(&tunnel_id);
            return Err(e);
        }

        let answer_frame = match tokio::time::timeout(Duration::from_secs(3), ans_rx).await {
            Ok(Ok(f)) => f,
            _ => {
                self.pending_p2p.lock().await.remove(&tunnel_id);
                anyhow::bail!("timed out waiting for P2P_ANSWER");
            }
        };

        verify_zellij_tunnel_frame(
            &answer_frame,
            NodeRole::Relay,
            &self.cfg.grant.user_pubkey,
            now_unix_sec(),
        )
        .context("P2P_ANSWER signature verification failed")?;

        let answer = P2pEndpointHandshake::from_bytes(&answer_frame.payload)
            .context("invalid P2P_ANSWER payload")?;

        for remote_udp in &answer.udp_candidates {
            if let Ok(addr) = remote_udp.parse::<SocketAddr>() {
                let _ = udp_sock.send_to(b"SC_P2P_PUNCH", addr).await;
            }
        }

        let (client_auth_token, relay_auth_token, cipher_key) = derive_p2p_session_keys(
            &tunnel_id,
            &offer,
            &offer_sig,
            &answer,
            &answer_frame.sender_signature,
        );

        for cand in &answer.tcp_candidates {
            let Ok(addr) = cand.parse::<SocketAddr>() else {
                continue;
            };
            let Ok(Ok(mut probe_stream)) =
                tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr)).await
            else {
                continue;
            };

            let mut c2r_cipher = P2pStreamCipher::new(cipher_key, b"c2r");
            let mut r2c_cipher = P2pStreamCipher::new(cipher_key, b"r2c");
            let mut auth_out = client_auth_token;
            c2r_cipher.apply_keystream(&mut auth_out);
            if probe_stream.write_all(&auth_out).await.is_err() {
                continue;
            }
            let mut auth_in = [0u8; 32];
            let Ok(Ok(_)) =
                tokio::time::timeout(Duration::from_millis(600), probe_stream.read_exact(&mut auth_in))
                    .await
            else {
                continue;
            };
            r2c_cipher.apply_keystream(&mut auth_in);
            if auth_in != relay_auth_token {
                continue;
            }
            let _ = probe_stream.shutdown().await;

            let canonical_id = answer_frame.relay_node_id.clone();
            let peer = DirectP2pPeer {
                addr,
                client_auth_token,
                relay_auth_token,
                cipher_key,
            };
            tracing::info!(
                "Established direct STUN/P2P channel to relay '{}' at {}",
                canonical_id,
                addr
            );
            let mut guard = self.direct_peers.write().await;
            guard.insert(canonical_id.clone(), peer.clone());
            guard.insert(relay_node_id.to_string(), peer);
            return Ok(());
        }

        anyhow::bail!("no TCP candidate reachable")
    }

    async fn try_proxy_via_direct_p2p(
        &self,
        peer: &DirectP2pPeer,
        initial_req_bytes: &[u8],
        browser_stream: &mut TcpStream,
    ) -> Result<()> {
        let mut p2p_stream =
            tokio::time::timeout(Duration::from_millis(600), TcpStream::connect(peer.addr))
                .await
                .context("direct P2P connect timeout")??;

        let mut c2r_cipher = P2pStreamCipher::new(peer.cipher_key, b"c2r");
        let mut r2c_cipher = P2pStreamCipher::new(peer.cipher_key, b"r2c");

        let mut auth_out = peer.client_auth_token;
        c2r_cipher.apply_keystream(&mut auth_out);
        p2p_stream.write_all(&auth_out).await?;

        let mut auth_in = [0u8; 32];
        tokio::time::timeout(Duration::from_secs(2), p2p_stream.read_exact(&mut auth_in))
            .await
            .context("direct P2P auth reply timeout")??;
        r2c_cipher.apply_keystream(&mut auth_in);
        if auth_in != peer.relay_auth_token {
            anyhow::bail!("direct P2P relay auth token mismatch");
        }

        if !initial_req_bytes.is_empty() {
            let mut enc = initial_req_bytes.to_vec();
            c2r_cipher.apply_keystream(&mut enc);
            p2p_stream.write_all(&enc).await?;
        }

        let (mut b_rd, mut b_wr) = browser_stream.split();
        let (mut p_rd, mut p_wr) = p2p_stream.split();

        let c2r = async {
            let mut buf = vec![0u8; 16384];
            loop {
                let n = match b_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let chunk = &mut buf[..n];
                c2r_cipher.apply_keystream(chunk);
                if p_wr.write_all(chunk).await.is_err() {
                    break;
                }
            }
            let _ = p_wr.shutdown().await;
        };

        let r2c = async {
            let mut buf = vec![0u8; 16384];
            loop {
                let n = match p_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let chunk = &mut buf[..n];
                r2c_cipher.apply_keystream(chunk);
                if b_wr.write_all(chunk).await.is_err() {
                    break;
                }
            }
            let _ = b_wr.shutdown().await;
        };

        tokio::pin!(c2r);
        tokio::pin!(r2c);
        tokio::select! {
            _ = &mut r2c => {
                let _ = tokio::time::timeout(Duration::from_millis(150), &mut c2r).await;
            }
            _ = &mut c2r => {
                r2c.await;
            }
        }
        Ok(())
    }

    async fn proxy_via_coordinator_tunnel(
        self: &Arc<Self>,
        relay_node_id: &str,
        initial_req_bytes: Vec<u8>,
        mut browser_stream: TcpStream,
    ) -> Result<()> {
        let tunnel_id = self.next_tunnel_id("zjt");
        let (in_tx, mut in_rx) = mpsc::channel::<ZellijTunnelFrame>(1024);
        self.active_tunnels
            .lock()
            .await
            .insert(tunnel_id.clone(), in_tx);

        let mut open_frame = ZellijTunnelFrame {
            tunnel_id: tunnel_id.clone(),
            relay_node_id: relay_node_id.to_string(),
            client_node_id: self.cfg.grant.node_id.clone(),
            frame_type: ZellijFrameType::Open as i32,
            payload: initial_req_bytes,
            error_message: String::new(),
            sender_grant: Some(self.cfg.grant.clone()),
            sender_signature: Vec::new(),
        };
        sign_zellij_tunnel_frame(&mut open_frame, &self.cfg.node_signing_key)?;

        if let Err(e) = self
            .send_to_coordinator(ClientStreamMessage {
                payload: Some(ClientPayload::ZellijFrame(open_frame)),
            })
            .await
        {
            self.active_tunnels.lock().await.remove(&tunnel_id);
            let body = format!("Sockcast coordinator offline: {e}");
            let resp = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = browser_stream.write_all(resp.as_bytes()).await;
            return Err(e);
        }

        let (mut b_rd, mut b_wr) = browser_stream.into_split();
        let hub_for_write = Arc::clone(self);
        let tunnel_id_wr = tunnel_id.clone();
        let relay_id_wr = relay_node_id.to_string();
        let client_id_wr = self.cfg.grant.node_id.clone();

        let mut b2r_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            loop {
                match b_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data_frame = ZellijTunnelFrame {
                            tunnel_id: tunnel_id_wr.clone(),
                            relay_node_id: relay_id_wr.clone(),
                            client_node_id: client_id_wr.clone(),
                            frame_type: ZellijFrameType::Data as i32,
                            payload: buf[..n].to_vec(),
                            error_message: String::new(),
                            sender_grant: None,
                            sender_signature: Vec::new(),
                        };
                        if hub_for_write
                            .send_to_coordinator(ClientStreamMessage {
                                payload: Some(ClientPayload::ZellijFrame(data_frame)),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });

        let mut received_any_data = false;
        let mut closed_by_relay = false;
        while let Some(frame) = in_rx.recv().await {
            if frame.frame_type == ZellijFrameType::Close as i32 {
                closed_by_relay = true;
                if !received_any_data && !frame.error_message.is_empty() {
                    let body = format!(
                        "<!doctype html><html><body style=\"font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:2rem;\"><h2>Zellij Web Tunnel Error</h2><p>{}</p><p><a href=\"http://localhost:{}/\" style=\"color:#38bdf8;\">&larr; Back to Sockcast Zellij Dashboard</a></p></body></html>",
                        html_escape(&frame.error_message),
                        self.cfg.zellij_listen_port
                    );
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = b_wr.write_all(resp.as_bytes()).await;
                }
                break;
            }
            if !frame.payload.is_empty() {
                received_any_data = true;
                if b_wr.write_all(&frame.payload).await.is_err() {
                    break;
                }
            }
        }

        let _ = b_wr.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_millis(150), &mut b2r_task).await;
        b2r_task.abort();
        self.active_tunnels.lock().await.remove(&tunnel_id);
        if !closed_by_relay {
            let close_frame = ZellijTunnelFrame {
                tunnel_id,
                relay_node_id: relay_node_id.to_string(),
                client_node_id: self.cfg.grant.node_id.clone(),
                frame_type: ZellijFrameType::Close as i32,
                payload: Vec::new(),
                error_message: String::new(),
                sender_grant: None,
                sender_signature: Vec::new(),
            };
            let _ = self
                .send_to_coordinator(ClientStreamMessage {
                    payload: Some(ClientPayload::ZellijFrame(close_frame)),
                })
                .await;
        }
        Ok(())
    }

    async fn render_dashboard_html(&self, bound_port: u16) -> String {
        let hosts = self.hosts.read().await.clone();
        let peers = self.direct_peers.read().await;

        let mut host_cards = String::new();
        if hosts.is_empty() {
            host_cards.push_str(
                r#"<div class="empty">
                    <h3>No Zellij-enabled relay hosts currently online</h3>
                    <p>To advertise Zellij sessions from a remote Linux relay host, run on that host:</p>
                    <pre>sockcast-relay zellij enable</pre>
                    <p>Or jump directly to a host and session via URL: <code>http://localhost:PORT/&lt;hostname&gt;/&lt;session&gt;</code></p>
                </div>"#,
            );
        } else {
            for h in &hosts {
                let short = short_host_label(&h.node_id);
                let is_p2p = peers.contains_key(&h.node_id) || peers.contains_key(short);
                let transport_badge = if is_p2p {
                    r#"<span class="badge p2p">Direct P2P (STUN)</span>"#
                } else {
                    r#"<span class="badge relay">Coordinator Tunnel (P2P ready)</span>"#
                };

                let mut sessions_html = String::new();
                if h.sessions.is_empty() {
                    sessions_html.push_str(
                        r#"<div class="muted">No existing Zellij sessions running yet. Create one below or open the host root.</div>"#,
                    );
                } else {
                    sessions_html.push_str(r#"<div class="sessions">"#);
                    for s in &h.sessions {
                        let s_name_esc = html_escape(&s.name);
                        let s_info_esc = html_escape(&s.created_info);
                        let short_esc = html_escape(short);
                        let state_badge = if s.exited {
                            r#"<span class="tag exited">EXITED (resurrect)</span>"#
                        } else {
                            r#"<span class="tag active">ACTIVE</span>"#
                        };
                        sessions_html.push_str(&format!(
                            r#"<a class="session-row" href="http://{short_esc}.localhost:{bound_port}/{s_name_esc}">
                                <div>
                                    <span class="session-name">{s_name_esc}</span>
                                    <span class="session-meta">{s_info_esc}</span>
                                </div>
                                <div>{state_badge} <span class="open-btn">Open &rarr;</span></div>
                            </a>"#
                        ));
                    }
                    sessions_html.push_str("</div>");
                }

                let node_esc = html_escape(&h.node_id);
                let short_esc = html_escape(short);
                host_cards.push_str(&format!(
                    r#"<div class="card">
                        <div class="card-header">
                            <div>
                                <h2>{short_esc}</h2>
                                <span class="sub">{node_esc}</span>
                            </div>
                            <div class="header-actions">
                                {transport_badge}
                                <a class="btn-secondary" href="http://{short_esc}.localhost:{bound_port}/">Zellij Home</a>
                            </div>
                        </div>
                        {sessions_html}
                        <form class="new-session" onsubmit="event.preventDefault(); var s = this.elements.session.value.trim(); window.location.href = 'http://{short_esc}.localhost:{bound_port}/' + encodeURIComponent(s);">
                            <input type="text" name="session" placeholder="New or existing session name (e.g. main)..." required />
                            <button type="submit">Launch Session</button>
                        </form>
                    </div>"#
                ));
            }
        }

        format!(
            r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sockcast — Zellij Web Sessions</title>
<style>
  :root {{
    color-scheme: dark;
  }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0b1120;
    color: #e2e8f0;
  }}
  .container {{
    max-width: 880px;
    margin: 0 auto;
    padding: 2.5rem 1.5rem;
  }}
  header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 2rem;
    border-bottom: 1px solid #1e293b;
    padding-bottom: 1.25rem;
  }}
  h1 {{
    margin: 0;
    font-size: 1.5rem;
    font-weight: 600;
    color: #f8fafc;
  }}
  .subtitle {{
    margin: 0.35rem 0 0;
    color: #94a3b8;
    font-size: 0.9rem;
  }}
  .btn-refresh {{
    background: #1e293b;
    color: #e2e8f0;
    text-decoration: none;
    padding: 0.5rem 0.95rem;
    border-radius: 6px;
    border: 1px solid #334155;
    font-size: 0.875rem;
  }}
  .btn-refresh:hover {{
    background: #334155;
  }}
  .card {{
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
  }}
  .card-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }}
  .card-header h2 {{
    margin: 0;
    font-size: 1.2rem;
    color: #38bdf8;
  }}
  .sub {{
    font-size: 0.8rem;
    color: #64748b;
  }}
  .header-actions {{
    display: flex;
    align-items: center;
    gap: 0.65rem;
  }}
  .badge {{
    font-size: 0.75rem;
    padding: 0.25rem 0.6rem;
    border-radius: 999px;
    font-weight: 500;
  }}
  .badge.p2p {{
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }}
  .badge.relay {{
    background: rgba(56, 189, 248, 0.12);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.25);
  }}
  .btn-secondary {{
    background: #1f2937;
    color: #cbd5e1;
    text-decoration: none;
    padding: 0.35rem 0.75rem;
    border-radius: 6px;
    font-size: 0.8rem;
    border: 1px solid #374151;
  }}
  .sessions {{
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }}
  .session-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #1e293b;
    padding: 0.65rem 0.9rem;
    border-radius: 7px;
    text-decoration: none;
    color: #f1f5f9;
    border: 1px solid transparent;
  }}
  .session-row:hover {{
    border-color: #38bdf8;
    background: #243247;
  }}
  .session-name {{
    font-weight: 600;
    margin-right: 0.75rem;
  }}
  .session-meta {{
    font-size: 0.8rem;
    color: #94a3b8;
  }}
  .tag {{
    font-size: 0.7rem;
    padding: 0.15rem 0.45rem;
    border-radius: 4px;
    margin-right: 0.5rem;
  }}
  .tag.active {{
    background: rgba(34, 197, 94, 0.15);
    color: #4ade80;
  }}
  .tag.exited {{
    background: rgba(245, 158, 11, 0.15);
    color: #fbbf24;
  }}
  .open-btn {{
    font-size: 0.85rem;
    color: #38bdf8;
  }}
  .new-session {{
    display: flex;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }}
  .new-session input {{
    flex: 1;
    background: #0f172a;
    border: 1px solid #334155;
    color: #f8fafc;
    padding: 0.5rem 0.75rem;
    border-radius: 6px;
    font-size: 0.875rem;
  }}
  .new-session button {{
    background: #0284c7;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-weight: 500;
    cursor: pointer;
  }}
  .new-session button:hover {{
    background: #0369a1;
  }}
  .empty {{
    background: #111827;
    border: 1px dashed #334155;
    border-radius: 10px;
    padding: 2rem;
    text-align: center;
    color: #94a3b8;
  }}
  pre {{
    background: #0f172a;
    padding: 0.75rem 1rem;
    border-radius: 6px;
    display: inline-block;
    color: #38bdf8;
  }}
  .muted {{
    color: #64748b;
    font-size: 0.875rem;
    margin-bottom: 0.75rem;
  }}
</style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Sockcast Zellij Web</h1>
        <p class="subtitle">Zero-config authenticated Zellij Web sessions over STUN Direct P2P &amp; Sockcast</p>
      </div>
      <a class="btn-refresh" href="/?refresh=1">&#x21bb; Refresh Sessions</a>
    </header>
    {host_cards}
  </div>
</body>
</html>"#
        )
    }

    pub async fn handle_browser_connection(
        self: Arc<Self>,
        mut stream: TcpStream,
        bound_port: u16,
    ) -> Result<()> {
        let mut init_buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
                .await
                .context("browser read timeout")??;
            if n == 0 {
                return Ok(());
            }
            init_buf.extend_from_slice(&tmp[..n]);
            if init_buf.windows(4).any(|w| w == b"\r\n\r\n") || init_buf.len() >= 32768 {
                break;
            }
        }

        let Some((_method, path, host_header)) = parse_http_host_and_path(&init_buf) else {
            return Ok(());
        };

        if let Some(target_host) = extract_relay_target_from_host_header(&host_header) {
            let relay_node_id = self.resolve_relay_node_id(&target_host).await;

            // Check if we already have a verified Direct P2P peer for this relay
            let maybe_peer = {
                let guard = self.direct_peers.read().await;
                guard
                    .get(&relay_node_id)
                    .or_else(|| guard.get(&target_host))
                    .cloned()
            };

            if let Some(peer) = maybe_peer {
                if self
                    .try_proxy_via_direct_p2p(&peer, &init_buf, &mut stream)
                    .await
                    .is_ok()
                {
                    return Ok(());
                }
                // Direct P2P failed (e.g. IP changed); evict cached peer and fall back to coordinator
                let mut guard = self.direct_peers.write().await;
                guard.remove(&relay_node_id);
                guard.remove(&target_host);
            }

            // Trigger background STUN/P2P negotiation for subsequent streams while immediately serving this stream
            self.maybe_spawn_p2p_negotiation(relay_node_id.clone()).await;
            return self
                .proxy_via_coordinator_tunnel(&relay_node_id, init_buf, stream)
                .await;
        }

        // Request is to `http://localhost:<port>...`
        if path == "/" || path.starts_with("/?") {
            let _ = self
                .send_to_coordinator(ClientStreamMessage {
                    payload: Some(ClientPayload::RequestZellijHosts(true)),
                })
                .await;
            if path.contains("refresh=1") {
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
            let html = self.render_dashboard_html(bound_port).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
                html.len(),
                html
            );
            stream.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        if path == "/favicon.ico" {
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            return Ok(());
        }

        // Support `http://localhost:PORT/<hostname>` and `http://localhost:PORT/<hostname>/<session>`
        let trimmed_path = path.trim_start_matches('/');
        let (host_seg, rest_seg) = match trimmed_path.split_once('/') {
            Some((h, r)) => (h.trim(), r),
            None => (trimmed_path.trim(), ""),
        };
        if !host_seg.is_empty() {
            let redirect_url = format!("http://{host_seg}.localhost:{bound_port}/{rest_seg}");
            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                redirect_url
            );
            stream.write_all(resp.as_bytes()).await?;
        }
        Ok(())
    }
}

/// Starts the local loopback Zellij Web HTTP/WebSocket proxy on `127.0.0.1:<listen_port>`.
pub async fn serve_zellij_proxy_with_listener(
    listener: TcpListener,
    hub: Arc<ZellijProxyHub>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let bound_port = listener.local_addr()?.port();
    tracing::info!(
        "Zellij Web local proxy listening on http://localhost:{}/ (and http://<host>.localhost:{}/<session>)",
        bound_port,
        bound_port
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
            res = listener.accept() => {
                let (stream, _) = match res {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::debug!("Zellij proxy accept error: {}", e);
                        continue;
                    }
                };
                let hub_clone = Arc::clone(&hub);
                tokio::spawn(async move {
                    let _ = hub_clone.handle_browser_connection(stream, bound_port).await;
                });
            }
        }
    }
}

/// Opens `http://localhost:<port>/` in the user's default system browser.
pub fn open_zellij_dashboard_in_browser(port: u16) {
    let url = format!("http://localhost:{}/", if port == 0 { 18080 } else { port });
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&url).spawn();
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    }
}
