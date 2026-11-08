use anyhow::{Context, Result};
use sockcast_proto::ssh::parse_public_key_blob;
use sockcast_proto::v1::PublicKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::KeyFilterConfig;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
pub const MAX_AGENT_FRAME_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct LocalAgentConnector {
    socket_override: Option<String>,
    filter: KeyFilterConfig,
}

impl LocalAgentConnector {
    pub fn new(socket_override: Option<String>, filter: KeyFilterConfig) -> Self {
        Self {
            socket_override,
            filter,
        }
    }

    pub fn resolve_endpoint(&self) -> Result<String> {
        if let Some(s) = &self.socket_override {
            if !s.trim().is_empty() {
                return Ok(s.trim().to_string());
            }
        }
        #[cfg(windows)]
        {
            if let Ok(env_sock) = std::env::var("SSH_AUTH_SOCK") {
                if !env_sock.trim().is_empty() {
                    return Ok(env_sock);
                }
            }
            Ok(r"\\.\pipe\openssh-ssh-agent".to_string())
        }
        #[cfg(not(windows))]
        {
            let sock = std::env::var("SSH_AUTH_SOCK")
                .context("SSH_AUTH_SOCK is not set and local_agent_socket is not configured")?;
            if sock.trim().is_empty() {
                anyhow::bail!("SSH_AUTH_SOCK is empty");
            }
            Ok(sock)
        }
    }

    /// Queries the local OS SSH agent (`SSH2_AGENTC_REQUEST_IDENTITIES`) and returns keys
    /// matching the configured `KeyFilterConfig`.
    pub async fn list_filtered_keys(&self) -> Result<Vec<PublicKey>> {
        let all_keys = self.list_all_keys().await?;
        Ok(filter_keys(all_keys, &self.filter))
    }

    pub async fn list_all_keys(&self) -> Result<Vec<PublicKey>> {
        #[cfg(unix)]
        {
            let path = self.resolve_endpoint()?;
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .with_context(|| format!("failed to connect to local SSH agent at {path}"))?;
            request_identities_over_stream(&mut stream).await
        }
        #[cfg(windows)]
        {
            let pipe_name = self.resolve_endpoint()?;
            let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&pipe_name)
                .with_context(|| {
                    format!("failed to connect to Windows OpenSSH agent pipe {pipe_name}")
                })?;
            request_identities_over_stream(&mut client).await
        }
    }

    /// Requests a signature from the local OS SSH agent (`SSH2_AGENTC_SIGN_REQUEST`),
    /// first verifying that `key_blob` is permitted by `KeyFilterConfig`.
    pub async fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Vec<u8>> {
        // If filtering is configured, verify that the requested key is allowed to be used
        if is_filter_active(&self.filter) {
            let allowed = self.list_filtered_keys().await?;
            if !allowed.iter().any(|k| k.key_blob == key_blob) {
                anyhow::bail!("requested SSH key is not permitted by client key_filter policy");
            }
        }

        #[cfg(unix)]
        {
            let path = self.resolve_endpoint()?;
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .with_context(|| format!("failed to connect to local SSH agent at {path}"))?;
            sign_over_stream(&mut stream, key_blob, data, flags).await
        }
        #[cfg(windows)]
        {
            let pipe_name = self.resolve_endpoint()?;
            let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&pipe_name)
                .with_context(|| {
                    format!("failed to connect to Windows OpenSSH agent pipe {pipe_name}")
                })?;
            sign_over_stream(&mut client, key_blob, data, flags).await
        }
    }
}

pub fn is_filter_active(filter: &KeyFilterConfig) -> bool {
    !filter.allowed_fingerprints.is_empty()
        || !filter.allowed_comment_substrings.is_empty()
        || !filter.excluded_fingerprints.is_empty()
}

pub fn filter_keys(keys: Vec<PublicKey>, filter: &KeyFilterConfig) -> Vec<PublicKey> {
    keys.into_iter()
        .filter(|k| key_matches_filter(k, filter))
        .collect()
}

pub fn key_matches_filter(key: &PublicKey, filter: &KeyFilterConfig) -> bool {
    if filter
        .excluded_fingerprints
        .iter()
        .any(|fp| fp.trim() == key.fingerprint_sha256)
    {
        return false;
    }

    let has_fp_allow = !filter.allowed_fingerprints.is_empty();
    let has_comment_allow = !filter.allowed_comment_substrings.is_empty();

    if !has_fp_allow && !has_comment_allow {
        return true;
    }

    let fp_match = filter
        .allowed_fingerprints
        .iter()
        .any(|fp| fp.trim() == key.fingerprint_sha256);
    let comment_match = filter
        .allowed_comment_substrings
        .iter()
        .any(|sub| !sub.is_empty() && key.comment.contains(sub));

    fp_match || comment_match
}

pub async fn request_identities_over_stream<S>(stream: &mut S) -> Result<Vec<PublicKey>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_frame(stream, &[SSH2_AGENTC_REQUEST_IDENTITIES]).await?;
    let resp = read_frame(stream).await?;
    let Some((&msg_type, mut cursor)) = resp.split_first() else {
        anyhow::bail!("empty response from local SSH agent");
    };
    if msg_type != SSH2_AGENT_IDENTITIES_ANSWER {
        anyhow::bail!("unexpected response type {msg_type} from local SSH agent");
    }
    let count = read_u32(&mut cursor).context("truncated identities answer count")? as usize;
    let mut keys = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let blob = read_ssh_bytes(&mut cursor).context("truncated key blob")?.to_vec();
        let comment_bytes = read_ssh_bytes(&mut cursor).context("truncated key comment")?;
        let comment = String::from_utf8_lossy(comment_bytes).into_owned();
        keys.push(parse_public_key_blob(blob, comment));
    }
    Ok(keys)
}

pub async fn sign_over_stream<S>(
    stream: &mut S,
    key_blob: &[u8],
    data: &[u8],
    flags: u32,
) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = Vec::with_capacity(13 + key_blob.len() + data.len());
    req.push(SSH2_AGENTC_SIGN_REQUEST);
    write_ssh_bytes(&mut req, key_blob);
    write_ssh_bytes(&mut req, data);
    req.extend_from_slice(&flags.to_be_bytes());

    write_frame(stream, &req).await?;
    let resp = read_frame(stream).await?;
    let Some((&msg_type, mut cursor)) = resp.split_first() else {
        anyhow::bail!("empty sign response from local SSH agent");
    };
    if msg_type == SSH_AGENT_FAILURE {
        anyhow::bail!("local SSH agent refused to sign (SSH_AGENT_FAILURE)");
    }
    if msg_type != SSH2_AGENT_SIGN_RESPONSE {
        anyhow::bail!("unexpected sign response type {msg_type} from local SSH agent");
    }
    let sig_blob = read_ssh_bytes(&mut cursor)
        .context("truncated signature blob from local SSH agent")?
        .to_vec();
    Ok(sig_blob)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AGENT_FRAME_LEN {
        anyhow::bail!("invalid frame length {len} from local SSH agent");
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

fn write_ssh_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_u32<'a>(cursor: &mut &'a [u8]) -> Option<u32> {
    if cursor.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Some(val)
}

fn read_ssh_bytes<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return None;
    }
    let slice = &cursor[..len];
    *cursor = &cursor[len..];
    Some(slice)
}
