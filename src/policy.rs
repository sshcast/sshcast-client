use sockcast_proto::v1::SignRequest;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_RULE_TTL: Duration = Duration::from_secs(15 * 60); // 15 minutes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Signs this single request only.
    ApproveOnce,
    /// Caches an in-memory approval rule matching `(verified_source_host, caller_tool_binary, key_blob, target_ssh_user)` for 15 minutes.
    ApproveToolOnHost15m,
    /// Approves any signing request for this key from `verified_source_host` for 15 minutes.
    ApproveAllOnHost15m,
    /// Immediately returns `approved = false` (`SSH_AGENT_FAILURE`).
    Deny,
}

#[derive(Debug, Clone)]
enum RuleScope {
    Tool {
        caller_tool: String,
        target_ssh_user: String,
    },
    AllOnHost,
}

#[derive(Debug, Clone)]
struct SessionRule {
    verified_source_host: String,
    key_blob: Vec<u8>,
    scope: RuleScope,
    expires_at: Instant,
}

/// Thread-safe 15-minute session trust rule engine for `sockcast-client`.
pub struct PolicyEngine {
    ttl: Duration,
    rules: Mutex<Vec<SessionRule>>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(DEFAULT_RULE_TTL)
    }
}

impl PolicyEngine {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            rules: Mutex::new(Vec::new()),
        }
    }

    /// Checks if `req` matches an active, unexpired session trust rule.
    pub fn check_auto_approved(&self, req: &SignRequest) -> bool {
        self.check_auto_approved_at(req, Instant::now())
    }

    pub fn check_auto_approved_at(&self, req: &SignRequest, now: Instant) -> bool {
        let host = extract_verified_host(req);
        if host.is_empty() {
            return false;
        }
        let tool = extract_primary_tool_binary(req);
        let target_user = extract_target_ssh_user(req);

        let mut guard = self.rules.lock().unwrap();
        guard.retain(|r| r.expires_at > now);

        guard.iter().any(|r| {
            if r.verified_source_host != host || r.key_blob != req.key_blob {
                return false;
            }
            match &r.scope {
                RuleScope::AllOnHost => true,
                RuleScope::Tool {
                    caller_tool,
                    target_ssh_user,
                } => caller_tool == &tool && target_ssh_user == &target_user,
            }
        })
    }

    /// Records a user's `ApprovalDecision` into the in-memory session rule table if applicable.
    pub fn record_decision(&self, req: &SignRequest, decision: ApprovalDecision) {
        self.record_decision_at(req, decision, Instant::now());
    }

    pub fn record_decision_at(&self, req: &SignRequest, decision: ApprovalDecision, now: Instant) {
        let host = extract_verified_host(req);
        if host.is_empty() {
            return;
        }
        let expires_at = now + self.ttl;

        let scope = match decision {
            ApprovalDecision::ApproveOnce | ApprovalDecision::Deny => return,
            ApprovalDecision::ApproveToolOnHost15m => RuleScope::Tool {
                caller_tool: extract_primary_tool_binary(req),
                target_ssh_user: extract_target_ssh_user(req),
            },
            ApprovalDecision::ApproveAllOnHost15m => RuleScope::AllOnHost,
        };

        let mut guard = self.rules.lock().unwrap();
        guard.retain(|r| r.expires_at > now);
        guard.push(SessionRule {
            verified_source_host: host,
            key_blob: req.key_blob.clone(),
            scope,
            expires_at,
        });
    }

    pub fn clear_rules(&self) {
        self.rules.lock().unwrap().clear();
    }
}

pub fn extract_verified_host(req: &SignRequest) -> String {
    req.relay_grant
        .as_ref()
        .map(|g| g.node_id.clone())
        .or_else(|| req.process_context.as_ref().map(|pc| pc.hostname.clone()))
        .unwrap_or_default()
}

pub fn extract_target_ssh_user(req: &SignRequest) -> String {
    let parsed = req
        .ssh_auth_context
        .clone()
        .unwrap_or_else(|| sockcast_proto::ssh::parse_ssh_auth_context(&req.data));
    if parsed.is_userauth_request {
        parsed.target_username
    } else {
        String::new()
    }
}

fn base_tool_name(comm: &str) -> &str {
    comm.trim()
        .rsplit('/')
        .next()
        .unwrap_or(comm)
        .trim_start_matches('-')
}

/// Identifies the primary invoking tool binary.
/// When `scp`, `rsync`, or `git` spawns `ssh` as a child transport, `process_context.comm` is `"ssh"`
/// and `ancestors[0].comm` is `"scp"` / `"rsync"` / `"git"`. Promoting that immediate parent tool
/// makes `[Approve <tool> on <host> for 15m]` scope to `scp` without blindly approving direct `ssh` shells.
pub fn extract_primary_tool_binary(req: &SignRequest) -> String {
    let Some(pc) = &req.process_context else {
        return "unknown".to_string();
    };
    let leaf = base_tool_name(&pc.comm);
    if leaf == "ssh" {
        if let Some(parent) = pc.ancestors.first() {
            let pcomm = base_tool_name(&parent.comm);
            if matches!(
                pcomm,
                "scp" | "rsync" | "git" | "git-remote-ext" | "sftp" | "borg" | "restic" | "ansible-playbook"
            ) {
                return pcomm.to_string();
            }
        }
    }
    if leaf.is_empty() {
        "unknown".to_string()
    } else {
        leaf.to_string()
    }
}

/// Extracts the primary human-readable command line for display in the approval prompt.
pub fn extract_primary_command(req: &SignRequest) -> String {
    let Some(pc) = &req.process_context else {
        return String::new();
    };
    let tool = extract_primary_tool_binary(req);
    let leaf = base_tool_name(&pc.comm);
    if tool != leaf {
        if let Some(parent) = pc.ancestors.first() {
            if !parent.cmdline.trim().is_empty() {
                return parent.cmdline.trim().to_string();
            }
        }
    }
    if !pc.cmdline.trim().is_empty() {
        pc.cmdline.trim().to_string()
    } else {
        pc.comm.trim().to_string()
    }
}
