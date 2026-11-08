use sockcast_proto::ssh::{extract_key_type, fingerprint_sha256};
use sockcast_proto::v1::{PublicKey, SignRequest};
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;

use crate::policy::{
    extract_primary_command, extract_primary_tool_binary, extract_target_ssh_user,
    extract_verified_host, ApprovalDecision,
};

#[derive(Debug, Clone)]
pub struct PromptDetails {
    pub request_id: String,
    pub verified_host: String,
    pub target_ssh_user: String,
    pub primary_tool: String,
    pub primary_command: String,
    pub ancestry_chain: String,
    pub cwd: String,
    pub key_summary: String,
}

impl PromptDetails {
    pub fn from_request(req: &SignRequest, known_keys: &[PublicKey]) -> Self {
        let verified_host = extract_verified_host(req);
        let target_user = extract_target_ssh_user(req);
        let target_ssh_user = if target_user.is_empty() {
            "<non-login / arbitrary signature>".to_string()
        } else {
            target_user
        };
        let primary_tool = extract_primary_tool_binary(req);
        let primary_command = extract_primary_command(req);

        let (ancestry_chain, cwd) = if let Some(pc) = &req.process_context {
            let mut chain_parts = Vec::new();
            for anc in pc.ancestors.iter().rev() {
                chain_parts.push(format!("{} ({})", anc.comm, anc.pid));
            }
            chain_parts.push(format!("{} ({})", pc.comm, pc.pid));
            (chain_parts.join(" -> "), pc.cwd.clone())
        } else {
            ("<unknown>".to_string(), String::new())
        };

        let fp = fingerprint_sha256(&req.key_blob);
        let ktype = extract_key_type(&req.key_blob);
        let comment = known_keys
            .iter()
            .find(|k| k.key_blob == req.key_blob)
            .map(|k| k.comment.as_str())
            .unwrap_or("");
        let key_summary = if comment.is_empty() {
            format!("{fp} ({ktype})")
        } else {
            format!("{fp} ({ktype} - {comment})")
        };

        Self {
            request_id: req.request_id.clone(),
            verified_host,
            target_ssh_user,
            primary_tool,
            primary_command,
            ancestry_chain,
            cwd,
            key_summary,
        }
    }
}

/// Pluggable approval prompter trait so unit/integration tests and different desktop/TUI frontends
/// can handle interactive `SignRequest` prompts and cancellation cleanly.
#[tonic::async_trait]
pub trait ApprovalPrompter: Send + Sync {
    async fn prompt_user(
        &self,
        details: PromptDetails,
        cancel_rx: watch::Receiver<Option<String>>,
    ) -> ApprovalDecision;
}

/// Static prompter used for automated `--auto-approve` or `--auto-deny` modes and integration tests.
pub struct StaticPrompter {
    decision: ApprovalDecision,
}

impl StaticPrompter {
    pub fn new(decision: ApprovalDecision) -> Self {
        Self { decision }
    }
}

#[tonic::async_trait]
impl ApprovalPrompter for StaticPrompter {
    async fn prompt_user(
        &self,
        _details: PromptDetails,
        _cancel_rx: watch::Receiver<Option<String>>,
    ) -> ApprovalDecision {
        self.decision
    }
}

/// Interactive desktop & terminal prompter:
/// 1. Fires a desktop notification (`notify-send`) if available.
/// 2. If a native desktop dialog helper (`zenity` or `kdialog` on Linux, `osascript` on macOS) is available,
///    pops a native GUI modal window and automatically kills the modal if `CancelSignRequest` arrives!
/// 3. Otherwise renders a rich interactive terminal modal on stderr/stdin.
#[derive(Default)]
pub struct InteractivePrompter {
    prompt_lock: Arc<tokio::sync::Mutex<()>>,
}

impl InteractivePrompter {
    pub fn new() -> Self {
        Self {
            prompt_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}

#[tonic::async_trait]
impl ApprovalPrompter for InteractivePrompter {
    async fn prompt_user(
        &self,
        details: PromptDetails,
        mut cancel_rx: watch::Receiver<Option<String>>,
    ) -> ApprovalDecision {
        let _guard = self.prompt_lock.lock().await;

        if cancel_rx.borrow().is_some() {
            return ApprovalDecision::Deny;
        }

        // Best-effort desktop notification on Linux
        let _ = Command::new("notify-send")
            .args([
                "-u",
                "critical",
                "-t",
                "10000",
                "Sockcast SSH Signature Request",
                &format!(
                    "Host: {}\nTarget User: {}\nCommand: {}",
                    details.verified_host, details.target_ssh_user, details.primary_command
                ),
            ])
            .status()
            .await;

        if let Some(decision) = try_native_gui_dialog(&details, &mut cancel_rx).await {
            return decision;
        }

        prompt_terminal_interactive(&details, &mut cancel_rx).await
    }
}

async fn try_native_gui_dialog(
    details: &PromptDetails,
    cancel_rx: &mut watch::Receiver<Option<String>>,
) -> Option<ApprovalDecision> {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "choose from list {{\"1. Approve Once\", \"2. Approve '{}' on '{}' for 15m\", \"3. Approve all on '{}' for 15m\", \"4. Deny\"}} \
             with title \"Sockcast SSH Agent Approval\" \
             with prompt \"Verified Host: {}\\nTarget SSH User: {}\\nCommand: {}\\nAncestry: {}\\nDirectory: {}\\nKey: {}\" \
             default items {{\"1. Approve Once\"}}",
            details.primary_tool.replace('"', "'"),
            details.verified_host.replace('"', "'"),
            details.verified_host.replace('"', "'"),
            details.verified_host.replace('"', "'"),
            details.target_ssh_user.replace('"', "'"),
            details.primary_command.replace('"', "'"),
            details.ancestry_chain.replace('"', "'"),
            details.cwd.replace('"', "'"),
            details.key_summary.replace('"', "'"),
        );
        let mut child = Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;

        let mut stdout = child.stdout.take()?;

        tokio::select! {
            _ = cancel_rx.changed() => {
                let _ = child.kill().await;
                return Some(ApprovalDecision::Deny);
            }
            status_res = child.wait() => {
                let status = status_res.ok()?;
                if !status.success() {
                    return Some(ApprovalDecision::Deny);
                }
                let mut out_bytes = Vec::new();
                let _ = stdout.read_to_end(&mut out_bytes).await;
                let s = String::from_utf8_lossy(&out_bytes);
                let trimmed = s.trim();
                if trimmed.starts_with("1.") {
                    return Some(ApprovalDecision::ApproveOnce);
                } else if trimmed.starts_with("2.") {
                    return Some(ApprovalDecision::ApproveToolOnHost15m);
                } else if trimmed.starts_with("3.") {
                    return Some(ApprovalDecision::ApproveAllOnHost15m);
                } else {
                    return Some(ApprovalDecision::Deny);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return None;
        }
        let text = format!(
            "Verified Source Host:  {}\n\
             Target SSH User:       {}\n\
             Primary Tool & Cmd:    {}\n\
             Process Ancestry:      {}\n\
             Working Directory:     {}\n\
             SSH Key:               {}",
            details.verified_host,
            details.target_ssh_user,
            details.primary_command,
            details.ancestry_chain,
            details.cwd,
            details.key_summary
        );
        let opt_once = "Approve Once".to_string();
        let opt_tool = format!(
            "Approve {} on {} for 15m",
            details.primary_tool, details.verified_host
        );
        let opt_host = format!("Approve all on {} for 15m", details.verified_host);
        let opt_deny = "Deny".to_string();

        let mut child = Command::new("zenity")
            .args([
                "--list",
                "--title=Sockcast SSH Agent Approval",
                "--width=680",
                "--height=380",
                &format!("--text={text}"),
                "--column=Action",
                &opt_once,
                &opt_tool,
                &opt_host,
                &opt_deny,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;

        let mut stdout = child.stdout.take()?;

        tokio::select! {
            _ = cancel_rx.changed() => {
                let _ = child.kill().await;
                return Some(ApprovalDecision::Deny);
            }
            status_res = child.wait() => {
                let status = status_res.ok()?;
                if !status.success() {
                    return Some(ApprovalDecision::Deny);
                }
                let mut out_bytes = Vec::new();
                let _ = stdout.read_to_end(&mut out_bytes).await;
                let choice = String::from_utf8_lossy(&out_bytes).trim().to_string();
                if choice == opt_once {
                    return Some(ApprovalDecision::ApproveOnce);
                } else if choice == opt_tool {
                    return Some(ApprovalDecision::ApproveToolOnHost15m);
                } else if choice == opt_host {
                    return Some(ApprovalDecision::ApproveAllOnHost15m);
                } else {
                    return Some(ApprovalDecision::Deny);
                }
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (details, cancel_rx);
        None
    }
}

async fn prompt_terminal_interactive(
    details: &PromptDetails,
    cancel_rx: &mut watch::Receiver<Option<String>>,
) -> ApprovalDecision {
    eprintln!("\n+=========================================================================+");
    eprintln!("|                 SOCKCAST SSH AGENT SIGNATURE REQUEST                    |");
    eprintln!("+=========================================================================+");
    eprintln!("  Verified Source Host : {}", details.verified_host);
    eprintln!("  Target SSH User      : {}", details.target_ssh_user);
    eprintln!("  Primary Command      : {}", details.primary_command);
    eprintln!("  Process Ancestry     : {}", details.ancestry_chain);
    eprintln!("  Working Directory    : {}", details.cwd);
    eprintln!("  SSH Key              : {}", details.key_summary);
    eprintln!("---------------------------------------------------------------------------");
    eprintln!("  [1] Approve Once");
    eprintln!(
        "  [2] Approve '{}' on '{}' for 15m",
        details.primary_tool, details.verified_host
    );
    eprintln!("  [3] Approve all on '{}' for 15m", details.verified_host);
    eprintln!("  [4] Deny (default)");
    eprint!("Select action [1-4]: ");
    let _ = std::io::stderr().flush();

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut line = String::new();

    tokio::select! {
        _ = cancel_rx.changed() => {
            if let Some(reason) = cancel_rx.borrow().as_deref() {
                eprintln!("\n[Canceled: {reason}]");
            }
            ApprovalDecision::Deny
        }
        res = stdin.read_line(&mut line) => {
            match res {
                Ok(0) | Err(_) => ApprovalDecision::Deny,
                Ok(_) => match line.trim() {
                    "1" | "y" | "yes" | "once" => ApprovalDecision::ApproveOnce,
                    "2" | "tool" => ApprovalDecision::ApproveToolOnHost15m,
                    "3" | "all" | "host" => ApprovalDecision::ApproveAllOnHost15m,
                    _ => ApprovalDecision::Deny,
                }
            }
        }
    }
}

pub fn format_prompt_summary_lines(details: &PromptDetails) -> Vec<String> {
    vec![
        format!("Verified Source Host: {}", details.verified_host),
        format!("Target SSH User:      {}", details.target_ssh_user),
        format!("Primary Tool & Cmd:   {}", details.primary_command),
        format!("Process Ancestry:     {}", details.ancestry_chain),
        format!("Working Directory:    {}", details.cwd),
        format!("SSH Key:              {}", details.key_summary),
    ]
}
