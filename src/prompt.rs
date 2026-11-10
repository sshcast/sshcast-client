use serde::{Deserialize, Serialize};
use sockcast_proto::ssh::{extract_key_type, fingerprint_sha256};
use sockcast_proto::v1::{PublicKey, SignRequest};
#[cfg(not(target_arch = "wasm32"))]
use std::io::Write;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
#[cfg(not(target_arch = "wasm32"))]
use tokio::process::Command;
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::watch;

#[cfg(not(target_arch = "wasm32"))]
use crate::policy::ApprovalDecision;
use crate::policy::{
    extract_primary_command, extract_primary_tool_binary, extract_target_ssh_user,
    extract_verified_host,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[cfg(not(target_arch = "wasm32"))]
mod native_prompter {
    use super::*;

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
/// 2. On Windows, displays a native Win32 `TaskDialogIndirect` (`comctl32.dll` v6) modal with Command-Link buttons
///    and automatic `CancelSignRequest` dismissal.
/// 3. On Linux/macOS, displays an `eframe`/`egui` modal or native desktop dialog (`zenity` / `osascript`)
///    and automatically kills the modal if `CancelSignRequest` arrives!
/// 4. Otherwise renders a rich interactive terminal modal on stderr/stdin.
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

        // Best-effort desktop notification on Linux / macOS
        #[cfg(target_os = "linux")]
        {
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
        }
        #[cfg(target_os = "macos")]
        {
            let notif_script = format!(
                "display notification \"Host: {} | User: {} | Cmd: {}\" with title \"Sockcast SSH Signature Request\"",
                details.verified_host.replace('"', "'"),
                details.target_ssh_user.replace('"', "'"),
                details.primary_command.replace('"', "'")
            );
            let _ = Command::new("osascript")
                .args(["-e", &notif_script])
                .status()
                .await;
        }

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
    // On Windows, prefer the in-process native Win32 TaskDialogIndirect (comctl32 v6) with Command-Link buttons
    #[cfg(target_os = "windows")]
    {
        if let Some(decision) = crate::win_native::prompt_task_dialog(details, cancel_rx).await {
            return Some(decision);
        }
    }

    // On macOS, prefer the in-process native AppKit NSAlert modal when sockcast-tray's NSApplication loop is running
    #[cfg(target_os = "macos")]
    {
        if let Some(decision) = crate::mac_native::prompt_macos_dialog(details, cancel_rx).await {
            return Some(decision);
        }
    }

    // Try native GUI modal subprocess on macOS (AppKit NSAlert) or Linux (eframe/egui)
    #[cfg(any(
        target_os = "macos",
        all(feature = "gui", not(target_os = "windows"))
    ))]
    {
        let has_display = if cfg!(target_os = "linux") {
            std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
        } else {
            true
        };
        if has_display {
            if let Ok(exe) = std::env::current_exe() {
                if let Ok(json_str) = serde_json::to_string(details) {
                    let mut cmd = Command::new(exe);
                    cmd.args(["internal-gui-prompt", "--payload-json", &json_str])
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .kill_on_drop(true);
                    if let Ok(mut child) = cmd.spawn() {
                        if let Some(mut stdout) = child.stdout.take() {
                            let egui_res = tokio::select! {
                                _ = cancel_rx.changed() => {
                                    let _ = child.kill().await;
                                    Some(ApprovalDecision::Deny)
                                }
                                status_res = child.wait() => {
                                    match status_res {
                                        Ok(st) if st.success() => {
                                            let mut out_bytes = Vec::new();
                                            let _ = stdout.read_to_end(&mut out_bytes).await;
                                            let token = String::from_utf8_lossy(&out_bytes);
                                            match token.trim() {
                                                "ONCE" => Some(ApprovalDecision::ApproveOnce),
                                                "TOOL_15M" => Some(ApprovalDecision::ApproveToolOnHost15m),
                                                "HOST_15M" => Some(ApprovalDecision::ApproveAllOnHost15m),
                                                "DENY" => Some(ApprovalDecision::Deny),
                                                _ => None,
                                            }
                                        }
                                        _ => None,
                                    }
                                }
                            };
                            if let Some(decision) = egui_res {
                                return Some(decision);
                            }
                        }
                    }
                }
            }
        }
    }

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

    #[cfg(target_os = "windows")]
    {
        let body = format!(
            "Verified Source Host: {}\\nTarget SSH User: {}\\nPrimary Command: {}\\nProcess Ancestry: {}\\nWorking Directory: {}\\nSSH Key: {}\\n\\n[Yes] = Approve Once\\n[No] = Approve '{}' on '{}' for 15m\\n[Cancel] = Deny",
            details.verified_host.replace('\'', "''"),
            details.target_ssh_user.replace('\'', "''"),
            details.primary_command.replace('\'', "''"),
            details.ancestry_chain.replace('\'', "''"),
            details.cwd.replace('\'', "''"),
            details.key_summary.replace('\'', "''"),
            details.primary_tool.replace('\'', "''"),
            details.verified_host.replace('\'', "''"),
        );
        let ps_script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             $msg = '{}' -replace '\\\\n', \"`r`n\"; \
             $res = [System.Windows.Forms.MessageBox]::Show($msg, 'Sockcast SSH Agent Approval', 'YesNoCancel', 'Warning'); \
             Write-Output $res",
            body
        );
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut cmd = Command::new("powershell");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &ps_script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
        let mut child = cmd.spawn().ok()?;
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
                return match choice.as_str() {
                    "Yes" => Some(ApprovalDecision::ApproveOnce),
                    "No" => Some(ApprovalDecision::ApproveToolOnHost15m),
                    _ => Some(ApprovalDecision::Deny),
                };
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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
}

#[cfg(not(target_arch = "wasm32"))]
pub use native_prompter::{ApprovalPrompter, InteractivePrompter, StaticPrompter};
