use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{define_class, msg_send, sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAlert, NSAlertFirstButtonReturn, NSAlertSecondButtonReturn, NSAlertStyle,
    NSAlertThirdButtonReturn, NSApplication, NSApplicationActivationPolicy, NSColor,
    NSControlStateValueOff, NSControlStateValueOn, NSEvent, NSEventModifierFlags, NSEventType,
    NSFont, NSImage, NSMenu, NSMenuDelegate, NSMenuItem, NSStatusBar, NSStatusItem, NSTextField,
    NSVariableStatusItemLength, NSView,
};
use objc2_core_foundation::{CGFloat, CGPoint, CGRect, CGSize};
use objc2_foundation::{NSObject, NSObjectProtocol, NSPoint, NSRect, NSSize, NSString};

use crate::config::{default_config_dir, ClientConfig};
use crate::local_agent::LocalAgentConnector;
use crate::mac_dialogs::{
    show_backends_window, show_bundle_generator_window, show_enroll_window, show_ssh_keys_window,
};
use crate::policy::ApprovalDecision;
use crate::prompt::{PairingPromptDetails, PromptDetails};

pub struct TraySharedContext {
    pub config_path: Option<PathBuf>,
    pub agent_socket_override: Option<String>,
    pub config_dir: PathBuf,
    pub active_config: Mutex<Option<ClientConfig>>,
    pub local_agent: Arc<LocalAgentConnector>,
    pub force_active_flag: Arc<AtomicBool>,
    pub connected_count: Arc<AtomicUsize>,
    pub reload_tx: watch::Sender<u64>,
    pub shutdown_tx: watch::Sender<bool>,
    pub status_dialog_open: AtomicBool,
}

impl TraySharedContext {
    pub fn current_config(&self) -> Option<ClientConfig> {
        self.active_config.lock().ok().and_then(|g| g.clone())
    }
}

static TRAY_CONTEXT: Mutex<Option<Arc<TraySharedContext>>> = Mutex::new(None);
static APPKIT_LOOP_RUNNING: AtomicBool = AtomicBool::new(false);

pub fn get_tray_context() -> Option<Arc<TraySharedContext>> {
    TRAY_CONTEXT
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}

pub fn is_appkit_loop_running() -> bool {
    APPKIT_LOOP_RUNNING.load(Ordering::SeqCst)
}

/// Executes `f` synchronously on the macOS main thread. If already on the main thread, executes
/// immediately without deadlocking `DispatchQueue::main()`.
pub fn run_on_main_sync<F, R>(f: F) -> R
where
    F: FnOnce(MainThreadMarker) -> R + Send,
    R: Send,
{
    if let Some(mtm) = MainThreadMarker::new() {
        f(mtm)
    } else {
        let mut out: Option<R> = None;
        let out_ref = &mut out;
        DispatchQueue::main().exec_sync(move || {
            let mtm = MainThreadMarker::new().expect("DispatchQueue::main must be on main thread");
            *out_ref = Some(f(mtm));
        });
        out.expect("main thread closure must produce output")
    }
}

/// Schedules `f` asynchronously on the macOS main thread.
pub fn run_on_main_async<F>(f: F)
where
    F: FnOnce(MainThreadMarker) + Send + 'static,
{
    DispatchQueue::main().exec_async(move || {
        if let Some(mtm) = MainThreadMarker::new() {
            f(mtm);
        }
    });
}

thread_local! {
    static STATUS_BAR_STATE: RefCell<Option<StatusBarWidgets>> = const { RefCell::new(None) };
}

struct StatusBarWidgets {
    status_item: Retained<NSStatusItem>,
    header_item: Retained<NSMenuItem>,
    conn_item: Retained<NSMenuItem>,
    zellij_action_item: Retained<NSMenuItem>,
    status_action_item: Retained<NSMenuItem>,
    backends_action_item: Retained<NSMenuItem>,
    bundle_action_item: Retained<NSMenuItem>,
    force_active_item: Retained<NSMenuItem>,
    _menu_target: Retained<SshcastMenuTarget>,
}

fn refresh_status_bar_widgets(mtm: MainThreadMarker) {
    let _ = mtm;
    let Some(ctx) = get_tray_context() else {
        return;
    };
    let maybe_cfg = ctx.current_config();
    let connected = ctx.connected_count.load(Ordering::Relaxed);
    let force_active = ctx.force_active_flag.load(Ordering::Relaxed);
    let is_enrolled = maybe_cfg.is_some();
    let has_root_key = crate::config::UserKeyFile::load(None).is_ok();

    let tip = match &maybe_cfg {
        Some(cfg) => format!("Sshcast — {} ({})", cfg.grant.node_id, cfg.grant.user_id),
        None => "Sshcast — Not Enrolled (Click to Setup)".to_string(),
    };
    let header_str = match &maybe_cfg {
        Some(cfg) => format!("Sshcast: {} ({})", cfg.grant.node_id, cfg.grant.user_id),
        None => "Sshcast: Workstation Not Enrolled".to_string(),
    };
    let conn_str = match &maybe_cfg {
        Some(cfg) => format!("Coordinators: {connected}/{} connected", cfg.servers.len()),
        None => "Coordinators: 0/0 connected".to_string(),
    };

    STATUS_BAR_STATE.with(|cell| {
        if let Some(ref w) = *cell.borrow() {
            if let Some(btn) = w.status_item.button(mtm) {
                btn.setToolTip(Some(&NSString::from_str(&tip)));
            }
            w.header_item.setTitle(&NSString::from_str(&header_str));
            w.conn_item.setTitle(&NSString::from_str(&conn_str));
            w.zellij_action_item.setEnabled(is_enrolled);
            w.status_action_item.setEnabled(is_enrolled);
            w.backends_action_item.setEnabled(is_enrolled);
            w.bundle_action_item.setEnabled(is_enrolled && has_root_key);
            w.force_active_item.setEnabled(is_enrolled);
            w.force_active_item.setState(if force_active {
                NSControlStateValueOn
            } else {
                NSControlStateValueOff
            });
        }
    });
}

/// Reloads `client.toml` from disk, updates the status bar tooltip/menu, and notifies the
/// background Tokio runtime in `sshcast-tray` to reconnect to all configured coordinator backends.
pub fn reload_tray_configuration() {
    let Some(ctx) = get_tray_context() else {
        return;
    };
    if let Ok(mut cfg) = ClientConfig::load(ctx.config_path.as_deref()) {
        if let Some(ref sock) = ctx.agent_socket_override {
            cfg.local_agent_socket = Some(sock.clone());
        }
        cfg.force_active = ctx.force_active_flag.load(Ordering::Relaxed);
        ctx.local_agent.sync_from_client_config(&cfg);
        if let Ok(mut guard) = ctx.active_config.lock() {
            *guard = Some(cfg);
        }
        let next_gen = (*ctx.reload_tx.borrow()).wrapping_add(1);
        let _ = ctx.reload_tx.send(next_gen);

        run_on_main_async(|mtm| {
            refresh_status_bar_widgets(mtm);
        });
    }
}

/// Displays a native macOS error alert modal.
pub fn show_tray_error_dialog(title: &str, instruction: &str, details: &str) {
    let title_owned = title.to_string();
    let instr_owned = instruction.to_string();
    let details_owned = details.to_string();

    run_on_main_sync(move |mtm| {
        let app = NSApplication::sharedApplication(mtm);
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let alert = NSAlert::new(mtm);
        alert.setAlertStyle(NSAlertStyle::Critical);
        alert.setMessageText(&NSString::from_str(&format!(
            "{title_owned} — {instr_owned}"
        )));
        alert.setInformativeText(&NSString::from_str(&details_owned));
        alert.addButtonWithTitle(&NSString::from_str("OK"));
        let _ = alert.runModal();
    });
}

/// Displays a native macOS warning confirmation dialog and returns `true` if the user clicked Overwrite/Yes.
pub fn confirm_overwrite_dialog(title: &str, instruction: &str, content: &str) -> bool {
    let title_owned = title.to_string();
    let instr_owned = instruction.to_string();
    let content_owned = content.to_string();

    run_on_main_sync(move |mtm| {
        let app = NSApplication::sharedApplication(mtm);
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let alert = NSAlert::new(mtm);
        alert.setAlertStyle(NSAlertStyle::Warning);
        alert.setMessageText(&NSString::from_str(&title_owned));
        alert.setInformativeText(&NSString::from_str(&format!(
            "{instr_owned}\n\n{content_owned}"
        )));
        alert.addButtonWithTitle(&NSString::from_str("Overwrite"));
        alert.addButtonWithTitle(&NSString::from_str("Cancel"));
        alert.runModal() == NSAlertFirstButtonReturn
    })
}

fn create_shield_icon(description: &str) -> Option<Retained<NSImage>> {
    let sym = NSString::from_str("lock.shield");
    let desc = NSString::from_str(description);
    NSImage::imageWithSystemSymbolName_accessibilityDescription(&sym, Some(&desc))
}

fn build_approval_alert(mtm: MainThreadMarker, details: &PromptDetails) -> Retained<NSAlert> {
    let alert = NSAlert::new(mtm);
    alert.setAlertStyle(NSAlertStyle::Informational);
    if let Some(icon) = create_shield_icon("Sshcast SSH Agent Approval") {
        unsafe {
            alert.setIcon(Some(&icon));
        }
    }
    alert.setMessageText(&NSString::from_str(&format!(
        "SSH Agent Signature Request from {}",
        details.verified_host
    )));
    alert.setInformativeText(&NSString::from_str(
        "End-to-end Ed25519 signature verified against your user root key.",
    ));

    let cwd_display = if details.cwd.is_empty() {
        "<unknown>"
    } else {
        &details.cwd
    };

    let rows: [(&str, &str); 7] = [
        ("Verified Source Host:", &details.verified_host),
        ("Target SSH User:", &details.target_ssh_user),
        ("Primary Tool & Cmd:", &details.primary_command),
        ("Working Directory:", cwd_display),
        ("Process Ancestry:", &details.ancestry_chain),
        ("SSH Key:", &details.key_summary),
        ("Request ID:", &details.request_id),
    ];

    let view_w: CGFloat = 500.0;
    let row_h: CGFloat = 22.0;
    let view_h: CGFloat = (rows.len() as CGFloat) * row_h + 12.0;
    let accessory = NSView::initWithFrame(
        mtm.alloc(),
        NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(view_w, view_h)),
    );

    let key_font = NSFont::systemFontOfSize_weight(12.0, 0.25);
    let val_font = NSFont::monospacedSystemFontOfSize_weight(12.0, 0.0);
    let key_color = NSColor::secondaryLabelColor();
    let val_color = NSColor::labelColor();

    for (idx, (k, v)) in rows.iter().enumerate() {
        let y = view_h - ((idx as CGFloat + 1.0) * row_h) - 4.0;

        let k_label = NSTextField::labelWithString(&NSString::from_str(k), mtm);
        k_label.setFrame(CGRect::new(
            CGPoint::new(0.0, y),
            CGSize::new(148.0, row_h - 2.0),
        ));
        k_label.setFont(Some(&key_font));
        k_label.setTextColor(Some(&key_color));
        accessory.addSubview(&k_label);

        let v_label = NSTextField::labelWithString(&NSString::from_str(v), mtm);
        v_label.setFrame(CGRect::new(
            CGPoint::new(154.0, y),
            CGSize::new(view_w - 154.0, row_h - 2.0),
        ));
        v_label.setFont(Some(&val_font));
        v_label.setTextColor(Some(&val_color));
        v_label.setSelectable(true);
        accessory.addSubview(&v_label);
    }

    alert.setAccessoryView(Some(&accessory));

    let btn1 = alert.addButtonWithTitle(&NSString::from_str(&format!(
        "Approve Once ({})",
        details.primary_tool
    )));
    btn1.setKeyEquivalent(&NSString::from_str("\r"));

    let _btn2 = alert.addButtonWithTitle(&NSString::from_str(&format!(
        "Approve '{}' on '{}' for 15 minutes",
        details.primary_tool, details.verified_host
    )));

    let _btn3 = alert.addButtonWithTitle(&NSString::from_str(&format!(
        "Approve all on '{}' for 15 minutes",
        details.verified_host
    )));

    let btn4 = alert.addButtonWithTitle(&NSString::from_str("Deny (Esc)"));
    btn4.setKeyEquivalent(&NSString::from_str("\u{1b}"));

    alert
}

fn build_pairing_alert(mtm: MainThreadMarker, details: &PairingPromptDetails) -> Retained<NSAlert> {
    let alert = NSAlert::new(mtm);
    alert.setAlertStyle(NSAlertStyle::Informational);
    if let Some(icon) = create_shield_icon("Sshcast Device Pairing Request") {
        unsafe {
            alert.setIcon(Some(&icon));
        }
    }
    alert.setMessageText(&NSString::from_str(&format!(
        "Approve new workstation '{}'?",
        details.node_name
    )));
    alert.setInformativeText(&NSString::from_str(
        "Confirm the 6-digit verification code matches the new device before approving and syncing your Sshcast root key.",
    ));

    let login_display = if details.github_login.is_empty() {
        "<unknown>".to_string()
    } else {
        format!("@{}", details.github_login)
    };

    let rows: [(&str, &str, bool); 5] = [
        ("New Workstation:", &details.node_name, false),
        ("Operating System:", &details.os_name, false),
        ("GitHub Account:", &login_display, false),
        ("Account ID:", &details.existing_user_id, false),
        ("Verification Code:", &details.sas_code, true),
    ];

    let view_w: CGFloat = 460.0;
    let row_h: CGFloat = 24.0;
    let view_h: CGFloat = (rows.len() as CGFloat) * row_h + 12.0;
    let accessory = NSView::initWithFrame(
        mtm.alloc(),
        NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(view_w, view_h)),
    );

    let key_font = NSFont::systemFontOfSize_weight(12.0, 0.25);
    let val_font = NSFont::monospacedSystemFontOfSize_weight(12.0, 0.0);
    let sas_font = NSFont::monospacedSystemFontOfSize_weight(14.0, 0.4);
    let key_color = NSColor::secondaryLabelColor();
    let val_color = NSColor::labelColor();
    let sas_color = NSColor::controlAccentColor();

    for (idx, (k, v, is_sas)) in rows.iter().enumerate() {
        let y = view_h - ((idx as CGFloat + 1.0) * row_h) - 4.0;

        let k_label = NSTextField::labelWithString(&NSString::from_str(k), mtm);
        k_label.setFrame(CGRect::new(
            CGPoint::new(0.0, y),
            CGSize::new(148.0, row_h - 2.0),
        ));
        k_label.setFont(Some(&key_font));
        k_label.setTextColor(Some(&key_color));
        accessory.addSubview(&k_label);

        let v_label = NSTextField::labelWithString(&NSString::from_str(v), mtm);
        v_label.setFrame(CGRect::new(
            CGPoint::new(154.0, y),
            CGSize::new(view_w - 154.0, row_h - 2.0),
        ));
        if *is_sas {
            v_label.setFont(Some(&sas_font));
            v_label.setTextColor(Some(&sas_color));
        } else {
            v_label.setFont(Some(&val_font));
            v_label.setTextColor(Some(&val_color));
        }
        v_label.setSelectable(true);
        accessory.addSubview(&v_label);
    }

    alert.setAccessoryView(Some(&accessory));

    let btn_approve = alert.addButtonWithTitle(&NSString::from_str("Approve"));
    btn_approve.setKeyEquivalent(&NSString::from_str("\r"));

    let btn_deny = alert.addButtonWithTitle(&NSString::from_str("Deny"));
    btn_deny.setKeyEquivalent(&NSString::from_str("\u{1b}"));

    alert
}

fn map_modal_response(resp: isize) -> ApprovalDecision {
    if resp == NSAlertFirstButtonReturn {
        ApprovalDecision::ApproveOnce
    } else if resp == NSAlertSecondButtonReturn {
        ApprovalDecision::ApproveToolOnHost15m
    } else if resp == NSAlertThirdButtonReturn {
        ApprovalDecision::ApproveAllOnHost15m
    } else {
        ApprovalDecision::Deny
    }
}

/// Runs the native macOS `NSAlert` approval dialog in a standalone helper process
/// (`sshcast-client internal-gui-prompt --payload-json <json>`).
pub fn run_macos_modal_process(details: PromptDetails) -> ApprovalDecision {
    let Some(mtm) = MainThreadMarker::new() else {
        return ApprovalDecision::Deny;
    };
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);

    let alert = build_approval_alert(mtm, &details);
    let alert_window = alert.window();
    alert_window.center();
    alert_window.makeKeyAndOrderFront(None);

    let resp = alert.runModal();
    map_modal_response(resp)
}

/// Runs the native macOS `NSAlert` device pairing dialog in a standalone helper process
/// (`sshcast-client internal-gui-pairing-prompt --payload-json <json>`).
pub fn run_macos_pairing_modal_process(details: PairingPromptDetails) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);

    let alert = build_pairing_alert(mtm, &details);
    let alert_window = alert.window();
    alert_window.center();
    alert_window.makeKeyAndOrderFront(None);

    alert.runModal() == NSAlertFirstButtonReturn
}

struct MacModalCancelState {
    app_ptr: Option<usize>,
    canceled: bool,
}

async fn run_cancellable_macos_alert<F>(
    cancel_rx: &mut watch::Receiver<Option<String>>,
    build_alert: F,
) -> Option<isize>
where
    F: FnOnce(MainThreadMarker) -> Retained<NSAlert> + Send + 'static,
{
    if !is_appkit_loop_running() {
        return None;
    }

    let state = Arc::new(Mutex::new(MacModalCancelState {
        app_ptr: None,
        canceled: false,
    }));
    let state_for_cancel = Arc::clone(&state);
    let mut cancel_watch = cancel_rx.clone();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();

    let cancel_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut done_rx => break,
                res = cancel_watch.changed() => {
                    if res.is_err() || cancel_watch.borrow().is_some() {
                        let maybe_app_ptr = if let Ok(mut guard) = state_for_cancel.lock() {
                            guard.canceled = true;
                            guard.app_ptr
                        } else {
                            None
                        };
                        if let Some(ptr) = maybe_app_ptr {
                            // `NSAlert::runModal()` spins `NSModalPanelRunLoopMode`, which blocks
                            // `DispatchQueue::main()`. `-[NSApplication abortModal]` and
                            // `-[NSApplication postEvent:atStart:]` are thread-safe in AppKit and
                            // must be invoked directly from the background thread to wake and exit
                            // the modal runloop immediately.
                            unsafe {
                                let app_ref = &*(ptr as *const NSApplication);
                                app_ref.abortModal();
                                if let Some(wake_event) = NSEvent::otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2(
                                    NSEventType::ApplicationDefined,
                                    NSPoint::new(0.0, 0.0),
                                    NSEventModifierFlags::empty(),
                                    0.0,
                                    0,
                                    None,
                                    0,
                                    0,
                                    0,
                                ) {
                                    app_ref.postEvent_atStart(&wake_event, true);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
    });

    let cancel_rx_check = cancel_rx.clone();
    let state_for_main = Arc::clone(&state);

    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel::<isize>();
    run_on_main_async(move |mtm| {
        let app = NSApplication::sharedApplication(mtm);
        {
            let Ok(mut guard) = state_for_main.lock() else {
                let _ = resp_tx.send(0);
                return;
            };
            if guard.canceled || cancel_rx_check.borrow().is_some() {
                let _ = resp_tx.send(0);
                return;
            }
            guard.app_ptr = Some(Retained::as_ptr(&app) as usize);
        }

        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let alert = build_alert(mtm);
        let resp = alert.runModal();
        if let Ok(mut guard) = state_for_main.lock() {
            guard.app_ptr = None;
        }
        let _ = resp_tx.send(resp);
    });

    let resp = resp_rx.await.ok();
    let _ = done_tx.send(());
    cancel_task.abort();

    resp
}

/// Displays a native macOS `NSAlert` approval modal on the AppKit main thread and automatically
/// aborts the modal if `cancel_rx` fires (`CancelSignRequest` from coordinator).
pub async fn prompt_macos_dialog(
    details: &PromptDetails,
    cancel_rx: &mut watch::Receiver<Option<String>>,
) -> Option<ApprovalDecision> {
    if cancel_rx.borrow().is_some() {
        return Some(ApprovalDecision::Deny);
    }

    let details_cloned = details.clone();
    let resp = run_cancellable_macos_alert(cancel_rx, move |mtm| {
        build_approval_alert(mtm, &details_cloned)
    })
    .await;

    if cancel_rx.borrow().is_some() {
        return Some(ApprovalDecision::Deny);
    }

    resp.map(map_modal_response)
}

/// Displays a native macOS `NSAlert` device pairing modal on the AppKit main thread and
/// automatically aborts the modal if `cancel_rx` fires.
pub async fn prompt_pairing_macos_dialog(
    details: &PairingPromptDetails,
    cancel_rx: &mut watch::Receiver<Option<String>>,
) -> Option<bool> {
    if cancel_rx.borrow().is_some() {
        return Some(false);
    }

    let details_cloned = details.clone();
    let resp = run_cancellable_macos_alert(cancel_rx, move |mtm| {
        build_pairing_alert(mtm, &details_cloned)
    })
    .await;

    if cancel_rx.borrow().is_some() {
        return Some(false);
    }

    resp.map(|r| r == NSAlertFirstButtonReturn)
}

pub fn spawn_status_dialog(ctx: Arc<TraySharedContext>) {
    let Some(cfg) = ctx.current_config() else {
        show_enroll_window();
        return;
    };

    if ctx.status_dialog_open.swap(true, Ordering::SeqCst) {
        return;
    }

    std::thread::spawn(move || {
        let local_agent = Arc::clone(&ctx.local_agent);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let keys = match rt {
            Ok(rt) => rt
                .block_on(local_agent.list_filtered_keys())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        let connected = ctx.connected_count.load(Ordering::Relaxed);
        let total = cfg.servers.len();
        let force_active = ctx.force_active_flag.load(Ordering::Relaxed);

        let servers_str = cfg.servers.join("\n  • ");
        let keys_str = if keys.is_empty() {
            "  (No local SSH keys currently loaded or matching filter)".to_string()
        } else {
            keys.iter()
                .map(|k| {
                    let src = if local_agent.is_loaded_key(&k.key_blob) {
                        "Built-in"
                    } else {
                        "OS Agent"
                    };
                    if k.comment.is_empty() {
                        format!("  • [{src}] {} ({})", k.fingerprint_sha256, k.key_type)
                    } else {
                        format!(
                            "  • [{src}] {} ({} — {})",
                            k.fingerprint_sha256, k.key_type, k.comment
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        let cert_str = match &cfg.grant.user_cert {
            Some(cert) => {
                let op_hex = hex::encode(&cert.operator_pubkey);
                let short_op = &op_hex[..12.min(op_hex.len())];
                format!("Certified (sc_op_pub_{short_op}...)")
            }
            None => "None (static public key)".to_string(),
        };
        let heading = format!(
            "Workstation '{}' ({}/{total} coordinators connected)",
            cfg.grant.node_id, connected
        );
        let body = format!(
            "User ID:             {}\n\
             Operator Cert:       {}\n\
             Force Active Mode:   {}\n\
             Config Directory:    {}\n\n\
             Coordinators:\n  • {}\n\n\
             Exported Local SSH Keys ({}):\n{}",
            cfg.grant.user_id,
            cert_str,
            if force_active {
                "Enabled"
            } else {
                "Disabled (Automatic Idle Detection)"
            },
            ctx.config_dir.display(),
            servers_str,
            keys.len(),
            keys_str
        );

        run_on_main_async(move |mtm| {
            let app = NSApplication::sharedApplication(mtm);
            #[allow(deprecated)]
            app.activateIgnoringOtherApps(true);

            let alert = NSAlert::new(mtm);
            alert.setAlertStyle(NSAlertStyle::Informational);
            if let Some(icon) = create_shield_icon("Sshcast Workstation Status") {
                unsafe {
                    alert.setIcon(Some(&icon));
                }
            }
            alert.setMessageText(&NSString::from_str(&heading));
            alert.setInformativeText(&NSString::from_str(&body));
            alert.addButtonWithTitle(&NSString::from_str("OK"));
            let _ = alert.runModal();

            ctx.status_dialog_open.store(false, Ordering::SeqCst);
        });
    });
}

#[derive(Default)]
struct MenuTargetIvars {}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "SshcastMenuTarget"]
    #[ivars = MenuTargetIvars]
    struct SshcastMenuTarget;

    unsafe impl NSObjectProtocol for SshcastMenuTarget {}

    unsafe impl NSMenuDelegate for SshcastMenuTarget {
        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: &NSMenu) {
            refresh_status_bar_widgets(self.mtm());
        }
    }

    impl SshcastMenuTarget {
        #[unsafe(method(onZellijDashboard:))]
        fn on_zellij_dashboard(&self, _sender: Option<&AnyObject>) {
            let port = get_tray_context()
                .and_then(|ctx| ctx.current_config())
                .map(|c| c.zellij_listen_port)
                .unwrap_or(18080);
            crate::zellij_proxy::open_zellij_dashboard_in_browser(port);
        }

        #[unsafe(method(onStatusDialog:))]
        fn on_status_dialog(&self, _sender: Option<&AnyObject>) {
            if let Some(ctx) = get_tray_context() {
                spawn_status_dialog(ctx);
            }
        }

        #[unsafe(method(onSshKeysWindow:))]
        fn on_ssh_keys_window(&self, _sender: Option<&AnyObject>) {
            show_ssh_keys_window();
        }

        #[unsafe(method(onBackendsWindow:))]
        fn on_backends_window(&self, _sender: Option<&AnyObject>) {
            show_backends_window();
        }

        #[unsafe(method(onBundleWindow:))]
        fn on_bundle_window(&self, _sender: Option<&AnyObject>) {
            show_bundle_generator_window();
        }

        #[unsafe(method(onEnrollWindow:))]
        fn on_enroll_window(&self, _sender: Option<&AnyObject>) {
            show_enroll_window();
        }

        #[unsafe(method(onToggleForceActive:))]
        fn on_toggle_force_active(&self, _sender: Option<&AnyObject>) {
            if let Some(ctx) = get_tray_context() {
                let prev = ctx.force_active_flag.fetch_xor(true, Ordering::SeqCst);
                tracing::info!("Toggled force_active to {}", !prev);
                refresh_status_bar_widgets(self.mtm());
            }
        }

        #[unsafe(method(onOpenConfigDir:))]
        fn on_open_config_dir(&self, _sender: Option<&AnyObject>) {
            if let Some(ctx) = get_tray_context() {
                let _ = std::fs::create_dir_all(&ctx.config_dir);
                let _ = std::process::Command::new("open")
                    .arg(&ctx.config_dir)
                    .spawn();
            }
        }

        #[unsafe(method(onQuit:))]
        fn on_quit(&self, _sender: Option<&AnyObject>) {
            if let Some(ctx) = get_tray_context() {
                let _ = ctx.shutdown_tx.send(true);
            }
            stop_appkit_run_loop(self.mtm());
        }
    }
);

impl SshcastMenuTarget {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(MenuTargetIvars::default());
        unsafe { msg_send![super(this), init] }
    }
}

fn stop_appkit_run_loop(mtm: MainThreadMarker) {
    let app = NSApplication::sharedApplication(mtm);
    app.stop(None);
    if let Some(event) = NSEvent::otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2(
        NSEventType::ApplicationDefined,
        NSPoint::new(0.0, 0.0),
        NSEventModifierFlags::empty(),
        0.0,
        0,
        None,
        0,
        0,
        0,
    ) {
        app.postEvent_atStart(&event, true);
    }
}

/// Runs the native macOS Menu Bar (`NSStatusBar`) event loop on the main thread while
/// `WorkstationManager` runs on a background multi-threaded Tokio runtime.
#[allow(clippy::too_many_arguments)]
pub fn run_macos_tray_loop(
    config_path: Option<PathBuf>,
    agent_socket_override: Option<String>,
    initial_cfg: Option<ClientConfig>,
    force_active_flag: Arc<AtomicBool>,
    connected_count: Arc<AtomicUsize>,
    reload_tx: watch::Sender<u64>,
    shutdown_tx: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mtm = MainThreadMarker::new()
        .ok_or_else(|| anyhow::anyhow!("run_macos_tray_loop must be called on the main thread"))?;

    let is_unconfigured = initial_cfg.is_none();
    let config_dir = default_config_dir().unwrap_or_else(|_| PathBuf::from("."));
    let local_agent = Arc::new(match &initial_cfg {
        Some(cfg) => LocalAgentConnector::from_client_config(cfg, &[], false).unwrap_or_else(|e| {
            tracing::warn!("Failed to load some built-in SSH keys on startup: {:#}", e);
            LocalAgentConnector::with_options(
                cfg.local_agent_socket.clone(),
                cfg.key_filter.clone(),
                cfg.disable_os_agent,
            )
        }),
        None => LocalAgentConnector::new(agent_socket_override.clone(), Default::default()),
    });
    let ctx = Arc::new(TraySharedContext {
        config_path,
        agent_socket_override,
        config_dir,
        active_config: Mutex::new(initial_cfg),
        local_agent,
        force_active_flag,
        connected_count,
        reload_tx,
        shutdown_tx,
        status_dialog_open: AtomicBool::new(false),
    });

    if let Ok(mut guard) = TRAY_CONTEXT.lock() {
        *guard = Some(Arc::clone(&ctx));
    }
    let _ = ctx.reload_tx.send(1);

    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    let status_bar = NSStatusBar::systemStatusBar();
    let status_item = status_bar.statusItemWithLength(NSVariableStatusItemLength);
    if let Some(button) = status_item.button(mtm) {
        if let Some(img) = create_shield_icon("Sshcast") {
            img.setTemplate(true);
            button.setImage(Some(&img));
        } else {
            button.setTitle(&NSString::from_str("🛡"));
        }
    }

    let menu_target = SshcastMenuTarget::new(mtm);
    let menu = NSMenu::new(mtm);
    menu.setAutoenablesItems(false);
    let delegate_proto = ProtocolObject::from_ref(&*menu_target);
    menu.setDelegate(Some(delegate_proto));

    let empty_key = NSString::from_str("");

    let header_item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc(),
            &NSString::from_str("Sshcast"),
            None,
            &empty_key,
        )
    };
    header_item.setEnabled(false);
    menu.addItem(&header_item);

    let conn_item = unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc(),
            &NSString::from_str("Coordinators: 0/0 connected"),
            None,
            &empty_key,
        )
    };
    conn_item.setEnabled(false);
    menu.addItem(&conn_item);

    menu.addItem(&NSMenuItem::separatorItem(mtm));

    let make_action_item = |title: &str, sel: objc2::runtime::Sel, key: &str| -> Retained<NSMenuItem> {
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                mtm.alloc(),
                &NSString::from_str(title),
                Some(sel),
                &NSString::from_str(key),
            )
        };
        unsafe {
            item.setTarget(Some(&menu_target));
        }
        menu.addItem(&item);
        item
    };

    let zellij_action_item =
        make_action_item("Open Zellij Web Dashboard...", sel!(onZellijDashboard:), "z");
    let status_action_item =
        make_action_item("Workstation Status & SSH Keys...", sel!(onStatusDialog:), "");
    let _ssh_keys_action_item = make_action_item(
        "Manage SSH Keys (Built-in & OS Agent)...",
        sel!(onSshKeysWindow:),
        "k",
    );
    let backends_action_item =
        make_action_item("Coordinator Backends (Servers)...", sel!(onBackendsWindow:), "");
    let bundle_action_item = make_action_item(
        "Generate Enrollment Bundle (Relay / Client)...",
        sel!(onBundleWindow:),
        "",
    );
    let _enroll_action_item =
        make_action_item("Initialize / Enroll Workstation...", sel!(onEnrollWindow:), "");

    menu.addItem(&NSMenuItem::separatorItem(mtm));

    let force_active_item =
        make_action_item("Force Active Workstation", sel!(onToggleForceActive:), "");
    let _open_cfg_item = make_action_item("Open Config Folder", sel!(onOpenConfigDir:), "");

    menu.addItem(&NSMenuItem::separatorItem(mtm));

    let _quit_item = make_action_item("Quit Sshcast", sel!(onQuit:), "q");

    status_item.setMenu(Some(&menu));

    STATUS_BAR_STATE.with(|cell| {
        *cell.borrow_mut() = Some(StatusBarWidgets {
            status_item,
            header_item,
            conn_item,
            zellij_action_item,
            status_action_item,
            backends_action_item,
            bundle_action_item,
            force_active_item,
            _menu_target: menu_target,
        });
    });

    refresh_status_bar_widgets(mtm);

    if is_unconfigured {
        show_enroll_window();
    }

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        if let Ok(rt) = rt {
            rt.block_on(async move {
                while shutdown_rx.changed().await.is_ok() {
                    if *shutdown_rx.borrow() {
                        run_on_main_async(|mtm| {
                            stop_appkit_run_loop(mtm);
                        });
                        break;
                    }
                }
            });
        }
    });

    APPKIT_LOOP_RUNNING.store(true, Ordering::SeqCst);
    app.run();
    APPKIT_LOOP_RUNNING.store(false, Ordering::SeqCst);

    STATUS_BAR_STATE.with(|cell| {
        *cell.borrow_mut() = None;
    });
    if let Ok(mut guard) = TRAY_CONTEXT.lock() {
        *guard = None;
    }

    Ok(())
}
