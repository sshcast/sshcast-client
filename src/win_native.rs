use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM, LRESULT, POINT, S_OK, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOGCONFIG_1,
    TASKDIALOG_BUTTON, TASKDIALOG_NOTIFICATIONS, TDCBF_CANCEL_BUTTON, TDCBF_OK_BUTTON,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_EXPANDED_BY_DEFAULT, TDF_SIZE_TO_CONTENT,
    TDF_USE_COMMAND_LINKS, TDM_CLICK_BUTTON, TDN_CREATED, TD_ERROR_ICON, TD_INFORMATION_ICON,
    TD_SHIELD_ICON,
};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, MessageBoxW, PostMessageW,
    PostQuitMessage, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, SetWindowPos,
    TrackPopupMenu, TranslateMessage, CW_USEDEFAULT, HICON, HWND_TOPMOST, IDCANCEL,
    IDI_APPLICATION, IDI_SHIELD, MB_ICONERROR, MB_OK, MF_CHECKED, MF_GRAYED, MF_SEPARATOR,
    MF_STRING, MF_UNCHECKED, MSG, SWP_NOMOVE, SWP_NOSIZE, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
    TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_APP, WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL,
    WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

use crate::config::{default_config_dir, ClientConfig};
use crate::local_agent::LocalAgentConnector;
use crate::policy::ApprovalDecision;
use crate::prompt::PromptDetails;
use crate::win_dialogs::{
    cleanup_dialog_fonts, is_any_management_dialog_message, show_backends_window,
    show_bundle_generator_window, show_enroll_window, show_ssh_keys_window,
};

const BTN_APPROVE_ONCE: i32 = 101;
const BTN_APPROVE_TOOL_15M: i32 = 102;
const BTN_APPROVE_HOST_15M: i32 = 103;
const BTN_DENY: i32 = 104;

const WM_TRAYICON: u32 = WM_APP + 1;
const WM_TRAY_SHUTDOWN: u32 = WM_APP + 2;
const TRAY_ICON_ID: u32 = 1;

const IDM_STATUS_DIALOG: u32 = 1001;
const IDM_BACKENDS_WINDOW: u32 = 1002;
const IDM_BUNDLE_GENERATOR_WINDOW: u32 = 1003;
const IDM_ENROLL_WINDOW: u32 = 1004;
const IDM_TOGGLE_FORCE_ACTIVE: u32 = 1005;
const IDM_OPEN_CONFIG_DIR: u32 = 1006;
const IDM_QUIT: u32 = 1007;
const IDM_ZELLIJ_DASHBOARD: u32 = 1008;
const IDM_SSH_KEYS_WINDOW: u32 = 1009;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

struct DialogCancelState {
    hwnd: Option<isize>,
    canceled: bool,
}

unsafe extern "system" fn task_dialog_callback(
    hwnd: HWND,
    msg: TASKDIALOG_NOTIFICATIONS,
    _wparam: WPARAM,
    _lparam: LPARAM,
    lprefdata: isize,
) -> windows_sys::core::HRESULT {
    if msg == TDN_CREATED && lprefdata != 0 {
        let state_ptr = lprefdata as *const Mutex<DialogCancelState>;
        if let Ok(mut guard) = (*state_ptr).lock() {
            if guard.canceled {
                PostMessageW(hwnd, TDM_CLICK_BUTTON as u32, IDCANCEL as usize, 0);
                return S_OK;
            }
            guard.hwnd = Some(hwnd as isize);
        }
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE,
        );
        SetForegroundWindow(hwnd);
    }
    S_OK
}

/// Displays a native Windows `TaskDialogIndirect` (`comctl32.dll` v6) modal with Command-Link buttons
/// and automatically dismisses it if `cancel_rx` fires (`CancelSignRequest` from coordinator).
pub async fn prompt_task_dialog(
    details: &PromptDetails,
    cancel_rx: &mut watch::Receiver<Option<String>>,
) -> Option<ApprovalDecision> {
    if cancel_rx.borrow().is_some() {
        return Some(ApprovalDecision::Deny);
    }

    let state = Arc::new(Mutex::new(DialogCancelState {
        hwnd: None,
        canceled: false,
    }));

    let state_for_cancel = Arc::clone(&state);
    let mut cancel_watch = cancel_rx.clone();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();

    let cancel_task = tokio::spawn(async move {
        tokio::select! {
            _ = &mut done_rx => {}
            _ = cancel_watch.changed() => {
                if let Ok(mut guard) = state_for_cancel.lock() {
                    guard.canceled = true;
                    if let Some(hwnd_raw) = guard.hwnd {
                        unsafe {
                            PostMessageW(
                                hwnd_raw as HWND,
                                TDM_CLICK_BUTTON as u32,
                                IDCANCEL as usize,
                                0,
                            );
                        }
                    }
                }
            }
        }
    });

    let details_cloned = details.clone();
    let state_for_dialog = Arc::clone(&state);

    let join_res = tokio::task::spawn_blocking(move || unsafe {
        let window_title = to_wide("Sshcast SSH Agent Approval");
        let main_instruction = to_wide(&format!(
            "SSH Agent Signature Request from {}",
            details_cloned.verified_host
        ));
        let cwd_display = if details_cloned.cwd.is_empty() {
            "<unknown>"
        } else {
            &details_cloned.cwd
        };
        let content = to_wide(&format!(
            "Verified Source Host:  {}\n\
             Target SSH User:       {}\n\
             Primary Tool & Cmd:    {}\n\
             Working Directory:     {}",
            details_cloned.verified_host,
            details_cloned.target_ssh_user,
            details_cloned.primary_command,
            cwd_display,
        ));
        let expanded_info = to_wide(&format!(
            "Process Ancestry:  {}\n\
             SSH Key:           {}\n\
             Request ID:        {}",
            details_cloned.ancestry_chain, details_cloned.key_summary, details_cloned.request_id,
        ));
        let expanded_ctrl = to_wide("Hide process & key details");
        let collapsed_ctrl = to_wide("Show process & key details");
        let footer = to_wide("End-to-end Ed25519 signature verified against your user root key.");

        let btn1_text = to_wide(&format!(
            "Approve Once\nSign this single request for {}",
            details_cloned.primary_command
        ));
        let btn2_text = to_wide(&format!(
            "Approve '{}' on '{}' for 15 minutes\nAuto-approve matching requests in this session",
            details_cloned.primary_tool, details_cloned.verified_host
        ));
        let btn3_text = to_wide(&format!(
            "Approve all on '{}' for 15 minutes\nAuto-approve all tools on this host for this key & user",
            details_cloned.verified_host
        ));
        let btn4_text = to_wide("Deny (Esc)\nReject this signature request");

        let buttons = [
            TASKDIALOG_BUTTON {
                nButtonID: BTN_APPROVE_ONCE,
                pszButtonText: btn1_text.as_ptr(),
            },
            TASKDIALOG_BUTTON {
                nButtonID: BTN_APPROVE_TOOL_15M,
                pszButtonText: btn2_text.as_ptr(),
            },
            TASKDIALOG_BUTTON {
                nButtonID: BTN_APPROVE_HOST_15M,
                pszButtonText: btn3_text.as_ptr(),
            },
            TASKDIALOG_BUTTON {
                nButtonID: BTN_DENY,
                pszButtonText: btn4_text.as_ptr(),
            },
        ];

        let state_ptr = Arc::as_ptr(&state_for_dialog) as isize;

        let config = TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            hwndParent: null_mut(),
            hInstance: null_mut(),
            dwFlags: TDF_USE_COMMAND_LINKS
                | TDF_ALLOW_DIALOG_CANCELLATION
                | TDF_SIZE_TO_CONTENT
                | TDF_EXPANDED_BY_DEFAULT,
            dwCommonButtons: TDCBF_CANCEL_BUTTON,
            pszWindowTitle: window_title.as_ptr(),
            Anonymous1: TASKDIALOGCONFIG_0 {
                pszMainIcon: TD_SHIELD_ICON,
            },
            pszMainInstruction: main_instruction.as_ptr(),
            pszContent: content.as_ptr(),
            cButtons: buttons.len() as u32,
            pButtons: buttons.as_ptr(),
            nDefaultButton: BTN_APPROVE_ONCE,
            cRadioButtons: 0,
            pRadioButtons: null(),
            nDefaultRadioButton: 0,
            pszVerificationText: null(),
            pszExpandedInformation: expanded_info.as_ptr(),
            pszExpandedControlText: expanded_ctrl.as_ptr(),
            pszCollapsedControlText: collapsed_ctrl.as_ptr(),
            Anonymous2: TASKDIALOGCONFIG_1 {
                pszFooterIcon: TD_INFORMATION_ICON,
            },
            pszFooter: footer.as_ptr(),
            pfCallback: Some(task_dialog_callback),
            lpCallbackData: state_ptr,
            cxWidth: 0,
        };

        let mut selected_button: i32 = 0;
        let hr = TaskDialogIndirect(&config, &mut selected_button, null_mut(), null_mut());
        if hr != S_OK {
            return None;
        }
        Some(selected_button)
    })
    .await;

    let _ = done_tx.send(());
    cancel_task.abort();

    if cancel_rx.borrow().is_some() {
        return Some(ApprovalDecision::Deny);
    }

    let selected = join_res.ok()??;
    match selected {
        BTN_APPROVE_ONCE => Some(ApprovalDecision::ApproveOnce),
        BTN_APPROVE_TOOL_15M => Some(ApprovalDecision::ApproveToolOnHost15m),
        BTN_APPROVE_HOST_15M => Some(ApprovalDecision::ApproveAllOnHost15m),
        _ => Some(ApprovalDecision::Deny),
    }
}

/// Displays a native Windows error dialog.
pub fn show_tray_error_dialog(title: &str, instruction: &str, details: &str) {
    unsafe {
        let title_w = to_wide(title);
        let instr_w = to_wide(instruction);
        let details_w = to_wide(details);

        let config = TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            hwndParent: null_mut(),
            hInstance: null_mut(),
            dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT,
            dwCommonButtons: TDCBF_OK_BUTTON,
            pszWindowTitle: title_w.as_ptr(),
            Anonymous1: TASKDIALOGCONFIG_0 {
                pszMainIcon: TD_ERROR_ICON,
            },
            pszMainInstruction: instr_w.as_ptr(),
            pszContent: details_w.as_ptr(),
            cButtons: 0,
            pButtons: null(),
            nDefaultButton: 0,
            cRadioButtons: 0,
            pRadioButtons: null(),
            nDefaultRadioButton: 0,
            pszVerificationText: null(),
            pszExpandedInformation: null(),
            pszExpandedControlText: null(),
            pszCollapsedControlText: null(),
            Anonymous2: TASKDIALOGCONFIG_1 {
                hFooterIcon: null_mut(),
            },
            pszFooter: null(),
            pfCallback: None,
            lpCallbackData: 0,
            cxWidth: 0,
        };

        let mut btn: i32 = 0;
        let hr = TaskDialogIndirect(&config, &mut btn, null_mut(), null_mut());
        if hr != S_OK {
            let fallback_body = to_wide(&format!("{instruction}\n\n{details}"));
            MessageBoxW(
                null_mut(),
                fallback_body.as_ptr(),
                title_w.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}

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
    pub taskbar_created_msg: u32,
    pub hicon_raw: isize,
    pub tray_hwnd: AtomicIsize,
}

impl TraySharedContext {
    pub fn current_config(&self) -> Option<ClientConfig> {
        self.active_config.lock().ok().and_then(|g| g.clone())
    }
}

static TRAY_CONTEXT: Mutex<Option<Arc<TraySharedContext>>> = Mutex::new(None);

pub fn get_tray_context() -> Option<Arc<TraySharedContext>> {
    TRAY_CONTEXT
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().cloned())
}

/// Reloads `client.toml` from disk, updates the tray icon tooltip, and notifies the background
/// Tokio runtime in `sshcast-tray.exe` to reconnect to all configured coordinator backends.
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

        let hwnd = ctx.tray_hwnd.load(Ordering::Relaxed) as HWND;
        if !hwnd.is_null() {
            unsafe {
                let _ = add_or_update_tray_icon(hwnd, &ctx, true);
            }
        }
    }
}

unsafe fn load_tray_icon() -> HICON {
    let shield = LoadIconW(null_mut(), IDI_SHIELD);
    if !shield.is_null() {
        return shield;
    }
    LoadIconW(null_mut(), IDI_APPLICATION)
}

unsafe fn add_or_update_tray_icon(hwnd: HWND, ctx: &TraySharedContext, modify: bool) -> BOOL {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = ctx.hicon_raw as HICON;

    let tip = match ctx.current_config() {
        Some(cfg) => format!("Sshcast — {} ({})", cfg.grant.node_id, cfg.grant.user_id),
        None => "Sshcast — Not Enrolled (Click to Setup)".to_string(),
    };
    let tip_wide = to_wide(&tip);
    let copy_len = tip_wide.len().min(nid.szTip.len() - 1);
    nid.szTip[..copy_len].copy_from_slice(&tip_wide[..copy_len]);

    Shell_NotifyIconW(if modify { NIM_MODIFY } else { NIM_ADD }, &nid)
}

unsafe fn remove_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

fn spawn_status_dialog(ctx: Arc<TraySharedContext>) {
    let Some(cfg) = ctx.current_config() else {
        unsafe {
            show_enroll_window();
        }
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

        unsafe {
            let cert_str = match &cfg.grant.user_cert {
                Some(cert) => {
                    let op_hex = hex::encode(&cert.operator_pubkey);
                    let short_op = &op_hex[..12.min(op_hex.len())];
                    format!("Certified (sc_op_pub_{short_op}...)")
                }
                None => "None (static public key)".to_string(),
            };
            let title_w = to_wide("Sshcast Workstation Status");
            let instr_w = to_wide(&format!(
                "Workstation '{}' ({}/{total} coordinators connected)",
                cfg.grant.node_id, connected
            ));
            let content_w = to_wide(&format!(
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
            ));

            let config = TASKDIALOGCONFIG {
                cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
                hwndParent: null_mut(),
                hInstance: null_mut(),
                dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT,
                dwCommonButtons: TDCBF_OK_BUTTON,
                pszWindowTitle: title_w.as_ptr(),
                Anonymous1: TASKDIALOGCONFIG_0 {
                    pszMainIcon: TD_SHIELD_ICON,
                },
                pszMainInstruction: instr_w.as_ptr(),
                pszContent: content_w.as_ptr(),
                cButtons: 0,
                pButtons: null(),
                nDefaultButton: 0,
                cRadioButtons: 0,
                pRadioButtons: null(),
                nDefaultRadioButton: 0,
                pszVerificationText: null(),
                pszExpandedInformation: null(),
                pszExpandedControlText: null(),
                pszCollapsedControlText: null(),
                Anonymous2: TASKDIALOGCONFIG_1 {
                    hFooterIcon: null_mut(),
                },
                pszFooter: null(),
                pfCallback: None,
                lpCallbackData: 0,
                cxWidth: 0,
            };

            let mut btn: i32 = 0;
            let _ = TaskDialogIndirect(&config, &mut btn, null_mut(), null_mut());
        }

        ctx.status_dialog_open.store(false, Ordering::SeqCst);
    });
}

unsafe fn show_tray_context_menu(hwnd: HWND, ctx: &Arc<TraySharedContext>) {
    let hmenu = CreatePopupMenu();
    if hmenu.is_null() {
        return;
    }

    let maybe_cfg = ctx.current_config();
    let connected = ctx.connected_count.load(Ordering::Relaxed);
    let force_active = ctx.force_active_flag.load(Ordering::Relaxed);

    let header_str = match &maybe_cfg {
        Some(cfg) => format!("Sshcast: {} ({})", cfg.grant.node_id, cfg.grant.user_id),
        None => "Sshcast: Workstation Not Enrolled".to_string(),
    };
    let conn_str = match &maybe_cfg {
        Some(cfg) => format!("Coordinators: {connected}/{} connected", cfg.servers.len()),
        None => "Coordinators: 0/0 connected".to_string(),
    };

    let header_label = to_wide(&header_str);
    let conn_label = to_wide(&conn_str);
    let zellij_label = to_wide("Open Zellij Web Dashboard...");
    let status_label = to_wide("Workstation Status & SSH Keys...");
    let ssh_keys_label = to_wide("Manage SSH Keys (Built-in & OS Agent)...");
    let backends_label = to_wide("Coordinator Backends (Servers)...");
    let bundle_label = to_wide("Generate Enrollment Bundle (Relay / Client)...");
    let enroll_label = to_wide("Initialize / Enroll Workstation...");
    let force_label = to_wide("Force Active Workstation");
    let open_cfg_label = to_wide("Open Config Folder");
    let quit_label = to_wide("Quit Sshcast");

    AppendMenuW(hmenu, MF_STRING | MF_GRAYED, 0, header_label.as_ptr());
    AppendMenuW(hmenu, MF_STRING | MF_GRAYED, 0, conn_label.as_ptr());
    AppendMenuW(hmenu, MF_SEPARATOR, 0, null());

    let is_enrolled = maybe_cfg.is_some();
    let has_root_key = crate::config::UserKeyFile::load(None).is_ok();

    let enrolled_flags = if is_enrolled {
        MF_STRING
    } else {
        MF_STRING | MF_GRAYED
    };
    let bundle_flags = if is_enrolled && has_root_key {
        MF_STRING
    } else {
        MF_STRING | MF_GRAYED
    };

    AppendMenuW(
        hmenu,
        enrolled_flags,
        IDM_ZELLIJ_DASHBOARD as usize,
        zellij_label.as_ptr(),
    );
    AppendMenuW(
        hmenu,
        enrolled_flags,
        IDM_STATUS_DIALOG as usize,
        status_label.as_ptr(),
    );
    AppendMenuW(
        hmenu,
        MF_STRING,
        IDM_SSH_KEYS_WINDOW as usize,
        ssh_keys_label.as_ptr(),
    );
    AppendMenuW(
        hmenu,
        enrolled_flags,
        IDM_BACKENDS_WINDOW as usize,
        backends_label.as_ptr(),
    );
    AppendMenuW(
        hmenu,
        bundle_flags,
        IDM_BUNDLE_GENERATOR_WINDOW as usize,
        bundle_label.as_ptr(),
    );
    AppendMenuW(
        hmenu,
        MF_STRING,
        IDM_ENROLL_WINDOW as usize,
        enroll_label.as_ptr(),
    );
    AppendMenuW(hmenu, MF_SEPARATOR, 0, null());

    let mut force_flags = if force_active {
        MF_STRING | MF_CHECKED
    } else {
        MF_STRING | MF_UNCHECKED
    };
    if !is_enrolled {
        force_flags |= MF_GRAYED;
    }
    AppendMenuW(
        hmenu,
        force_flags,
        IDM_TOGGLE_FORCE_ACTIVE as usize,
        force_label.as_ptr(),
    );
    AppendMenuW(
        hmenu,
        MF_STRING,
        IDM_OPEN_CONFIG_DIR as usize,
        open_cfg_label.as_ptr(),
    );
    AppendMenuW(hmenu, MF_SEPARATOR, 0, null());
    AppendMenuW(hmenu, MF_STRING, IDM_QUIT as usize, quit_label.as_ptr());

    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);

    SetForegroundWindow(hwnd);
    let cmd = TrackPopupMenu(
        hmenu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
        pt.x,
        pt.y,
        0,
        hwnd,
        null(),
    ) as u32;
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(hmenu);

    match cmd {
        IDM_ZELLIJ_DASHBOARD => {
            let port = maybe_cfg
                .as_ref()
                .map(|c| c.zellij_listen_port)
                .unwrap_or(18080);
            crate::zellij_proxy::open_zellij_dashboard_in_browser(port);
        }
        IDM_STATUS_DIALOG => {
            spawn_status_dialog(Arc::clone(ctx));
        }
        IDM_SSH_KEYS_WINDOW => {
            show_ssh_keys_window();
        }
        IDM_BACKENDS_WINDOW => {
            show_backends_window();
        }
        IDM_BUNDLE_GENERATOR_WINDOW => {
            show_bundle_generator_window();
        }
        IDM_ENROLL_WINDOW => {
            show_enroll_window();
        }
        IDM_TOGGLE_FORCE_ACTIVE => {
            let prev = ctx.force_active_flag.fetch_xor(true, Ordering::SeqCst);
            tracing::info!("Toggled force_active to {}", !prev);
        }
        IDM_OPEN_CONFIG_DIR => {
            let _ = std::fs::create_dir_all(&ctx.config_dir);
            let _ = std::process::Command::new("explorer.exe")
                .arg(&ctx.config_dir)
                .spawn();
        }
        IDM_QUIT => {
            let _ = ctx.shutdown_tx.send(true);
            remove_tray_icon(hwnd);
            DestroyWindow(hwnd);
        }
        _ => {}
    }
}

unsafe extern "system" fn tray_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let maybe_ctx = get_tray_context();

    if let Some(ref ctx) = maybe_ctx {
        if ctx.taskbar_created_msg != 0 && msg == ctx.taskbar_created_msg {
            add_or_update_tray_icon(hwnd, ctx, false);
            return 0;
        }
    }

    match msg {
        WM_TRAYICON => {
            let event = (lparam as u32) & 0xFFFF;
            if let Some(ctx) = maybe_ctx {
                match event {
                    WM_RBUTTONUP | WM_LBUTTONUP => {
                        show_tray_context_menu(hwnd, &ctx);
                    }
                    WM_LBUTTONDBLCLK => {
                        if ctx.current_config().is_some() {
                            spawn_status_dialog(ctx);
                        } else {
                            show_enroll_window();
                        }
                    }
                    _ => {}
                }
            }
            0
        }
        WM_TRAY_SHUTDOWN => {
            remove_tray_icon(hwnd);
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            remove_tray_icon(hwnd);
            cleanup_dialog_fonts();
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Runs the native Win32 System Tray message loop on the main thread while `WorkstationManager`
/// runs on a background multi-threaded Tokio runtime.
#[allow(clippy::too_many_arguments)]
pub fn run_windows_tray_loop(
    config_path: Option<PathBuf>,
    agent_socket_override: Option<String>,
    initial_cfg: Option<ClientConfig>,
    force_active_flag: Arc<AtomicBool>,
    connected_count: Arc<AtomicUsize>,
    reload_tx: watch::Sender<u64>,
    shutdown_tx: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    unsafe {
        let hinstance = GetModuleHandleW(null());
        let class_name = to_wide("SshcastTrayHiddenWindowClass");
        let window_name = to_wide("Sshcast System Tray");
        let taskbar_created_name = to_wide("TaskbarCreated");
        let taskbar_created_msg = RegisterWindowMessageW(taskbar_created_name.as_ptr());
        let hicon = load_tray_icon();

        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(tray_wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: hicon,
            hCursor: null_mut(),
            hbrBackground: null_mut(),
            lpszMenuName: null(),
            lpszClassName: class_name.as_ptr(),
        };
        RegisterClassW(&wc);

        let is_unconfigured = initial_cfg.is_none();
        let config_dir = default_config_dir().unwrap_or_else(|_| PathBuf::from("."));
        let local_agent = Arc::new(match &initial_cfg {
            Some(cfg) => LocalAgentConnector::from_client_config(cfg, &[], false)
                .unwrap_or_else(|e| {
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
            taskbar_created_msg,
            hicon_raw: hicon as isize,
            tray_hwnd: AtomicIsize::new(0),
        });

        if let Ok(mut guard) = TRAY_CONTEXT.lock() {
            *guard = Some(Arc::clone(&ctx));
        }
        let _ = ctx.reload_tx.send(1);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            window_name.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            null_mut(),
            null_mut(),
            hinstance,
            null(),
        );
        if hwnd.is_null() {
            anyhow::bail!("CreateWindowExW failed for system tray message window");
        }
        ctx.tray_hwnd.store(hwnd as isize, Ordering::Relaxed);

        add_or_update_tray_icon(hwnd, &ctx, false);

        if is_unconfigured {
            show_enroll_window();
        }

        let hwnd_raw = hwnd as isize;
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            if let Ok(rt) = rt {
                rt.block_on(async move {
                    while shutdown_rx.changed().await.is_ok() {
                        if *shutdown_rx.borrow() {
                            PostMessageW(hwnd_raw as HWND, WM_TRAY_SHUTDOWN, 0, 0);
                            break;
                        }
                    }
                });
            }
        });

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if !is_any_management_dialog_message(&msg) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        if let Ok(mut guard) = TRAY_CONTEXT.lock() {
            *guard = None;
        }
    }
    Ok(())
}
