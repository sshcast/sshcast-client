use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
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

const BTN_APPROVE_ONCE: i32 = 101;
const BTN_APPROVE_TOOL_15M: i32 = 102;
const BTN_APPROVE_HOST_15M: i32 = 103;
const BTN_DENY: i32 = 104;

const WM_TRAYICON: u32 = WM_APP + 1;
const WM_TRAY_SHUTDOWN: u32 = WM_APP + 2;
const TRAY_ICON_ID: u32 = 1;

const IDM_STATUS_DIALOG: u32 = 1001;
const IDM_TOGGLE_FORCE_ACTIVE: u32 = 1002;
const IDM_OPEN_CONFIG_DIR: u32 = 1003;
const IDM_QUIT: u32 = 1004;

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
        let window_title = to_wide("Sockcast SSH Agent Approval");
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

/// Displays a native Windows error dialog (used by `sockcast-tray.exe` when startup fails).
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

struct TraySharedContext {
    node_id: String,
    user_id: String,
    servers: Vec<String>,
    config_dir: PathBuf,
    local_agent: Arc<LocalAgentConnector>,
    force_active_flag: Arc<AtomicBool>,
    connected_count: Arc<AtomicUsize>,
    shutdown_tx: watch::Sender<bool>,
    status_dialog_open: AtomicBool,
    taskbar_created_msg: u32,
    hicon_raw: isize,
}

static TRAY_CONTEXT: Mutex<Option<Arc<TraySharedContext>>> = Mutex::new(None);

unsafe fn load_tray_icon() -> HICON {
    let shield = LoadIconW(null_mut(), IDI_SHIELD);
    if !shield.is_null() {
        return shield;
    }
    LoadIconW(null_mut(), IDI_APPLICATION)
}

unsafe fn add_tray_icon(hwnd: HWND, ctx: &TraySharedContext) -> BOOL {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = ctx.hicon_raw as HICON;

    let tip = format!("Sockcast — {} ({})", ctx.node_id, ctx.user_id);
    let tip_wide = to_wide(&tip);
    let copy_len = tip_wide.len().min(nid.szTip.len() - 1);
    nid.szTip[..copy_len].copy_from_slice(&tip_wide[..copy_len]);

    Shell_NotifyIconW(NIM_ADD, &nid)
}

unsafe fn remove_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

fn spawn_status_dialog(ctx: Arc<TraySharedContext>) {
    if ctx.status_dialog_open.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let keys = match rt {
            Ok(rt) => rt
                .block_on(ctx.local_agent.list_filtered_keys())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        let connected = ctx.connected_count.load(Ordering::Relaxed);
        let total = ctx.servers.len();
        let force_active = ctx.force_active_flag.load(Ordering::Relaxed);

        let servers_str = ctx.servers.join("\n  • ");
        let keys_str = if keys.is_empty() {
            "  (No local SSH keys currently loaded or matching filter)".to_string()
        } else {
            keys.iter()
                .map(|k| {
                    if k.comment.is_empty() {
                        format!("  • {} ({})", k.fingerprint_sha256, k.key_type)
                    } else {
                        format!(
                            "  • {} ({} — {})",
                            k.fingerprint_sha256, k.key_type, k.comment
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        unsafe {
            let title_w = to_wide("Sockcast Workstation Status");
            let instr_w = to_wide(&format!(
                "Workstation '{}' ({}/{total} coordinators connected)",
                ctx.node_id, connected
            ));
            let content_w = to_wide(&format!(
                "User ID:             {}\n\
                 Force Active Mode:   {}\n\
                 Config Directory:    {}\n\n\
                 Coordinators:\n  • {}\n\n\
                 Exported Local SSH Keys ({}):\n{}",
                ctx.user_id,
                if force_active { "Enabled" } else { "Disabled (Automatic Idle Detection)" },
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

    let connected = ctx.connected_count.load(Ordering::Relaxed);
    let total = ctx.servers.len();
    let force_active = ctx.force_active_flag.load(Ordering::Relaxed);

    let header_label = to_wide(&format!(
        "Sockcast: {} ({})",
        ctx.node_id, ctx.user_id
    ));
    let conn_label = to_wide(&format!(
        "Coordinators: {connected}/{total} connected"
    ));
    let status_label = to_wide("Workstation Status & SSH Keys...");
    let force_label = to_wide("Force Active Workstation");
    let open_cfg_label = to_wide("Open Config Folder");
    let quit_label = to_wide("Quit Sockcast");

    AppendMenuW(hmenu, MF_STRING | MF_GRAYED, 0, header_label.as_ptr());
    AppendMenuW(hmenu, MF_STRING | MF_GRAYED, 0, conn_label.as_ptr());
    AppendMenuW(hmenu, MF_SEPARATOR, 0, null());
    AppendMenuW(
        hmenu,
        MF_STRING,
        IDM_STATUS_DIALOG as usize,
        status_label.as_ptr(),
    );
    let force_flags = if force_active {
        MF_STRING | MF_CHECKED
    } else {
        MF_STRING | MF_UNCHECKED
    };
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
        IDM_STATUS_DIALOG => {
            spawn_status_dialog(Arc::clone(ctx));
        }
        IDM_TOGGLE_FORCE_ACTIVE => {
            let prev = ctx.force_active_flag.fetch_xor(true, Ordering::SeqCst);
            tracing::info!("Toggled force_active to {}", !prev);
        }
        IDM_OPEN_CONFIG_DIR => {
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
    let maybe_ctx = TRAY_CONTEXT
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().cloned());

    if let Some(ref ctx) = maybe_ctx {
        if ctx.taskbar_created_msg != 0 && msg == ctx.taskbar_created_msg {
            add_tray_icon(hwnd, ctx);
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
                        spawn_status_dialog(ctx);
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
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// Runs the native Win32 System Tray message loop on the main thread while `WorkstationManager`
/// runs on a background multi-threaded Tokio runtime.
pub fn run_windows_tray_loop(
    cfg: &ClientConfig,
    local_agent: Arc<LocalAgentConnector>,
    force_active_flag: Arc<AtomicBool>,
    connected_count: Arc<AtomicUsize>,
    shutdown_tx: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    unsafe {
        let hinstance = GetModuleHandleW(null());
        let class_name = to_wide("SockcastTrayHiddenWindowClass");
        let window_name = to_wide("Sockcast System Tray");
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

        let config_dir = default_config_dir().unwrap_or_else(|_| PathBuf::from("."));
        let ctx = Arc::new(TraySharedContext {
            node_id: cfg.grant.node_id.clone(),
            user_id: cfg.grant.user_id.clone(),
            servers: cfg.servers.clone(),
            config_dir,
            local_agent,
            force_active_flag,
            connected_count,
            shutdown_tx,
            status_dialog_open: AtomicBool::new(false),
            taskbar_created_msg,
            hicon_raw: hicon as isize,
        });

        if let Ok(mut guard) = TRAY_CONTEXT.lock() {
            *guard = Some(Arc::clone(&ctx));
        }

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

        add_tray_icon(hwnd, &ctx);

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
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if let Ok(mut guard) = TRAY_CONTEXT.lock() {
            *guard = None;
        }
    }
    Ok(())
}
