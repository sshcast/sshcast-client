use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::sync::Mutex;

use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::v1::NodeRole;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, S_OK, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, GetDC, GetDeviceCaps, GetSysColorBrush, ReleaseDC,
    CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, COLOR_BTNFACE, DEFAULT_CHARSET, DEFAULT_PITCH,
    FF_DONTCARE, FW_NORMAL, FW_SEMIBOLD, HFONT, LOGPIXELSX, OUT_DEFAULT_PRECIS,
};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::UI::Controls::{
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOGCONFIG_1,
    TDCBF_CANCEL_BUTTON, TDCBF_YES_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION, TDF_SIZE_TO_CONTENT,
    TD_WARNING_ICON,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetDlgItem, GetSystemMetrics,
    GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW, IsWindow, LoadCursorW, LoadIconW,
    RegisterClassW, SendMessageW, SetForegroundWindow, SetWindowTextW, ShowWindow, IDC_ARROW,
    IDI_SHIELD, IDYES, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_RESTORE, SW_SHOW, WM_CLOSE, WM_COMMAND,
    WM_CREATE, WM_DESTROY, WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_GROUP,
    WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

use crate::config::{default_client_config_path, ClientConfigFile, UserKeyFile};
use crate::enroll::{
    load_user_signing_key, mint_enrollment_bundle, run_keygen, write_client_config_from_bundle,
};
use crate::win_native::{show_tray_error_dialog, TraySharedContext};

const ES_MULTILINE: u32 = 0x0004;
const ES_AUTOVSCROLL: u32 = 0x0040;
const ES_AUTOHSCROLL: u32 = 0x0080;
const ES_READONLY: u32 = 0x0800;

const BS_PUSHBUTTON: u32 = 0x0000;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const BS_GROUPBOX: u32 = 0x0007;
const BS_AUTORADIOBUTTON: u32 = 0x0009;

const LBS_NOTIFY: u32 = 0x0001;
const LB_ADDSTRING: u32 = 0x0180;
const LB_DELETESTRING: u32 = 0x0182;
const LB_RESETCONTENT: u32 = 0x0184;
const LB_SETCURSEL: u32 = 0x0186;
const LB_GETCURSEL: u32 = 0x0188;
const LB_GETTEXT: u32 = 0x0189;
const LB_GETTEXTLEN: u32 = 0x018A;
const LB_GETCOUNT: u32 = 0x018B;
const LB_ERR: isize = -1;

const BM_GETCHECK: u32 = 0x00F0;
const BM_SETCHECK: u32 = 0x00F1;
const BST_CHECKED: usize = 1;
const BN_CLICKED: u32 = 0;

const CF_UNICODETEXT: u32 = 13;

// Control IDs for Initialize / Enroll Window
const ID_ENROLL_ROOT_KEY_EDIT: i32 = 2001;
const ID_ENROLL_BTN_KEYGEN: i32 = 2002;
const ID_ENROLL_BTN_COPY_PUBKEY: i32 = 2003;
const ID_ENROLL_NODE_EDIT: i32 = 2004;
const ID_ENROLL_SERVERS_EDIT: i32 = 2005;
const ID_ENROLL_BTN_ENROLL_PRIMARY: i32 = 2006;
const ID_ENROLL_BTN_PASTE_BUNDLE: i32 = 2007;
const ID_ENROLL_BUNDLE_EDIT: i32 = 2008;
const ID_ENROLL_BTN_INIT_BUNDLE: i32 = 2009;
const ID_ENROLL_STATUS_LABEL: i32 = 2010;
const ID_ENROLL_BTN_CLOSE: i32 = 2011;

// Control IDs for Bundle Generator Window
const ID_BUNDLE_ROOT_PUBKEY_EDIT: i32 = 3001;
const ID_BUNDLE_BTN_KEYGEN: i32 = 3002;
const ID_BUNDLE_BTN_COPY_PUBKEY: i32 = 3003;
const ID_BUNDLE_RADIO_RELAY: i32 = 3004;
const ID_BUNDLE_RADIO_CLIENT: i32 = 3005;
const ID_BUNDLE_NODE_EDIT: i32 = 3006;
const ID_BUNDLE_EXPIRES_EDIT: i32 = 3007;
const ID_BUNDLE_SERVERS_EDIT: i32 = 3008;
const ID_BUNDLE_BTN_GENERATE: i32 = 3009;
const ID_BUNDLE_TOKEN_OUT_EDIT: i32 = 3010;
const ID_BUNDLE_BTN_COPY_TOKEN: i32 = 3011;
const ID_BUNDLE_CMD_OUT_EDIT: i32 = 3012;
const ID_BUNDLE_BTN_COPY_CMD: i32 = 3013;
const ID_BUNDLE_STATUS_LABEL: i32 = 3014;
const ID_BUNDLE_BTN_CLOSE: i32 = 3015;

// Control IDs for Coordinator Backends Window
const ID_BACKENDS_LISTBOX: i32 = 4001;
const ID_BACKENDS_BTN_REMOVE: i32 = 4002;
const ID_BACKENDS_ADD_EDIT: i32 = 4003;
const ID_BACKENDS_BTN_ADD: i32 = 4004;
const ID_BACKENDS_BTN_SAVE: i32 = 4005;
const ID_BACKENDS_STATUS_LABEL: i32 = 4006;
const ID_BACKENDS_BTN_CLOSE: i32 = 4007;

struct DialogHandles {
    enroll_hwnd: isize,
    bundle_hwnd: isize,
    backends_hwnd: isize,
    font_ui: isize,
    font_bold: isize,
    font_mono: isize,
}

static DIALOG_HANDLES: Mutex<DialogHandles> = Mutex::new(DialogHandles {
    enroll_hwnd: 0,
    bundle_hwnd: 0,
    backends_hwnd: 0,
    font_ui: 0,
    font_bold: 0,
    font_mono: 0,
});

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

unsafe fn get_dpi_scale() -> i32 {
    let hdc = GetDC(null_mut());
    if hdc.is_null() {
        return 96;
    }
    let dpi = GetDeviceCaps(hdc, LOGPIXELSX as i32).max(96);
    ReleaseDC(null_mut(), hdc);
    dpi
}

fn scale_px(px: i32, dpi: i32) -> i32 {
    (px * dpi + 48) / 96
}

unsafe fn ensure_dialog_fonts(dpi: i32) -> (HFONT, HFONT, HFONT) {
    let mut guard = DIALOG_HANDLES.lock().unwrap();
    if guard.font_ui == 0 {
        let segoe = to_wide("Segoe UI");
        let consolas = to_wide("Consolas");
        let ui_height = -scale_px(15, dpi);
        let mono_height = -scale_px(14, dpi);

        let f_ui = CreateFontW(
            ui_height,
            0,
            0,
            0,
            FW_NORMAL as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32,
            (DEFAULT_PITCH | FF_DONTCARE) as u32,
            segoe.as_ptr(),
        );
        let f_bold = CreateFontW(
            ui_height,
            0,
            0,
            0,
            FW_SEMIBOLD as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32,
            (DEFAULT_PITCH | FF_DONTCARE) as u32,
            segoe.as_ptr(),
        );
        let f_mono = CreateFontW(
            mono_height,
            0,
            0,
            0,
            FW_NORMAL as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32,
            (DEFAULT_PITCH | FF_DONTCARE) as u32,
            consolas.as_ptr(),
        );
        guard.font_ui = f_ui as isize;
        guard.font_bold = f_bold as isize;
        guard.font_mono = f_mono as isize;
    }
    (
        guard.font_ui as HFONT,
        guard.font_bold as HFONT,
        guard.font_mono as HFONT,
    )
}

pub unsafe fn cleanup_dialog_fonts() {
    if let Ok(mut guard) = DIALOG_HANDLES.lock() {
        if guard.font_ui != 0 {
            DeleteObject(guard.font_ui as _);
            guard.font_ui = 0;
        }
        if guard.font_bold != 0 {
            DeleteObject(guard.font_bold as _);
            guard.font_bold = 0;
        }
        if guard.font_mono != 0 {
            DeleteObject(guard.font_mono as _);
            guard.font_mono = 0;
        }
    }
}

pub unsafe fn is_any_management_dialog_message(msg: &MSG) -> bool {
    let (h1, h2, h3) = match DIALOG_HANDLES.lock() {
        Ok(g) => (g.enroll_hwnd as HWND, g.bundle_hwnd as HWND, g.backends_hwnd as HWND),
        Err(_) => return false,
    };
    if !h1.is_null() && IsWindow(h1) != 0 && IsDialogMessageW(h1, msg) != 0 {
        return true;
    }
    if !h2.is_null() && IsWindow(h2) != 0 && IsDialogMessageW(h2, msg) != 0 {
        return true;
    }
    if !h3.is_null() && IsWindow(h3) != 0 && IsDialogMessageW(h3, msg) != 0 {
        return true;
    }
    false
}

unsafe fn set_ctrl_font(hwnd_ctrl: HWND, font: HFONT) {
    SendMessageW(hwnd_ctrl, WM_SETFONT, font as WPARAM, 1);
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_child(
    parent: HWND,
    class_name: &str,
    text: &str,
    style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    let cls_w = to_wide(class_name);
    let txt_w = to_wide(text);
    let hinstance = GetModuleHandleW(null());
    let hwnd = CreateWindowExW(
        0,
        cls_w.as_ptr(),
        txt_w.as_ptr(),
        WS_CHILD | WS_VISIBLE | style,
        scale_px(x, dpi),
        scale_px(y, dpi),
        scale_px(w, dpi),
        scale_px(h, dpi),
        parent,
        id as isize as _,
        hinstance,
        null(),
    );
    if !hwnd.is_null() && !font.is_null() {
        set_ctrl_font(hwnd, font);
    }
    hwnd
}

unsafe fn get_dlg_item_string(hwnd: HWND, id: i32) -> String {
    let ctrl = GetDlgItem(hwnd, id);
    if ctrl.is_null() {
        return String::new();
    }
    let len = GetWindowTextLengthW(ctrl);
    if len <= 0 {
        return String::new();
    }
    let mut buf = vec![0u16; (len as usize) + 1];
    let read = GetWindowTextW(ctrl, buf.as_mut_ptr(), buf.len() as i32);
    if read <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..read as usize])
}

unsafe fn set_dlg_item_string(hwnd: HWND, id: i32, text: &str) {
    let ctrl = GetDlgItem(hwnd, id);
    if !ctrl.is_null() {
        let wide = to_wide(text);
        SetWindowTextW(ctrl, wide.as_ptr());
    }
}

pub unsafe fn copy_to_clipboard(owner: HWND, text: &str) -> bool {
    if OpenClipboard(owner) == 0 {
        return false;
    }
    EmptyClipboard();
    let wide = to_wide(text);
    let byte_len = wide.len() * std::mem::size_of::<u16>();
    let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
    if hmem.is_null() {
        CloseClipboard();
        return false;
    }
    let dst = GlobalLock(hmem) as *mut u16;
    if dst.is_null() {
        CloseClipboard();
        return false;
    }
    std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
    GlobalUnlock(hmem);
    let ok = !SetClipboardData(CF_UNICODETEXT, hmem).is_null();
    CloseClipboard();
    ok
}

pub unsafe fn paste_from_clipboard(owner: HWND) -> Option<String> {
    if OpenClipboard(owner) == 0 {
        return None;
    }
    let hmem = GetClipboardData(CF_UNICODETEXT);
    if hmem.is_null() {
        CloseClipboard();
        return None;
    }
    let ptr = GlobalLock(hmem) as *const u16;
    if ptr.is_null() {
        CloseClipboard();
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    let s = String::from_utf16_lossy(slice);
    GlobalUnlock(hmem);
    CloseClipboard();
    Some(s)
}

unsafe fn confirm_overwrite_dialog(parent: HWND, title: &str, instruction: &str, content: &str) -> bool {
    let title_w = to_wide(title);
    let instr_w = to_wide(instruction);
    let content_w = to_wide(content);

    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: parent,
        hInstance: null_mut(),
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT,
        dwCommonButtons: TDCBF_YES_BUTTON | TDCBF_CANCEL_BUTTON,
        pszWindowTitle: title_w.as_ptr(),
        Anonymous1: TASKDIALOGCONFIG_0 {
            pszMainIcon: TD_WARNING_ICON,
        },
        pszMainInstruction: instr_w.as_ptr(),
        pszContent: content_w.as_ptr(),
        cButtons: 0,
        pButtons: null(),
        nDefaultButton: IDYES,
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
    hr == S_OK && btn == IDYES
}

fn parse_servers_input(raw: &str) -> Vec<String> {
    raw.split([',', ';', '\n', '\r', ' '])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn format_root_key_allowlist() -> Option<String> {
    if let Ok((_, uk)) = UserKeyFile::load(None) {
        Some(format!(
            "allowed_user_pubkeys = [\"{}\"]",
            uk.user_pubkey_token
        ))
    } else {
        None
    }
}

fn default_workstation_node_name(ctx: &TraySharedContext) -> String {
    if let Some(cfg) = ctx.current_config() {
        if !cfg.grant.node_id.is_empty() {
            return cfg.grant.node_id;
        }
    }
    std::env::var("COMPUTERNAME")
        .unwrap_or_else(|_| "workstation".to_string())
        .to_lowercase()
}

fn default_servers_csv(ctx: &TraySharedContext) -> String {
    if let Some(cfg) = ctx.current_config() {
        if !cfg.servers.is_empty() {
            return cfg.servers.join(", ");
        }
    }
    "https://sockcast.stingr.net".to_string()
}

// ============================================================================
// 1. INITIALIZE / ENROLL WORKSTATION WINDOW
// ============================================================================

unsafe extern "system" fn enroll_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let (font_ui, font_bold, font_mono) = ensure_dialog_fonts(dpi);
            let maybe_ctx = crate::win_native::get_tray_context();

            // Group A: Primary Enrollment
            create_child(
                hwnd,
                "BUTTON",
                "Option A — Enroll Primary Workstation (Using Local Root Key)",
                BS_GROUPBOX,
                16,
                12,
                628,
                274,
                0,
                dpi,
                font_bold,
            );
            create_child(
                hwnd,
                "STATIC",
                "User Root Key (server.toml allowlist entry):",
                0,
                32,
                38,
                400,
                20,
                0,
                dpi,
                font_ui,
            );
            let root_str = format_root_key_allowlist().unwrap_or_else(|| {
                "<No user_key.toml yet — click 'Generate Key' or 'Enroll This Workstation'>".to_string()
            });
            create_child(
                hwnd,
                "EDIT",
                &root_str,
                ES_AUTOHSCROLL | ES_READONLY | WS_BORDER | WS_TABSTOP,
                32,
                60,
                390,
                26,
                ID_ENROLL_ROOT_KEY_EDIT,
                dpi,
                font_mono,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Generate Key",
                BS_PUSHBUTTON | WS_TABSTOP,
                430,
                58,
                100,
                30,
                ID_ENROLL_BTN_KEYGEN,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Copy Allowlist",
                BS_PUSHBUTTON | WS_TABSTOP,
                536,
                58,
                94,
                30,
                ID_ENROLL_BTN_COPY_PUBKEY,
                dpi,
                font_ui,
            );

            create_child(
                hwnd,
                "STATIC",
                "Workstation Node Name (e.g. bandura, laptop-win):",
                0,
                32,
                98,
                450,
                20,
                0,
                dpi,
                font_ui,
            );
            let node_default = maybe_ctx
                .as_ref()
                .map(|c| default_workstation_node_name(c))
                .unwrap_or_else(|| "workstation".to_string());
            create_child(
                hwnd,
                "EDIT",
                &node_default,
                ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                32,
                120,
                598,
                26,
                ID_ENROLL_NODE_EDIT,
                dpi,
                font_ui,
            );

            create_child(
                hwnd,
                "STATIC",
                "Coordinator Backend URL(s) (comma-separated, e.g. https://sockcast.stingr.net):",
                0,
                32,
                156,
                598,
                20,
                0,
                dpi,
                font_ui,
            );
            let servers_default = maybe_ctx
                .as_ref()
                .map(|c| default_servers_csv(c))
                .unwrap_or_else(|| "https://sockcast.stingr.net".to_string());
            create_child(
                hwnd,
                "EDIT",
                &servers_default,
                ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                32,
                178,
                598,
                26,
                ID_ENROLL_SERVERS_EDIT,
                dpi,
                font_mono,
            );

            create_child(
                hwnd,
                "BUTTON",
                "Enroll This Workstation (Mint Grant & Save client.toml)",
                BS_DEFPUSHBUTTON | WS_TABSTOP,
                32,
                220,
                598,
                36,
                ID_ENROLL_BTN_ENROLL_PRIMARY,
                dpi,
                font_bold,
            );

            // Group B: Init from Bundle
            create_child(
                hwnd,
                "BUTTON",
                "Option B — Initialize Workstation from Enrollment Bundle (sc1_...)",
                BS_GROUPBOX,
                16,
                298,
                628,
                198,
                0,
                dpi,
                font_bold,
            );
            create_child(
                hwnd,
                "STATIC",
                "Paste an sc1_<base64> Client Enrollment Bundle minted on another machine:",
                0,
                32,
                326,
                460,
                20,
                0,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Paste Clipboard",
                BS_PUSHBUTTON | WS_TABSTOP,
                500,
                320,
                130,
                28,
                ID_ENROLL_BTN_PASTE_BUNDLE,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "EDIT",
                "",
                ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER | WS_TABSTOP,
                32,
                354,
                598,
                76,
                ID_ENROLL_BUNDLE_EDIT,
                dpi,
                font_mono,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Initialize Workstation from Bundle",
                BS_PUSHBUTTON | WS_TABSTOP,
                32,
                442,
                598,
                36,
                ID_ENROLL_BTN_INIT_BUNDLE,
                dpi,
                font_bold,
            );

            // Status & Close
            create_child(
                hwnd,
                "STATIC",
                "Ready.",
                0,
                18,
                510,
                490,
                24,
                ID_ENROLL_STATUS_LABEL,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Close",
                BS_PUSHBUTTON | WS_TABSTOP,
                524,
                506,
                120,
                32,
                ID_ENROLL_BTN_CLOSE,
                dpi,
                font_ui,
            );
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            let code = ((wparam >> 16) & 0xFFFF) as u32;
            if code == BN_CLICKED {
                match id {
                    ID_ENROLL_BTN_KEYGEN => {
                        let exists = format_root_key_allowlist().is_some();
                        if exists
                            && !confirm_overwrite_dialog(
                                hwnd,
                                "Overwrite User Root Key?",
                                "A user root key (user_key.toml) already exists.",
                                "Generating a new user root key will invalidate previous allowlist entries unless you update server.toml. Overwrite user_key.toml?",
                            )
                        {
                            return 0;
                        }
                        match run_keygen(None, true) {
                            Ok(out) => {
                                let allow = format!(
                                    "allowed_user_pubkeys = [\"{}\"]",
                                    out.user_pubkey_token
                                );
                                set_dlg_item_string(hwnd, ID_ENROLL_ROOT_KEY_EDIT, &allow);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_ENROLL_STATUS_LABEL,
                                    &format!("Generated root key (User ID: {}).", out.user_id),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Keygen Failed",
                                    "Failed to generate user_key.toml",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_ENROLL_BTN_COPY_PUBKEY => {
                        if let Some(allow) = format_root_key_allowlist() {
                            if copy_to_clipboard(hwnd, &allow) {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_ENROLL_STATUS_LABEL,
                                    "Copied allowed_user_pubkeys line to clipboard!",
                                );
                            }
                        } else {
                            set_dlg_item_string(
                                hwnd,
                                ID_ENROLL_STATUS_LABEL,
                                "Generate a root key first before copying.",
                            );
                        }
                    }
                    ID_ENROLL_BTN_ENROLL_PRIMARY => {
                        let node_name = get_dlg_item_string(hwnd, ID_ENROLL_NODE_EDIT);
                        let servers_raw = get_dlg_item_string(hwnd, ID_ENROLL_SERVERS_EDIT);
                        let servers = parse_servers_input(&servers_raw);
                        if node_name.trim().is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Workstation Node Name is required",
                                "Please enter a workstation identifier (e.g. 'bandura').",
                            );
                            return 0;
                        }
                        if servers.is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "At least one Coordinator Server URL is required",
                                "Please enter your coordinator URL (e.g. 'https://sockcast.stingr.net').",
                            );
                            return 0;
                        }

                        // Auto-create user_key.toml if not present yet
                        if format_root_key_allowlist().is_none() {
                            if let Err(e) = run_keygen(None, false) {
                                show_tray_error_dialog(
                                    "Keygen Failed",
                                    "Failed to create user_key.toml",
                                    &format!("{e:#}"),
                                );
                                return 0;
                            }
                            if let Some(allow) = format_root_key_allowlist() {
                                set_dlg_item_string(hwnd, ID_ENROLL_ROOT_KEY_EDIT, &allow);
                            }
                        }

                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());

                        if let Some(ref p) = cfg_path {
                            if p.exists()
                                && !confirm_overwrite_dialog(
                                    hwnd,
                                    "Overwrite Existing Workstation Config?",
                                    "A client.toml file already exists for this workstation.",
                                    &format!("Do you want to overwrite {} and re-enroll as '{}'?", p.display(), node_name.trim()),
                                )
                            {
                                return 0;
                            }
                        }

                        let res = (|| -> anyhow::Result<std::path::PathBuf> {
                            let user_sk = load_user_signing_key(None)?;
                            let bundle = mint_enrollment_bundle(
                                &user_sk,
                                node_name.trim(),
                                NodeRole::Client,
                                servers,
                                0,
                            )?;
                            write_client_config_from_bundle(&bundle, cfg_path.as_deref(), true)
                        })();

                        match res {
                            Ok(path) => {
                                crate::win_native::reload_tray_configuration();
                                set_dlg_item_string(
                                    hwnd,
                                    ID_ENROLL_STATUS_LABEL,
                                    &format!(
                                        "Enrolled '{}' and saved {} — reconnecting now!",
                                        node_name.trim(),
                                        path.display()
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Enrollment Failed",
                                    "Failed to enroll workstation",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_ENROLL_BTN_PASTE_BUNDLE => {
                        if let Some(clip) = paste_from_clipboard(hwnd) {
                            // Extract sc1_ token if the user copied a full CLI command
                            let token = clip
                                .split_whitespace()
                                .find(|w| w.starts_with("sc1_"))
                                .unwrap_or(clip.trim());
                            set_dlg_item_string(hwnd, ID_ENROLL_BUNDLE_EDIT, token);
                            set_dlg_item_string(
                                hwnd,
                                ID_ENROLL_STATUS_LABEL,
                                "Pasted bundle token from clipboard.",
                            );
                        }
                    }
                    ID_ENROLL_BTN_INIT_BUNDLE => {
                        let raw_input = get_dlg_item_string(hwnd, ID_ENROLL_BUNDLE_EDIT);
                        let token = raw_input
                            .split_whitespace()
                            .find(|w| w.starts_with("sc1_"))
                            .unwrap_or(raw_input.trim());
                        if token.is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Enrollment Bundle is empty",
                                "Please paste an sc1_<base64> client enrollment bundle first.",
                            );
                            return 0;
                        }

                        let decoded = match EnrollmentBundle::decode(token) {
                            Ok(b) => b,
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Invalid Bundle",
                                    "Failed to decode sc1_ enrollment bundle",
                                    &format!("{e:#}"),
                                );
                                return 0;
                            }
                        };

                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());

                        if let Some(ref p) = cfg_path {
                            if p.exists()
                                && !confirm_overwrite_dialog(
                                    hwnd,
                                    "Overwrite Existing Workstation Config?",
                                    "A client.toml file already exists for this workstation.",
                                    &format!(
                                        "Overwrite {} with bundle for workstation '{}'?",
                                        p.display(),
                                        decoded.grant.node_id
                                    ),
                                )
                            {
                                return 0;
                            }
                        }

                        match write_client_config_from_bundle(&decoded, cfg_path.as_deref(), true) {
                            Ok(path) => {
                                crate::win_native::reload_tray_configuration();
                                set_dlg_item_string(
                                    hwnd,
                                    ID_ENROLL_STATUS_LABEL,
                                    &format!(
                                        "Initialized workstation '{}' ({}) — reconnecting now!",
                                        decoded.grant.node_id,
                                        path.display()
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Initialization Failed",
                                    "Failed to write client.toml from bundle",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_ENROLL_BTN_CLOSE => {
                        DestroyWindow(hwnd);
                    }
                    _ => {}
                }
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            if let Ok(mut g) = DIALOG_HANDLES.lock() {
                if g.enroll_hwnd == hwnd as isize {
                    g.enroll_hwnd = 0;
                }
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe fn show_enroll_window() {
    {
        let g = DIALOG_HANDLES.lock().unwrap();
        let existing = g.enroll_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SockcastEnrollWndClass");
    let title = to_wide("Sockcast — Initialize / Enroll Workstation");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(enroll_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let w = scale_px(676, dpi);
    let h = scale_px(585, dpi);
    let x = (GetSystemMetrics(SM_CXSCREEN) - w).max(0) / 2;
    let y = (GetSystemMetrics(SM_CYSCREEN) - h).max(0) / 2;

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        title.as_ptr(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
        x,
        y,
        w,
        h,
        null_mut(),
        null_mut(),
        hinstance,
        null(),
    );
    if !hwnd.is_null() {
        DIALOG_HANDLES.lock().unwrap().enroll_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

// ============================================================================
// 2. GENERATE ENROLLMENT BUNDLE (RELAY / CLIENT) WINDOW
// ============================================================================

unsafe extern "system" fn bundle_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let (font_ui, font_bold, font_mono) = ensure_dialog_fonts(dpi);
            let maybe_ctx = crate::win_native::get_tray_context();

            // Group 1: Root Key
            create_child(
                hwnd,
                "BUTTON",
                "User Root Key (for /etc/sockcast/server.toml allowed_user_pubkeys)",
                BS_GROUPBOX,
                16,
                12,
                628,
                84,
                0,
                dpi,
                font_bold,
            );
            let root_str = format_root_key_allowlist().unwrap_or_else(|| {
                "<No user_key.toml yet — click 'Generate Key' to create one>".to_string()
            });
            create_child(
                hwnd,
                "EDIT",
                &root_str,
                ES_AUTOHSCROLL | ES_READONLY | WS_BORDER | WS_TABSTOP,
                32,
                42,
                390,
                26,
                ID_BUNDLE_ROOT_PUBKEY_EDIT,
                dpi,
                font_mono,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Generate Key",
                BS_PUSHBUTTON | WS_TABSTOP,
                430,
                40,
                100,
                30,
                ID_BUNDLE_BTN_KEYGEN,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Copy Allowlist",
                BS_PUSHBUTTON | WS_TABSTOP,
                536,
                40,
                94,
                30,
                ID_BUNDLE_BTN_COPY_PUBKEY,
                dpi,
                font_ui,
            );

            // Group 2: Mint Parameters
            create_child(
                hwnd,
                "BUTTON",
                "Mint Signed Enrollment Bundle (sc1_...)",
                BS_GROUPBOX,
                16,
                108,
                628,
                222,
                0,
                dpi,
                font_bold,
            );
            create_child(
                hwnd,
                "STATIC",
                "Target Role:",
                0,
                32,
                136,
                90,
                20,
                0,
                dpi,
                font_ui,
            );
            let r_relay = create_child(
                hwnd,
                "BUTTON",
                "Remote Linux Relay (sockcast-relay)",
                BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP,
                126,
                134,
                258,
                22,
                ID_BUNDLE_RADIO_RELAY,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Secondary Workstation (sockcast-client)",
                BS_AUTORADIOBUTTON | WS_TABSTOP,
                392,
                134,
                244,
                22,
                ID_BUNDLE_RADIO_CLIENT,
                dpi,
                font_ui,
            );
            SendMessageW(r_relay, BM_SETCHECK, BST_CHECKED, 0);

            create_child(
                hwnd,
                "STATIC",
                "Target Hostname / Node ID (must match /proc hostname on relays):",
                0,
                32,
                166,
                444,
                20,
                0,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "STATIC",
                "Expires (days, 0=never):",
                0,
                486,
                166,
                148,
                20,
                0,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "EDIT",
                "",
                ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                32,
                188,
                444,
                26,
                ID_BUNDLE_NODE_EDIT,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "EDIT",
                "0",
                ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                486,
                188,
                144,
                26,
                ID_BUNDLE_EXPIRES_EDIT,
                dpi,
                font_ui,
            );

            create_child(
                hwnd,
                "STATIC",
                "Coordinator Backend URL(s) (comma-separated):",
                0,
                32,
                224,
                598,
                20,
                0,
                dpi,
                font_ui,
            );
            let servers_default = maybe_ctx
                .as_ref()
                .map(|c| default_servers_csv(c))
                .unwrap_or_else(|| "https://sockcast.stingr.net".to_string());
            create_child(
                hwnd,
                "EDIT",
                &servers_default,
                ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                32,
                246,
                598,
                26,
                ID_BUNDLE_SERVERS_EDIT,
                dpi,
                font_mono,
            );

            create_child(
                hwnd,
                "BUTTON",
                "Generate Signed Enrollment Bundle",
                BS_DEFPUSHBUTTON | WS_TABSTOP,
                32,
                282,
                598,
                36,
                ID_BUNDLE_BTN_GENERATE,
                dpi,
                font_bold,
            );

            // Group 3: Output & Copy
            create_child(
                hwnd,
                "BUTTON",
                "Generated Bundle Token & Ready-to-Run Command",
                BS_GROUPBOX,
                16,
                342,
                628,
                166,
                0,
                dpi,
                font_bold,
            );
            create_child(
                hwnd,
                "STATIC",
                "Raw Enrollment Token (sc1_...):",
                0,
                32,
                370,
                380,
                20,
                0,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Copy Bundle Token",
                BS_PUSHBUTTON | WS_TABSTOP,
                480,
                364,
                150,
                28,
                ID_BUNDLE_BTN_COPY_TOKEN,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "EDIT",
                "",
                ES_AUTOHSCROLL | ES_READONLY | WS_BORDER | WS_TABSTOP,
                32,
                394,
                598,
                26,
                ID_BUNDLE_TOKEN_OUT_EDIT,
                dpi,
                font_mono,
            );

            create_child(
                hwnd,
                "STATIC",
                "Ready-to-Run CLI Command:",
                0,
                32,
                432,
                380,
                20,
                0,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Copy CLI Command",
                BS_PUSHBUTTON | WS_TABSTOP,
                480,
                426,
                150,
                28,
                ID_BUNDLE_BTN_COPY_CMD,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "EDIT",
                "",
                ES_AUTOHSCROLL | ES_READONLY | WS_BORDER | WS_TABSTOP,
                32,
                456,
                598,
                26,
                ID_BUNDLE_CMD_OUT_EDIT,
                dpi,
                font_mono,
            );

            // Status & Close
            create_child(
                hwnd,
                "STATIC",
                "Enter target hostname and click 'Generate Signed Enrollment Bundle'.",
                0,
                18,
                520,
                490,
                24,
                ID_BUNDLE_STATUS_LABEL,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Close",
                BS_PUSHBUTTON | WS_TABSTOP,
                524,
                516,
                120,
                32,
                ID_BUNDLE_BTN_CLOSE,
                dpi,
                font_ui,
            );
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            let code = ((wparam >> 16) & 0xFFFF) as u32;
            if code == BN_CLICKED {
                match id {
                    ID_BUNDLE_BTN_KEYGEN => {
                        let exists = format_root_key_allowlist().is_some();
                        if exists
                            && !confirm_overwrite_dialog(
                                hwnd,
                                "Overwrite User Root Key?",
                                "A user root key (user_key.toml) already exists.",
                                "Generating a new user root key will invalidate previous allowlist entries unless you update server.toml. Overwrite user_key.toml?",
                            )
                        {
                            return 0;
                        }
                        match run_keygen(None, true) {
                            Ok(out) => {
                                let allow = format!(
                                    "allowed_user_pubkeys = [\"{}\"]",
                                    out.user_pubkey_token
                                );
                                set_dlg_item_string(hwnd, ID_BUNDLE_ROOT_PUBKEY_EDIT, &allow);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_BUNDLE_STATUS_LABEL,
                                    &format!("Generated root key (User ID: {}).", out.user_id),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Keygen Failed",
                                    "Failed to generate user_key.toml",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_BUNDLE_BTN_COPY_PUBKEY => {
                        if let Some(allow) = format_root_key_allowlist() {
                            if copy_to_clipboard(hwnd, &allow) {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_BUNDLE_STATUS_LABEL,
                                    "Copied allowed_user_pubkeys line to clipboard!",
                                );
                            }
                        } else {
                            set_dlg_item_string(
                                hwnd,
                                ID_BUNDLE_STATUS_LABEL,
                                "Generate a root key first before copying.",
                            );
                        }
                    }
                    ID_BUNDLE_BTN_GENERATE => {
                        let node_name = get_dlg_item_string(hwnd, ID_BUNDLE_NODE_EDIT);
                        let expires_str = get_dlg_item_string(hwnd, ID_BUNDLE_EXPIRES_EDIT);
                        let servers_raw = get_dlg_item_string(hwnd, ID_BUNDLE_SERVERS_EDIT);
                        let servers = parse_servers_input(&servers_raw);

                        if node_name.trim().is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Target Hostname / Node ID is required",
                                "Enter the relay hostname (e.g. 'server-x.infra.local') or workstation name.",
                            );
                            return 0;
                        }
                        if servers.is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "At least one Coordinator URL is required",
                                "Enter at least one coordinator URL (e.g. 'https://sockcast.stingr.net').",
                            );
                            return 0;
                        }
                        let expires_days: u64 = match expires_str.trim().parse() {
                            Ok(v) => v,
                            Err(_) => {
                                show_tray_error_dialog(
                                    "Validation Error",
                                    "Invalid Expiration Days",
                                    "Expiration days must be a non-negative integer (0 = never expires).",
                                );
                                return 0;
                            }
                        };

                        if format_root_key_allowlist().is_none() {
                            if let Err(e) = run_keygen(None, false) {
                                show_tray_error_dialog(
                                    "Keygen Failed",
                                    "Failed to generate user_key.toml",
                                    &format!("{e:#}"),
                                );
                                return 0;
                            }
                            if let Some(allow) = format_root_key_allowlist() {
                                set_dlg_item_string(hwnd, ID_BUNDLE_ROOT_PUBKEY_EDIT, &allow);
                            }
                        }

                        let relay_radio = GetDlgItem(hwnd, ID_BUNDLE_RADIO_RELAY);
                        let is_relay =
                            SendMessageW(relay_radio, BM_GETCHECK, 0, 0) as usize == BST_CHECKED;
                        let role = if is_relay {
                            NodeRole::Relay
                        } else {
                            NodeRole::Client
                        };

                        let res = (|| -> anyhow::Result<String> {
                            let user_sk = load_user_signing_key(None)?;
                            let bundle = mint_enrollment_bundle(
                                &user_sk,
                                node_name.trim(),
                                role,
                                servers,
                                expires_days,
                            )?;
                            Ok(bundle.encode()?)
                        })();

                        match res {
                            Ok(token) => {
                                let cli_cmd = if is_relay {
                                    format!("sockcast-relay init --bundle {token}")
                                } else {
                                    format!("sockcast-client init --bundle {token}")
                                };
                                set_dlg_item_string(hwnd, ID_BUNDLE_TOKEN_OUT_EDIT, &token);
                                set_dlg_item_string(hwnd, ID_BUNDLE_CMD_OUT_EDIT, &cli_cmd);
                                let _ = copy_to_clipboard(hwnd, &cli_cmd);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_BUNDLE_STATUS_LABEL,
                                    &format!(
                                        "Minted bundle for '{}' and copied CLI command to clipboard!",
                                        node_name.trim()
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Bundle Generation Failed",
                                    "Failed to mint enrollment bundle",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_BUNDLE_BTN_COPY_TOKEN => {
                        let tok = get_dlg_item_string(hwnd, ID_BUNDLE_TOKEN_OUT_EDIT);
                        if !tok.is_empty() && copy_to_clipboard(hwnd, &tok) {
                            set_dlg_item_string(
                                hwnd,
                                ID_BUNDLE_STATUS_LABEL,
                                "Copied sc1_ bundle token to clipboard!",
                            );
                        }
                    }
                    ID_BUNDLE_BTN_COPY_CMD => {
                        let cmd = get_dlg_item_string(hwnd, ID_BUNDLE_CMD_OUT_EDIT);
                        if !cmd.is_empty() && copy_to_clipboard(hwnd, &cmd) {
                            set_dlg_item_string(
                                hwnd,
                                ID_BUNDLE_STATUS_LABEL,
                                "Copied CLI command to clipboard!",
                            );
                        }
                    }
                    ID_BUNDLE_BTN_CLOSE => {
                        DestroyWindow(hwnd);
                    }
                    _ => {}
                }
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            if let Ok(mut g) = DIALOG_HANDLES.lock() {
                if g.bundle_hwnd == hwnd as isize {
                    g.bundle_hwnd = 0;
                }
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe fn show_bundle_generator_window() {
    {
        let g = DIALOG_HANDLES.lock().unwrap();
        let existing = g.bundle_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SockcastBundleWndClass");
    let title = to_wide("Sockcast — Generate Enrollment Bundle (Relay / Workstation)");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(bundle_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let w = scale_px(676, dpi);
    let h = scale_px(596, dpi);
    let x = (GetSystemMetrics(SM_CXSCREEN) - w).max(0) / 2;
    let y = (GetSystemMetrics(SM_CYSCREEN) - h).max(0) / 2;

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        title.as_ptr(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
        x,
        y,
        w,
        h,
        null_mut(),
        null_mut(),
        hinstance,
        null(),
    );
    if !hwnd.is_null() {
        DIALOG_HANDLES.lock().unwrap().bundle_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

// ============================================================================
// 3. MANAGE COORDINATOR BACKENDS (SERVERS) WINDOW
// ============================================================================

unsafe fn listbox_get_items(lb: HWND) -> Vec<String> {
    let count = SendMessageW(lb, LB_GETCOUNT, 0, 0);
    if count <= 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let len = SendMessageW(lb, LB_GETTEXTLEN, i as usize, 0);
        if len >= 0 {
            let mut buf = vec![0u16; (len as usize) + 1];
            let actual = SendMessageW(lb, LB_GETTEXT, i as usize, buf.as_mut_ptr() as isize);
            if actual >= 0 {
                let s = String::from_utf16_lossy(&buf[..actual as usize]);
                if !s.trim().is_empty() {
                    out.push(s.trim().to_string());
                }
            }
        }
    }
    out
}

unsafe extern "system" fn backends_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let (font_ui, font_bold, font_mono) = ensure_dialog_fonts(dpi);
            let maybe_ctx = crate::win_native::get_tray_context();

            create_child(
                hwnd,
                "BUTTON",
                "Configured Coordinator Backend Servers (client.toml)",
                BS_GROUPBOX,
                16,
                12,
                528,
                320,
                0,
                dpi,
                font_bold,
            );
            create_child(
                hwnd,
                "STATIC",
                "Active Coordinator gRPC URLs (Workstation connects to all concurrently):",
                0,
                32,
                38,
                496,
                20,
                0,
                dpi,
                font_ui,
            );
            let lb = create_child(
                hwnd,
                "LISTBOX",
                "",
                WS_BORDER | WS_VSCROLL | LBS_NOTIFY | WS_TABSTOP,
                32,
                62,
                368,
                140,
                ID_BACKENDS_LISTBOX,
                dpi,
                font_mono,
            );
            if let Some(ref ctx) = maybe_ctx {
                if let Some(cfg) = ctx.current_config() {
                    for srv in &cfg.servers {
                        let w = to_wide(srv);
                        SendMessageW(lb, LB_ADDSTRING, 0, w.as_ptr() as isize);
                    }
                    if !cfg.servers.is_empty() {
                        SendMessageW(lb, LB_SETCURSEL, 0, 0);
                    }
                }
            }

            create_child(
                hwnd,
                "BUTTON",
                "Remove Selected",
                BS_PUSHBUTTON | WS_TABSTOP,
                410,
                62,
                118,
                32,
                ID_BACKENDS_BTN_REMOVE,
                dpi,
                font_ui,
            );

            create_child(
                hwnd,
                "STATIC",
                "Add Coordinator Server URL (http:// or https://):",
                0,
                32,
                210,
                496,
                20,
                0,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "EDIT",
                "https://",
                ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
                32,
                232,
                368,
                28,
                ID_BACKENDS_ADD_EDIT,
                dpi,
                font_mono,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Add Server",
                BS_PUSHBUTTON | WS_TABSTOP,
                410,
                230,
                118,
                30,
                ID_BACKENDS_BTN_ADD,
                dpi,
                font_ui,
            );

            create_child(
                hwnd,
                "BUTTON",
                "Save Backends & Reconnect Now",
                BS_DEFPUSHBUTTON | WS_TABSTOP,
                32,
                278,
                496,
                38,
                ID_BACKENDS_BTN_SAVE,
                dpi,
                font_bold,
            );

            create_child(
                hwnd,
                "STATIC",
                "Add or remove coordinator URLs, then click 'Save Backends & Reconnect Now'.",
                0,
                18,
                344,
                394,
                24,
                ID_BACKENDS_STATUS_LABEL,
                dpi,
                font_ui,
            );
            create_child(
                hwnd,
                "BUTTON",
                "Close",
                BS_PUSHBUTTON | WS_TABSTOP,
                424,
                340,
                120,
                32,
                ID_BACKENDS_BTN_CLOSE,
                dpi,
                font_ui,
            );
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            let code = ((wparam >> 16) & 0xFFFF) as u32;
            if code == BN_CLICKED {
                let lb = GetDlgItem(hwnd, ID_BACKENDS_LISTBOX);
                match id {
                    ID_BACKENDS_BTN_ADD => {
                        let raw = get_dlg_item_string(hwnd, ID_BACKENDS_ADD_EDIT);
                        let trimmed = raw.trim();
                        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://")
                            || trimmed.len() <= 8
                        {
                            show_tray_error_dialog(
                                "Invalid Server URL",
                                "Coordinator URL must start with http:// or https://",
                                "Example: https://sockcast.stingr.net",
                            );
                            return 0;
                        }
                        let existing = listbox_get_items(lb);
                        if existing.iter().any(|s| s.eq_ignore_ascii_case(trimmed)) {
                            set_dlg_item_string(
                                hwnd,
                                ID_BACKENDS_STATUS_LABEL,
                                "That coordinator URL is already in the list.",
                            );
                            return 0;
                        }
                        let w = to_wide(trimmed);
                        let idx = SendMessageW(lb, LB_ADDSTRING, 0, w.as_ptr() as isize);
                        SendMessageW(lb, LB_SETCURSEL, idx as usize, 0);
                        set_dlg_item_string(hwnd, ID_BACKENDS_ADD_EDIT, "https://");
                        set_dlg_item_string(
                            hwnd,
                            ID_BACKENDS_STATUS_LABEL,
                            &format!("Added '{trimmed}'. Click Save Backends to apply."),
                        );
                    }
                    ID_BACKENDS_BTN_REMOVE => {
                        let sel = SendMessageW(lb, LB_GETCURSEL, 0, 0);
                        if sel != LB_ERR {
                            SendMessageW(lb, LB_DELETESTRING, sel as usize, 0);
                            let count = SendMessageW(lb, LB_GETCOUNT, 0, 0);
                            if count > 0 {
                                let next_sel = sel.min(count - 1);
                                SendMessageW(lb, LB_SETCURSEL, next_sel as usize, 0);
                            }
                            set_dlg_item_string(
                                hwnd,
                                ID_BACKENDS_STATUS_LABEL,
                                "Removed selected server. Click Save Backends to apply.",
                            );
                        }
                    }
                    ID_BACKENDS_BTN_SAVE => {
                        let servers = listbox_get_items(lb);
                        if servers.is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "At least one Coordinator Server URL is required",
                                "Please add at least one coordinator server before saving.",
                            );
                            return 0;
                        }
                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone());

                        match ClientConfigFile::load(cfg_path.as_deref()) {
                            Ok((_, mut cfg_file)) => {
                                cfg_file.servers = servers.clone();
                                match cfg_file.save(cfg_path.as_deref()) {
                                    Ok(saved_path) => {
                                        crate::win_native::reload_tray_configuration();
                                        SendMessageW(lb, LB_RESETCONTENT, 0, 0);
                                        for srv in &servers {
                                            let w = to_wide(srv);
                                            SendMessageW(lb, LB_ADDSTRING, 0, w.as_ptr() as isize);
                                        }
                                        set_dlg_item_string(
                                            hwnd,
                                            ID_BACKENDS_STATUS_LABEL,
                                            &format!(
                                                "Saved {} server(s) to {} & reconnecting!",
                                                servers.len(),
                                                saved_path.display()
                                            ),
                                        );
                                    }
                                    Err(e) => {
                                        show_tray_error_dialog(
                                            "Save Failed",
                                            "Failed to save client.toml",
                                            &format!("{e:#}"),
                                        );
                                    }
                                }
                            }
                            Err(_) => {
                                show_tray_error_dialog(
                                    "Workstation Not Enrolled Yet",
                                    "client.toml does not exist yet",
                                    "Please enroll or initialize this workstation first via 'Initialize / Enroll Workstation...'.",
                                );
                            }
                        }
                    }
                    ID_BACKENDS_BTN_CLOSE => {
                        DestroyWindow(hwnd);
                    }
                    _ => {}
                }
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            if let Ok(mut g) = DIALOG_HANDLES.lock() {
                if g.backends_hwnd == hwnd as isize {
                    g.backends_hwnd = 0;
                }
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe fn show_backends_window() {
    {
        let g = DIALOG_HANDLES.lock().unwrap();
        let existing = g.backends_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SockcastBackendsWndClass");
    let title = to_wide("Sockcast — Manage Coordinator Backends (Servers)");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(backends_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let w = scale_px(576, dpi);
    let h = scale_px(420, dpi);
    let x = (GetSystemMetrics(SM_CXSCREEN) - w).max(0) / 2;
    let y = (GetSystemMetrics(SM_CYSCREEN) - h).max(0) / 2;

    let hwnd = CreateWindowExW(
        0,
        class_name.as_ptr(),
        title.as_ptr(),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE,
        x,
        y,
        w,
        h,
        null_mut(),
        null_mut(),
        hinstance,
        null(),
    );
    if !hwnd.is_null() {
        DIALOG_HANDLES.lock().unwrap().backends_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}
