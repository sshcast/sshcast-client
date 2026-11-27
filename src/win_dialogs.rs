use std::collections::VecDeque;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use sshcast_proto::bundle::USER_CERT_PREFIX;
use sshcast_proto::crypto::derive_user_id;
use sshcast_proto::v1::NodeRole;
use zeroize::Zeroizing;

use windows_sys::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, S_OK, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, EndPaint, FillRect, GetDC,
    GetDeviceCaps, InvalidateRect, ReleaseDC, SetBkColor, SetBkMode, SetTextColor,
    CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, DEFAULT_CHARSET, DEFAULT_PITCH, FF_DONTCARE, FW_NORMAL,
    FW_SEMIBOLD, HBRUSH, HDC, HFONT, LOGPIXELSX, OPAQUE, OUT_DEFAULT_PRECIS, PAINTSTRUCT,
};
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::UI::Controls::{
    TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOGCONFIG_1, TDCBF_CANCEL_BUTTON,
    TDCBF_YES_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION, TDF_SIZE_TO_CONTENT, TD_WARNING_ICON,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DrawIconEx, GetClientRect,
    GetDlgCtrlID, GetDlgItem, GetSystemMetrics, GetWindowTextLengthW, GetWindowTextW,
    IsDialogMessageW, IsWindow, LoadCursorW, LoadIconW, MessageBoxW, PostMessageW, RegisterClassW,
    SendMessageW, SetForegroundWindow, SetWindowTextW, ShowWindow, DI_NORMAL, IDC_ARROW,
    IDI_SHIELD, IDYES, MB_ICONWARNING, MB_YESNO, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_RESTORE,
    SW_SHOW, WM_APP, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_ERASEBKGND, WM_PAINT,
    WM_SETFONT, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE, WS_GROUP, WS_MINIMIZEBOX,
    WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

use crate::config::{default_client_config_path, ClientConfig, ClientConfigFile, UserKeyFile};
use crate::enroll::{
    decode_enrollment_bundle_token, encode_enrollment_bundle_token, export_user_root_key,
    import_user_cert, import_user_root_key, load_user_cert, load_user_signing_key,
    mint_enrollment_bundle, run_keygen, write_client_config_and_optional_root_key,
    write_client_config_from_bundle, USER_KEY_TOKEN_PREFIX,
};
use crate::operator::{
    cancel_enrollment_pairing, complete_paired_enrollment, confirm_replace_lost_root_key,
    delete_recovery_vault_http, finalize_new_or_same_key_enrollment,
    get_recovery_vault_status_http, is_terminal_enroll_error, poll_enrollment_once,
    resolve_operator_url, start_github_enrollment, unlock_with_recovery_passphrase,
    upload_recovery_vault_http, EnrollPollStep, LoginOutcome, PendingPairingInfo,
};
use crate::pairing::{encrypt_recovery_vault, ScryptParams, VaultDecryptError};
use crate::win_native::{
    show_tray_error_dialog, TraySharedContext, WM_TRAY_GITHUB_LOGIN_DONE,
    WM_TRAY_OPEN_PAIRING_WINDOW, WM_TRAY_PAIRING_UPDATE,
};

const ES_CENTER: u32 = 0x0001;
const ES_PASSWORD: u32 = 0x0020;
const ES_AUTOHSCROLL: u32 = 0x0080;
const ES_READONLY: u32 = 0x0800;

const BS_PUSHBUTTON: u32 = 0x0000;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const BS_AUTOCHECKBOX: u32 = 0x0003;
const BS_AUTORADIOBUTTON: u32 = 0x0009;
const BS_COMMANDLINK: u32 = 0x000E;
const BS_DEFCOMMANDLINK: u32 = 0x000F;

const BCM_SETNOTE: u32 = 0x1609;
const EM_SETCUEBANNER: u32 = 0x1501;

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
const BST_UNCHECKED: usize = 0;
const BST_CHECKED: usize = 1;
const BN_CLICKED: u32 = 0;

const WM_CTLCOLORBTN: u32 = 0x0135;
const WM_CTLCOLORSTATIC: u32 = 0x0138;

const CF_UNICODETEXT: u32 = 13;

// Special control ID ranges for styling in WM_CTLCOLORSTATIC
const ID_STYLE_MAIN_HEADER: i32 = 1900;
const ID_STYLE_SECTION_HEADER_1: i32 = 1901;
const ID_STYLE_SECTION_HEADER_2: i32 = 1902;
const ID_STYLE_SECTION_HEADER_3: i32 = 1903;
const ID_STYLE_FOOTER_STATUS: i32 = 1910;
const ID_STYLE_READONLY_CODE_MIN: i32 = 1950;
const ID_STYLE_READONLY_CODE_MAX: i32 = 1959;

// Control IDs for Initialize / Enroll Window
const ID_ENROLL_ROOT_KEY_EDIT: i32 = 1951;
const ID_ENROLL_BTN_KEYGEN: i32 = 2002;
const ID_ENROLL_BTN_COPY_PUBKEY: i32 = 2003;
const ID_ENROLL_NODE_EDIT: i32 = 2004;
const ID_ENROLL_SERVERS_EDIT: i32 = 2005;
const ID_ENROLL_BTN_ENROLL_PRIMARY: i32 = 2006;
const ID_ENROLL_BTN_PASTE_BUNDLE: i32 = 2007;
const ID_ENROLL_BUNDLE_EDIT: i32 = 2008;
const ID_ENROLL_BTN_INIT_BUNDLE: i32 = 2009;
const ID_ENROLL_BTN_CLOSE: i32 = 2011;
const ID_ENROLL_CERT_EDIT: i32 = 2012;
const ID_ENROLL_BTN_PASTE_CERT: i32 = 2013;
const ID_ENROLL_BTN_IMPORT_CERT: i32 = 2014;
const ID_ENROLL_BTN_GITHUB_LOGIN: i32 = 2015;
const WM_ENROLL_GITHUB_DONE: u32 = WM_APP + 20;
const WM_ENROLL_PAIRING_REQUIRED: u32 = WM_APP + 21;
const WM_PAIRING_UPDATE: u32 = WM_APP + 22;
const WM_ENROLL_STATUS_TEXT: u32 = WM_APP + 23;
const WM_RECOVERY_ASYNC_DONE: u32 = WM_APP + 30;

#[derive(Debug, Clone)]
enum PairingUiAction {
    Unlock(Zeroizing<String>),
    Reset,
    Cancel,
}

#[derive(Debug, Clone)]
enum PairingUiEvent {
    Completed(LoginOutcome),
    TransientError { message: String, show_dialog: bool },
    TerminalError(String),
    Canceled,
}

struct PairingUiState {
    session_gen: u64,
    info: PendingPairingInfo,
    completed: bool,
    events: VecDeque<PairingUiEvent>,
}

enum RecoveryAsyncKind {
    StatusChecked {
        gen: u64,
        res: Result<(bool, i64), String>,
    },
    Saved(Result<i64, String>),
    Removed(Result<(), String>),
}

struct RecoveryAsyncEvent {
    kind: RecoveryAsyncKind,
}

static GITHUB_LOGIN_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static LOGIN_SESSION_GEN: AtomicU64 = AtomicU64::new(0);
static GITHUB_LOGIN_RESULT: Mutex<Option<Result<LoginOutcome, String>>> = Mutex::new(None);
static ENROLL_STATUS_TEXT: Mutex<Option<String>> = Mutex::new(None);
static ACTIVE_PAIRING_TX: Mutex<Option<tokio::sync::mpsc::UnboundedSender<PairingUiAction>>> =
    Mutex::new(None);
static PAIRING_UI_STATE: Mutex<Option<PairingUiState>> = Mutex::new(None);
static RECOVERY_EVENTS: Mutex<VecDeque<RecoveryAsyncEvent>> = Mutex::new(VecDeque::new());
static RECOVERY_OP_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static RECOVERY_STATUS_GEN: AtomicU64 = AtomicU64::new(0);

// Control IDs for Bundle Generator Window
const ID_BUNDLE_ROOT_PUBKEY_EDIT: i32 = 1952;
const ID_BUNDLE_BTN_KEYGEN: i32 = 3002;
const ID_BUNDLE_BTN_COPY_PUBKEY: i32 = 3003;
const ID_BUNDLE_BTN_ROOT_KEY_ACTION: i32 = 3016;
const ID_BUNDLE_BTN_IMPORT_CERT: i32 = 3017;
const ID_BUNDLE_RADIO_RELAY: i32 = 3004;
const ID_BUNDLE_RADIO_CLIENT: i32 = 3005;
const ID_BUNDLE_NODE_EDIT: i32 = 3006;
const ID_BUNDLE_EXPIRES_EDIT: i32 = 3007;
const ID_BUNDLE_SERVERS_EDIT: i32 = 3008;
const ID_BUNDLE_BTN_GENERATE: i32 = 3009;
const ID_BUNDLE_TOKEN_OUT_EDIT: i32 = 1953;
const ID_BUNDLE_BTN_COPY_TOKEN: i32 = 3011;
const ID_BUNDLE_CMD_OUT_EDIT: i32 = 1954;
const ID_BUNDLE_BTN_COPY_CMD: i32 = 3013;
const ID_BUNDLE_BTN_CLOSE: i32 = 3015;

// Control IDs for Coordinator Backends Window
const ID_BACKENDS_LISTBOX: i32 = 4001;
const ID_BACKENDS_BTN_REMOVE: i32 = 4002;
const ID_BACKENDS_ADD_EDIT: i32 = 4003;
const ID_BACKENDS_BTN_ADD: i32 = 4004;
const ID_BACKENDS_BTN_SAVE: i32 = 4005;
const ID_BACKENDS_BTN_CLOSE: i32 = 4007;

// Control IDs for SSH Keys Manager Window
const ID_SSHKEYS_LISTBOX: i32 = 5001;
const ID_SSHKEYS_BTN_REMOVE: i32 = 5002;
const ID_SSHKEYS_BTN_REFRESH: i32 = 5003;
const ID_SSHKEYS_CHK_NO_OS_AGENT: i32 = 5004;
const ID_SSHKEYS_PATH_EDIT: i32 = 5005;
const ID_SSHKEYS_PASS_EDIT: i32 = 5006;
const ID_SSHKEYS_BTN_ADD_FILE: i32 = 5007;
const ID_SSHKEYS_BTN_PASTE_PEM: i32 = 5008;
const ID_SSHKEYS_BTN_CLOSE: i32 = 5009;

// Control IDs for Device Pairing Wait Window
const ID_PAIRING_SAS_EDIT: i32 = 1955;
const ID_PAIRING_ACCOUNT_LABEL: i32 = 6001;
const ID_PAIRING_STATUS_LABEL: i32 = 6002;
const ID_PAIRING_PASS_EDIT: i32 = 6003;
const ID_PAIRING_BTN_UNLOCK: i32 = 6004;
const ID_PAIRING_BTN_RESET: i32 = 6005;
const ID_PAIRING_BTN_CANCEL: i32 = 6006;

// Control IDs for Recovery Passphrase Window
const ID_RECOVERY_STATUS_LABEL: i32 = 7001;
const ID_RECOVERY_PASS_EDIT: i32 = 7002;
const ID_RECOVERY_CONFIRM_EDIT: i32 = 7003;
const ID_RECOVERY_BTN_SAVE: i32 = 7004;
const ID_RECOVERY_BTN_REMOVE: i32 = 7005;
const ID_RECOVERY_BTN_CLOSE: i32 = 7006;

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

const COLOR_WHITE: COLORREF = rgb(255, 255, 255);
const COLOR_TASKDIALOG_BLUE: COLORREF = rgb(0, 51, 153);
const COLOR_SECTION_TITLE: COLORREF = rgb(15, 23, 42);
const COLOR_LABEL_TEXT: COLORREF = rgb(71, 85, 105);
const COLOR_CODE_BG: COLORREF = rgb(246, 248, 250);
const COLOR_CODE_TEXT: COLORREF = rgb(15, 23, 42);
const COLOR_FOOTER_BG: COLORREF = rgb(242, 243, 245);
const COLOR_FOOTER_TEXT: COLORREF = rgb(51, 65, 85);
const COLOR_DIVIDER: COLORREF = rgb(226, 232, 240);
const COLOR_FOOTER_BORDER: COLORREF = rgb(212, 216, 222);

const FOOTER_HEIGHT_96DPI: i32 = 54;

struct DialogResources {
    enroll_hwnd: isize,
    bundle_hwnd: isize,
    backends_hwnd: isize,
    ssh_keys_hwnd: isize,
    pairing_hwnd: isize,
    recovery_hwnd: isize,
    font_title: isize,
    font_section: isize,
    font_ui: isize,
    font_mono: isize,
    font_sas: isize,
    brush_white: isize,
    brush_code_bg: isize,
    brush_footer_bg: isize,
    brush_divider: isize,
    brush_footer_border: isize,
}

static DIALOG_RES: Mutex<DialogResources> = Mutex::new(DialogResources {
    enroll_hwnd: 0,
    bundle_hwnd: 0,
    backends_hwnd: 0,
    ssh_keys_hwnd: 0,
    pairing_hwnd: 0,
    recovery_hwnd: 0,
    font_title: 0,
    font_section: 0,
    font_ui: 0,
    font_mono: 0,
    font_sas: 0,
    brush_white: 0,
    brush_code_bg: 0,
    brush_footer_bg: 0,
    brush_divider: 0,
    brush_footer_border: 0,
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

struct ThemeAssets {
    font_title: HFONT,
    font_section: HFONT,
    font_ui: HFONT,
    font_mono: HFONT,
    font_sas: HFONT,
    brush_white: HBRUSH,
    brush_code_bg: HBRUSH,
    brush_footer_bg: HBRUSH,
    brush_divider: HBRUSH,
    brush_footer_border: HBRUSH,
}

unsafe fn ensure_theme_assets(dpi: i32) -> ThemeAssets {
    let mut g = DIALOG_RES.lock().unwrap();
    if g.font_ui == 0 {
        let segoe = to_wide("Segoe UI");
        let consolas = to_wide("Consolas");

        g.font_title = CreateFontW(
            -scale_px(20, dpi),
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
        ) as isize;

        g.font_section = CreateFontW(
            -scale_px(15, dpi),
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
        ) as isize;

        g.font_ui = CreateFontW(
            -scale_px(14, dpi),
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
        ) as isize;

        g.font_mono = CreateFontW(
            -scale_px(14, dpi),
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
        ) as isize;

        g.font_sas = CreateFontW(
            -scale_px(20, dpi),
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
            consolas.as_ptr(),
        ) as isize;

        g.brush_white = CreateSolidBrush(COLOR_WHITE) as isize;
        g.brush_code_bg = CreateSolidBrush(COLOR_CODE_BG) as isize;
        g.brush_footer_bg = CreateSolidBrush(COLOR_FOOTER_BG) as isize;
        g.brush_divider = CreateSolidBrush(COLOR_DIVIDER) as isize;
        g.brush_footer_border = CreateSolidBrush(COLOR_FOOTER_BORDER) as isize;
    }

    ThemeAssets {
        font_title: g.font_title as HFONT,
        font_section: g.font_section as HFONT,
        font_ui: g.font_ui as HFONT,
        font_mono: g.font_mono as HFONT,
        font_sas: g.font_sas as HFONT,
        brush_white: g.brush_white as HBRUSH,
        brush_code_bg: g.brush_code_bg as HBRUSH,
        brush_footer_bg: g.brush_footer_bg as HBRUSH,
        brush_divider: g.brush_divider as HBRUSH,
        brush_footer_border: g.brush_footer_border as HBRUSH,
    }
}

pub unsafe fn cleanup_dialog_fonts() {
    if let Ok(mut g) = DIALOG_RES.lock() {
        let handles = [
            g.font_title,
            g.font_section,
            g.font_ui,
            g.font_mono,
            g.font_sas,
            g.brush_white,
            g.brush_code_bg,
            g.brush_footer_bg,
            g.brush_divider,
            g.brush_footer_border,
        ];
        g.font_title = 0;
        g.font_section = 0;
        g.font_ui = 0;
        g.font_mono = 0;
        g.font_sas = 0;
        g.brush_white = 0;
        g.brush_code_bg = 0;
        g.brush_footer_bg = 0;
        g.brush_divider = 0;
        g.brush_footer_border = 0;
        for h in handles {
            if h != 0 {
                DeleteObject(h as _);
            }
        }
    }
}

pub unsafe fn is_any_management_dialog_message(msg: &MSG) -> bool {
    let hwnds = match DIALOG_RES.lock() {
        Ok(g) => [
            g.enroll_hwnd as HWND,
            g.bundle_hwnd as HWND,
            g.backends_hwnd as HWND,
            g.ssh_keys_hwnd as HWND,
            g.pairing_hwnd as HWND,
            g.recovery_hwnd as HWND,
        ],
        Err(_) => return false,
    };
    for h in hwnds {
        if !h.is_null() && IsWindow(h) != 0 && IsDialogMessageW(h, msg) != 0 {
            return true;
        }
    }
    false
}

unsafe fn set_ctrl_font(hwnd_ctrl: HWND, font: HFONT) {
    SendMessageW(hwnd_ctrl, WM_SETFONT, font as WPARAM, 1);
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_child_ex(
    parent: HWND,
    ex_style: u32,
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
        ex_style,
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

#[allow(clippy::too_many_arguments)]
unsafe fn create_label(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    create_child_ex(parent, 0, "STATIC", text, 0, x, y, w, h, id, dpi, font)
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_edit_with_style(
    parent: HWND,
    text: &str,
    cue_banner: &str,
    style: u32,
    apply_cue: bool,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    let hwnd = create_child_ex(
        parent,
        WS_EX_CLIENTEDGE,
        "EDIT",
        text,
        style,
        x,
        y,
        w,
        h,
        id,
        dpi,
        font,
    );
    if !hwnd.is_null() && apply_cue && !cue_banner.is_empty() {
        let cue_w = to_wide(cue_banner);
        SendMessageW(hwnd, EM_SETCUEBANNER, 1, cue_w.as_ptr() as isize);
    }
    hwnd
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_edit(
    parent: HWND,
    text: &str,
    cue_banner: &str,
    readonly: bool,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    let style = ES_AUTOHSCROLL | WS_TABSTOP | if readonly { ES_READONLY } else { 0 };
    create_edit_with_style(
        parent,
        text,
        cue_banner,
        style,
        !readonly,
        x,
        y,
        w,
        h,
        id,
        dpi,
        font,
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_password_edit(
    parent: HWND,
    cue_banner: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    create_edit_with_style(
        parent,
        "",
        cue_banner,
        ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP,
        true,
        x,
        y,
        w,
        h,
        id,
        dpi,
        font,
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_button_styled(
    parent: HWND,
    text: &str,
    btn_style: u32,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    create_child_ex(
        parent,
        0,
        "BUTTON",
        text,
        btn_style | WS_TABSTOP,
        x,
        y,
        w,
        h,
        id,
        dpi,
        font,
    )
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_button(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    create_button_styled(parent, text, BS_PUSHBUTTON, x, y, w, h, id, dpi, font)
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_default_button(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    create_button_styled(parent, text, BS_DEFPUSHBUTTON, x, y, w, h, id, dpi, font)
}

unsafe fn set_ctrl_enabled(hwnd: HWND, id: i32, enabled: bool) {
    #[link(name = "user32")]
    extern "system" {
        fn EnableWindow(
            hwnd: HWND,
            benable: windows_sys::Win32::Foundation::BOOL,
        ) -> windows_sys::Win32::Foundation::BOOL;
    }
    let ctrl = GetDlgItem(hwnd, id);
    if !ctrl.is_null() {
        EnableWindow(ctrl, if enabled { 1 } else { 0 });
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_command_link(
    parent: HWND,
    title: &str,
    note: &str,
    is_default: bool,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    dpi: i32,
    font: HFONT,
) -> HWND {
    let cmd_style = if is_default {
        BS_DEFCOMMANDLINK
    } else {
        BS_COMMANDLINK
    };
    let hwnd = create_child_ex(
        parent,
        0,
        "BUTTON",
        title,
        cmd_style | WS_TABSTOP,
        x,
        y,
        w,
        h,
        id,
        dpi,
        font,
    );
    if !hwnd.is_null() && !note.is_empty() {
        let note_w = to_wide(note);
        SendMessageW(hwnd, BCM_SETNOTE, 0, note_w.as_ptr() as isize);
    }
    hwnd
}

/// Paints the modern TaskDialog-style white canvas, top shield icon, horizontal section dividers,
/// and bottom `#F2F3F5` footer strip.
unsafe fn paint_taskdialog_frame(hwnd: HWND, divider_ys_96dpi: &[i32]) {
    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);

    let mut ps: PAINTSTRUCT = std::mem::zeroed();
    let hdc = BeginPaint(hwnd, &mut ps);

    let mut rc = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    GetClientRect(hwnd, &mut rc);
    let footer_h = scale_px(FOOTER_HEIGHT_96DPI, dpi);
    let footer_top = (rc.bottom - footer_h).max(0);

    // 1. White main canvas
    let body_rc = RECT {
        left: 0,
        top: 0,
        right: rc.right,
        bottom: footer_top,
    };
    FillRect(hdc, &body_rc, assets.brush_white);

    // 2. Top shield icon next to the blue Main Instruction header
    let hicon = LoadIconW(null_mut(), IDI_SHIELD);
    if !hicon.is_null() {
        let icon_sz = scale_px(28, dpi);
        DrawIconEx(
            hdc,
            scale_px(24, dpi),
            scale_px(18, dpi),
            hicon,
            icon_sz,
            icon_sz,
            0,
            null_mut(),
            DI_NORMAL,
        );
    }

    // 3. Horizontal section dividers
    let pad_x = scale_px(24, dpi);
    for &y96 in divider_ys_96dpi {
        let y = scale_px(y96, dpi);
        let div_rc = RECT {
            left: pad_x,
            top: y,
            right: (rc.right - pad_x).max(pad_x),
            bottom: y + scale_px(1, dpi).max(1),
        };
        FillRect(hdc, &div_rc, assets.brush_divider);
    }

    // 4. Footer 1px top border + #F2F3F5 footer strip
    let border_rc = RECT {
        left: 0,
        top: footer_top,
        right: rc.right,
        bottom: footer_top + scale_px(1, dpi).max(1),
    };
    FillRect(hdc, &border_rc, assets.brush_footer_border);

    let footer_rc = RECT {
        left: 0,
        top: footer_top + scale_px(1, dpi).max(1),
        right: rc.right,
        bottom: rc.bottom,
    };
    FillRect(hdc, &footer_rc, assets.brush_footer_bg);

    EndPaint(hwnd, &ps);
}

/// Colors static labels, headers, radio buttons, and read-only code edits cleanly on the white canvas
/// or footer strip without 90s gray boxes.
unsafe fn handle_ctlcolor(wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let hdc = wparam as HDC;
    let ctrl_hwnd = lparam as HWND;
    let id = GetDlgCtrlID(ctrl_hwnd);
    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);

    SetBkMode(hdc, OPAQUE as i32);

    if id == ID_STYLE_MAIN_HEADER {
        SetTextColor(hdc, COLOR_TASKDIALOG_BLUE);
        SetBkColor(hdc, COLOR_WHITE);
        return assets.brush_white as LRESULT;
    }
    if (ID_STYLE_SECTION_HEADER_1..=ID_STYLE_SECTION_HEADER_3).contains(&id)
        || id == ID_RECOVERY_STATUS_LABEL
    {
        SetTextColor(hdc, COLOR_SECTION_TITLE);
        SetBkColor(hdc, COLOR_WHITE);
        return assets.brush_white as LRESULT;
    }
    if id == ID_STYLE_FOOTER_STATUS {
        SetTextColor(hdc, COLOR_FOOTER_TEXT);
        SetBkColor(hdc, COLOR_FOOTER_BG);
        return assets.brush_footer_bg as LRESULT;
    }
    if (ID_STYLE_READONLY_CODE_MIN..=ID_STYLE_READONLY_CODE_MAX).contains(&id) {
        SetTextColor(hdc, COLOR_CODE_TEXT);
        SetBkColor(hdc, COLOR_CODE_BG);
        return assets.brush_code_bg as LRESULT;
    }

    SetTextColor(hdc, COLOR_LABEL_TEXT);
    SetBkColor(hdc, COLOR_WHITE);
    assets.brush_white as LRESULT
}

unsafe fn create_centered_dialog_window(
    class_name: &[u16],
    title: &[u16],
    client_w_96dpi: i32,
    client_h_96dpi: i32,
    dpi: i32,
) -> HWND {
    let hinstance = GetModuleHandleW(null());
    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: scale_px(client_w_96dpi, dpi),
        bottom: scale_px(client_h_96dpi, dpi),
    };
    AdjustWindowRectEx(&mut rc, style, 0, 0);
    let win_w = rc.right - rc.left;
    let win_h = rc.bottom - rc.top;
    let x = (GetSystemMetrics(SM_CXSCREEN) - win_w).max(0) / 2;
    let y = (GetSystemMetrics(SM_CYSCREEN) - win_h).max(0) / 2;

    CreateWindowExW(
        0,
        class_name.as_ptr(),
        title.as_ptr(),
        style,
        x,
        y,
        win_w,
        win_h,
        null_mut(),
        null_mut(),
        hinstance,
        null(),
    )
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
        InvalidateRect(ctrl, null(), 1);
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

unsafe fn confirm_overwrite_dialog(
    parent: HWND,
    title: &str,
    instruction: &str,
    content: &str,
) -> bool {
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
    let hr = crate::win_native::call_task_dialog_indirect(&config, &mut btn, null_mut(), null_mut());
    if hr == S_OK {
        return btn == IDYES;
    }
    let fallback_body = to_wide(&format!("{instruction}\n\n{content}"));
    MessageBoxW(
        parent,
        fallback_body.as_ptr(),
        title_w.as_ptr(),
        MB_YESNO | MB_ICONWARNING,
    ) == IDYES
}

fn parse_servers_input(raw: &str) -> Vec<String> {
    raw.split([',', ';', '\n', '\r', ' '])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub(crate) fn resolve_tray_user_key_path(
    config_path: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    if let Some(sibling) = config_path
        .and_then(|p| p.parent())
        .map(|d| d.join("user_key.toml"))
    {
        if sibling.exists() {
            return Some(sibling);
        }
    }
    None
}

pub(crate) fn load_tray_user_key_file(
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<(std::path::PathBuf, UserKeyFile)> {
    if let Some(sibling) = resolve_tray_user_key_path(config_path) {
        if let Ok(loaded) = UserKeyFile::load(Some(&sibling)) {
            return Ok(loaded);
        }
    }
    UserKeyFile::load(None)
}

pub(crate) fn load_tray_user_signing_key(
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<SigningKey> {
    if let Some(sibling) = resolve_tray_user_key_path(config_path) {
        if let Ok(sk) = load_user_signing_key(Some(&sibling)) {
            return Ok(sk);
        }
    }
    load_user_signing_key(None)
}

fn format_root_key_allowlist() -> Option<String> {
    let cfg_path = crate::win_native::get_tray_context().and_then(|c| c.config_path.clone());
    load_tray_user_key_file(cfg_path.as_deref())
        .ok()
        .map(|(_, uk)| uk.user_pubkey_token)
}

fn format_user_cert_status(cfg_path: Option<&std::path::Path>) -> Option<String> {
    let cert = load_user_cert(None, cfg_path)?;
    let op_hex = hex::encode(&cert.operator_pubkey);
    let short_op = &op_hex[..12.min(op_hex.len())];
    Some(format!(
        "Certified by sc_op_pub_{short_op}... (User: {})",
        cert.user_id
    ))
}

fn is_valid_coordinator_entry(trimmed: &str) -> bool {
    ((trimmed.starts_with("http://") || trimmed.starts_with("https://")) && trimmed.len() > 8)
        || sshcast_proto::dns::is_dns_discovery_entry(trimmed).is_some()
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
    "sshcast.net".to_string()
}

// ============================================================================
// 1. INITIALIZE / ENROLL WORKSTATION WINDOW (640 x 600 Client Area)
// ============================================================================

unsafe extern "system" fn enroll_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint_taskdialog_frame(hwnd, &[56, 360]);
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => handle_ctlcolor(wparam, lparam),
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let assets = ensure_theme_assets(dpi);
            let maybe_ctx = crate::win_native::get_tray_context();
            let cfg_path = maybe_ctx
                .as_ref()
                .and_then(|c| c.config_path.clone())
                .or_else(|| default_client_config_path().ok());

            // Main TaskDialog-style Header
            create_label(
                hwnd,
                "Initialize or Enroll This Workstation",
                62,
                18,
                554,
                28,
                ID_STYLE_MAIN_HEADER,
                dpi,
                assets.font_title,
            );

            // Section 1: Primary Workstation Enrollment
            create_label(
                hwnd,
                "1. Enroll Primary Workstation Using Local Root Key",
                24,
                70,
                592,
                22,
                ID_STYLE_SECTION_HEADER_1,
                dpi,
                assets.font_section,
            );
            create_label(
                hwnd,
                "User Root Public Key (sc_pub_...):",
                24,
                96,
                400,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            let root_str = format_root_key_allowlist().unwrap_or_else(|| {
                "No user_key.toml yet — click 'Generate Key' or 'Enroll' below".to_string()
            });
            create_edit(
                hwnd,
                &root_str,
                "",
                true,
                24,
                116,
                384,
                26,
                ID_ENROLL_ROOT_KEY_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Generate Key",
                416,
                115,
                96,
                28,
                ID_ENROLL_BTN_KEYGEN,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Copy Public Key",
                518,
                115,
                98,
                28,
                ID_ENROLL_BTN_COPY_PUBKEY,
                dpi,
                assets.font_ui,
            );

            create_label(
                hwnd,
                "Operator Signed Certificate (sc_cert_...):",
                24,
                152,
                400,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            let cert_initial =
                format_user_cert_status(cfg_path.as_deref()).unwrap_or_default();
            create_edit(
                hwnd,
                &cert_initial,
                "Paste sc_cert_... token from Operator Console",
                false,
                24,
                172,
                384,
                26,
                ID_ENROLL_CERT_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Paste Cert",
                416,
                171,
                96,
                28,
                ID_ENROLL_BTN_PASTE_CERT,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Import Cert",
                518,
                171,
                98,
                28,
                ID_ENROLL_BTN_IMPORT_CERT,
                dpi,
                assets.font_ui,
            );

            create_label(
                hwnd,
                "Workstation Name:",
                24,
                210,
                190,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_label(
                hwnd,
                "Coordinator Domain or URL(s) (comma-separated):",
                228,
                210,
                388,
                18,
                0,
                dpi,
                assets.font_ui,
            );

            let node_default = maybe_ctx
                .as_ref()
                .map(|c| default_workstation_node_name(c))
                .unwrap_or_else(|| "workstation".to_string());
            create_edit(
                hwnd,
                &node_default,
                "e.g. bandura",
                false,
                24,
                230,
                192,
                26,
                ID_ENROLL_NODE_EDIT,
                dpi,
                assets.font_ui,
            );

            let servers_default = maybe_ctx
                .as_ref()
                .map(|c| default_servers_csv(c))
                .unwrap_or_else(|| "sshcast.net".to_string());
            create_edit(
                hwnd,
                &servers_default,
                "sshcast.net or https://sshcast.example.com",
                false,
                228,
                230,
                388,
                26,
                ID_ENROLL_SERVERS_EDIT,
                dpi,
                assets.font_mono,
            );

            create_command_link(
                hwnd,
                "Sign in with GitHub",
                "Open browser OAuth to get an auto-renewing cert & enroll",
                true,
                24,
                270,
                288,
                58,
                ID_ENROLL_BTN_GITHUB_LOGIN,
                dpi,
                assets.font_ui,
            );
            create_command_link(
                hwnd,
                "Enroll This Workstation",
                "Mint grant with local root key & save client.toml",
                false,
                328,
                270,
                288,
                58,
                ID_ENROLL_BTN_ENROLL_PRIMARY,
                dpi,
                assets.font_ui,
            );

            // Section 2: Initialize from Bundle
            create_label(
                hwnd,
                "2. Or Initialize Secondary Workstation from an Enrollment Bundle",
                24,
                374,
                592,
                22,
                ID_STYLE_SECTION_HEADER_2,
                dpi,
                assets.font_section,
            );
            create_label(
                hwnd,
                "Client Enrollment Bundle Token (sc1_<base64>):",
                24,
                400,
                400,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_edit(
                hwnd,
                "",
                "Paste sc1_... client bundle token here",
                false,
                24,
                420,
                464,
                26,
                ID_ENROLL_BUNDLE_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Paste Clipboard",
                496,
                419,
                120,
                28,
                ID_ENROLL_BTN_PASTE_BUNDLE,
                dpi,
                assets.font_ui,
            );

            create_command_link(
                hwnd,
                "Initialize Workstation from Bundle",
                "Verify the pasted sc1_ token, write ~/.config/sshcast/client.toml, and connect immediately",
                false,
                24,
                460,
                592,
                58,
                ID_ENROLL_BTN_INIT_BUNDLE,
                dpi,
                assets.font_ui,
            );

            // Footer Bar (y = 546 .. 600)
            create_label(
                hwnd,
                "Ready.",
                24,
                563,
                470,
                20,
                ID_STYLE_FOOTER_STATUS,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Close",
                516,
                558,
                100,
                30,
                ID_ENROLL_BTN_CLOSE,
                dpi,
                assets.font_ui,
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
                                "Generating a new user root key will invalidate previous certificates and allowlist entries. Overwrite user_key.toml?",
                            )
                        {
                            return 0;
                        }
                        match run_keygen(None, true) {
                            Ok(out) => {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_ENROLL_ROOT_KEY_EDIT,
                                    &out.user_pubkey_token,
                                );
                                set_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT, "");
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
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
                        if let Some(pubkey) = format_root_key_allowlist() {
                            if copy_to_clipboard(hwnd, &pubkey) {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "Copied sc_pub_... public key to clipboard!",
                                );
                            }
                        } else {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Generate a root key first before copying.",
                            );
                        }
                    }
                    ID_ENROLL_BTN_PASTE_CERT => {
                        if let Some(clip) = paste_from_clipboard(hwnd) {
                            let token = clip
                                .split_whitespace()
                                .find(|w| w.starts_with(USER_CERT_PREFIX))
                                .unwrap_or(clip.trim());
                            set_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT, token);
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Pasted certificate token from clipboard. Click 'Import Cert' to apply.",
                            );
                        }
                    }
                    ID_ENROLL_BTN_IMPORT_CERT => {
                        let raw_edit = get_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT);
                        let mut token = raw_edit
                            .split_whitespace()
                            .find(|w| w.starts_with(USER_CERT_PREFIX))
                            .unwrap_or("")
                            .to_string();
                        if token.is_empty() {
                            if let Some(clip) = paste_from_clipboard(hwnd) {
                                if let Some(found) =
                                    clip.split_whitespace().find(|w| w.starts_with(USER_CERT_PREFIX))
                                {
                                    token = found.to_string();
                                }
                            }
                        }
                        if token.is_empty() {
                            show_tray_error_dialog(
                                "No Certificate Token Found",
                                "Please paste an sc_cert_<base64> token first",
                                "Sign your sc_pub_... key in the Operator Console, copy the sc_cert_... token, and click 'Paste Cert' or 'Import Cert'.",
                            );
                            return 0;
                        }
                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());
                        match import_user_cert(&token, None, cfg_path.as_deref()) {
                            Ok((_, updated_cfg, cert)) => {
                                if updated_cfg.is_some() {
                                    crate::win_native::reload_tray_configuration();
                                }
                                if let Some(status) = format_user_cert_status(cfg_path.as_deref()) {
                                    set_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT, &status);
                                }
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    &format!(
                                        "Imported operator certificate for {}!",
                                        cert.user_id
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Certificate Import Failed",
                                    "Failed to import sc_cert_ operator certificate",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_ENROLL_BTN_GITHUB_LOGIN => {
                        if GITHUB_LOGIN_IN_FLIGHT
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_err()
                        {
                            let existing_pairing = DIALOG_RES
                                .lock()
                                .ok()
                                .map(|g| g.pairing_hwnd as HWND)
                                .unwrap_or(null_mut());
                            if !existing_pairing.is_null() && IsWindow(existing_pairing) != 0 {
                                ShowWindow(existing_pairing, SW_RESTORE);
                                SetForegroundWindow(existing_pairing);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "Device pairing window is already open.",
                                );
                            } else {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "GitHub sign-in is already in progress in your browser...",
                                );
                            }
                            return 0;
                        }
                        let my_gen = LOGIN_SESSION_GEN
                            .fetch_add(1, Ordering::SeqCst)
                            .wrapping_add(1);
                        let node_name = get_dlg_item_string(hwnd, ID_ENROLL_NODE_EDIT);
                        let servers_raw = get_dlg_item_string(hwnd, ID_ENROLL_SERVERS_EDIT);
                        let servers = parse_servers_input(&servers_raw);
                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());
                        let explicit_op = crate::win_native::get_tray_context()
                            .and_then(|c| c.current_config())
                            .and_then(|c| c.operator_url);
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
                            "Opening browser for GitHub sign-in... Complete login in browser.",
                        );
                        let hwnd_raw = hwnd as isize;
                        std::thread::spawn(move || {
                            run_github_login_actor_thread(
                                my_gen,
                                hwnd_raw,
                                servers,
                                explicit_op,
                                node_name,
                                cfg_path,
                            );
                        });
                    }
                    ID_ENROLL_BTN_ENROLL_PRIMARY => {
                        let node_name = get_dlg_item_string(hwnd, ID_ENROLL_NODE_EDIT);
                        let servers_raw = get_dlg_item_string(hwnd, ID_ENROLL_SERVERS_EDIT);
                        let servers = parse_servers_input(&servers_raw);
                        if node_name.trim().is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Workstation Name is required",
                                "Please enter a workstation identifier (e.g. 'bandura').",
                            );
                            return 0;
                        }
                        if servers.is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "At least one Coordinator Domain or URL is required",
                                "Please enter your coordinator domain (e.g. 'sshcast.net') or URL (e.g. 'https://c1.sshcast.net').",
                            );
                            return 0;
                        }

                        if format_root_key_allowlist().is_none() {
                            if let Err(e) = run_keygen(None, false) {
                                show_tray_error_dialog(
                                    "Keygen Failed",
                                    "Failed to create user_key.toml",
                                    &format!("{e:#}"),
                                );
                                return 0;
                            }
                            if let Some(pubkey) = format_root_key_allowlist() {
                                set_dlg_item_string(hwnd, ID_ENROLL_ROOT_KEY_EDIT, &pubkey);
                            }
                        }

                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());

                        // If the user pasted an sc_cert_ token into the cert box without clicking Import Cert yet, import it now
                        let raw_cert_edit = get_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT);
                        if let Some(cert_tok) = raw_cert_edit
                            .split_whitespace()
                            .find(|w| w.starts_with(USER_CERT_PREFIX))
                        {
                            if let Err(e) = import_user_cert(cert_tok, None, cfg_path.as_deref()) {
                                show_tray_error_dialog(
                                    "Certificate Import Failed",
                                    "Failed to import pasted sc_cert_ operator certificate",
                                    &format!("{e:#}"),
                                );
                                return 0;
                            }
                            if let Some(status) = format_user_cert_status(cfg_path.as_deref()) {
                                set_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT, &status);
                            }
                        }

                        if let Some(ref p) = cfg_path {
                            if p.exists()
                                && !confirm_overwrite_dialog(
                                    hwnd,
                                    "Overwrite Existing Workstation Config?",
                                    "A client.toml file already exists for this workstation.",
                                    &format!(
                                        "Do you want to overwrite {} and re-enroll as '{}'?",
                                        p.display(),
                                        node_name.trim()
                                    ),
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
                            Ok(_path) => {
                                crate::win_native::reload_tray_configuration();
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    &format!(
                                        "Enrolled '{}' and saved client.toml — connecting now!",
                                        node_name.trim()
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
                            let token = clip
                                .split_whitespace()
                                .find(|w| {
                                    w.starts_with("sc1_")
                                        || w.starts_with(USER_KEY_TOKEN_PREFIX)
                                        || w.starts_with(USER_CERT_PREFIX)
                                })
                                .unwrap_or(clip.trim());
                            set_dlg_item_string(hwnd, ID_ENROLL_BUNDLE_EDIT, token);
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Pasted token from clipboard.",
                            );
                        }
                    }
                    ID_ENROLL_BTN_INIT_BUNDLE => {
                        let raw_input = get_dlg_item_string(hwnd, ID_ENROLL_BUNDLE_EDIT);
                        let token = raw_input
                            .split_whitespace()
                            .find(|w| {
                                w.starts_with("sc1_")
                                    || w.starts_with(USER_KEY_TOKEN_PREFIX)
                                    || w.starts_with(USER_CERT_PREFIX)
                            })
                            .unwrap_or(raw_input.trim());
                        if token.is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Enrollment Bundle is empty",
                                "Please paste an sc1_<base64> client enrollment bundle (or scu1_ root key / sc_cert_ certificate) first.",
                            );
                            return 0;
                        }

                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());

                        if token.starts_with(USER_CERT_PREFIX) {
                            match import_user_cert(token, None, cfg_path.as_deref()) {
                                Ok((_, updated_cfg, cert)) => {
                                    if updated_cfg.is_some() {
                                        crate::win_native::reload_tray_configuration();
                                    }
                                    if let Some(status) = format_user_cert_status(cfg_path.as_deref()) {
                                        set_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT, &status);
                                    }
                                    set_dlg_item_string(
                                        hwnd,
                                        ID_STYLE_FOOTER_STATUS,
                                        &format!(
                                            "Imported operator certificate for {}!",
                                            cert.user_id
                                        ),
                                    );
                                }
                                Err(e) => {
                                    show_tray_error_dialog(
                                        "Certificate Import Failed",
                                        "Failed to import sc_cert_ operator certificate",
                                        &format!("{e:#}"),
                                    );
                                }
                            }
                            return 0;
                        }

                        if token.starts_with(USER_KEY_TOKEN_PREFIX) {
                            match import_user_root_key(token, None, cfg_path.as_deref(), true) {
                                Ok(out) => {
                                    set_dlg_item_string(
                                        hwnd,
                                        ID_ENROLL_ROOT_KEY_EDIT,
                                        &out.user_pubkey_token,
                                    );
                                    if let Some(status) = format_user_cert_status(cfg_path.as_deref()) {
                                        set_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT, &status);
                                    }
                                    set_dlg_item_string(
                                        hwnd,
                                        ID_STYLE_FOOTER_STATUS,
                                        &format!(
                                            "Imported user root key (User ID: {})!",
                                            out.user_id
                                        ),
                                    );
                                }
                                Err(e) => {
                                    show_tray_error_dialog(
                                        "Root Key Import Failed",
                                        "Failed to import scu1_ user root key",
                                        &format!("{e:#}"),
                                    );
                                }
                            }
                            return 0;
                        }

                        let (decoded, maybe_root_key) = match decode_enrollment_bundle_token(token) {
                            Ok(pair) => pair,
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Invalid Bundle",
                                    "Failed to decode sc1_ enrollment bundle",
                                    &format!("{e:#}"),
                                );
                                return 0;
                            }
                        };

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

                        match write_client_config_and_optional_root_key(
                            &decoded,
                            maybe_root_key.as_ref(),
                            cfg_path.as_deref(),
                            None,
                            true,
                        ) {
                            Ok((_cfg_path, maybe_key_path)) => {
                                if let Some(pubkey) = format_root_key_allowlist() {
                                    set_dlg_item_string(hwnd, ID_ENROLL_ROOT_KEY_EDIT, &pubkey);
                                }
                                if let Some(status) = format_user_cert_status(cfg_path.as_deref()) {
                                    set_dlg_item_string(hwnd, ID_ENROLL_CERT_EDIT, &status);
                                }
                                crate::win_native::reload_tray_configuration();
                                let msg = if maybe_key_path.is_some() {
                                    format!(
                                        "Initialized workstation '{}' (with root key) — connecting now!",
                                        decoded.grant.node_id
                                    )
                                } else {
                                    format!(
                                        "Initialized workstation '{}' — connecting now!",
                                        decoded.grant.node_id
                                    )
                                };
                                set_dlg_item_string(hwnd, ID_STYLE_FOOTER_STATUS, &msg);
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
                    2 | ID_ENROLL_BTN_CLOSE => {
                        DestroyWindow(hwnd);
                    }
                    _ => {}
                }
            }
            0
        }
        WM_ENROLL_GITHUB_DONE => {
            handle_github_login_done_from_tray();
            0
        }
        WM_ENROLL_PAIRING_REQUIRED => {
            set_dlg_item_string(
                hwnd,
                ID_STYLE_FOOTER_STATUS,
                "Device pairing required — complete verification in the pairing window.",
            );
            show_pairing_wait_window();
            0
        }
        WM_ENROLL_STATUS_TEXT => {
            if let Some(txt) = ENROLL_STATUS_TEXT.lock().ok().and_then(|mut g| g.take()) {
                set_dlg_item_string(hwnd, ID_STYLE_FOOTER_STATUS, &txt);
            }
            0
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            if let Ok(mut g) = DIALOG_RES.lock() {
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
        let g = DIALOG_RES.lock().unwrap();
        let existing = g.enroll_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            if let Some(pubkey) = format_root_key_allowlist() {
                set_dlg_item_string(existing, ID_ENROLL_ROOT_KEY_EDIT, &pubkey);
            }
            let cfg_path = crate::win_native::get_tray_context()
                .and_then(|c| c.config_path.clone())
                .or_else(|| default_client_config_path().ok());
            if let Some(status) = format_user_cert_status(cfg_path.as_deref()) {
                set_dlg_item_string(existing, ID_ENROLL_CERT_EDIT, &status);
            }
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SshcastEnrollWndClassV2");
    let title = to_wide("Sshcast — Initialize / Enroll Workstation");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(enroll_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: assets.brush_white,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let hwnd = create_centered_dialog_window(&class_name, &title, 640, 600, dpi);
    if !hwnd.is_null() {
        DIALOG_RES.lock().unwrap().enroll_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

// ============================================================================
// 2. GENERATE ENROLLMENT BUNDLE WINDOW (640 x 560 Client Area)
// ============================================================================

unsafe extern "system" fn bundle_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint_taskdialog_frame(hwnd, &[56, 146, 368]);
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => handle_ctlcolor(wparam, lparam),
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let assets = ensure_theme_assets(dpi);
            let maybe_ctx = crate::win_native::get_tray_context();

            // Main TaskDialog-style Header
            create_label(
                hwnd,
                "Generate Signed Enrollment Bundle",
                62,
                18,
                554,
                28,
                ID_STYLE_MAIN_HEADER,
                dpi,
                assets.font_title,
            );

            // Section 1: Root Public Key & Certificate
            create_label(
                hwnd,
                "User Root Public Key & Operator Certificate:",
                24,
                70,
                464,
                18,
                ID_STYLE_SECTION_HEADER_1,
                dpi,
                assets.font_section,
            );
            let has_root_key = format_root_key_allowlist().is_some();
            let root_str = format_root_key_allowlist().unwrap_or_else(|| {
                "No user_key.toml found — click 'Paste Root Key' to import scu1_ key".to_string()
            });
            create_edit(
                hwnd,
                &root_str,
                "",
                true,
                24,
                96,
                282,
                26,
                ID_BUNDLE_ROOT_PUBKEY_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Copy Public Key",
                314,
                95,
                96,
                28,
                ID_BUNDLE_BTN_COPY_PUBKEY,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Import Cert",
                416,
                95,
                96,
                28,
                ID_BUNDLE_BTN_IMPORT_CERT,
                dpi,
                assets.font_ui,
            );
            let root_action_label = if has_root_key {
                "Copy Root Key"
            } else {
                "Paste Root Key"
            };
            create_button(
                hwnd,
                root_action_label,
                518,
                95,
                98,
                28,
                ID_BUNDLE_BTN_ROOT_KEY_ACTION,
                dpi,
                assets.font_ui,
            );

            // Section 2: Target Node Parameters
            create_label(
                hwnd,
                "Target Node & Coordinator Configuration",
                24,
                160,
                592,
                22,
                ID_STYLE_SECTION_HEADER_2,
                dpi,
                assets.font_section,
            );
            let r_relay = create_child_ex(
                hwnd,
                0,
                "BUTTON",
                "Remote Linux Server Relay (sshcast-relay)",
                BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP,
                24,
                188,
                286,
                22,
                ID_BUNDLE_RADIO_RELAY,
                dpi,
                assets.font_ui,
            );
            create_child_ex(
                hwnd,
                0,
                "BUTTON",
                "Secondary Workstation (sshcast-client)",
                BS_AUTORADIOBUTTON | WS_TABSTOP,
                326,
                188,
                286,
                22,
                ID_BUNDLE_RADIO_CLIENT,
                dpi,
                assets.font_ui,
            );
            SendMessageW(r_relay, BM_SETCHECK, BST_CHECKED, 0);

            create_label(
                hwnd,
                "Target Hostname / Node ID:",
                24,
                220,
                190,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_label(
                hwnd,
                "Coordinator URL(s):",
                226,
                220,
                274,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_label(
                hwnd,
                "Expires (days):",
                512,
                220,
                104,
                18,
                0,
                dpi,
                assets.font_ui,
            );

            create_edit(
                hwnd,
                "",
                "e.g. server-x.infra.local",
                false,
                24,
                240,
                190,
                26,
                ID_BUNDLE_NODE_EDIT,
                dpi,
                assets.font_ui,
            );
            let servers_default = maybe_ctx
                .as_ref()
                .map(|c| default_servers_csv(c))
                .unwrap_or_else(|| "sshcast.net".to_string());
            create_edit(
                hwnd,
                &servers_default,
                "https://sshcast.example.com",
                false,
                226,
                240,
                274,
                26,
                ID_BUNDLE_SERVERS_EDIT,
                dpi,
                assets.font_mono,
            );
            create_edit(
                hwnd,
                "0",
                "0 = never",
                false,
                512,
                240,
                104,
                26,
                ID_BUNDLE_EXPIRES_EDIT,
                dpi,
                assets.font_ui,
            );

            create_command_link(
                hwnd,
                "Generate Signed Enrollment Bundle",
                "Sign a NodeGrant with your root key and copy the ready-to-run init command to clipboard",
                true,
                24,
                282,
                592,
                58,
                ID_BUNDLE_BTN_GENERATE,
                dpi,
                assets.font_ui,
            );

            // Section 3: Output Token & Command
            create_label(
                hwnd,
                "Generated Bundle Token (sc1_...):",
                24,
                382,
                400,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_edit(
                hwnd,
                "",
                "",
                true,
                24,
                402,
                464,
                26,
                ID_BUNDLE_TOKEN_OUT_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Copy Token",
                496,
                401,
                120,
                28,
                ID_BUNDLE_BTN_COPY_TOKEN,
                dpi,
                assets.font_ui,
            );

            create_label(
                hwnd,
                "Ready-to-Run CLI Command:",
                24,
                438,
                400,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_edit(
                hwnd,
                "",
                "",
                true,
                24,
                458,
                464,
                26,
                ID_BUNDLE_CMD_OUT_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Copy Command",
                496,
                457,
                120,
                28,
                ID_BUNDLE_BTN_COPY_CMD,
                dpi,
                assets.font_ui,
            );

            // Footer Bar (y = 506 .. 560)
            create_label(
                hwnd,
                "Enter target hostname and click 'Generate Signed Enrollment Bundle'.",
                24,
                523,
                470,
                20,
                ID_STYLE_FOOTER_STATUS,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Close",
                516,
                518,
                100,
                30,
                ID_BUNDLE_BTN_CLOSE,
                dpi,
                assets.font_ui,
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
                                "Generating a new user root key will invalidate previous certificates and allowlist entries. Overwrite user_key.toml?",
                            )
                        {
                            return 0;
                        }
                        match run_keygen(None, true) {
                            Ok(out) => {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_BUNDLE_ROOT_PUBKEY_EDIT,
                                    &out.user_pubkey_token,
                                );
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
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
                        if let Some(pubkey) = format_root_key_allowlist() {
                            if copy_to_clipboard(hwnd, &pubkey) {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "Copied sc_pub_... public key to clipboard!",
                                );
                            }
                        } else {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Import or generate a root key first before copying.",
                            );
                        }
                    }
                    ID_BUNDLE_BTN_IMPORT_CERT => {
                        let Some(clip) = paste_from_clipboard(hwnd) else {
                            show_tray_error_dialog(
                                "Clipboard Empty",
                                "No sc_cert_ operator certificate token found on clipboard",
                                "Sign your sc_pub_... key in the Operator Console, copy the sc_cert_... token to clipboard, and click 'Import Cert'.",
                            );
                            return 0;
                        };
                        let token = clip
                            .split_whitespace()
                            .find(|w| w.starts_with(USER_CERT_PREFIX))
                            .unwrap_or(clip.trim());
                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());
                        match import_user_cert(token, None, cfg_path.as_deref()) {
                            Ok((_, updated_cfg, cert)) => {
                                if updated_cfg.is_some() {
                                    crate::win_native::reload_tray_configuration();
                                }
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    &format!(
                                        "Imported operator certificate for {}!",
                                        cert.user_id
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Certificate Import Failed",
                                    "Failed to import sc_cert_ operator certificate from clipboard",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_BUNDLE_BTN_ROOT_KEY_ACTION => {
                        if format_root_key_allowlist().is_some() {
                            match export_user_root_key(None) {
                                Ok(tok) => {
                                    if copy_to_clipboard(hwnd, &tok) {
                                        set_dlg_item_string(
                                            hwnd,
                                            ID_STYLE_FOOTER_STATUS,
                                            "Copied scu1_ user root key to clipboard (paste on secondary workstation)!",
                                        );
                                    }
                                }
                                Err(e) => {
                                    show_tray_error_dialog(
                                        "Export Failed",
                                        "Failed to export user root key",
                                        &format!("{e:#}"),
                                    );
                                }
                            }
                        } else {
                            let Some(clip) = paste_from_clipboard(hwnd) else {
                                show_tray_error_dialog(
                                    "Clipboard Empty",
                                    "No scu1_ root key token found on clipboard",
                                    "On your primary workstation, open 'Generate Enrollment Bundle' and click 'Copy Root Key', then click 'Paste Root Key' here.",
                                );
                                return 0;
                            };
                            let cfg_path = crate::win_native::get_tray_context()
                                .and_then(|c| c.config_path.clone())
                                .or_else(|| default_client_config_path().ok());
                            match import_user_root_key(&clip, None, cfg_path.as_deref(), true) {
                                Ok(out) => {
                                    set_dlg_item_string(
                                        hwnd,
                                        ID_BUNDLE_ROOT_PUBKEY_EDIT,
                                        &out.user_pubkey_token,
                                    );
                                    set_dlg_item_string(
                                        hwnd,
                                        ID_BUNDLE_BTN_ROOT_KEY_ACTION,
                                        "Copy Root Key",
                                    );
                                    set_dlg_item_string(
                                        hwnd,
                                        ID_STYLE_FOOTER_STATUS,
                                        &format!(
                                            "Imported root key (User ID: {}) and saved user_key.toml!",
                                            out.user_id
                                        ),
                                    );
                                }
                                Err(e) => {
                                    show_tray_error_dialog(
                                        "Import Root Key Failed",
                                        "Failed to import scu1_ user root key from clipboard",
                                        &format!("{e:#}"),
                                    );
                                }
                            }
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
                                "Enter at least one coordinator domain or URL (e.g. 'sshcast.net' or 'https://c1.sshcast.net').",
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
                            show_tray_error_dialog(
                                "User Root Key Required",
                                "No user_key.toml found on this workstation",
                                "On your primary workstation, open 'Generate Enrollment Bundle' and click 'Copy Root Key', then click 'Paste Root Key' above on this workstation.",
                            );
                            return 0;
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
                            let include_rk = if is_relay { None } else { Some(&user_sk) };
                            encode_enrollment_bundle_token(&bundle, include_rk)
                        })();

                        match res {
                            Ok(token) => {
                                let cli_cmd = if is_relay {
                                    format!("sshcast-relay init --bundle {token}")
                                } else {
                                    format!("sshcast-client init --bundle {token}")
                                };
                                set_dlg_item_string(hwnd, ID_BUNDLE_TOKEN_OUT_EDIT, &token);
                                set_dlg_item_string(hwnd, ID_BUNDLE_CMD_OUT_EDIT, &cli_cmd);
                                let _ = copy_to_clipboard(hwnd, &cli_cmd);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    &format!(
                                        "Minted bundle for '{}' & copied CLI command to clipboard!",
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
                                ID_STYLE_FOOTER_STATUS,
                                "Copied sc1_ bundle token to clipboard!",
                            );
                        }
                    }
                    ID_BUNDLE_BTN_COPY_CMD => {
                        let cmd = get_dlg_item_string(hwnd, ID_BUNDLE_CMD_OUT_EDIT);
                        if !cmd.is_empty() && copy_to_clipboard(hwnd, &cmd) {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Copied CLI command to clipboard!",
                            );
                        }
                    }
                    2 | ID_BUNDLE_BTN_CLOSE => {
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
            if let Ok(mut g) = DIALOG_RES.lock() {
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
    let is_enrolled = crate::win_native::get_tray_context()
        .and_then(|c| c.current_config())
        .is_some();
    if !is_enrolled {
        show_enroll_window();
        return;
    }

    {
        let g = DIALOG_RES.lock().unwrap();
        let existing = g.bundle_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            if let Some(allow) = format_root_key_allowlist() {
                set_dlg_item_string(existing, ID_BUNDLE_ROOT_PUBKEY_EDIT, &allow);
                set_dlg_item_string(existing, ID_BUNDLE_BTN_ROOT_KEY_ACTION, "Copy Root Key");
            } else {
                set_dlg_item_string(existing, ID_BUNDLE_BTN_ROOT_KEY_ACTION, "Paste Root Key");
            }
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SshcastBundleWndClassV2");
    let title = to_wide("Sshcast — Generate Enrollment Bundle");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(bundle_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: assets.brush_white,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let hwnd = create_centered_dialog_window(&class_name, &title, 640, 560, dpi);
    if !hwnd.is_null() {
        DIALOG_RES.lock().unwrap().bundle_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

// ============================================================================
// 3. MANAGE COORDINATOR BACKENDS WINDOW (560 x 420 Client Area)
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
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint_taskdialog_frame(hwnd, &[56]);
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => handle_ctlcolor(wparam, lparam),
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let assets = ensure_theme_assets(dpi);
            let maybe_ctx = crate::win_native::get_tray_context();

            // Main TaskDialog-style Header
            create_label(
                hwnd,
                "Coordinator Backend Servers",
                62,
                18,
                474,
                28,
                ID_STYLE_MAIN_HEADER,
                dpi,
                assets.font_title,
            );

            create_label(
                hwnd,
                "Active Coordinator gRPC URLs (Workstation connects to all concurrently):",
                24,
                70,
                512,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            let lb = create_child_ex(
                hwnd,
                WS_EX_CLIENTEDGE,
                "LISTBOX",
                "",
                WS_VSCROLL | LBS_NOTIFY | WS_TABSTOP,
                24,
                92,
                384,
                124,
                ID_BACKENDS_LISTBOX,
                dpi,
                assets.font_mono,
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

            create_button(
                hwnd,
                "Remove Selected",
                416,
                92,
                120,
                30,
                ID_BACKENDS_BTN_REMOVE,
                dpi,
                assets.font_ui,
            );

            create_label(
                hwnd,
                "Add Coordinator Domain (_sshcast TXT) or Server URL (https://):",
                24,
                226,
                512,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_edit(
                hwnd,
                "",
                "sshcast.net or https://sshcast.example.com",
                false,
                24,
                246,
                384,
                26,
                ID_BACKENDS_ADD_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Add Server",
                416,
                245,
                120,
                28,
                ID_BACKENDS_BTN_ADD,
                dpi,
                assets.font_ui,
            );

            create_command_link(
                hwnd,
                "Save Backends & Reconnect Now",
                "Write updated coordinator URLs to client.toml and immediately reconnect active streams",
                true,
                24,
                290,
                512,
                58,
                ID_BACKENDS_BTN_SAVE,
                dpi,
                assets.font_ui,
            );

            // Footer Bar (y = 366 .. 420)
            create_label(
                hwnd,
                "Add or remove coordinator URLs, then click Save.",
                24,
                383,
                396,
                20,
                ID_STYLE_FOOTER_STATUS,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Close",
                436,
                378,
                100,
                30,
                ID_BACKENDS_BTN_CLOSE,
                dpi,
                assets.font_ui,
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
                        if !is_valid_coordinator_entry(trimmed) {
                            show_tray_error_dialog(
                                "Invalid Coordinator Entry",
                                "Enter a domain name (_sshcast DNS TXT) or an http(s):// URL",
                                "Example: sshcast.net or https://c1.sshcast.net",
                            );
                            return 0;
                        }
                        let existing = listbox_get_items(lb);
                        if existing.iter().any(|s| s.eq_ignore_ascii_case(trimmed)) {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "That coordinator entry is already in the list.",
                            );
                            return 0;
                        }
                        let w = to_wide(trimmed);
                        let idx = SendMessageW(lb, LB_ADDSTRING, 0, w.as_ptr() as isize);
                        SendMessageW(lb, LB_SETCURSEL, idx as usize, 0);
                        set_dlg_item_string(hwnd, ID_BACKENDS_ADD_EDIT, "");
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
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
                                ID_STYLE_FOOTER_STATUS,
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
                                    Ok(_saved_path) => {
                                        crate::win_native::reload_tray_configuration();
                                        SendMessageW(lb, LB_RESETCONTENT, 0, 0);
                                        for srv in &servers {
                                            let w = to_wide(srv);
                                            SendMessageW(lb, LB_ADDSTRING, 0, w.as_ptr() as isize);
                                        }
                                        set_dlg_item_string(
                                            hwnd,
                                            ID_STYLE_FOOTER_STATUS,
                                            &format!(
                                                "Saved {} server(s) to client.toml & reconnecting!",
                                                servers.len()
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
                    2 | ID_BACKENDS_BTN_CLOSE => {
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
            if let Ok(mut g) = DIALOG_RES.lock() {
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
    let is_enrolled = crate::win_native::get_tray_context()
        .and_then(|c| c.current_config())
        .is_some();
    if !is_enrolled {
        show_enroll_window();
        return;
    }

    {
        let g = DIALOG_RES.lock().unwrap();
        let existing = g.backends_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SshcastBackendsWndClassV2");
    let title = to_wide("Sshcast — Manage Coordinator Backends");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(backends_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: assets.brush_white,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let hwnd = create_centered_dialog_window(&class_name, &title, 560, 420, dpi);
    if !hwnd.is_null() {
        DIALOG_RES.lock().unwrap().backends_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

// ============================================================================
// 4. MANAGE SSH KEYS WINDOW (620 x 490 Client Area)
// ============================================================================

static SSH_KEYS_ITEMS: Mutex<Vec<crate::local_agent::HeldKeyDisplayItem>> = Mutex::new(Vec::new());

unsafe fn refresh_ssh_keys_listbox(hwnd: HWND) {
    let lb = GetDlgItem(hwnd, ID_SSHKEYS_LISTBOX);
    if lb.is_null() {
        return;
    }
    SendMessageW(lb, LB_RESETCONTENT, 0, 0);

    let Some(ctx) = crate::win_native::get_tray_context() else {
        return;
    };

    let chk = GetDlgItem(hwnd, ID_SSHKEYS_CHK_NO_OS_AGENT);
    if !chk.is_null() {
        let state = if ctx.local_agent.is_os_agent_disabled() {
            BST_CHECKED
        } else {
            BST_UNCHECKED
        };
        SendMessageW(chk, BM_SETCHECK, state, 0);
    }

    let items = ctx.local_agent.query_held_keys_for_ui();
    for item in &items {
        let w = to_wide(&item.display_line);
        SendMessageW(lb, LB_ADDSTRING, 0, w.as_ptr() as isize);
    }
    if !items.is_empty() {
        SendMessageW(lb, LB_SETCURSEL, 0, 0);
    }
    if let Ok(mut guard) = SSH_KEYS_ITEMS.lock() {
        *guard = items;
    }
}

unsafe extern "system" fn ssh_keys_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint_taskdialog_frame(hwnd, &[56, 260]);
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => handle_ctlcolor(wparam, lparam),
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let assets = ensure_theme_assets(dpi);

            create_label(
                hwnd,
                "Manage SSH Agent Keys (Built-in, OS Agent & Pageant)",
                62,
                18,
                534,
                28,
                ID_STYLE_MAIN_HEADER,
                dpi,
                assets.font_title,
            );

            create_label(
                hwnd,
                "Held SSH Keys ([Built-in], [OS Agent] & [Pageant]):",
                24,
                68,
                572,
                18,
                ID_STYLE_SECTION_HEADER_1,
                dpi,
                assets.font_section,
            );

            create_child_ex(
                hwnd,
                WS_EX_CLIENTEDGE,
                "LISTBOX",
                "",
                WS_VSCROLL | LBS_NOTIFY | WS_TABSTOP,
                24,
                92,
                436,
                128,
                ID_SSHKEYS_LISTBOX,
                dpi,
                assets.font_mono,
            );

            create_button(
                hwnd,
                "Remove Selected",
                468,
                92,
                128,
                30,
                ID_SSHKEYS_BTN_REMOVE,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Refresh List",
                468,
                130,
                128,
                30,
                ID_SSHKEYS_BTN_REFRESH,
                dpi,
                assets.font_ui,
            );

            create_child_ex(
                hwnd,
                0,
                "BUTTON",
                "Use Built-in Keys Only (Disable external OS ssh-agent & Pageant)",
                BS_AUTOCHECKBOX | WS_TABSTOP,
                24,
                228,
                572,
                22,
                ID_SSHKEYS_CHK_NO_OS_AGENT,
                dpi,
                assets.font_ui,
            );

            create_label(
                hwnd,
                "Add OpenSSH Private Key to Built-in Agent",
                24,
                272,
                572,
                20,
                ID_STYLE_SECTION_HEADER_2,
                dpi,
                assets.font_section,
            );

            create_label(
                hwnd,
                "Private Key File Path (e.g. ~/.ssh/id_ed25519):",
                24,
                298,
                356,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_label(
                hwnd,
                "Passphrase (if encrypted):",
                392,
                298,
                204,
                18,
                0,
                dpi,
                assets.font_ui,
            );

            create_edit(
                hwnd,
                "~/.ssh/id_ed25519",
                "~/.ssh/id_ed25519",
                false,
                24,
                318,
                356,
                26,
                ID_SSHKEYS_PATH_EDIT,
                dpi,
                assets.font_mono,
            );

            let pass_hwnd = create_child_ex(
                hwnd,
                WS_EX_CLIENTEDGE,
                "EDIT",
                "",
                ES_AUTOHSCROLL | ES_PASSWORD | WS_TABSTOP,
                392,
                318,
                204,
                26,
                ID_SSHKEYS_PASS_EDIT,
                dpi,
                assets.font_ui,
            );
            if !pass_hwnd.is_null() {
                let cue_w = to_wide("Optional passphrase");
                SendMessageW(pass_hwnd, EM_SETCUEBANNER, 1, cue_w.as_ptr() as isize);
            }

            create_command_link(
                hwnd,
                "Add Key File to Built-in Agent",
                "Load OpenSSH private key into memory and save path in client.toml",
                true,
                24,
                356,
                356,
                58,
                ID_SSHKEYS_BTN_ADD_FILE,
                dpi,
                assets.font_ui,
            );

            create_command_link(
                hwnd,
                "Paste PEM Key",
                "Import from clipboard",
                false,
                392,
                356,
                204,
                58,
                ID_SSHKEYS_BTN_PASTE_PEM,
                dpi,
                assets.font_ui,
            );

            // Footer Bar (y = 436 .. 490)
            create_label(
                hwnd,
                "Manage built-in SSH private keys or view OS ssh-agent keys.",
                24,
                453,
                456,
                20,
                ID_STYLE_FOOTER_STATUS,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Close",
                496,
                448,
                100,
                30,
                ID_SSHKEYS_BTN_CLOSE,
                dpi,
                assets.font_ui,
            );

            refresh_ssh_keys_listbox(hwnd);
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            let code = ((wparam >> 16) & 0xFFFF) as u32;
            if code == BN_CLICKED {
                match id {
                    ID_SSHKEYS_BTN_REFRESH => {
                        refresh_ssh_keys_listbox(hwnd);
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
                            "Refreshed built-in and OS ssh-agent key list.",
                        );
                    }
                    ID_SSHKEYS_CHK_NO_OS_AGENT => {
                        let chk = GetDlgItem(hwnd, ID_SSHKEYS_CHK_NO_OS_AGENT);
                        let checked =
                            SendMessageW(chk, BM_GETCHECK, 0, 0) as usize == BST_CHECKED;
                        if let Some(ctx) = crate::win_native::get_tray_context() {
                            if let Err(e) = ctx
                                .local_agent
                                .ui_set_disable_os_agent(checked, ctx.config_path.as_deref())
                            {
                                show_tray_error_dialog(
                                    "Failed to Save Setting",
                                    "Could not update disable_os_agent in client.toml",
                                    &format!("{e:#}"),
                                );
                            }
                            crate::win_native::reload_tray_configuration();
                        }
                        refresh_ssh_keys_listbox(hwnd);
                        let msg = if checked {
                            "Enabled Built-in Keys Only mode (OS ssh-agent disabled)."
                        } else {
                            "Enabled Hybrid mode (Built-in + OS ssh-agent keys)."
                        };
                        set_dlg_item_string(hwnd, ID_STYLE_FOOTER_STATUS, msg);
                    }
                    ID_SSHKEYS_BTN_ADD_FILE => {
                        let raw_path = get_dlg_item_string(hwnd, ID_SSHKEYS_PATH_EDIT);
                        let passphrase = get_dlg_item_string(hwnd, ID_SSHKEYS_PASS_EDIT);
                        let Some(ctx) = crate::win_native::get_tray_context() else {
                            return 0;
                        };
                        match ctx.local_agent.ui_add_key_from_file(
                            &raw_path,
                            &passphrase,
                            ctx.config_path.as_deref(),
                        ) {
                            Ok(pk) => {
                                set_dlg_item_string(hwnd, ID_SSHKEYS_PASS_EDIT, "");
                                crate::win_native::reload_tray_configuration();
                                refresh_ssh_keys_listbox(hwnd);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    &format!(
                                        "Loaded built-in key {} ({})!",
                                        pk.fingerprint_sha256, pk.comment
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Failed to Load SSH Key",
                                    "Could not load OpenSSH private key file",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_SSHKEYS_BTN_PASTE_PEM => {
                        let Some(clip_pem) = paste_from_clipboard(hwnd) else {
                            show_tray_error_dialog(
                                "Clipboard Empty",
                                "No text found on the clipboard",
                                "Copy an OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) to the clipboard first.",
                            );
                            return 0;
                        };
                        let passphrase = get_dlg_item_string(hwnd, ID_SSHKEYS_PASS_EDIT);
                        let Some(ctx) = crate::win_native::get_tray_context() else {
                            return 0;
                        };
                        match ctx.local_agent.ui_add_key_from_pem(
                            &clip_pem,
                            &passphrase,
                            ctx.config_path.as_deref(),
                        ) {
                            Ok(pk) => {
                                set_dlg_item_string(hwnd, ID_SSHKEYS_PASS_EDIT, "");
                                crate::win_native::reload_tray_configuration();
                                refresh_ssh_keys_listbox(hwnd);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    &format!(
                                        "Imported inline SSH key {} ({}) from clipboard!",
                                        pk.fingerprint_sha256, pk.comment
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Failed to Import SSH Key",
                                    "Clipboard does not contain a valid OpenSSH private key or passphrase is required",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    ID_SSHKEYS_BTN_REMOVE => {
                        let lb = GetDlgItem(hwnd, ID_SSHKEYS_LISTBOX);
                        let sel = SendMessageW(lb, LB_GETCURSEL, 0, 0);
                        if sel == LB_ERR {
                            return 0;
                        }
                        let maybe_item = SSH_KEYS_ITEMS
                            .lock()
                            .ok()
                            .and_then(|items| items.get(sel as usize).cloned());
                        let Some(item) = maybe_item else {
                            return 0;
                        };
                        let Some(ctx) = crate::win_native::get_tray_context() else {
                            return 0;
                        };
                        match ctx
                            .local_agent
                            .ui_remove_builtin_key(&item, ctx.config_path.as_deref())
                        {
                            Ok(_) => {
                                crate::win_native::reload_tray_configuration();
                                refresh_ssh_keys_listbox(hwnd);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    &format!(
                                        "Removed built-in key {} ({}).",
                                        item.fingerprint_sha256, item.comment
                                    ),
                                );
                            }
                            Err(e) => {
                                show_tray_error_dialog(
                                    "Cannot Remove Key",
                                    "Selected key is managed by the external OS ssh-agent",
                                    &format!("{e:#}"),
                                );
                            }
                        }
                    }
                    2 | ID_SSHKEYS_BTN_CLOSE => {
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
            if let Ok(mut g) = DIALOG_RES.lock() {
                if g.ssh_keys_hwnd == hwnd as isize {
                    g.ssh_keys_hwnd = 0;
                }
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe fn show_ssh_keys_window() {
    {
        let g = DIALOG_RES.lock().unwrap();
        let existing = g.ssh_keys_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            refresh_ssh_keys_listbox(existing);
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SshcastSshKeysWndClassV1");
    let title = to_wide("Sshcast — Manage SSH Keys");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(ssh_keys_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: assets.brush_white,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let hwnd = create_centered_dialog_window(&class_name, &title, 620, 490, dpi);
    if !hwnd.is_null() {
        DIALOG_RES.lock().unwrap().ssh_keys_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

// ============================================================================
// 5. GITHUB LOGIN & DEVICE PAIRING WAIT WINDOW (560 x 430 Client Area)
// ============================================================================

struct LoginActorGuard {
    session_gen: u64,
}

impl Drop for LoginActorGuard {
    fn drop(&mut self) {
        if LOGIN_SESSION_GEN.load(Ordering::SeqCst) == self.session_gen {
            GITHUB_LOGIN_IN_FLIGHT.store(false, Ordering::SeqCst);
            if let Ok(mut tx_guard) = ACTIVE_PAIRING_TX.lock() {
                *tx_guard = None;
            }
        }
    }
}

fn post_to_tray_or_dialog(tray_msg: u32, fallback_hwnd_raw: isize, fallback_msg: u32) {
    let tray_raw = crate::win_native::get_tray_context()
        .map(|c| c.tray_hwnd.load(Ordering::Relaxed))
        .unwrap_or(0);
    unsafe {
        if tray_raw != 0 && IsWindow(tray_raw as HWND) != 0 {
            PostMessageW(tray_raw as HWND, tray_msg, 0, 0);
        } else if fallback_hwnd_raw != 0 && IsWindow(fallback_hwnd_raw as HWND) != 0 {
            PostMessageW(fallback_hwnd_raw as HWND, fallback_msg, 0, 0);
        }
    }
}

fn post_enroll_status_update(text: &str) {
    if LOGIN_SESSION_GEN.load(Ordering::SeqCst) == 0 {
        return;
    }
    let enroll_raw = DIALOG_RES
        .lock()
        .ok()
        .map(|g| g.enroll_hwnd)
        .unwrap_or(0);
    if enroll_raw == 0 {
        return;
    }
    if let Ok(mut guard) = ENROLL_STATUS_TEXT.lock() {
        *guard = Some(text.to_string());
    }
    unsafe {
        if IsWindow(enroll_raw as HWND) != 0 {
            PostMessageW(enroll_raw as HWND, WM_ENROLL_STATUS_TEXT, 0, 0);
        }
    }
}

fn finish_github_login_with_result(
    session_gen: u64,
    enroll_hwnd_raw: isize,
    res: Result<LoginOutcome, String>,
) {
    if LOGIN_SESSION_GEN.load(Ordering::SeqCst) != session_gen {
        return;
    }
    if let Ok(mut guard) = GITHUB_LOGIN_RESULT.lock() {
        *guard = Some(res);
    }
    GITHUB_LOGIN_IN_FLIGHT.store(false, Ordering::SeqCst);
    let current_enroll_raw = DIALOG_RES
        .lock()
        .ok()
        .map(|g| g.enroll_hwnd)
        .filter(|&h| h != 0)
        .unwrap_or(enroll_hwnd_raw);
    post_to_tray_or_dialog(
        WM_TRAY_GITHUB_LOGIN_DONE,
        current_enroll_raw,
        WM_ENROLL_GITHUB_DONE,
    );
}

fn open_pairing_wait_from_actor(
    session_gen: u64,
    enroll_hwnd_raw: isize,
    info: PendingPairingInfo,
    action_tx: tokio::sync::mpsc::UnboundedSender<PairingUiAction>,
) {
    if LOGIN_SESSION_GEN.load(Ordering::SeqCst) != session_gen {
        return;
    }
    if let Ok(mut tx_guard) = ACTIVE_PAIRING_TX.lock() {
        *tx_guard = Some(action_tx);
    }
    if let Ok(mut state_guard) = PAIRING_UI_STATE.lock() {
        *state_guard = Some(PairingUiState {
            session_gen,
            info,
            completed: false,
            events: VecDeque::new(),
        });
    }
    let current_enroll_raw = DIALOG_RES
        .lock()
        .ok()
        .map(|g| g.enroll_hwnd)
        .filter(|&h| h != 0)
        .unwrap_or(enroll_hwnd_raw);
    post_to_tray_or_dialog(
        WM_TRAY_OPEN_PAIRING_WINDOW,
        current_enroll_raw,
        WM_ENROLL_PAIRING_REQUIRED,
    );
}

fn push_pairing_event_from_actor(session_gen: u64, event: PairingUiEvent) {
    if LOGIN_SESSION_GEN.load(Ordering::SeqCst) != session_gen {
        return;
    }
    if let Ok(mut state_guard) = PAIRING_UI_STATE.lock() {
        if let Some(ref mut st) = *state_guard {
            if st.session_gen == session_gen {
                st.events.push_back(event);
            }
        }
    }
    let pairing_raw = DIALOG_RES
        .lock()
        .ok()
        .map(|g| g.pairing_hwnd)
        .unwrap_or(0);
    post_to_tray_or_dialog(WM_TRAY_PAIRING_UPDATE, pairing_raw, WM_PAIRING_UPDATE);
}

fn finish_pairing_with_outcome(session_gen: u64, res: Result<LoginOutcome, String>) {
    if LOGIN_SESSION_GEN.load(Ordering::SeqCst) != session_gen {
        return;
    }
    if let Ok(mut tx_guard) = ACTIVE_PAIRING_TX.lock() {
        *tx_guard = None;
    }
    GITHUB_LOGIN_IN_FLIGHT.store(false, Ordering::SeqCst);
    let event = match res {
        Ok(outcome) => PairingUiEvent::Completed(outcome),
        Err(msg) => PairingUiEvent::TerminalError(msg),
    };
    push_pairing_event_from_actor(session_gen, event);
}

fn run_github_login_actor_thread(
    session_gen: u64,
    enroll_hwnd_raw: isize,
    servers: Vec<String>,
    explicit_op: Option<String>,
    node_name: String,
    cfg_path: Option<std::path::PathBuf>,
) {
    let _guard = LoginActorGuard { session_gen };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            finish_github_login_with_result(
                session_gen,
                enroll_hwnd_raw,
                Err(format!("failed to start async runtime: {e}")),
            );
            return;
        }
    };

    rt.block_on(async move {
        let key_file = resolve_tray_user_key_path(cfg_path.as_deref());
        let started = match start_github_enrollment(
            &servers,
            explicit_op.as_deref(),
            Some(node_name.trim()).filter(|s| !s.is_empty()),
            key_file.as_deref(),
            cfg_path.as_deref(),
            true,
            |_| {},
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                finish_github_login_with_result(
                    session_gen,
                    enroll_hwnd_raw,
                    Err(format!("{e:#}")),
                );
                return;
            }
        };

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
        let mut poll_sleep = std::pin::pin!(tokio::time::sleep(std::time::Duration::from_secs(2)));
        let (action_tx, mut action_rx) = tokio::sync::mpsc::unbounded_channel::<PairingUiAction>();
        let mut current_pairing_info: Option<PendingPairingInfo> = None;
        let mut displayed_pairing_id: Option<String> = None;
        let mut logged_awaiting = false;

        loop {
            if LOGIN_SESSION_GEN.load(Ordering::SeqCst) != session_gen {
                let _ = cancel_enrollment_pairing(&started).await;
                return;
            }

            tokio::select! {
                maybe_action = action_rx.recv() => {
                    let Some(action) = maybe_action else {
                        return;
                    };
                    match action {
                        PairingUiAction::Unlock(pass) => {
                            let Some(ref info) = current_pairing_info else {
                                push_pairing_event_from_actor(
                                    session_gen,
                                    PairingUiEvent::TransientError {
                                        message: "Pairing details are not ready yet; please wait.".to_string(),
                                        show_dialog: false,
                                    },
                                );
                                continue;
                            };
                            match unlock_with_recovery_passphrase(&started, info, &pass).await {
                                Ok(outcome) => {
                                    finish_pairing_with_outcome(session_gen, Ok(outcome));
                                    return;
                                }
                                Err(e) => {
                                    let is_wrong_pass = e.chain().any(|cause| {
                                        matches!(
                                            cause.downcast_ref::<VaultDecryptError>(),
                                            Some(VaultDecryptError::WrongPassphrase)
                                        )
                                    });
                                    if is_wrong_pass {
                                        push_pairing_event_from_actor(
                                            session_gen,
                                            PairingUiEvent::TransientError {
                                                message: "Incorrect recovery passphrase. Please try again.".to_string(),
                                                show_dialog: false,
                                            },
                                        );
                                    } else {
                                        push_pairing_event_from_actor(
                                            session_gen,
                                            PairingUiEvent::TransientError {
                                                message: format!("Recovery unlock failed: {e:#}"),
                                                show_dialog: true,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                        PairingUiAction::Reset => {
                            match confirm_replace_lost_root_key(&started).await {
                                Ok(outcome) => {
                                    finish_pairing_with_outcome(session_gen, Ok(outcome));
                                    return;
                                }
                                Err(e) => {
                                    push_pairing_event_from_actor(
                                        session_gen,
                                        PairingUiEvent::TransientError {
                                            message: format!("Failed to replace lost root key: {e:#}"),
                                            show_dialog: true,
                                        },
                                    );
                                }
                            }
                        }
                        PairingUiAction::Cancel => {
                            let _ = cancel_enrollment_pairing(&started).await;
                            push_pairing_event_from_actor(session_gen, PairingUiEvent::Canceled);
                            return;
                        }
                    }
                }
                _ = &mut poll_sleep => {
                    if tokio::time::Instant::now() >= deadline {
                        let _ = cancel_enrollment_pairing(&started).await;
                        let msg = "Timed out waiting for GitHub OAuth enrollment completion.".to_string();
                        if current_pairing_info.is_some() {
                            finish_pairing_with_outcome(session_gen, Err(msg));
                        } else {
                            finish_github_login_with_result(session_gen, enroll_hwnd_raw, Err(msg));
                        }
                        return;
                    }
                    poll_sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(2));

                    let step = match poll_enrollment_once(&started).await {
                        Ok(s) => s,
                        Err(e) if is_terminal_enroll_error(&e) => {
                            let msg = format!("{e:#}");
                            if current_pairing_info.is_some() {
                                finish_pairing_with_outcome(session_gen, Err(msg));
                            } else {
                                finish_github_login_with_result(session_gen, enroll_hwnd_raw, Err(msg));
                            }
                            return;
                        }
                        Err(e) => {
                            tracing::debug!("Enrollment poll transient error: {e:#}");
                            continue;
                        }
                    };

                    if LOGIN_SESSION_GEN.load(Ordering::SeqCst) != session_gen {
                        let _ = cancel_enrollment_pairing(&started).await;
                        return;
                    }

                    match step {
                        EnrollPollStep::Pending => {}
                        EnrollPollStep::AwaitingApproval => {
                            if !logged_awaiting {
                                logged_awaiting = true;
                                post_enroll_status_update(
                                    "GitHub sign-in completed; waiting for operator approval...",
                                );
                            }
                        }
                        EnrollPollStep::Approved { cert_token } => {
                            let res = finalize_new_or_same_key_enrollment(&started, &cert_token)
                                .map_err(|e| format!("{e:#}"));
                            if current_pairing_info.is_some() {
                                finish_pairing_with_outcome(session_gen, res);
                            } else {
                                finish_github_login_with_result(session_gen, enroll_hwnd_raw, res);
                            }
                            return;
                        }
                        EnrollPollStep::Paired {
                            pairing_id,
                            existing_user_pubkey,
                            envelope,
                            ..
                        } => {
                            let res = complete_paired_enrollment(
                                started,
                                &existing_user_pubkey,
                                &pairing_id,
                                &envelope,
                            )
                            .await
                            .map_err(|e| format!("{e:#}"));
                            if current_pairing_info.is_some() {
                                finish_pairing_with_outcome(session_gen, res);
                            } else {
                                finish_github_login_with_result(session_gen, enroll_hwnd_raw, res);
                            }
                            return;
                        }
                        EnrollPollStep::PairingRequired(info) => {
                            let is_new = displayed_pairing_id.as_deref() != Some(&info.pairing_id);
                            current_pairing_info = Some(info.clone());
                            if is_new {
                                displayed_pairing_id = Some(info.pairing_id.clone());
                                open_pairing_wait_from_actor(
                                    session_gen,
                                    enroll_hwnd_raw,
                                    info,
                                    action_tx.clone(),
                                );
                            }
                        }
                        EnrollPollStep::Denied(reason) => {
                            let msg = format!("Enrollment rejected ({reason})");
                            if current_pairing_info.is_some() {
                                finish_pairing_with_outcome(session_gen, Err(msg));
                            } else {
                                finish_github_login_with_result(session_gen, enroll_hwnd_raw, Err(msg));
                            }
                            return;
                        }
                    }
                }
            }
        }
    });
}

unsafe fn apply_login_outcome_to_ui(outcome: &LoginOutcome) {
    crate::win_native::reload_tray_configuration();
    let enroll_hwnd = DIALOG_RES
        .lock()
        .ok()
        .map(|g| g.enroll_hwnd as HWND)
        .unwrap_or(null_mut());
    if !enroll_hwnd.is_null() && IsWindow(enroll_hwnd) != 0 {
        set_dlg_item_string(
            enroll_hwnd,
            ID_ENROLL_ROOT_KEY_EDIT,
            &outcome.user_pubkey_token,
        );
        if let Some(status) = format_user_cert_status(Some(&outcome.config_path)) {
            set_dlg_item_string(enroll_hwnd, ID_ENROLL_CERT_EDIT, &status);
        }
        set_dlg_item_string(
            enroll_hwnd,
            ID_STYLE_FOOTER_STATUS,
            &format!("Signed in via GitHub as '{}' — connecting!", outcome.user_id),
        );
    }
}

pub unsafe fn handle_github_login_done_from_tray() {
    let outcome_opt = GITHUB_LOGIN_RESULT.lock().ok().and_then(|mut g| g.take());
    if let Some(outcome_res) = outcome_opt {
        match outcome_res {
            Ok(outcome) => {
                apply_login_outcome_to_ui(&outcome);
            }
            Err(err_msg) => {
                let enroll_hwnd = DIALOG_RES
                    .lock()
                    .ok()
                    .map(|g| g.enroll_hwnd as HWND)
                    .unwrap_or(null_mut());
                if !enroll_hwnd.is_null() && IsWindow(enroll_hwnd) != 0 {
                    set_dlg_item_string(
                        enroll_hwnd,
                        ID_STYLE_FOOTER_STATUS,
                        "GitHub sign-in failed.",
                    );
                }
                show_tray_error_dialog(
                    "GitHub Sign-In Failed",
                    "Could not complete GitHub OAuth enrollment",
                    &err_msg,
                );
            }
        }
    }
}

unsafe fn drain_pairing_events() -> Vec<PairingUiEvent> {
    let mut out = Vec::new();
    if let Ok(mut state_guard) = PAIRING_UI_STATE.lock() {
        if let Some(ref mut st) = *state_guard {
            while let Some(ev) = st.events.pop_front() {
                out.push(ev);
            }
        }
    }
    out
}

unsafe fn mark_pairing_completed() {
    if let Ok(mut state_guard) = PAIRING_UI_STATE.lock() {
        if let Some(ref mut st) = *state_guard {
            st.completed = true;
        }
    }
}

unsafe fn set_pairing_action_buttons_enabled(hwnd: HWND, enabled: bool) {
    set_ctrl_enabled(hwnd, ID_PAIRING_BTN_UNLOCK, enabled);
    set_ctrl_enabled(hwnd, ID_PAIRING_BTN_RESET, enabled);
}

unsafe fn cancel_and_close_pairing_window(hwnd: HWND) {
    let should_cancel = if let Ok(mut state_guard) = PAIRING_UI_STATE.lock() {
        if let Some(ref mut st) = *state_guard {
            if st.completed {
                false
            } else {
                st.completed = true;
                true
            }
        } else {
            false
        }
    } else {
        false
    };

    if should_cancel {
        let tx_opt = ACTIVE_PAIRING_TX.lock().ok().and_then(|mut g| g.take());
        LOGIN_SESSION_GEN.fetch_add(1, Ordering::SeqCst);
        GITHUB_LOGIN_IN_FLIGHT.store(false, Ordering::SeqCst);
        if let Some(tx) = tx_opt {
            let _ = tx.send(PairingUiAction::Cancel);
        }
        let enroll_hwnd = DIALOG_RES
            .lock()
            .ok()
            .map(|g| g.enroll_hwnd as HWND)
            .unwrap_or(null_mut());
        if !enroll_hwnd.is_null() && IsWindow(enroll_hwnd) != 0 {
            set_dlg_item_string(
                enroll_hwnd,
                ID_STYLE_FOOTER_STATUS,
                "GitHub sign-in / pairing canceled.",
            );
        }
    }
    DestroyWindow(hwnd);
}

unsafe fn process_pairing_events(hwnd_opt: Option<HWND>) {
    let events = drain_pairing_events();
    for ev in events {
        match ev {
            PairingUiEvent::Completed(outcome) => {
                mark_pairing_completed();
                apply_login_outcome_to_ui(&outcome);
                if let Some(hwnd) = hwnd_opt {
                    if !hwnd.is_null() && IsWindow(hwnd) != 0 {
                        set_dlg_item_string(hwnd, ID_PAIRING_PASS_EDIT, "");
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
                            "Workstation paired and enrolled! Closing...",
                        );
                        DestroyWindow(hwnd);
                    }
                }
            }
            PairingUiEvent::TransientError {
                message,
                show_dialog,
            } => {
                if let Some(hwnd) = hwnd_opt {
                    if !hwnd.is_null() && IsWindow(hwnd) != 0 {
                        set_pairing_action_buttons_enabled(hwnd, true);
                        set_dlg_item_string(hwnd, ID_STYLE_FOOTER_STATUS, &message);
                        if !show_dialog {
                            set_dlg_item_string(hwnd, ID_PAIRING_PASS_EDIT, "");
                        }
                    }
                }
                if show_dialog {
                    show_tray_error_dialog(
                        "Device Pairing Error",
                        "Could not complete pairing action",
                        &message,
                    );
                }
            }
            PairingUiEvent::TerminalError(err_msg) => {
                mark_pairing_completed();
                if let Some(hwnd) = hwnd_opt {
                    if !hwnd.is_null() && IsWindow(hwnd) != 0 {
                        set_dlg_item_string(hwnd, ID_PAIRING_PASS_EDIT, "");
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
                            "Pairing failed or expired.",
                        );
                        DestroyWindow(hwnd);
                    }
                }
                let enroll_hwnd = DIALOG_RES
                    .lock()
                    .ok()
                    .map(|g| g.enroll_hwnd as HWND)
                    .unwrap_or(null_mut());
                if !enroll_hwnd.is_null() && IsWindow(enroll_hwnd) != 0 {
                    set_dlg_item_string(
                        enroll_hwnd,
                        ID_STYLE_FOOTER_STATUS,
                        "Device pairing failed.",
                    );
                }
                show_tray_error_dialog(
                    "Device Pairing Failed",
                    "Could not complete workstation pairing",
                    &err_msg,
                );
            }
            PairingUiEvent::Canceled => {
                mark_pairing_completed();
                let enroll_hwnd = DIALOG_RES
                    .lock()
                    .ok()
                    .map(|g| g.enroll_hwnd as HWND)
                    .unwrap_or(null_mut());
                if !enroll_hwnd.is_null() && IsWindow(enroll_hwnd) != 0 {
                    set_dlg_item_string(
                        enroll_hwnd,
                        ID_STYLE_FOOTER_STATUS,
                        "GitHub sign-in / pairing canceled.",
                    );
                }
                if let Some(hwnd) = hwnd_opt {
                    if !hwnd.is_null() && IsWindow(hwnd) != 0 {
                        DestroyWindow(hwnd);
                    }
                }
            }
        }
    }
}

pub unsafe fn handle_pairing_update_from_tray() {
    let pairing_hwnd = DIALOG_RES
        .lock()
        .ok()
        .map(|g| g.pairing_hwnd as HWND)
        .unwrap_or(null_mut());
    let hwnd_opt = if !pairing_hwnd.is_null() && IsWindow(pairing_hwnd) != 0 {
        Some(pairing_hwnd)
    } else {
        None
    };
    process_pairing_events(hwnd_opt);
}

unsafe extern "system" fn pairing_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            let has_vault = PAIRING_UI_STATE
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.info.has_recovery_vault))
                .unwrap_or(false);
            if has_vault {
                paint_taskdialog_frame(hwnd, &[56, 202, 304]);
            } else {
                paint_taskdialog_frame(hwnd, &[56, 202]);
            }
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => handle_ctlcolor(wparam, lparam),
        WM_CREATE => {
            let dpi = get_dpi_scale();
            let assets = ensure_theme_assets(dpi);
            let info_opt = PAIRING_UI_STATE
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.info.clone()));
            let Some(info) = info_opt else {
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
                return 0;
            };

            let user_id = derive_user_id(&info.existing_user_pubkey);
            let account_text = if info.github_login.trim().is_empty() {
                format!("Existing Sshcast Account (User ID: {user_id})")
            } else {
                format!(
                    "GitHub: @{}   (User ID: {user_id})",
                    info.github_login.trim()
                )
            };

            create_label(
                hwnd,
                "Approve This Workstation",
                62,
                18,
                474,
                28,
                ID_STYLE_MAIN_HEADER,
                dpi,
                assets.font_title,
            );

            create_label(
                hwnd,
                "1. Pair with an Existing Workstation",
                24,
                68,
                512,
                20,
                ID_STYLE_SECTION_HEADER_1,
                dpi,
                assets.font_section,
            );
            create_label(
                hwnd,
                &account_text,
                24,
                92,
                512,
                18,
                ID_PAIRING_ACCOUNT_LABEL,
                dpi,
                assets.font_ui,
            );

            let sas_text = format!("Verification Code: {}", info.sas_code);
            create_edit_with_style(
                hwnd,
                &sas_text,
                "",
                ES_CENTER | ES_READONLY | ES_AUTOHSCROLL | WS_TABSTOP,
                false,
                24,
                116,
                512,
                38,
                ID_PAIRING_SAS_EDIT,
                dpi,
                assets.font_sas,
            );

            create_label(
                hwnd,
                "Verify this code matches and click Approve on an existing Sshcast workstation.",
                24,
                162,
                512,
                32,
                ID_PAIRING_STATUS_LABEL,
                dpi,
                assets.font_ui,
            );

            let footer_y = if info.has_recovery_vault {
                create_label(
                    hwnd,
                    "2. Or Unlock Offline with Recovery Passphrase",
                    24,
                    214,
                    512,
                    20,
                    ID_STYLE_SECTION_HEADER_2,
                    dpi,
                    assets.font_section,
                );
                create_label(
                    hwnd,
                    "Recovery Passphrase:",
                    24,
                    240,
                    512,
                    18,
                    0,
                    dpi,
                    assets.font_ui,
                );
                create_password_edit(
                    hwnd,
                    "Enter recovery passphrase",
                    24,
                    262,
                    404,
                    26,
                    ID_PAIRING_PASS_EDIT,
                    dpi,
                    assets.font_ui,
                );
                create_default_button(
                    hwnd,
                    "Unlock",
                    436,
                    261,
                    100,
                    28,
                    ID_PAIRING_BTN_UNLOCK,
                    dpi,
                    assets.font_ui,
                );

                create_button(
                    hwnd,
                    "Lost Old Devices? Reset Account...",
                    24,
                    318,
                    250,
                    30,
                    ID_PAIRING_BTN_RESET,
                    dpi,
                    assets.font_ui,
                );
                create_label(
                    hwnd,
                    "Replaces lost root key; stops old renewals.",
                    284,
                    324,
                    252,
                    20,
                    0,
                    dpi,
                    assets.font_ui,
                );
                376
            } else {
                create_label(
                    hwnd,
                    "No recovery passphrase is configured on this account.",
                    24,
                    214,
                    512,
                    18,
                    0,
                    dpi,
                    assets.font_ui,
                );
                create_button(
                    hwnd,
                    "Lost Old Devices? Reset Account...",
                    24,
                    244,
                    250,
                    30,
                    ID_PAIRING_BTN_RESET,
                    dpi,
                    assets.font_ui,
                );
                create_label(
                    hwnd,
                    "Replaces lost root key; stops old renewals.",
                    284,
                    250,
                    252,
                    20,
                    0,
                    dpi,
                    assets.font_ui,
                );
                296
            };

            create_label(
                hwnd,
                "Waiting for approval on an existing workstation...",
                24,
                footer_y + 9,
                396,
                36,
                ID_STYLE_FOOTER_STATUS,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Cancel",
                436,
                footer_y + 12,
                100,
                30,
                ID_PAIRING_BTN_CANCEL,
                dpi,
                assets.font_ui,
            );

            PostMessageW(hwnd, WM_PAIRING_UPDATE, 0, 0);
            0
        }
        WM_PAIRING_UPDATE => {
            process_pairing_events(Some(hwnd));
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            let code = ((wparam >> 16) & 0xFFFF) as u32;
            if code == BN_CLICKED {
                match id {
                    ID_PAIRING_BTN_UNLOCK => {
                        let pass = Zeroizing::new(get_dlg_item_string(hwnd, ID_PAIRING_PASS_EDIT));
                        if pass.is_empty() {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Please enter your recovery passphrase first.",
                            );
                            return 0;
                        }
                        let tx_opt = ACTIVE_PAIRING_TX.lock().ok().and_then(|g| g.clone());
                        if let Some(tx) = tx_opt {
                            set_pairing_action_buttons_enabled(hwnd, false);
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Unlocking root key with recovery passphrase...",
                            );
                            if tx.send(PairingUiAction::Unlock(pass)).is_err() {
                                set_pairing_action_buttons_enabled(hwnd, true);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "Pairing session ended; please close and sign in again.",
                                );
                            }
                        } else {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "No active pairing session.",
                            );
                        }
                    }
                    ID_PAIRING_BTN_RESET => {
                        if !confirm_overwrite_dialog(
                            null_mut(),
                            "Replace Lost Account Root Key?",
                            "Replacing your lost root key is irreversible.",
                            "This will generate a new root key for your GitHub account. Existing workstations and relays enrolled with the old root key will stop renewing certificates and must be re-enrolled.\n\nAre you sure you want to reset your account root key?",
                        ) {
                            return 0;
                        }
                        let still_active = IsWindow(hwnd) != 0
                            && PAIRING_UI_STATE
                                .lock()
                                .ok()
                                .and_then(|g| g.as_ref().map(|st| !st.completed))
                                .unwrap_or(false);
                        if !still_active {
                            return 0;
                        }
                        let tx_opt = ACTIVE_PAIRING_TX.lock().ok().and_then(|g| g.clone());
                        if let Some(tx) = tx_opt {
                            set_pairing_action_buttons_enabled(hwnd, false);
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Replacing lost root key and enrolling workstation...",
                            );
                            if tx.send(PairingUiAction::Reset).is_err() {
                                set_pairing_action_buttons_enabled(hwnd, true);
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "Pairing session ended; please close and sign in again.",
                                );
                            }
                        }
                    }
                    2 | ID_PAIRING_BTN_CANCEL => {
                        cancel_and_close_pairing_window(hwnd);
                    }
                    _ => {}
                }
            }
            0
        }
        WM_CLOSE => {
            cancel_and_close_pairing_window(hwnd);
            0
        }
        WM_DESTROY => {
            set_dlg_item_string(hwnd, ID_PAIRING_PASS_EDIT, "");
            if let Ok(mut g) = DIALOG_RES.lock() {
                if g.pairing_hwnd == hwnd as isize {
                    g.pairing_hwnd = 0;
                }
            }
            // Safety cancel if destroyed externally without WM_CLOSE while still incomplete
            let should_cancel = PAIRING_UI_STATE
                .lock()
                .ok()
                .and_then(|mut g| {
                    g.as_mut().map(|st| {
                        if st.completed {
                            false
                        } else {
                            st.completed = true;
                            true
                        }
                    })
                })
                .unwrap_or(false);
            if should_cancel {
                let tx_opt = ACTIVE_PAIRING_TX.lock().ok().and_then(|mut g| g.take());
                LOGIN_SESSION_GEN.fetch_add(1, Ordering::SeqCst);
                GITHUB_LOGIN_IN_FLIGHT.store(false, Ordering::SeqCst);
                if let Some(tx) = tx_opt {
                    let _ = tx.send(PairingUiAction::Cancel);
                }
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe fn show_pairing_wait_window() {
    {
        let enroll_hwnd = DIALOG_RES
            .lock()
            .ok()
            .map(|g| g.enroll_hwnd as HWND)
            .unwrap_or(null_mut());
        if !enroll_hwnd.is_null() && IsWindow(enroll_hwnd) != 0 {
            set_dlg_item_string(
                enroll_hwnd,
                ID_STYLE_FOOTER_STATUS,
                "Device pairing required — complete verification in the pairing window.",
            );
        }
    }

    // If the pairing actor already finished or canceled before this window opened,
    // process the pending outcome directly without flashing a window open and closed.
    let pre_terminal = PAIRING_UI_STATE
        .lock()
        .ok()
        .map(|g| {
            match g.as_ref() {
                None => true,
                Some(st) => {
                    st.completed
                        || st.events.iter().any(|ev| {
                            matches!(
                                ev,
                                PairingUiEvent::Completed(_)
                                    | PairingUiEvent::TerminalError(_)
                                    | PairingUiEvent::Canceled
                            )
                        })
                }
            }
        })
        .unwrap_or(true);
    if pre_terminal {
        process_pairing_events(None);
        return;
    }

    let has_vault = PAIRING_UI_STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.info.has_recovery_vault))
        .unwrap_or(false);

    {
        let g = DIALOG_RES.lock().unwrap();
        let existing = g.pairing_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SshcastPairingWaitWndClassV1");
    let title = to_wide("Sshcast — Approve This Workstation");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(pairing_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: assets.brush_white,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let client_h = if has_vault { 430 } else { 350 };
    let hwnd = create_centered_dialog_window(&class_name, &title, 560, client_h, dpi);
    if !hwnd.is_null() {
        DIALOG_RES.lock().unwrap().pairing_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

// ============================================================================
// 6. RECOVERY PASSPHRASE WINDOW (540 x 400 Client Area)
// ============================================================================

fn format_unix_utc(unix_sec: i64) -> String {
    if unix_sec <= 0 {
        return "unknown".to_string();
    }
    let days = unix_sec.div_euclid(86_400);
    let secs_of_day = unix_sec.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02} {hour:02}:{min:02} UTC")
}

fn push_recovery_event(kind: RecoveryAsyncKind) {
    let live_hwnd = DIALOG_RES
        .lock()
        .ok()
        .map(|g| g.recovery_hwnd)
        .unwrap_or(0);
    unsafe {
        if live_hwnd != 0 && IsWindow(live_hwnd as HWND) != 0 {
            if let Ok(mut q) = RECOVERY_EVENTS.lock() {
                q.push_back(RecoveryAsyncEvent { kind });
            }
            PostMessageW(live_hwnd as HWND, WM_RECOVERY_ASYNC_DONE, 0, 0);
            return;
        }
    }

    // No recovery window is currently open: keep generation accurate and still surface errors.
    match kind {
        RecoveryAsyncKind::StatusChecked { .. } => {}
        RecoveryAsyncKind::Saved(Ok(_)) | RecoveryAsyncKind::Removed(Ok(())) => {
            RECOVERY_STATUS_GEN.fetch_add(1, Ordering::SeqCst);
        }
        RecoveryAsyncKind::Saved(Err(err_msg)) => {
            RECOVERY_STATUS_GEN.fetch_add(1, Ordering::SeqCst);
            show_tray_error_dialog(
                "Save Recovery Passphrase Failed",
                "Could not encrypt or upload recovery vault",
                &err_msg,
            );
        }
        RecoveryAsyncKind::Removed(Err(err_msg)) => {
            RECOVERY_STATUS_GEN.fetch_add(1, Ordering::SeqCst);
            show_tray_error_dialog(
                "Remove Recovery Passphrase Failed",
                "Could not delete recovery vault on operator",
                &err_msg,
            );
        }
    }
}

fn resolve_recovery_operator(cfg: &ClientConfig) -> anyhow::Result<String> {
    resolve_operator_url(cfg.operator_url.as_deref(), &cfg.servers).ok_or_else(|| {
        anyhow::anyhow!(
            "could not discover operator URL via _sshcast DNS TXT for {:?}",
            cfg.servers
        )
    })
}

fn load_recovery_client_config(
    cfg_path: Option<&std::path::Path>,
) -> anyhow::Result<ClientConfig> {
    if let Ok(cfg) = ClientConfig::load(cfg_path) {
        return Ok(cfg);
    }
    crate::win_native::get_tray_context()
        .and_then(|c| c.current_config())
        .ok_or_else(|| anyhow::anyhow!("workstation is not enrolled (client.toml not found)"))
}

unsafe fn set_recovery_buttons_enabled(hwnd: HWND, enabled: bool) {
    set_ctrl_enabled(hwnd, ID_RECOVERY_BTN_SAVE, enabled);
    set_ctrl_enabled(hwnd, ID_RECOVERY_BTN_REMOVE, enabled);
}

unsafe fn spawn_recovery_status_check(hwnd: HWND) {
    let gen = RECOVERY_STATUS_GEN
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    set_dlg_item_string(hwnd, ID_RECOVERY_STATUS_LABEL, "Status: Checking...");
    set_dlg_item_string(
        hwnd,
        ID_STYLE_FOOTER_STATUS,
        "Checking recovery vault status on operator...",
    );

    let cfg_path = crate::win_native::get_tray_context().and_then(|c| c.config_path.clone());
    std::thread::spawn(move || {
        let res = (|| -> anyhow::Result<(bool, i64)> {
            let cfg = load_recovery_client_config(cfg_path.as_deref())?;
            let op_url = resolve_recovery_operator(&cfg)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(get_recovery_vault_status_http(
                &op_url,
                &cfg.grant,
                &cfg.node_signing_key,
            ))
        })()
        .map_err(|e| format!("{e:#}"));
        push_recovery_event(RecoveryAsyncKind::StatusChecked { gen, res });
    });
}

unsafe fn spawn_recovery_save(hwnd: HWND, passphrase: Zeroizing<String>) {
    if RECOVERY_OP_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    set_recovery_buttons_enabled(hwnd, false);
    set_dlg_item_string(
        hwnd,
        ID_STYLE_FOOTER_STATUS,
        "Encrypting recovery vault (scrypt) and uploading...",
    );

    let cfg_path = crate::win_native::get_tray_context().and_then(|c| c.config_path.clone());
    std::thread::spawn(move || {
        let res = (|| -> anyhow::Result<i64> {
            let cfg = load_recovery_client_config(cfg_path.as_deref())?;
            let user_sk = load_tray_user_signing_key(cfg_path.as_deref())?;
            if user_sk.verifying_key().to_bytes().as_slice() != cfg.grant.user_pubkey.as_slice() {
                anyhow::bail!(
                    "local user_key.toml does not match this workstation's enrolled user ({}) in client.toml",
                    cfg.grant.user_id
                );
            }
            let op_url = resolve_recovery_operator(&cfg)?;
            let vault = encrypt_recovery_vault(&user_sk, &passphrase, ScryptParams::default())?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(upload_recovery_vault_http(
                &op_url,
                &cfg.grant,
                &cfg.node_signing_key,
                &vault,
            ))
        })()
        .map_err(|e| format!("{e:#}"));
        RECOVERY_OP_IN_FLIGHT.store(false, Ordering::SeqCst);
        push_recovery_event(RecoveryAsyncKind::Saved(res));
    });
}

unsafe fn spawn_recovery_remove(hwnd: HWND) {
    if RECOVERY_OP_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    set_recovery_buttons_enabled(hwnd, false);
    set_dlg_item_string(
        hwnd,
        ID_STYLE_FOOTER_STATUS,
        "Removing recovery vault from operator...",
    );

    let cfg_path = crate::win_native::get_tray_context().and_then(|c| c.config_path.clone());
    std::thread::spawn(move || {
        let res = (|| -> anyhow::Result<()> {
            let cfg = load_recovery_client_config(cfg_path.as_deref())?;
            let op_url = resolve_recovery_operator(&cfg)?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(delete_recovery_vault_http(
                &op_url,
                &cfg.grant,
                &cfg.node_signing_key,
            ))
        })()
        .map_err(|e| format!("{e:#}"));
        RECOVERY_OP_IN_FLIGHT.store(false, Ordering::SeqCst);
        push_recovery_event(RecoveryAsyncKind::Removed(res));
    });
}

unsafe fn process_recovery_events() {
    let mut events = Vec::new();
    if let Ok(mut q) = RECOVERY_EVENTS.lock() {
        while let Some(ev) = q.pop_front() {
            events.push(ev);
        }
    }
    for ev in events {
        let live_hwnd = DIALOG_RES
            .lock()
            .ok()
            .map(|g| g.recovery_hwnd as HWND)
            .filter(|&h| !h.is_null() && IsWindow(h) != 0);
        match ev.kind {
            RecoveryAsyncKind::StatusChecked { gen, res } => {
                if gen != RECOVERY_STATUS_GEN.load(Ordering::SeqCst) {
                    continue;
                }
                let Some(hwnd) = live_hwnd else {
                    continue;
                };
                match res {
                    Ok((true, updated_at)) => {
                        let status_text = if updated_at > 0 {
                            format!("Status: Configured (updated {})", format_unix_utc(updated_at))
                        } else {
                            "Status: Configured".to_string()
                        };
                        set_dlg_item_string(hwnd, ID_RECOVERY_STATUS_LABEL, &status_text);
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
                            "Recovery vault is active on the operator.",
                        );
                    }
                    Ok((false, _)) => {
                        set_dlg_item_string(
                            hwnd,
                            ID_RECOVERY_STATUS_LABEL,
                            "Status: Not configured",
                        );
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
                            "No recovery passphrase is set yet.",
                        );
                    }
                    Err(e) => {
                        set_dlg_item_string(
                            hwnd,
                            ID_RECOVERY_STATUS_LABEL,
                            "Status: Unavailable (check network / operator)",
                        );
                        set_dlg_item_string(
                            hwnd,
                            ID_STYLE_FOOTER_STATUS,
                            &format!("Status check failed: {e}"),
                        );
                    }
                }
            }
            RecoveryAsyncKind::Saved(res) => {
                RECOVERY_STATUS_GEN.fetch_add(1, Ordering::SeqCst);
                if let Some(hwnd) = live_hwnd {
                    set_recovery_buttons_enabled(hwnd, true);
                }
                match res {
                    Ok(updated_at) => {
                        if let Some(hwnd) = live_hwnd {
                            set_dlg_item_string(hwnd, ID_RECOVERY_PASS_EDIT, "");
                            set_dlg_item_string(hwnd, ID_RECOVERY_CONFIRM_EDIT, "");
                            let status_text = if updated_at > 0 {
                                format!(
                                    "Status: Configured (updated {})",
                                    format_unix_utc(updated_at)
                                )
                            } else {
                                "Status: Configured".to_string()
                            };
                            set_dlg_item_string(hwnd, ID_RECOVERY_STATUS_LABEL, &status_text);
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Saved encrypted recovery vault to operator!",
                            );
                        }
                    }
                    Err(err_msg) => {
                        if let Some(hwnd) = live_hwnd {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Failed to upload recovery vault.",
                            );
                        }
                        show_tray_error_dialog(
                            "Save Recovery Passphrase Failed",
                            "Could not encrypt or upload recovery vault",
                            &err_msg,
                        );
                    }
                }
            }
            RecoveryAsyncKind::Removed(res) => {
                RECOVERY_STATUS_GEN.fetch_add(1, Ordering::SeqCst);
                if let Some(hwnd) = live_hwnd {
                    set_recovery_buttons_enabled(hwnd, true);
                }
                match res {
                    Ok(()) => {
                        if let Some(hwnd) = live_hwnd {
                            set_dlg_item_string(hwnd, ID_RECOVERY_PASS_EDIT, "");
                            set_dlg_item_string(hwnd, ID_RECOVERY_CONFIRM_EDIT, "");
                            set_dlg_item_string(
                                hwnd,
                                ID_RECOVERY_STATUS_LABEL,
                                "Status: Not configured",
                            );
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Removed recovery vault from operator.",
                            );
                        }
                    }
                    Err(err_msg) => {
                        if let Some(hwnd) = live_hwnd {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
                                "Failed to remove recovery vault.",
                            );
                        }
                        show_tray_error_dialog(
                            "Remove Recovery Passphrase Failed",
                            "Could not delete recovery vault on operator",
                            &err_msg,
                        );
                    }
                }
            }
        }
    }
}

unsafe extern "system" fn recovery_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint_taskdialog_frame(hwnd, &[56, 158]);
            0
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => handle_ctlcolor(wparam, lparam),
        WM_CREATE => {
            if let Ok(mut g) = DIALOG_RES.lock() {
                g.recovery_hwnd = hwnd as isize;
            }
            let dpi = get_dpi_scale();
            let assets = ensure_theme_assets(dpi);

            create_label(
                hwnd,
                "Recovery Passphrase (Offline Device Sync)",
                62,
                18,
                454,
                28,
                ID_STYLE_MAIN_HEADER,
                dpi,
                assets.font_title,
            );

            create_label(
                hwnd,
                "1. Operator Recovery Vault Status",
                24,
                68,
                492,
                20,
                ID_STYLE_SECTION_HEADER_1,
                dpi,
                assets.font_section,
            );
            create_label(
                hwnd,
                "Status: Checking...",
                24,
                94,
                492,
                20,
                ID_RECOVERY_STATUS_LABEL,
                dpi,
                assets.font_section,
            );
            create_label(
                hwnd,
                "Encrypts your user root key locally with scrypt + ChaCha20-Poly1305 so you can enroll new workstations when all existing devices are offline.",
                24,
                118,
                492,
                34,
                0,
                dpi,
                assets.font_ui,
            );

            create_label(
                hwnd,
                "2. Set or Update Recovery Passphrase",
                24,
                170,
                492,
                20,
                ID_STYLE_SECTION_HEADER_2,
                dpi,
                assets.font_section,
            );
            create_label(
                hwnd,
                "New Recovery Passphrase (min 8 chars):",
                24,
                196,
                492,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_password_edit(
                hwnd,
                "Enter at least 8 characters",
                24,
                216,
                492,
                26,
                ID_RECOVERY_PASS_EDIT,
                dpi,
                assets.font_ui,
            );

            create_label(
                hwnd,
                "Confirm Passphrase:",
                24,
                250,
                492,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_password_edit(
                hwnd,
                "Re-enter recovery passphrase",
                24,
                270,
                492,
                26,
                ID_RECOVERY_CONFIRM_EDIT,
                dpi,
                assets.font_ui,
            );

            create_default_button(
                hwnd,
                "Save Recovery Passphrase",
                24,
                306,
                238,
                30,
                ID_RECOVERY_BTN_SAVE,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Remove Recovery Passphrase",
                278,
                306,
                238,
                30,
                ID_RECOVERY_BTN_REMOVE,
                dpi,
                assets.font_ui,
            );

            // Footer Bar (y = 346 .. 400)
            create_label(
                hwnd,
                "Checking recovery vault status on operator...",
                24,
                355,
                376,
                36,
                ID_STYLE_FOOTER_STATUS,
                dpi,
                assets.font_ui,
            );
            create_button(
                hwnd,
                "Close",
                416,
                358,
                100,
                30,
                ID_RECOVERY_BTN_CLOSE,
                dpi,
                assets.font_ui,
            );

            if RECOVERY_OP_IN_FLIGHT.load(Ordering::SeqCst) {
                set_recovery_buttons_enabled(hwnd, false);
                set_dlg_item_string(
                    hwnd,
                    ID_RECOVERY_STATUS_LABEL,
                    "Status: Operation in progress...",
                );
                set_dlg_item_string(
                    hwnd,
                    ID_STYLE_FOOTER_STATUS,
                    "Operation in progress...",
                );
            } else {
                spawn_recovery_status_check(hwnd);
            }
            PostMessageW(hwnd, WM_RECOVERY_ASYNC_DONE, 0, 0);
            0
        }
        WM_RECOVERY_ASYNC_DONE => {
            process_recovery_events();
            0
        }
        WM_COMMAND => {
            let id = (wparam & 0xFFFF) as i32;
            let code = ((wparam >> 16) & 0xFFFF) as u32;
            if code == BN_CLICKED {
                match id {
                    ID_RECOVERY_BTN_SAVE => {
                        let pass = Zeroizing::new(get_dlg_item_string(hwnd, ID_RECOVERY_PASS_EDIT));
                        let confirm =
                            Zeroizing::new(get_dlg_item_string(hwnd, ID_RECOVERY_CONFIRM_EDIT));
                        if pass.chars().count() < 8 {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Recovery Passphrase Too Short",
                                "Recovery passphrase must be at least 8 characters long.",
                            );
                            return 0;
                        }
                        if *pass != *confirm {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Passphrases Do Not Match",
                                "The two recovery passphrase fields must match.",
                            );
                            return 0;
                        }
                        spawn_recovery_save(hwnd, pass);
                    }
                    ID_RECOVERY_BTN_REMOVE => {
                        if RECOVERY_OP_IN_FLIGHT.load(Ordering::SeqCst) {
                            return 0;
                        }
                        if !confirm_overwrite_dialog(
                            null_mut(),
                            "Remove Recovery Passphrase?",
                            "Delete the encrypted recovery vault from the operator?",
                            "If removed, enrolling a new workstation will require approval from an already-enrolled workstation unless you set a new recovery passphrase.",
                        ) {
                            return 0;
                        }
                        if IsWindow(hwnd) == 0 || RECOVERY_OP_IN_FLIGHT.load(Ordering::SeqCst) {
                            return 0;
                        }
                        spawn_recovery_remove(hwnd);
                    }
                    2 | ID_RECOVERY_BTN_CLOSE => {
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
            set_dlg_item_string(hwnd, ID_RECOVERY_PASS_EDIT, "");
            set_dlg_item_string(hwnd, ID_RECOVERY_CONFIRM_EDIT, "");
            if let Ok(mut g) = DIALOG_RES.lock() {
                if g.recovery_hwnd == hwnd as isize {
                    g.recovery_hwnd = 0;
                }
            }
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe fn show_recovery_window() {
    let maybe_ctx = crate::win_native::get_tray_context();
    let is_enrolled = maybe_ctx
        .as_ref()
        .and_then(|c| c.current_config())
        .is_some();
    if !is_enrolled {
        show_enroll_window();
        return;
    }

    let cfg_path = maybe_ctx.as_ref().and_then(|c| c.config_path.clone());
    if load_tray_user_key_file(cfg_path.as_deref()).is_err() {
        show_tray_error_dialog(
            "User Root Key Required",
            "No user_key.toml found on this workstation",
            "A local user root key (user_key.toml) is required to configure an encrypted recovery passphrase.",
        );
        return;
    }

    RECOVERY_STATUS_GEN.fetch_add(1, Ordering::SeqCst);

    {
        let g = DIALOG_RES.lock().unwrap();
        let existing = g.recovery_hwnd as HWND;
        if !existing.is_null() && IsWindow(existing) != 0 {
            if !RECOVERY_OP_IN_FLIGHT.load(Ordering::SeqCst) {
                spawn_recovery_status_check(existing);
            }
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
            return;
        }
    }

    let dpi = get_dpi_scale();
    let assets = ensure_theme_assets(dpi);
    let hinstance = GetModuleHandleW(null());
    let class_name = to_wide("SshcastRecoveryWndClassV1");
    let title = to_wide("Sshcast — Recovery Passphrase");

    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(recovery_wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: LoadIconW(null_mut(), IDI_SHIELD),
        hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: assets.brush_white,
        lpszMenuName: null(),
        lpszClassName: class_name.as_ptr(),
    };
    RegisterClassW(&wc);

    let hwnd = create_centered_dialog_window(&class_name, &title, 540, 400, dpi);
    if !hwnd.is_null() {
        DIALOG_RES.lock().unwrap().recovery_hwnd = hwnd as isize;
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}
