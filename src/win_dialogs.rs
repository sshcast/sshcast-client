use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::sync::Mutex;

use sshcast_proto::v1::NodeRole;

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
    TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOGCONFIG_1,
    TDCBF_CANCEL_BUTTON, TDCBF_YES_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION, TDF_SIZE_TO_CONTENT,
    TD_WARNING_ICON,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DrawIconEx, GetClientRect,
    GetDlgCtrlID, GetDlgItem, GetSystemMetrics, GetWindowTextLengthW, GetWindowTextW,
    IsDialogMessageW, IsWindow, LoadCursorW, LoadIconW, RegisterClassW, SendMessageW,
    SetForegroundWindow, SetWindowTextW, ShowWindow, DI_NORMAL, IDC_ARROW, IDI_SHIELD, IDYES, MSG,
    SM_CXSCREEN, SM_CYSCREEN, SW_RESTORE, SW_SHOW, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY,
    WM_ERASEBKGND, WM_PAINT, WM_SETFONT, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE,
    WS_GROUP, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

use crate::config::{default_client_config_path, ClientConfigFile, UserKeyFile};
use crate::enroll::{
    decode_enrollment_bundle_token, encode_enrollment_bundle_token, export_user_root_key,
    import_user_root_key, load_user_signing_key, mint_enrollment_bundle, run_keygen,
    write_client_config_and_optional_root_key, write_client_config_from_bundle,
    USER_KEY_TOKEN_PREFIX,
};
use crate::win_native::{show_tray_error_dialog, TraySharedContext};

const ES_PASSWORD: u32 = 0x0020;
const ES_AUTOHSCROLL: u32 = 0x0080;
const ES_READONLY: u32 = 0x0800;

const BS_PUSHBUTTON: u32 = 0x0000;
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

// Control IDs for Bundle Generator Window
const ID_BUNDLE_ROOT_PUBKEY_EDIT: i32 = 1952;
const ID_BUNDLE_BTN_KEYGEN: i32 = 3002;
const ID_BUNDLE_BTN_COPY_PUBKEY: i32 = 3003;
const ID_BUNDLE_BTN_ROOT_KEY_ACTION: i32 = 3016;
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
    font_title: isize,
    font_section: isize,
    font_ui: isize,
    font_mono: isize,
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
    font_title: 0,
    font_section: 0,
    font_ui: 0,
    font_mono: 0,
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
    let (h1, h2, h3, h4) = match DIALOG_RES.lock() {
        Ok(g) => (
            g.enroll_hwnd as HWND,
            g.bundle_hwnd as HWND,
            g.backends_hwnd as HWND,
            g.ssh_keys_hwnd as HWND,
        ),
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
    if !h4.is_null() && IsWindow(h4) != 0 && IsDialogMessageW(h4, msg) != 0 {
        return true;
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
    if !hwnd.is_null() && !cue_banner.is_empty() && !readonly {
        let cue_w = to_wide(cue_banner);
        SendMessageW(hwnd, EM_SETCUEBANNER, 1, cue_w.as_ptr() as isize);
    }
    hwnd
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
    create_child_ex(
        parent,
        0,
        "BUTTON",
        text,
        BS_PUSHBUTTON | WS_TABSTOP,
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
    if (ID_STYLE_SECTION_HEADER_1..=ID_STYLE_SECTION_HEADER_3).contains(&id) {
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
    "https://sshcast.stingr.net".to_string()
}

// ============================================================================
// 1. INITIALIZE / ENROLL WORKSTATION WINDOW (640 x 540 Client Area)
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
            paint_taskdialog_frame(hwnd, &[56, 304]);
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
                "User Root Key (for /etc/sshcast/server.toml):",
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
                "Copy Allowlist",
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
                "Workstation Name:",
                24,
                154,
                190,
                18,
                0,
                dpi,
                assets.font_ui,
            );
            create_label(
                hwnd,
                "Coordinator Backend URL(s) (comma-separated):",
                228,
                154,
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
                174,
                192,
                26,
                ID_ENROLL_NODE_EDIT,
                dpi,
                assets.font_ui,
            );

            let servers_default = maybe_ctx
                .as_ref()
                .map(|c| default_servers_csv(c))
                .unwrap_or_else(|| "https://sshcast.stingr.net".to_string());
            create_edit(
                hwnd,
                &servers_default,
                "https://sshcast.example.com",
                false,
                228,
                174,
                388,
                26,
                ID_ENROLL_SERVERS_EDIT,
                dpi,
                assets.font_mono,
            );

            create_command_link(
                hwnd,
                "Enroll This Workstation",
                "Mint a signed client grant using your local root key and save ~/.config/sshcast/client.toml",
                true,
                24,
                214,
                592,
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
                318,
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
                344,
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
                364,
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
                363,
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
                404,
                592,
                58,
                ID_ENROLL_BTN_INIT_BUNDLE,
                dpi,
                assets.font_ui,
            );

            // Footer Bar (y = 486 .. 540)
            create_label(
                hwnd,
                "Ready.",
                24,
                503,
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
                498,
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
                        if let Some(allow) = format_root_key_allowlist() {
                            if copy_to_clipboard(hwnd, &allow) {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "Copied allowed_user_pubkeys line to clipboard!",
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
                                "At least one Coordinator Server URL is required",
                                "Please enter your coordinator URL (e.g. 'https://sshcast.stingr.net').",
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
                                    w.starts_with("sc1_") || w.starts_with(USER_KEY_TOKEN_PREFIX)
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
                                w.starts_with("sc1_") || w.starts_with(USER_KEY_TOKEN_PREFIX)
                            })
                            .unwrap_or(raw_input.trim());
                        if token.is_empty() {
                            show_tray_error_dialog(
                                "Validation Error",
                                "Enrollment Bundle is empty",
                                "Please paste an sc1_<base64> client enrollment bundle (or scu1_<base64> user root key) first.",
                            );
                            return 0;
                        }

                        let cfg_path = crate::win_native::get_tray_context()
                            .and_then(|c| c.config_path.clone())
                            .or_else(|| default_client_config_path().ok());

                        if token.starts_with(USER_KEY_TOKEN_PREFIX) {
                            match import_user_root_key(token, None, cfg_path.as_deref(), true) {
                                Ok(out) => {
                                    let allow = format!(
                                        "allowed_user_pubkeys = [\"{}\"]",
                                        out.user_pubkey_token
                                    );
                                    set_dlg_item_string(hwnd, ID_ENROLL_ROOT_KEY_EDIT, &allow);
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
                                if let Some(allow) = format_root_key_allowlist() {
                                    set_dlg_item_string(hwnd, ID_ENROLL_ROOT_KEY_EDIT, &allow);
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
            if let Some(allow) = format_root_key_allowlist() {
                set_dlg_item_string(existing, ID_ENROLL_ROOT_KEY_EDIT, &allow);
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

    let hwnd = create_centered_dialog_window(&class_name, &title, 640, 540, dpi);
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

            // Section 1: Root Key Allowlist
            create_label(
                hwnd,
                "User Root Key (for /etc/sshcast/server.toml):",
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
                384,
                26,
                ID_BUNDLE_ROOT_PUBKEY_EDIT,
                dpi,
                assets.font_mono,
            );
            create_button(
                hwnd,
                "Copy Allowlist",
                416,
                95,
                96,
                28,
                ID_BUNDLE_BTN_COPY_PUBKEY,
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
                .unwrap_or_else(|| "https://sshcast.stingr.net".to_string());
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
                        if let Some(allow) = format_root_key_allowlist() {
                            if copy_to_clipboard(hwnd, &allow) {
                                set_dlg_item_string(
                                    hwnd,
                                    ID_STYLE_FOOTER_STATUS,
                                    "Copied allowed_user_pubkeys line to clipboard!",
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
                                    let allow = format!(
                                        "allowed_user_pubkeys = [\"{}\"]",
                                        out.user_pubkey_token
                                    );
                                    set_dlg_item_string(hwnd, ID_BUNDLE_ROOT_PUBKEY_EDIT, &allow);
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
                                "Enter at least one coordinator URL (e.g. 'https://sshcast.stingr.net').",
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
                "Add Coordinator Server URL (http:// or https://):",
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
                "https://",
                "https://sshcast.example.com",
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
                        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://")
                            || trimmed.len() <= 8
                        {
                            show_tray_error_dialog(
                                "Invalid Server URL",
                                "Coordinator URL must start with http:// or https://",
                                "Example: https://sshcast.stingr.net",
                            );
                            return 0;
                        }
                        let existing = listbox_get_items(lb);
                        if existing.iter().any(|s| s.eq_ignore_ascii_case(trimmed)) {
                            set_dlg_item_string(
                                hwnd,
                                ID_STYLE_FOOTER_STATUS,
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
                "Manage SSH Agent Keys (Built-in & OS Agent)",
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
                "Held SSH Keys ([Built-in] in-memory keys & [OS Agent] keys):",
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
                "Use Built-in Keys Only (Disable external OS ssh-agent)",
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
