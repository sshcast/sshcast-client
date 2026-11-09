use std::cell::RefCell;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, Sel};
use objc2::{define_class, msg_send, sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSBox, NSBoxType, NSButton, NSColor,
    NSControlStateValueOff, NSControlStateValueOn, NSFont, NSImage, NSImageView, NSPasteboard,
    NSPasteboardTypeString, NSPopUpButton, NSTextField, NSTitlePosition, NSView, NSWindow,
    NSWindowStyleMask,
};
use objc2_core_foundation::{CGFloat, CGPoint, CGRect, CGSize};
use objc2_foundation::{
    NSObject, NSObjectProtocol, NSPoint, NSProcessInfo, NSRect, NSSize, NSString,
};

use sockcast_proto::v1::NodeRole;

use crate::config::{default_client_config_path, ClientConfigFile, UserKeyFile};
use crate::enroll::{
    decode_enrollment_bundle_token, encode_enrollment_bundle_token, export_user_root_key,
    import_user_root_key, load_user_signing_key, mint_enrollment_bundle, run_keygen,
    write_client_config_and_optional_root_key, write_client_config_from_bundle,
    USER_KEY_TOKEN_PREFIX,
};
use crate::mac_native::{
    confirm_overwrite_dialog, get_tray_context, reload_tray_configuration, run_on_main_async,
    show_tray_error_dialog, TraySharedContext,
};

const FOOTER_HEIGHT: CGFloat = 52.0;

fn top_rect(win_h: CGFloat, x: CGFloat, y: CGFloat, w: CGFloat, h: CGFloat) -> NSRect {
    NSRect::new(NSPoint::new(x, win_h - y - h), NSSize::new(w, h))
}

fn top_cgrect(win_h: CGFloat, x: CGFloat, y: CGFloat, w: CGFloat, h: CGFloat) -> CGRect {
    CGRect::new(CGPoint::new(x, win_h - y - h), CGSize::new(w, h))
}

pub fn copy_to_clipboard(text: &str) -> bool {
    let pb = NSPasteboard::generalPasteboard();
    pb.clearContents();
    let ns_str = NSString::from_str(text);
    unsafe { pb.setString_forType(&ns_str, NSPasteboardTypeString) }
}

pub fn paste_from_clipboard() -> Option<String> {
    let pb = NSPasteboard::generalPasteboard();
    let ns_str = unsafe { pb.stringForType(NSPasteboardTypeString) }?;
    Some(ns_str.to_string())
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

fn default_workstation_node_name(ctx: Option<&TraySharedContext>) -> String {
    if let Some(c) = ctx {
        if let Some(cfg) = c.current_config() {
            if !cfg.grant.node_id.is_empty() {
                return cfg.grant.node_id;
            }
        }
    }
    let host = NSProcessInfo::processInfo().hostName().to_string();
    let cleaned = host
        .strip_suffix(".local")
        .unwrap_or(&host)
        .trim()
        .to_lowercase();
    if cleaned.is_empty() {
        "workstation".to_string()
    } else {
        cleaned
    }
}

fn default_servers_csv(ctx: Option<&TraySharedContext>) -> String {
    if let Some(c) = ctx {
        if let Some(cfg) = c.current_config() {
            if !cfg.servers.is_empty() {
                return cfg.servers.join(", ");
            }
        }
    }
    "https://sockcast.stingr.net".to_string()
}

fn add_window_chrome(
    mtm: MainThreadMarker,
    content_view: &NSView,
    win_w: CGFloat,
    win_h: CGFloat,
    header_title: &str,
    divider_ys: &[CGFloat],
) {
    let sym = NSString::from_str("lock.shield");
    let desc = NSString::from_str("Sockcast");
    if let Some(img) = NSImage::imageWithSystemSymbolName_accessibilityDescription(&sym, Some(&desc))
    {
        let iv = NSImageView::imageViewWithImage(&img, mtm);
        iv.setFrame(top_cgrect(win_h, 24.0, 16.0, 28.0, 28.0));
        let accent = NSColor::controlAccentColor();
        iv.setContentTintColor(Some(&accent));
        content_view.addSubview(&iv);
    }

    let title_label = NSTextField::labelWithString(&NSString::from_str(header_title), mtm);
    title_label.setFrame(top_cgrect(win_h, 58.0, 16.0, win_w - 82.0, 28.0));
    let title_font = NSFont::systemFontOfSize_weight(18.0, 0.3);
    title_label.setFont(Some(&title_font));
    let title_color = NSColor::labelColor();
    title_label.setTextColor(Some(&title_color));
    content_view.addSubview(&title_label);

    for &y in divider_ys {
        let sep = NSBox::initWithFrame(mtm.alloc(), top_rect(win_h, 24.0, y, win_w - 48.0, 1.0));
        sep.setBoxType(NSBoxType::Separator);
        content_view.addSubview(&sep);
    }

    let footer_sep = NSBox::initWithFrame(
        mtm.alloc(),
        top_rect(win_h, 0.0, win_h - FOOTER_HEIGHT, win_w, 1.0),
    );
    footer_sep.setBoxType(NSBoxType::Separator);
    content_view.addSubview(&footer_sep);
}

#[allow(clippy::too_many_arguments)]
fn add_section_header(
    mtm: MainThreadMarker,
    parent: &NSView,
    win_h: CGFloat,
    text: &str,
    x: CGFloat,
    y: CGFloat,
    w: CGFloat,
    h: CGFloat,
) -> Retained<NSTextField> {
    let lbl = NSTextField::labelWithString(&NSString::from_str(text), mtm);
    lbl.setFrame(top_cgrect(win_h, x, y, w, h));
    let font = NSFont::systemFontOfSize_weight(13.5, 0.3);
    lbl.setFont(Some(&font));
    let color = NSColor::labelColor();
    lbl.setTextColor(Some(&color));
    parent.addSubview(&lbl);
    lbl
}

#[allow(clippy::too_many_arguments)]
fn add_label(
    mtm: MainThreadMarker,
    parent: &NSView,
    win_h: CGFloat,
    text: &str,
    x: CGFloat,
    y: CGFloat,
    w: CGFloat,
    h: CGFloat,
) -> Retained<NSTextField> {
    let lbl = NSTextField::labelWithString(&NSString::from_str(text), mtm);
    lbl.setFrame(top_cgrect(win_h, x, y, w, h));
    let font = NSFont::systemFontOfSize(12.5);
    lbl.setFont(Some(&font));
    let color = NSColor::secondaryLabelColor();
    lbl.setTextColor(Some(&color));
    parent.addSubview(&lbl);
    lbl
}

#[allow(clippy::too_many_arguments)]
fn add_edit_field(
    mtm: MainThreadMarker,
    parent: &NSView,
    win_h: CGFloat,
    text: &str,
    placeholder: &str,
    readonly: bool,
    monospaced: bool,
    x: CGFloat,
    y: CGFloat,
    w: CGFloat,
    h: CGFloat,
) -> Retained<NSTextField> {
    let tf = NSTextField::initWithFrame(mtm.alloc(), top_rect(win_h, x, y, w, h));
    tf.setStringValue(&NSString::from_str(text));
    if !placeholder.is_empty() && !readonly {
        tf.setPlaceholderString(Some(&NSString::from_str(placeholder)));
    }
    tf.setEditable(!readonly);
    tf.setSelectable(true);
    tf.setBezeled(true);
    tf.setDrawsBackground(true);
    if readonly {
        let bg = NSColor::quaternarySystemFillColor();
        tf.setBackgroundColor(Some(&bg));
    } else {
        let bg = NSColor::textBackgroundColor();
        tf.setBackgroundColor(Some(&bg));
    }
    let font = if monospaced {
        NSFont::monospacedSystemFontOfSize_weight(12.0, 0.0)
    } else {
        NSFont::systemFontOfSize(12.5)
    };
    tf.setFont(Some(&font));
    parent.addSubview(&tf);
    tf
}

#[allow(clippy::too_many_arguments)]
fn add_push_button(
    mtm: MainThreadMarker,
    parent: &NSView,
    win_h: CGFloat,
    title: &str,
    target: &AnyObject,
    action: Sel,
    is_default: bool,
    x: CGFloat,
    y: CGFloat,
    w: CGFloat,
    h: CGFloat,
) -> Retained<NSButton> {
    let btn = unsafe {
        NSButton::buttonWithTitle_target_action(
            &NSString::from_str(title),
            Some(target),
            Some(action),
            mtm,
        )
    };
    btn.setFrame(top_cgrect(win_h, x, y, w, h));
    if is_default {
        btn.setKeyEquivalent(&NSString::from_str("\r"));
    }
    parent.addSubview(&btn);
    btn
}

#[allow(clippy::too_many_arguments)]
fn add_action_card_button(
    mtm: MainThreadMarker,
    parent: &NSView,
    win_h: CGFloat,
    title: &str,
    subtitle: &str,
    target: &AnyObject,
    action: Sel,
    is_default: bool,
    x: CGFloat,
    y: CGFloat,
    w: CGFloat,
    h: CGFloat,
) -> Retained<NSButton> {
    let card = NSBox::initWithFrame(mtm.alloc(), top_rect(win_h, x, y, w, h));
    card.setBoxType(NSBoxType::Primary);
    card.setTitlePosition(NSTitlePosition::NoTitle);
    parent.addSubview(&card);

    let sub_lbl = NSTextField::labelWithString(&NSString::from_str(subtitle), mtm);
    sub_lbl.setFrame(top_cgrect(win_h, x + 14.0, y + 32.0, w - 28.0, 18.0));
    let sub_font = NSFont::systemFontOfSize(11.5);
    sub_lbl.setFont(Some(&sub_font));
    let sub_color = NSColor::secondaryLabelColor();
    sub_lbl.setTextColor(Some(&sub_color));
    parent.addSubview(&sub_lbl);

    let btn = unsafe {
        NSButton::buttonWithTitle_target_action(
            &NSString::from_str(title),
            Some(target),
            Some(action),
            mtm,
        )
    };
    btn.setFrame(top_cgrect(win_h, x + 10.0, y + 5.0, 260.0, 28.0));
    if is_default {
        btn.setKeyEquivalent(&NSString::from_str("\r"));
    }
    parent.addSubview(&btn);
    btn
}

fn create_centered_window(
    mtm: MainThreadMarker,
    title: &str,
    win_w: CGFloat,
    win_h: CGFloat,
) -> Retained<NSWindow> {
    let style = NSWindowStyleMask::Titled
        | NSWindowStyleMask::Closable
        | NSWindowStyleMask::Miniaturizable;
    let rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(win_w, win_h));
    let window = unsafe {
        NSWindow::initWithContentRect_styleMask_backing_defer(
            mtm.alloc(),
            rect,
            style,
            NSBackingStoreType::Buffered,
            false,
        )
    };
    window.setTitle(&NSString::from_str(title));
    unsafe {
        window.setReleasedWhenClosed(false);
    }
    window.center();
    window
}

// ============================================================================
// 1. INITIALIZE / ENROLL WORKSTATION WINDOW (640 x 540)
// ============================================================================

struct EnrollWindowWidgets {
    window: Retained<NSWindow>,
    root_key_edit: Retained<NSTextField>,
    node_edit: Retained<NSTextField>,
    servers_edit: Retained<NSTextField>,
    bundle_edit: Retained<NSTextField>,
    footer_status: Retained<NSTextField>,
    _handler: Retained<EnrollWindowHandler>,
}

thread_local! {
    static ENROLL_WINDOW: RefCell<Option<EnrollWindowWidgets>> = const { RefCell::new(None) };
    static BUNDLE_WINDOW: RefCell<Option<BundleWindowWidgets>> = const { RefCell::new(None) };
    static BACKENDS_WINDOW: RefCell<Option<BackendsWindowWidgets>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct EmptyIvars {}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "SockcastEnrollWindowHandler"]
    #[ivars = EmptyIvars]
    struct EnrollWindowHandler;

    unsafe impl NSObjectProtocol for EnrollWindowHandler {}

    impl EnrollWindowHandler {
        #[unsafe(method(onKeygen:))]
        fn on_keygen(&self, _sender: Option<&AnyObject>) {
            let exists = format_root_key_allowlist().is_some();
            if exists
                && !confirm_overwrite_dialog(
                    "Overwrite User Root Key?",
                    "A user root key (user_key.toml) already exists.",
                    "Generating a new user root key will invalidate previous allowlist entries unless you update server.toml. Overwrite user_key.toml?",
                )
            {
                return;
            }
            match run_keygen(None, true) {
                Ok(out) => {
                    let allow = format!(
                        "allowed_user_pubkeys = [\"{}\"]",
                        out.user_pubkey_token
                    );
                    let status = format!("Generated root key (User ID: {}).", out.user_id);
                    ENROLL_WINDOW.with(|cell| {
                        if let Some(ref w) = *cell.borrow() {
                            w.root_key_edit.setStringValue(&NSString::from_str(&allow));
                            w.footer_status.setStringValue(&NSString::from_str(&status));
                        }
                    });
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

        #[unsafe(method(onCopyPubkey:))]
        fn on_copy_pubkey(&self, _sender: Option<&AnyObject>) {
            let msg = if let Some(allow) = format_root_key_allowlist() {
                if copy_to_clipboard(&allow) {
                    "Copied allowed_user_pubkeys line to clipboard!"
                } else {
                    "Failed to copy to clipboard."
                }
            } else {
                "Generate a root key first before copying."
            };
            ENROLL_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    w.footer_status.setStringValue(&NSString::from_str(msg));
                }
            });
        }

        #[unsafe(method(onEnrollPrimary:))]
        fn on_enroll_primary(&self, _sender: Option<&AnyObject>) {
            let (node_name, servers_raw) = ENROLL_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    (
                        w.node_edit.stringValue().to_string(),
                        w.servers_edit.stringValue().to_string(),
                    )
                } else {
                    (String::new(), String::new())
                }
            });

            let servers = parse_servers_input(&servers_raw);
            if node_name.trim().is_empty() {
                show_tray_error_dialog(
                    "Validation Error",
                    "Workstation Name is required",
                    "Please enter a workstation identifier (e.g. 'bandura').",
                );
                return;
            }
            if servers.is_empty() {
                show_tray_error_dialog(
                    "Validation Error",
                    "At least one Coordinator Server URL is required",
                    "Please enter your coordinator URL (e.g. 'https://sockcast.stingr.net').",
                );
                return;
            }

            if format_root_key_allowlist().is_none() {
                if let Err(e) = run_keygen(None, false) {
                    show_tray_error_dialog(
                        "Keygen Failed",
                        "Failed to create user_key.toml",
                        &format!("{e:#}"),
                    );
                    return;
                }
                if let Some(allow) = format_root_key_allowlist() {
                    ENROLL_WINDOW.with(|cell| {
                        if let Some(ref w) = *cell.borrow() {
                            w.root_key_edit.setStringValue(&NSString::from_str(&allow));
                        }
                    });
                }
            }

            let cfg_path = get_tray_context()
                .and_then(|c| c.config_path.clone())
                .or_else(|| default_client_config_path().ok());

            if let Some(ref p) = cfg_path {
                if p.exists()
                    && !confirm_overwrite_dialog(
                        "Overwrite Existing Workstation Config?",
                        "A client.toml file already exists for this workstation.",
                        &format!(
                            "Do you want to overwrite {} and re-enroll as '{}'?",
                            p.display(),
                            node_name.trim()
                        ),
                    )
                {
                    return;
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
                    reload_tray_configuration();
                    let msg = format!(
                        "Enrolled '{}' and saved client.toml — connecting now!",
                        node_name.trim()
                    );
                    ENROLL_WINDOW.with(|cell| {
                        if let Some(ref w) = *cell.borrow() {
                            w.footer_status.setStringValue(&NSString::from_str(&msg));
                        }
                    });
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

        #[unsafe(method(onPasteBundle:))]
        fn on_paste_bundle(&self, _sender: Option<&AnyObject>) {
            if let Some(clip) = paste_from_clipboard() {
                let token = clip
                    .split_whitespace()
                    .find(|w| w.starts_with("sc1_") || w.starts_with(USER_KEY_TOKEN_PREFIX))
                    .unwrap_or(clip.trim());
                ENROLL_WINDOW.with(|cell| {
                    if let Some(ref w) = *cell.borrow() {
                        w.bundle_edit.setStringValue(&NSString::from_str(token));
                        w.footer_status.setStringValue(&NSString::from_str(
                            "Pasted token from clipboard.",
                        ));
                    }
                });
            }
        }

        #[unsafe(method(onInitBundle:))]
        fn on_init_bundle(&self, _sender: Option<&AnyObject>) {
            let raw_input = ENROLL_WINDOW.with(|cell| {
                cell.borrow()
                    .as_ref()
                    .map(|w| w.bundle_edit.stringValue().to_string())
                    .unwrap_or_default()
            });
            let token = raw_input
                .split_whitespace()
                .find(|w| w.starts_with("sc1_") || w.starts_with(USER_KEY_TOKEN_PREFIX))
                .unwrap_or(raw_input.trim());
            if token.is_empty() {
                show_tray_error_dialog(
                    "Validation Error",
                    "Enrollment Bundle is empty",
                    "Please paste an sc1_<base64> client enrollment bundle (or scu1_<base64> user root key) first.",
                );
                return;
            }

            let cfg_path = get_tray_context()
                .and_then(|c| c.config_path.clone())
                .or_else(|| default_client_config_path().ok());

            if token.starts_with(USER_KEY_TOKEN_PREFIX) {
                match import_user_root_key(token, None, cfg_path.as_deref(), true) {
                    Ok(out) => {
                        let allow = format!(
                            "allowed_user_pubkeys = [\"{}\"]",
                            out.user_pubkey_token
                        );
                        let msg = format!(
                            "Imported user root key (User ID: {})!",
                            out.user_id
                        );
                        ENROLL_WINDOW.with(|cell| {
                            if let Some(ref w) = *cell.borrow() {
                                w.root_key_edit.setStringValue(&NSString::from_str(&allow));
                                w.footer_status.setStringValue(&NSString::from_str(&msg));
                            }
                        });
                    }
                    Err(e) => {
                        show_tray_error_dialog(
                            "Root Key Import Failed",
                            "Failed to import scu1_ user root key",
                            &format!("{e:#}"),
                        );
                    }
                }
                return;
            }

            let (decoded, maybe_root_key) = match decode_enrollment_bundle_token(token) {
                Ok(pair) => pair,
                Err(e) => {
                    show_tray_error_dialog(
                        "Invalid Bundle",
                        "Failed to decode sc1_ enrollment bundle",
                        &format!("{e:#}"),
                    );
                    return;
                }
            };

            if let Some(ref p) = cfg_path {
                if p.exists()
                    && !confirm_overwrite_dialog(
                        "Overwrite Existing Workstation Config?",
                        "A client.toml file already exists for this workstation.",
                        &format!(
                            "Overwrite {} with bundle for workstation '{}'?",
                            p.display(),
                            decoded.grant.node_id
                        ),
                    )
                {
                    return;
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
                    reload_tray_configuration();
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
                    let allow = format_root_key_allowlist();
                    ENROLL_WINDOW.with(|cell| {
                        if let Some(ref w) = *cell.borrow() {
                            if let Some(ref a) = allow {
                                w.root_key_edit.setStringValue(&NSString::from_str(a));
                            }
                            w.footer_status.setStringValue(&NSString::from_str(&msg));
                        }
                    });
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

        #[unsafe(method(onClose:))]
        fn on_close(&self, _sender: Option<&AnyObject>) {
            ENROLL_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    w.window.close();
                }
            });
        }
    }
);

impl EnrollWindowHandler {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(EmptyIvars::default());
        unsafe { msg_send![super(this), init] }
    }
}

pub fn show_enroll_window() {
    run_on_main_async(|mtm| {
        let app = NSApplication::sharedApplication(mtm);
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let already_created = ENROLL_WINDOW.with(|cell| {
            if let Some(ref w) = *cell.borrow() {
                if let Some(allow) = format_root_key_allowlist() {
                    w.root_key_edit.setStringValue(&NSString::from_str(&allow));
                }
                w.window.makeKeyAndOrderFront(None);
                true
            } else {
                false
            }
        });
        if already_created {
            return;
        }

        let win_w: CGFloat = 640.0;
        let win_h: CGFloat = 540.0;
        let window = create_centered_window(
            mtm,
            "Sockcast — Initialize / Enroll Workstation",
            win_w,
            win_h,
        );
        let content_view = window.contentView().expect("window has contentView");
        let handler = EnrollWindowHandler::new(mtm);
        let maybe_ctx = get_tray_context();

        add_window_chrome(
            mtm,
            &content_view,
            win_w,
            win_h,
            "Initialize or Enroll This Workstation",
            &[56.0, 304.0],
        );

        add_section_header(
            mtm,
            &content_view,
            win_h,
            "1. Enroll Primary Workstation Using Local Root Key",
            24.0,
            68.0,
            592.0,
            22.0,
        );
        add_label(
            mtm,
            &content_view,
            win_h,
            "User Root Key (for /etc/sockcast/server.toml):",
            24.0,
            94.0,
            400.0,
            18.0,
        );

        let root_str = format_root_key_allowlist().unwrap_or_else(|| {
            "No user_key.toml yet — click 'Generate Key' or 'Enroll' below".to_string()
        });
        let root_key_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            &root_str,
            "",
            true,
            true,
            24.0,
            115.0,
            376.0,
            24.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Generate Key",
            &handler,
            sel!(onKeygen:),
            false,
            408.0,
            113.0,
            102.0,
            28.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Copy Allowlist",
            &handler,
            sel!(onCopyPubkey:),
            false,
            514.0,
            113.0,
            102.0,
            28.0,
        );

        add_label(
            mtm,
            &content_view,
            win_h,
            "Workstation Name:",
            24.0,
            152.0,
            190.0,
            18.0,
        );
        add_label(
            mtm,
            &content_view,
            win_h,
            "Coordinator Backend URL(s) (comma-separated):",
            228.0,
            152.0,
            388.0,
            18.0,
        );

        let node_default = default_workstation_node_name(maybe_ctx.as_deref());
        let node_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            &node_default,
            "e.g. bandura",
            false,
            false,
            24.0,
            173.0,
            192.0,
            24.0,
        );

        let servers_default = default_servers_csv(maybe_ctx.as_deref());
        let servers_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            &servers_default,
            "https://sockcast.example.com",
            false,
            true,
            228.0,
            173.0,
            388.0,
            24.0,
        );

        add_action_card_button(
            mtm,
            &content_view,
            win_h,
            "Enroll This Workstation",
            "Mint a signed client grant using your local root key and save ~/.config/sockcast/client.toml",
            &handler,
            sel!(onEnrollPrimary:),
            true,
            24.0,
            212.0,
            592.0,
            58.0,
        );

        add_section_header(
            mtm,
            &content_view,
            win_h,
            "2. Or Initialize Secondary Workstation from an Enrollment Bundle",
            24.0,
            316.0,
            592.0,
            22.0,
        );
        add_label(
            mtm,
            &content_view,
            win_h,
            "Client Enrollment Bundle Token (sc1_<base64>):",
            24.0,
            342.0,
            400.0,
            18.0,
        );
        let bundle_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            "",
            "Paste sc1_... client bundle token here",
            false,
            true,
            24.0,
            363.0,
            460.0,
            24.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Paste Clipboard",
            &handler,
            sel!(onPasteBundle:),
            false,
            492.0,
            361.0,
            124.0,
            28.0,
        );

        add_action_card_button(
            mtm,
            &content_view,
            win_h,
            "Initialize Workstation from Bundle",
            "Verify the pasted sc1_ token, write ~/.config/sockcast/client.toml, and connect immediately",
            &handler,
            sel!(onInitBundle:),
            false,
            24.0,
            402.0,
            592.0,
            58.0,
        );

        let footer_status = add_label(
            mtm,
            &content_view,
            win_h,
            "Ready.",
            24.0,
            504.0,
            470.0,
            20.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Close",
            &handler,
            sel!(onClose:),
            false,
            516.0,
            498.0,
            100.0,
            28.0,
        );

        window.makeKeyAndOrderFront(None);

        ENROLL_WINDOW.with(|cell| {
            *cell.borrow_mut() = Some(EnrollWindowWidgets {
                window,
                root_key_edit,
                node_edit,
                servers_edit,
                bundle_edit,
                footer_status,
                _handler: handler,
            });
        });
    });
}

// ============================================================================
// 2. GENERATE ENROLLMENT BUNDLE WINDOW (640 x 560)
// ============================================================================

struct BundleWindowWidgets {
    window: Retained<NSWindow>,
    root_pubkey_edit: Retained<NSTextField>,
    root_key_action_btn: Retained<NSButton>,
    radio_relay: Retained<NSButton>,
    radio_client: Retained<NSButton>,
    node_edit: Retained<NSTextField>,
    servers_edit: Retained<NSTextField>,
    expires_edit: Retained<NSTextField>,
    token_out_edit: Retained<NSTextField>,
    cmd_out_edit: Retained<NSTextField>,
    footer_status: Retained<NSTextField>,
    _handler: Retained<BundleWindowHandler>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "SockcastBundleWindowHandler"]
    #[ivars = EmptyIvars]
    struct BundleWindowHandler;

    unsafe impl NSObjectProtocol for BundleWindowHandler {}

    impl BundleWindowHandler {
        #[unsafe(method(onSelectRelay:))]
        fn on_select_relay(&self, _sender: Option<&AnyObject>) {
            BUNDLE_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    w.radio_relay.setState(NSControlStateValueOn);
                    w.radio_client.setState(NSControlStateValueOff);
                }
            });
        }

        #[unsafe(method(onSelectClient:))]
        fn on_select_client(&self, _sender: Option<&AnyObject>) {
            BUNDLE_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    w.radio_relay.setState(NSControlStateValueOff);
                    w.radio_client.setState(NSControlStateValueOn);
                }
            });
        }

        #[unsafe(method(onCopyPubkey:))]
        fn on_copy_pubkey(&self, _sender: Option<&AnyObject>) {
            let msg = if let Some(allow) = format_root_key_allowlist() {
                if copy_to_clipboard(&allow) {
                    "Copied allowed_user_pubkeys line to clipboard!"
                } else {
                    "Failed to copy to clipboard."
                }
            } else {
                "Import or generate a root key first before copying."
            };
            BUNDLE_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    w.footer_status.setStringValue(&NSString::from_str(msg));
                }
            });
        }

        #[unsafe(method(onRootKeyAction:))]
        fn on_root_key_action(&self, _sender: Option<&AnyObject>) {
            if format_root_key_allowlist().is_some() {
                match export_user_root_key(None) {
                    Ok(tok) => {
                        let msg = if copy_to_clipboard(&tok) {
                            "Copied scu1_ user root key to clipboard (paste on secondary workstation)!"
                        } else {
                            "Failed to copy scu1_ root key to clipboard."
                        };
                        BUNDLE_WINDOW.with(|cell| {
                            if let Some(ref w) = *cell.borrow() {
                                w.footer_status.setStringValue(&NSString::from_str(msg));
                            }
                        });
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
                let Some(clip) = paste_from_clipboard() else {
                    show_tray_error_dialog(
                        "Clipboard Empty",
                        "No scu1_ root key token found on clipboard",
                        "On your primary workstation, open 'Generate Enrollment Bundle' and click 'Copy Root Key', then click 'Paste Root Key' here.",
                    );
                    return;
                };
                let cfg_path = get_tray_context()
                    .and_then(|c| c.config_path.clone())
                    .or_else(|| default_client_config_path().ok());
                match import_user_root_key(&clip, None, cfg_path.as_deref(), true) {
                    Ok(out) => {
                        let allow = format!(
                            "allowed_user_pubkeys = [\"{}\"]",
                            out.user_pubkey_token
                        );
                        let msg = format!(
                            "Imported root key (User ID: {}) and saved user_key.toml!",
                            out.user_id
                        );
                        BUNDLE_WINDOW.with(|cell| {
                            if let Some(ref w) = *cell.borrow() {
                                w.root_pubkey_edit.setStringValue(&NSString::from_str(&allow));
                                w.root_key_action_btn
                                    .setTitle(&NSString::from_str("Copy Root Key"));
                                w.footer_status.setStringValue(&NSString::from_str(&msg));
                            }
                        });
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

        #[unsafe(method(onGenerate:))]
        fn on_generate(&self, _sender: Option<&AnyObject>) {
            let (node_name, servers_raw, expires_str, is_relay) = BUNDLE_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    (
                        w.node_edit.stringValue().to_string(),
                        w.servers_edit.stringValue().to_string(),
                        w.expires_edit.stringValue().to_string(),
                        w.radio_relay.state() == NSControlStateValueOn,
                    )
                } else {
                    (String::new(), String::new(), String::new(), true)
                }
            });

            let servers = parse_servers_input(&servers_raw);
            if node_name.trim().is_empty() {
                show_tray_error_dialog(
                    "Validation Error",
                    "Target Hostname / Node ID is required",
                    "Enter the relay hostname (e.g. 'server-x.infra.local') or workstation name.",
                );
                return;
            }
            if servers.is_empty() {
                show_tray_error_dialog(
                    "Validation Error",
                    "At least one Coordinator URL is required",
                    "Enter at least one coordinator URL (e.g. 'https://sockcast.stingr.net').",
                );
                return;
            }
            let expires_days: u64 = match expires_str.trim().parse() {
                Ok(v) => v,
                Err(_) => {
                    show_tray_error_dialog(
                        "Validation Error",
                        "Invalid Expiration Days",
                        "Expiration days must be a non-negative integer (0 = never expires).",
                    );
                    return;
                }
            };

            if format_root_key_allowlist().is_none() {
                show_tray_error_dialog(
                    "User Root Key Required",
                    "No user_key.toml found on this workstation",
                    "On your primary workstation, open 'Generate Enrollment Bundle' and click 'Copy Root Key', then click 'Paste Root Key' above on this workstation.",
                );
                return;
            }

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
                        format!("sockcast-relay init --bundle {token}")
                    } else {
                        format!("sockcast-client init --bundle {token}")
                    };
                    let _ = copy_to_clipboard(&cli_cmd);
                    let status = format!(
                        "Minted bundle for '{}' & copied CLI command to clipboard!",
                        node_name.trim()
                    );
                    BUNDLE_WINDOW.with(|cell| {
                        if let Some(ref w) = *cell.borrow() {
                            w.token_out_edit.setStringValue(&NSString::from_str(&token));
                            w.cmd_out_edit.setStringValue(&NSString::from_str(&cli_cmd));
                            w.footer_status.setStringValue(&NSString::from_str(&status));
                        }
                    });
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

        #[unsafe(method(onCopyToken:))]
        fn on_copy_token(&self, _sender: Option<&AnyObject>) {
            BUNDLE_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    let tok = w.token_out_edit.stringValue().to_string();
                    if !tok.is_empty() && copy_to_clipboard(&tok) {
                        w.footer_status.setStringValue(&NSString::from_str(
                            "Copied sc1_ bundle token to clipboard!",
                        ));
                    }
                }
            });
        }

        #[unsafe(method(onCopyCmd:))]
        fn on_copy_cmd(&self, _sender: Option<&AnyObject>) {
            BUNDLE_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    let cmd = w.cmd_out_edit.stringValue().to_string();
                    if !cmd.is_empty() && copy_to_clipboard(&cmd) {
                        w.footer_status.setStringValue(&NSString::from_str(
                            "Copied CLI command to clipboard!",
                        ));
                    }
                }
            });
        }

        #[unsafe(method(onClose:))]
        fn on_close(&self, _sender: Option<&AnyObject>) {
            BUNDLE_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    w.window.close();
                }
            });
        }
    }
);

impl BundleWindowHandler {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(EmptyIvars::default());
        unsafe { msg_send![super(this), init] }
    }
}

pub fn show_bundle_generator_window() {
    let is_enrolled = get_tray_context()
        .and_then(|c| c.current_config())
        .is_some();
    if !is_enrolled {
        show_enroll_window();
        return;
    }

    run_on_main_async(|mtm| {
        let app = NSApplication::sharedApplication(mtm);
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let already_created = BUNDLE_WINDOW.with(|cell| {
            if let Some(ref w) = *cell.borrow() {
                if let Some(allow) = format_root_key_allowlist() {
                    w.root_pubkey_edit
                        .setStringValue(&NSString::from_str(&allow));
                    w.root_key_action_btn
                        .setTitle(&NSString::from_str("Copy Root Key"));
                } else {
                    w.root_key_action_btn
                        .setTitle(&NSString::from_str("Paste Root Key"));
                }
                w.window.makeKeyAndOrderFront(None);
                true
            } else {
                false
            }
        });
        if already_created {
            return;
        }

        let win_w: CGFloat = 640.0;
        let win_h: CGFloat = 560.0;
        let window = create_centered_window(
            mtm,
            "Sockcast — Generate Enrollment Bundle",
            win_w,
            win_h,
        );
        let content_view = window.contentView().expect("window has contentView");
        let handler = BundleWindowHandler::new(mtm);
        let maybe_ctx = get_tray_context();

        add_window_chrome(
            mtm,
            &content_view,
            win_w,
            win_h,
            "Generate Signed Enrollment Bundle",
            &[56.0, 146.0, 368.0],
        );

        add_section_header(
            mtm,
            &content_view,
            win_h,
            "User Root Key (for /etc/sockcast/server.toml):",
            24.0,
            68.0,
            464.0,
            20.0,
        );
        let has_root_key = format_root_key_allowlist().is_some();
        let root_str = format_root_key_allowlist().unwrap_or_else(|| {
            "No user_key.toml found — click 'Paste Root Key' to import scu1_ key".to_string()
        });
        let root_pubkey_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            &root_str,
            "",
            true,
            true,
            24.0,
            95.0,
            376.0,
            24.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Copy Allowlist",
            &handler,
            sel!(onCopyPubkey:),
            false,
            408.0,
            93.0,
            102.0,
            28.0,
        );
        let root_action_label = if has_root_key {
            "Copy Root Key"
        } else {
            "Paste Root Key"
        };
        let root_key_action_btn = add_push_button(
            mtm,
            &content_view,
            win_h,
            root_action_label,
            &handler,
            sel!(onRootKeyAction:),
            false,
            514.0,
            93.0,
            102.0,
            28.0,
        );

        add_section_header(
            mtm,
            &content_view,
            win_h,
            "Target Node & Coordinator Configuration",
            24.0,
            158.0,
            592.0,
            22.0,
        );

        let radio_relay = unsafe {
            NSButton::radioButtonWithTitle_target_action(
                &NSString::from_str("Remote Linux Server Relay (sockcast-relay)"),
                Some(&handler),
                Some(sel!(onSelectRelay:)),
                mtm,
            )
        };
        radio_relay.setFrame(top_cgrect(win_h, 24.0, 186.0, 290.0, 22.0));
        radio_relay.setState(NSControlStateValueOn);
        content_view.addSubview(&radio_relay);

        let radio_client = unsafe {
            NSButton::radioButtonWithTitle_target_action(
                &NSString::from_str("Secondary Workstation (sockcast-client)"),
                Some(&handler),
                Some(sel!(onSelectClient:)),
                mtm,
            )
        };
        radio_client.setFrame(top_cgrect(win_h, 326.0, 186.0, 290.0, 22.0));
        radio_client.setState(NSControlStateValueOff);
        content_view.addSubview(&radio_client);

        add_label(
            mtm,
            &content_view,
            win_h,
            "Target Hostname / Node ID:",
            24.0,
            218.0,
            190.0,
            18.0,
        );
        add_label(
            mtm,
            &content_view,
            win_h,
            "Coordinator URL(s):",
            226.0,
            218.0,
            274.0,
            18.0,
        );
        add_label(
            mtm,
            &content_view,
            win_h,
            "Expires (days):",
            512.0,
            218.0,
            104.0,
            18.0,
        );

        let node_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            "",
            "e.g. server-x.infra.local",
            false,
            false,
            24.0,
            239.0,
            190.0,
            24.0,
        );
        let servers_default = default_servers_csv(maybe_ctx.as_deref());
        let servers_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            &servers_default,
            "https://sockcast.example.com",
            false,
            true,
            226.0,
            239.0,
            274.0,
            24.0,
        );
        let expires_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            "0",
            "0 = never",
            false,
            false,
            512.0,
            239.0,
            104.0,
            24.0,
        );

        add_action_card_button(
            mtm,
            &content_view,
            win_h,
            "Generate Signed Enrollment Bundle",
            "Sign a NodeGrant with your root key and copy the ready-to-run init command to clipboard",
            &handler,
            sel!(onGenerate:),
            true,
            24.0,
            280.0,
            592.0,
            58.0,
        );

        add_label(
            mtm,
            &content_view,
            win_h,
            "Generated Bundle Token (sc1_...):",
            24.0,
            380.0,
            400.0,
            18.0,
        );
        let token_out_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            "",
            "",
            true,
            true,
            24.0,
            401.0,
            460.0,
            24.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Copy Token",
            &handler,
            sel!(onCopyToken:),
            false,
            492.0,
            399.0,
            124.0,
            28.0,
        );

        add_label(
            mtm,
            &content_view,
            win_h,
            "Ready-to-Run CLI Command:",
            24.0,
            436.0,
            400.0,
            18.0,
        );
        let cmd_out_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            "",
            "",
            true,
            true,
            24.0,
            457.0,
            460.0,
            24.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Copy Command",
            &handler,
            sel!(onCopyCmd:),
            false,
            492.0,
            455.0,
            124.0,
            28.0,
        );

        let footer_status = add_label(
            mtm,
            &content_view,
            win_h,
            "Enter target hostname and click 'Generate Signed Enrollment Bundle'.",
            24.0,
            524.0,
            470.0,
            20.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Close",
            &handler,
            sel!(onClose:),
            false,
            516.0,
            518.0,
            100.0,
            28.0,
        );

        window.makeKeyAndOrderFront(None);

        BUNDLE_WINDOW.with(|cell| {
            *cell.borrow_mut() = Some(BundleWindowWidgets {
                window,
                root_pubkey_edit,
                root_key_action_btn,
                radio_relay,
                radio_client,
                node_edit,
                servers_edit,
                expires_edit,
                token_out_edit,
                cmd_out_edit,
                footer_status,
                _handler: handler,
            });
        });
    });
}

// ============================================================================
// 3. MANAGE COORDINATOR BACKENDS WINDOW (560 x 420)
// ============================================================================

struct BackendsWindowWidgets {
    window: Retained<NSWindow>,
    servers: Vec<String>,
    servers_display: Retained<NSTextField>,
    server_popup: Retained<NSPopUpButton>,
    add_edit: Retained<NSTextField>,
    footer_status: Retained<NSTextField>,
    _handler: Retained<BackendsWindowHandler>,
}

impl BackendsWindowWidgets {
    fn sync_ui(&self) {
        self.server_popup.removeAllItems();
        for srv in &self.servers {
            self.server_popup.addItemWithTitle(&NSString::from_str(srv));
        }
        let summary = if self.servers.is_empty() {
            "(No coordinator servers in list)".to_string()
        } else {
            self.servers
                .iter()
                .enumerate()
                .map(|(i, s)| format!("  {}. {}", i + 1, s))
                .collect::<Vec<_>>()
                .join("\n")
        };
        self.servers_display
            .setStringValue(&NSString::from_str(&summary));
    }
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "SockcastBackendsWindowHandler"]
    #[ivars = EmptyIvars]
    struct BackendsWindowHandler;

    unsafe impl NSObjectProtocol for BackendsWindowHandler {}

    impl BackendsWindowHandler {
        #[unsafe(method(onAddServer:))]
        fn on_add_server(&self, _sender: Option<&AnyObject>) {
            BACKENDS_WINDOW.with(|cell| {
                if let Some(ref mut w) = *cell.borrow_mut() {
                    let raw = w.add_edit.stringValue().to_string();
                    let trimmed = raw.trim();
                    if (!trimmed.starts_with("http://") && !trimmed.starts_with("https://"))
                        || trimmed.len() <= 8
                    {
                        show_tray_error_dialog(
                            "Invalid Server URL",
                            "Coordinator URL must start with http:// or https://",
                            "Example: https://sockcast.stingr.net",
                        );
                        return;
                    }
                    if w.servers.iter().any(|s| s.eq_ignore_ascii_case(trimmed)) {
                        w.footer_status.setStringValue(&NSString::from_str(
                            "That coordinator URL is already in the list.",
                        ));
                        return;
                    }
                    w.servers.push(trimmed.to_string());
                    w.sync_ui();
                    let last_idx = (w.servers.len() as isize) - 1;
                    if last_idx >= 0 {
                        w.server_popup.selectItemAtIndex(last_idx);
                    }
                    w.add_edit.setStringValue(&NSString::from_str("https://"));
                    w.footer_status.setStringValue(&NSString::from_str(&format!(
                        "Added '{trimmed}'. Click Save Backends to apply."
                    )));
                }
            });
        }

        #[unsafe(method(onRemoveServer:))]
        fn on_remove_server(&self, _sender: Option<&AnyObject>) {
            BACKENDS_WINDOW.with(|cell| {
                if let Some(ref mut w) = *cell.borrow_mut() {
                    let sel_idx = w.server_popup.indexOfSelectedItem();
                    if sel_idx >= 0 && (sel_idx as usize) < w.servers.len() {
                        w.servers.remove(sel_idx as usize);
                        w.sync_ui();
                        w.footer_status.setStringValue(&NSString::from_str(
                            "Removed selected server. Click Save Backends to apply.",
                        ));
                    }
                }
            });
        }

        #[unsafe(method(onSaveBackends:))]
        fn on_save_backends(&self, _sender: Option<&AnyObject>) {
            let servers = BACKENDS_WINDOW.with(|cell| {
                cell.borrow()
                    .as_ref()
                    .map(|w| w.servers.clone())
                    .unwrap_or_default()
            });
            if servers.is_empty() {
                show_tray_error_dialog(
                    "Validation Error",
                    "At least one Coordinator Server URL is required",
                    "Please add at least one coordinator server before saving.",
                );
                return;
            }
            let cfg_path = get_tray_context().and_then(|c| c.config_path.clone());
            match ClientConfigFile::load(cfg_path.as_deref()) {
                Ok((_, mut cfg_file)) => {
                    cfg_file.servers = servers.clone();
                    match cfg_file.save(cfg_path.as_deref()) {
                        Ok(_saved_path) => {
                            reload_tray_configuration();
                            let msg = format!(
                                "Saved {} server(s) to client.toml & reconnecting!",
                                servers.len()
                            );
                            BACKENDS_WINDOW.with(|cell| {
                                if let Some(ref mut w) = *cell.borrow_mut() {
                                    w.servers = servers;
                                    w.sync_ui();
                                    w.footer_status.setStringValue(&NSString::from_str(&msg));
                                }
                            });
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

        #[unsafe(method(onClose:))]
        fn on_close(&self, _sender: Option<&AnyObject>) {
            BACKENDS_WINDOW.with(|cell| {
                if let Some(ref w) = *cell.borrow() {
                    w.window.close();
                }
            });
        }
    }
);

impl BackendsWindowHandler {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(EmptyIvars::default());
        unsafe { msg_send![super(this), init] }
    }
}

pub fn show_backends_window() {
    let is_enrolled = get_tray_context()
        .and_then(|c| c.current_config())
        .is_some();
    if !is_enrolled {
        show_enroll_window();
        return;
    }

    run_on_main_async(|mtm| {
        let app = NSApplication::sharedApplication(mtm);
        #[allow(deprecated)]
        app.activateIgnoringOtherApps(true);

        let initial_servers = get_tray_context()
            .and_then(|c| c.current_config())
            .map(|cfg| cfg.servers)
            .unwrap_or_default();

        let already_created = BACKENDS_WINDOW.with(|cell| {
            if let Some(ref mut w) = *cell.borrow_mut() {
                w.servers = initial_servers.clone();
                w.sync_ui();
                w.window.makeKeyAndOrderFront(None);
                true
            } else {
                false
            }
        });
        if already_created {
            return;
        }

        let win_w: CGFloat = 560.0;
        let win_h: CGFloat = 420.0;
        let window = create_centered_window(
            mtm,
            "Sockcast — Manage Coordinator Backends",
            win_w,
            win_h,
        );
        let content_view = window.contentView().expect("window has contentView");
        let handler = BackendsWindowHandler::new(mtm);

        add_window_chrome(
            mtm,
            &content_view,
            win_w,
            win_h,
            "Coordinator Backend Servers",
            &[56.0],
        );

        add_label(
            mtm,
            &content_view,
            win_h,
            "Active Coordinator gRPC URLs (Workstation connects to all concurrently):",
            24.0,
            68.0,
            512.0,
            18.0,
        );

        let servers_display = add_edit_field(
            mtm,
            &content_view,
            win_h,
            "",
            "",
            true,
            true,
            24.0,
            90.0,
            512.0,
            88.0,
        );

        let server_popup = NSPopUpButton::initWithFrame_pullsDown(
            mtm.alloc(),
            top_rect(win_h, 24.0, 186.0, 380.0, 28.0),
            false,
        );
        content_view.addSubview(&server_popup);

        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Remove Selected",
            &handler,
            sel!(onRemoveServer:),
            false,
            412.0,
            186.0,
            124.0,
            28.0,
        );

        add_label(
            mtm,
            &content_view,
            win_h,
            "Add Coordinator Server URL (http:// or https://):",
            24.0,
            224.0,
            512.0,
            18.0,
        );
        let add_edit = add_edit_field(
            mtm,
            &content_view,
            win_h,
            "https://",
            "https://sockcast.example.com",
            false,
            true,
            24.0,
            245.0,
            380.0,
            24.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Add Server",
            &handler,
            sel!(onAddServer:),
            false,
            412.0,
            243.0,
            124.0,
            28.0,
        );

        add_action_card_button(
            mtm,
            &content_view,
            win_h,
            "Save Backends & Reconnect Now",
            "Write updated coordinator URLs to client.toml and immediately reconnect active streams",
            &handler,
            sel!(onSaveBackends:),
            true,
            24.0,
            288.0,
            512.0,
            58.0,
        );

        let footer_status = add_label(
            mtm,
            &content_view,
            win_h,
            "Add or remove coordinator URLs, then click Save.",
            24.0,
            384.0,
            396.0,
            20.0,
        );
        add_push_button(
            mtm,
            &content_view,
            win_h,
            "Close",
            &handler,
            sel!(onClose:),
            false,
            436.0,
            378.0,
            100.0,
            28.0,
        );

        let widgets = BackendsWindowWidgets {
            window,
            servers: initial_servers,
            servers_display,
            server_popup,
            add_edit,
            footer_status,
            _handler: handler,
        };
        widgets.sync_ui();
        widgets.window.makeKeyAndOrderFront(None);

        BACKENDS_WINDOW.with(|cell| {
            *cell.borrow_mut() = Some(widgets);
        });
    });
}
