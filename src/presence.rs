use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Returns the estimated timestamp (epoch milliseconds) of the user's most recent keyboard/mouse input
/// on this workstation. Used by `sockcast-server` to route prompts to the workstation currently in use.
pub fn query_last_input_epoch_ms() -> u64 {
    let now = now_unix_ms();
    let idle_ms = query_os_idle_ms().unwrap_or(0);
    now.saturating_sub(idle_ms)
}

pub fn query_os_idle_ms() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // Try freedesktop / GNOME Mutter IdleMonitor or xprintidle if available, with fast fallback
        if let Some(ms) = query_linux_xprintidle() {
            return Some(ms);
        }
        if let Some(ms) = query_linux_mutter_idle() {
            return Some(ms);
        }
        Some(0)
    }
    #[cfg(target_os = "macos")]
    {
        query_macos_ioreg_idle()
    }
    #[cfg(target_os = "windows")]
    {
        Some(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Some(0)
    }
}

#[cfg(target_os = "linux")]
fn query_linux_xprintidle() -> Option<u64> {
    if std::env::var_os("DISPLAY").is_none() {
        return None;
    }
    let out = Command::new("xprintidle").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.trim().parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn query_linux_mutter_idle() -> Option<u64> {
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        return None;
    }
    let out = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.gnome.Mutter.IdleMonitor",
            "--object-path",
            "/org/gnome/Mutter/IdleMonitor/Core",
            "--method",
            "org.gnome.Mutter.IdleMonitor.GetIdletime",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // Output format: "(uint64 1234,)"
    let s = String::from_utf8_lossy(&out.stdout);
    let digits: String = s
        .split_whitespace()
        .nth(1)?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

#[cfg(target_os = "macos")]
fn query_macos_ioreg_idle() -> Option<u64> {
    let out = Command::new("ioreg")
        .args(["-c", "IOHIDSystem", "-d", "4"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.contains("HIDIdleTime") {
            if let Some(eq_idx) = line.find('=') {
                let num_str = line[eq_idx + 1..].trim();
                if let Ok(ns) = num_str.parse::<u64>() {
                    return Some(ns / 1_000_000);
                }
            }
        }
    }
    None
}
