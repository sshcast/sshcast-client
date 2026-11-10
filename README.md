# `sshcast-client`

Cross-platform Workstation GUI & Enrollment CLI for the **Sshcast** Roaming SSH Agent architecture.

## Key Features
- **Native Desktop Approval UI & System Tray / Menu Bar (`src/win_native.rs`, `src/mac_native.rs`, `src/gui.rs`):**
  - **Windows (`sshcast-tray.exe` + `TaskDialogIndirect`):** Pure GUI-subsystem tray application (`windows_subsystem = "windows"`, zero console window) sitting in the Windows System Tray (`Shell_NotifyIconW`) with a native context menu, Win32 management dialogs (`src/win_dialogs.rs`), and `TaskDialogIndirect` (`comctl32.dll` v6) Command-Link approval dialogs.
  - **macOS (`sshcast-tray` + `objc2-app-kit`):** Native AppKit Menu Bar application (`NSStatusBar`, `NSApplicationActivationPolicy::Accessory` — no Dock icon) with an SF Symbol shield menu bar icon, native `NSWindow` management dialogs (`src/mac_dialogs.rs`), and native `NSAlert` approval modals with custom monospaced accessory views.
  - **Linux (`eframe`/`egui` + native dialogs):** Renders a native approval modal displaying the cryptographically verified source hostname, RFC 4252 target SSH username, primary tool & command, 6-level `/proc` process ancestry tree, working directory, and SSH key fingerprint.
  - Supports 4 one-click actions:
    1. **`[Approve Once]`**: Signs this single request.
    2. **`[Approve <tool> on <host> for 15m]`**: Caches an in-memory session rule matching `(verified_host, caller_tool, key_blob, target_ssh_user)` for 15 minutes.
    3. **`[Approve all on <host> for 15m]`**: Approves any request for this key from `verified_host` for 15 minutes.
    4. **`[Deny (Esc)]`**: Rejects the request (`SSH_AGENT_FAILURE`).
  - Automatically dismisses the dialog if `CancelSignRequest` arrives from a coordinator (e.g., answered on another workstation).
- **End-to-End Zero-Trust Verification (`src/coordinator.rs`):**
  - Independently verifies the relay's `NodeGrant` signature against `user_pubkey`, verifies `ProcessContext.hostname == NodeGrant.node_id`, and verifies the relay's Ed25519 signature over the `SignRequest` before showing any UI or accessing the local SSH agent.
- **Local OS SSH Agent Bridge & Key Filtering (`src/local_agent.rs`):**
  - Connects to `$SSH_AUTH_SOCK` on Linux/macOS (`UnixStream`) and `\\.\pipe\openssh-ssh-agent` on Windows (`NamedPipe`).
  - Filters exported keys by `allowed_fingerprints`, `allowed_comment_substrings`, and `excluded_fingerprints` in `~/.config/sshcast/client.toml`.

## Quickstart & Enrollment CLI

```bash
# 1. Generate User Root Ed25519 keypair (~/.config/sshcast/user_key.toml)
sshcast-client keygen

# 2. Enroll this workstation (~/.config/sshcast/client.toml)
sshcast-client grant-client --node my-workstation --server https://sshcast.example.com

# 3. Mint an enrollment bundle for a remote Linux server
sshcast-client grant-relay --node server-x.infra.local --server https://sshcast.example.com

# 4. Run the workstation client daemon (or launch sshcast-tray.exe on Windows)
sshcast-client run
```

## Platform Installation & Background Daemon

### Linux (Fedora / RHEL / systemd)
```bash
# Build RPM via tito:
tito build --test --rpm -o /tmp/tito-sshcast-client

# Enable and start user systemd service:
systemctl --user enable --now sshcast-client.service
```

### macOS (Menu Bar App & `launchd` User Agent)
- Connects automatically to `$SSH_AUTH_SOCK` (Apple `ssh-agent`, 1Password, Secretive, YubiKey) and reports idle time via `IOHIDSystem` (`HIDIdleTime`).
- Builds two binaries on macOS:
  - `sshcast-client`: CLI for `keygen`, `grant-client`, `grant-relay`, `init`, `list-keys`, and `run`.
  - `sshcast-tray`: Native AppKit Menu Bar daemon (`objc2-app-kit`) with full GUI windows for workstation enrollment, signed bundle generation, coordinator backend management, and `NSAlert` signature approval modals.
```bash
cargo build --release --locked
sudo cp target/release/sshcast-client target/release/sshcast-tray /usr/local/bin/
./macos/install-macos-agent.sh
```

### Windows (System Tray App, OpenSSH Named Pipe & Scheduled Task)
- Connects automatically to `\\.\pipe\openssh-ssh-agent` (Windows OpenSSH Agent, 1Password for Windows, KeePassXC) and tracks workstation activity via Win32 `GetLastInputInfo`.
- Builds two binaries on Windows:
  - `sshcast-client.exe`: Console CLI for `keygen`, `grant-client`, `grant-relay`, `init`, `list-keys`, and interactive terminal `run`.
  - `sshcast-tray.exe`: Windowless system tray daemon (`windows_subsystem = "windows"`) with native Win32 tray menu and `TaskDialogIndirect` approval dialogs.
```powershell
cargo build --release --locked
New-Item -ItemType Directory -Force -Path "$env:LOCALAPPDATA\Programs\Sshcast"
Copy-Item target\release\sshcast-client.exe "$env:LOCALAPPDATA\Programs\Sshcast\sshcast-client.exe"
Copy-Item target\release\sshcast-tray.exe "$env:LOCALAPPDATA\Programs\Sshcast\sshcast-tray.exe"
.\windows\install-windows-task.ps1
```

### Automated Cross-Platform Builds (GitHub Actions)
- [`.github/workflows/build-and-release.yml`](.github/workflows/build-and-release.yml) automatically builds and tests release archives for:
  - `x86_64-unknown-linux-gnu` (`sshcast-client-linux-x86_64.tar.gz`)
  - `aarch64-apple-darwin` (`sshcast-client-macos-arm64.tar.gz`)
  - `x86_64-apple-darwin` (`sshcast-client-macos-x86_64.tar.gz`)
  - `x86_64-pc-windows-msvc` (`sshcast-client-windows-x86_64.zip`)
