# `sockcast-client`

Cross-platform Workstation GUI & Enrollment CLI for the **Sockcast** Roaming SSH Agent architecture.

## Key Features
- **Native Desktop Approval UI & Windows System Tray (`src/win_native.rs`, `src/gui.rs`):**
  - **Windows (`sockcast-tray.exe` + `TaskDialogIndirect`):** Pure GUI-subsystem tray application (`windows_subsystem = "windows"`, zero console window) sitting in the Windows System Tray (`Shell_NotifyIconW`) with a native context menu, plus native Win32 `TaskDialogIndirect` (`comctl32.dll` v6) Command-Link approval dialogs.
  - **Linux / macOS (`eframe`/`egui` + native dialogs):** Renders a native approval modal displaying the cryptographically verified source hostname, RFC 4252 target SSH username, primary tool & command, 6-level `/proc` process ancestry tree, working directory, and SSH key fingerprint.
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
  - Filters exported keys by `allowed_fingerprints`, `allowed_comment_substrings`, and `excluded_fingerprints` in `~/.config/sockcast/client.toml`.

## Quickstart & Enrollment CLI

```bash
# 1. Generate User Root Ed25519 keypair (~/.config/sockcast/user_key.toml)
sockcast-client keygen

# 2. Enroll this workstation (~/.config/sockcast/client.toml)
sockcast-client grant-client --node my-workstation --server https://sockcast.example.com

# 3. Mint an enrollment bundle for a remote Linux server
sockcast-client grant-relay --node server-x.infra.local --server https://sockcast.example.com

# 4. Run the workstation client daemon (or launch sockcast-tray.exe on Windows)
sockcast-client run
```

## Platform Installation & Background Daemon

### Linux (Fedora / RHEL / systemd)
```bash
# Build RPM via tito:
tito build --test --rpm -o /tmp/tito-sockcast-client

# Enable and start user systemd service:
systemctl --user enable --now sockcast-client.service
```

### macOS (`launchd` User Agent)
- Connects automatically to `$SSH_AUTH_SOCK` (Apple `ssh-agent`, 1Password, Secretive, YubiKey) and reports idle time via `IOHIDSystem` (`HIDIdleTime`).
```bash
cargo build --release --locked
sudo cp target/release/sockcast-client /usr/local/bin/
./macos/install-macos-agent.sh
```

### Windows (System Tray App, OpenSSH Named Pipe & Scheduled Task)
- Connects automatically to `\\.\pipe\openssh-ssh-agent` (Windows OpenSSH Agent, 1Password for Windows, KeePassXC) and tracks workstation activity via Win32 `GetLastInputInfo`.
- Builds two binaries on Windows:
  - `sockcast-client.exe`: Console CLI for `keygen`, `grant-client`, `grant-relay`, `init`, `list-keys`, and interactive terminal `run`.
  - `sockcast-tray.exe`: Windowless system tray daemon (`windows_subsystem = "windows"`) with native Win32 tray menu and `TaskDialogIndirect` approval dialogs.
```powershell
cargo build --release --locked
New-Item -ItemType Directory -Force -Path "$env:LOCALAPPDATA\Programs\Sockcast"
Copy-Item target\release\sockcast-client.exe "$env:LOCALAPPDATA\Programs\Sockcast\sockcast-client.exe"
Copy-Item target\release\sockcast-tray.exe "$env:LOCALAPPDATA\Programs\Sockcast\sockcast-tray.exe"
.\windows\install-windows-task.ps1
```

### Automated Cross-Platform Builds (GitHub Actions)
- [`.github/workflows/build-and-release.yml`](.github/workflows/build-and-release.yml) automatically builds and tests release archives for:
  - `x86_64-unknown-linux-gnu` (`sockcast-client-linux-x86_64.tar.gz`)
  - `aarch64-apple-darwin` (`sockcast-client-macos-arm64.tar.gz`)
  - `x86_64-apple-darwin` (`sockcast-client-macos-x86_64.tar.gz`)
  - `x86_64-pc-windows-msvc` (`sockcast-client-windows-x86_64.zip`)
