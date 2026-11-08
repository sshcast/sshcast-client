# `sockcast-client`

Cross-platform Workstation GUI & Enrollment CLI for the **Sockcast** Roaming SSH Agent architecture.

## Key Features
- **Native `eframe`/`egui` Approval Modal (`src/gui.rs`):**
  - Displays the cryptographically verified source hostname, RFC 4252 target SSH username, primary tool & command, 6-level `/proc` process ancestry tree, working directory, and SSH key fingerprint.
  - Supports 4 one-click actions:
    1. **`[Approve Once]`**: Signs this single request.
    2. **`[Approve <tool> on <host> for 15m]`**: Caches an in-memory session rule matching `(verified_host, caller_tool, key_blob, target_ssh_user)` for 15 minutes.
    3. **`[Approve all on <host> for 15m]`**: Approves any request for this key from `verified_host` for 15 minutes.
    4. **`[Deny (Esc)]`**: Rejects the request (`SSH_AGENT_FAILURE`).
  - Automatically dismisses the window if `CancelSignRequest` arrives from a coordinator (e.g., answered on another workstation).
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

# 4. Run the workstation client daemon
sockcast-client run
```
