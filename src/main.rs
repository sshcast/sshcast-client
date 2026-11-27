use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sshcast_client::config::{expand_tilde_path, ClientConfig, ClientConfigFile};
use sshcast_client::coordinator::WorkstationManager;
use sshcast_client::enroll::{
    decode_enrollment_bundle_token, encode_enrollment_bundle_token, export_user_root_key,
    import_user_cert, import_user_root_key, load_user_cert, load_user_signing_key,
    mint_enrollment_bundle_with_cert, run_keygen, write_client_config_and_optional_root_key,
    write_client_config_from_bundle,
};
use sshcast_client::gui::{run_egui_modal_process, run_egui_pairing_modal_process};
use sshcast_client::local_agent::LocalAgentConnector;
use sshcast_client::operator::{
    cancel_enrollment_pairing, complete_paired_enrollment, confirm_replace_lost_root_key,
    delete_recovery_vault_http, finalize_new_or_same_key_enrollment,
    get_recovery_vault_status_http, is_terminal_enroll_error, poll_enrollment_once,
    resolve_operator_url, start_github_enrollment, unlock_with_recovery_passphrase,
    upload_recovery_vault_http, EnrollPollStep, LoginOutcome, PendingPairingInfo,
};
use sshcast_client::pairing::{encrypt_recovery_vault, ScryptParams, VaultDecryptError};
use sshcast_client::policy::{ApprovalDecision, PolicyEngine};
use sshcast_client::prompt::{
    ApprovalPrompter, InteractivePrompter, PairingPromptDetails, PromptDetails, StaticPrompter,
};
use sshcast_proto::v1::NodeRole;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "sshcast-client",
    version,
    about = "Sshcast Roaming SSH Agent Workstation Client & Enrollment CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Sign in with GitHub via an Sshcast Operator to obtain an auto-renewing UserCert and enroll this workstation
    Login {
        /// Swarm domain for `_sshcast.<domain>` DNS TXT discovery (default: `sshcast.net`)
        #[arg(long, default_value = "sshcast.net")]
        domain: String,

        /// Explicit Operator URL override (e.g. `https://op.sshcast.net`)
        #[arg(long)]
        operator: Option<String>,

        /// Optional workstation identifier (defaults to hostname; enrolls client.toml if missing or specified)
        #[arg(long)]
        node: Option<String>,

        /// Optional path to `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,

        /// Do not open a browser automatically; print the sign-in URL instead
        #[arg(long, default_value_t = false)]
        no_browser: bool,
    },
    /// Generate a new User Root Ed25519 keypair (`user_key.toml`)
    Keygen {
        /// Optional path for `user_key.toml` (defaults to `~/.config/sshcast/user_key.toml`)
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Overwrite existing root key if present
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Export the local `user_key.toml` as a compact single-line `scu1_<base64>` token for another workstation
    ExportKey {
        /// Optional path for `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Import a `scu1_<base64>` user root key token into `user_key.toml` on this workstation
    ImportKey {
        /// User root key token (`scu1_<base64>`)
        #[arg(long)]
        key: String,

        /// Optional path to write `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Optional path to `client.toml` (used to verify the key matches the enrolled user)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Overwrite existing `user_key.toml` if present
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Import an operator-signed `sc_cert_<base64>` certificate into `user_key.toml` and `client.toml`
    ImportCert {
        /// Operator-signed user certificate token (`sc_cert_<base64>`)
        #[arg(long)]
        cert: String,

        /// Optional path to `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Mint a signed `NodeGrant` (`NODE_ROLE_RELAY`) and output an `sc1_<base64>` bundle for `sshcast-relay init`
    GrantRelay {
        /// Target relay hostname (must match `/proc` hostname on the target server, e.g. `server-x.infra.local`)
        #[arg(long)]
        node: String,

        /// Coordinator server URL(s) or swarm domain(s) (defaults to `servers` in `client.toml` if omitted)
        #[arg(long = "server")]
        servers: Vec<String>,

        /// Swarm domain(s) to resolve via `_sshcast.<domain>` DNS TXT records (e.g. `sshcast.net`)
        #[arg(long = "domain")]
        domains: Vec<String>,

        /// Optional grant expiration in days (0 = no expiration)
        #[arg(long, default_value_t = 0)]
        expires_days: u64,

        /// Optional path to `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Mint a signed `NodeGrant` (`NODE_ROLE_CLIENT`) for this or another workstation
    GrantClient {
        /// Workstation identifier (e.g. `macbook-pro` or `linux-desktop`)
        #[arg(long)]
        node: String,

        /// Coordinator server URL(s) or swarm domain(s) (defaults to `servers` in `client.toml` if omitted)
        #[arg(long = "server")]
        servers: Vec<String>,

        /// Swarm domain(s) to resolve via `_sshcast.<domain>` DNS TXT records (e.g. `sshcast.net`)
        #[arg(long = "domain")]
        domains: Vec<String>,

        /// Optional grant expiration in days (0 = no expiration)
        #[arg(long, default_value_t = 0)]
        expires_days: u64,

        /// Optional path to `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Optional path to write `client.toml` (defaults to `~/.config/sshcast/client.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Only print the `sc1_<base64>` enrollment token instead of writing `client.toml` locally
        #[arg(long, default_value_t = false)]
        bundle_only: bool,

        /// Omit the user root key (`.rk_<seed>`) from the emitted client bundle
        #[arg(long, default_value_t = false)]
        no_root_key: bool,

        /// Overwrite existing `client.toml` if present
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Initialize `client.toml` (and `user_key.toml` if embedded) on a secondary workstation from an `sc1_<base64>` client bundle
    Init {
        /// Client enrollment bundle token (`sc1_<base64>`)
        #[arg(long)]
        bundle: String,

        /// Optional path to write `client.toml` (defaults to `~/.config/sshcast/client.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional path to write `user_key.toml` when embedded in the bundle
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Overwrite existing `client.toml` if present
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Validate an OpenSSH private key and register it in `client.toml` (`ssh_key_files` or `ssh_keys_inline`)
    AddKey {
        /// Path to the OpenSSH private key file (e.g. `~/.ssh/id_ed25519`)
        #[arg(long = "ssh-key", visible_alias = "key-path")]
        ssh_key: PathBuf,

        /// Embed the private key PEM directly into `client.toml` (`ssh_keys_inline`) instead of referencing its file path
        #[arg(long, default_value_t = false)]
        inline: bool,

        /// Optional path to `client.toml` (defaults to `~/.config/sshcast/client.toml`)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List built-in and local OS SSH agent public keys (showing which keys pass `key_filter`)
    ListKeys {
        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional local SSH agent socket override
        #[arg(long)]
        agent_socket: Option<String>,

        /// Additional OpenSSH private key file(s) to load into the built-in agent
        #[arg(long = "ssh-key")]
        ssh_keys: Vec<PathBuf>,

        /// Disable querying the external OS SSH agent (`$SSH_AUTH_SOCK` / Windows `openssh-ssh-agent`)
        #[arg(long = "no-os-agent", default_value_t = false)]
        no_os_agent: bool,
    },
    /// Run the workstation client daemon (connects to all coordinators, sends 25s heartbeats, prompts & bridges to built-in/OS SSH agent)
    Run {
        /// Optional path to `client.toml` (defaults to `~/.config/sshcast/client.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional local SSH agent socket override
        #[arg(long)]
        agent_socket: Option<String>,

        /// Additional OpenSSH private key file(s) to load into the built-in agent
        #[arg(long = "ssh-key")]
        ssh_keys: Vec<PathBuf>,

        /// Disable querying the external OS SSH agent (`$SSH_AUTH_SOCK` / Windows `openssh-ssh-agent`)
        #[arg(long = "no-os-agent", default_value_t = false)]
        no_os_agent: bool,

        /// Force this workstation to be prioritized as active
        #[arg(long, default_value_t = false)]
        force_active: bool,

        /// Automatically approve all verified requests without interactive prompting (useful for testing)
        #[arg(long, default_value_t = false)]
        auto_approve: bool,

        /// Optional override for local Zellij Web HTTP proxy port (default from client.toml: 18080; 0 to disable)
        #[arg(long)]
        zellij_port: Option<u16>,
    },
    /// Open the local Zellij Web dashboard (or a specific remote relay host/session) in your browser
    Zellij {
        /// Optional target relay hostname (e.g. `sunduk`)
        #[arg(long)]
        host: Option<String>,

        /// Optional Zellij session name on the target host
        #[arg(long)]
        session: Option<String>,

        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Manage the optional passphrase-encrypted recovery vault stored on the Sshcast Operator
    Recovery {
        #[command(subcommand)]
        action: RecoveryAction,
    },
    /// Internal helper subcommand that renders the native `eframe`/`egui` approval modal window
    #[command(hide = true)]
    InternalGuiPrompt {
        #[arg(long)]
        payload_json: String,
    },
    /// Internal helper subcommand that renders the native `eframe`/`egui` device pairing approval window
    #[command(hide = true)]
    InternalGuiPairingPrompt {
        #[arg(long)]
        payload_json: String,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryAction {
    /// Encrypt and upload your user root key with a recovery passphrase for offline device enrollment
    Set {
        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional path to `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Explicit Operator URL override (e.g. `https://op.sshcast.net`)
        #[arg(long)]
        operator: Option<String>,

        /// Read the recovery passphrase as a single line from stdin instead of prompting interactively
        #[arg(long, default_value_t = false)]
        passphrase_stdin: bool,
    },
    /// Check whether a recovery vault is currently configured on the Operator
    Status {
        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,

        /// Explicit Operator URL override (e.g. `https://op.sshcast.net`)
        #[arg(long)]
        operator: Option<String>,
    },
    /// Remove the encrypted recovery vault from the Operator
    Remove {
        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,

        /// Explicit Operator URL override (e.g. `https://op.sshcast.net`)
        #[arg(long)]
        operator: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Run {
        config: None,
        agent_socket: None,
        ssh_keys: Vec::new(),
        no_os_agent: false,
        force_active: false,
        auto_approve: false,
        zellij_port: None,
    }) {
        Commands::Login {
            domain,
            operator,
            node,
            key_file,
            config,
            no_browser,
        } => {
            run_interactive_login(
                &domain,
                operator.as_deref(),
                node.as_deref(),
                key_file.as_deref(),
                config.as_deref(),
                !no_browser,
            )
            .await
        }
        Commands::Keygen { key_file, force } => {
            let out = run_keygen(key_file.as_deref(), force)?;
            println!("Generated User Root Ed25519 keypair!");
            println!("  Saved to:          {}", out.key_path.display());
            println!("  User ID:           {}", out.user_id);
            println!("  Server Allowlist:  {}", out.user_pubkey_token);
            println!(
                "\nAdd the following to `/etc/sshcast/server.toml` on your coordinator(s):\n  allowed_user_pubkeys = [\"{}\"]",
                out.user_pubkey_token
            );
            Ok(())
        }
        Commands::ExportKey { key_file } => {
            let token = export_user_root_key(key_file.as_deref())?;
            println!("{token}");
            Ok(())
        }
        Commands::ImportKey {
            key,
            key_file,
            config,
            force,
        } => {
            let out = import_user_root_key(&key, key_file.as_deref(), config.as_deref(), force)?;
            println!("Imported User Root Ed25519 keypair!");
            println!("  Saved to:          {}", out.key_path.display());
            println!("  User ID:           {}", out.user_id);
            println!("  Server Allowlist:  {}", out.user_pubkey_token);
            Ok(())
        }
        Commands::ImportCert {
            cert,
            key_file,
            config,
        } => {
            let (updated_key, updated_cfg, parsed_cert) =
                import_user_cert(&cert, key_file.as_deref(), config.as_deref())?;
            println!(
                "Imported Operator-Signed User Certificate for '{}'!",
                parsed_cert.user_id
            );
            println!(
                "  Operator Pubkey:   sc_op_pub_{}",
                hex::encode(&parsed_cert.operator_pubkey)
            );
            if let Some(kp) = updated_key {
                println!("  Updated root key:  {}", kp.display());
            }
            if let Some(cp) = updated_cfg {
                println!("  Updated config:    {}", cp.display());
            }
            Ok(())
        }
        Commands::GrantRelay {
            node,
            mut servers,
            domains,
            expires_days,
            key_file,
        } => {
            for d in domains {
                let clean = d
                    .trim()
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string();
                if !clean.is_empty() && !servers.contains(&clean) {
                    servers.push(clean);
                }
            }
            let resolved_servers = if servers.is_empty() {
                ClientConfig::load(None)
                    .map(|c| c.servers)
                    .context("no --server or --domain provided and failed to load default servers from client.toml")?
            } else {
                servers
            };
            let user_sk = load_user_signing_key(key_file.as_deref())?;
            let user_cert = load_user_cert(key_file.as_deref(), None);
            let bundle = mint_enrollment_bundle_with_cert(
                &user_sk,
                &node,
                NodeRole::Relay,
                resolved_servers,
                expires_days,
                user_cert,
            )?;
            let token = bundle.encode().context("failed to encode relay bundle")?;
            println!("Enrollment bundle for relay node '{node}':\n");
            println!("{token}\n");
            println!("Run this on '{node}':");
            println!("  sshcast-relay init --bundle {token}");
            Ok(())
        }
        Commands::GrantClient {
            node,
            mut servers,
            domains,
            expires_days,
            key_file,
            config,
            bundle_only,
            no_root_key,
            force,
        } => {
            for d in domains {
                let clean = d
                    .trim()
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/')
                    .to_string();
                if !clean.is_empty() && !servers.contains(&clean) {
                    servers.push(clean);
                }
            }
            let resolved_servers = if servers.is_empty() {
                ClientConfig::load(config.as_deref())
                    .map(|c| c.servers)
                    .context("no --server or --domain provided and failed to load default servers from client.toml")?
            } else {
                servers
            };
            let user_sk = load_user_signing_key(key_file.as_deref())?;
            let user_cert = load_user_cert(key_file.as_deref(), config.as_deref());
            let bundle = mint_enrollment_bundle_with_cert(
                &user_sk,
                &node,
                NodeRole::Client,
                resolved_servers,
                expires_days,
                user_cert,
            )?;
            let include_rk = if no_root_key { None } else { Some(&user_sk) };
            let token = encode_enrollment_bundle_token(&bundle, include_rk)
                .context("failed to encode client bundle")?;
            if bundle_only {
                println!("{token}");
            } else {
                let path = write_client_config_from_bundle(&bundle, config.as_deref(), force)?;
                println!(
                    "Enrolled workstation '{}' (user '{}')",
                    bundle.grant.node_id, bundle.grant.user_id
                );
                println!("  Client config written to: {}", path.display());
            }
            Ok(())
        }
        Commands::Init {
            bundle,
            config,
            key_file,
            force,
        } => {
            let (decoded, maybe_root_key) =
                decode_enrollment_bundle_token(&bundle).context("failed to decode client bundle")?;
            let (cfg_path, key_path) = write_client_config_and_optional_root_key(
                &decoded,
                maybe_root_key.as_ref(),
                config.as_deref(),
                key_file.as_deref(),
                force,
            )?;
            println!(
                "Enrolled workstation '{}' (user '{}')",
                decoded.grant.node_id, decoded.grant.user_id
            );
            println!("  Client config written to: {}", cfg_path.display());
            if let Some(kp) = key_path {
                println!("  User root key written to: {}", kp.display());
            }
            Ok(())
        }
        Commands::AddKey {
            ssh_key,
            inline,
            config,
        } => {
            let expanded = expand_tilde_path(&ssh_key.to_string_lossy());
            let connector = LocalAgentConnector::with_options(None, Default::default(), true);
            let pk = connector.load_private_key_file_interactive(&expanded, true)?;
            let (cfg_path, mut cfg_file) = ClientConfigFile::load(config.as_deref())?;
            if inline {
                let raw_pem = std::fs::read_to_string(&expanded)
                    .with_context(|| format!("failed to read {}", expanded.display()))?;
                if !cfg_file.ssh_keys_inline.iter().any(|k| k.trim() == raw_pem.trim()) {
                    cfg_file.ssh_keys_inline.push(raw_pem);
                }
            } else {
                let path_str = ssh_key.to_string_lossy().to_string();
                if !cfg_file.ssh_key_files.contains(&path_str) {
                    cfg_file.ssh_key_files.push(path_str);
                }
            }
            let saved_path = cfg_file.save(Some(&cfg_path))?;
            println!("Registered built-in SSH private key in {}:", saved_path.display());
            println!(
                "  - [built-in] {} {} ({})",
                pk.key_type, pk.fingerprint_sha256, pk.comment
            );
            Ok(())
        }
        Commands::ListKeys {
            config,
            agent_socket,
            ssh_keys,
            no_os_agent,
        } => {
            let connector = match ClientConfig::load(config.as_deref()) {
                Ok(mut c) => {
                    if let Some(sock) = agent_socket {
                        c.local_agent_socket = Some(sock);
                    }
                    if no_os_agent {
                        c.disable_os_agent = true;
                    }
                    LocalAgentConnector::from_client_config(&c, &ssh_keys, true)?
                }
                Err(_) => {
                    let conn =
                        LocalAgentConnector::with_options(agent_socket, Default::default(), no_os_agent);
                    for path in &ssh_keys {
                        let expanded = expand_tilde_path(&path.to_string_lossy());
                        conn.load_private_key_file_interactive(&expanded, true)?;
                    }
                    conn
                }
            };
            let keys = connector.list_filtered_keys_with_source_labels().await?;
            println!("Exported local SSH keys ({}):", keys.len());
            for (k, _, source) in keys {
                println!(
                    "  - [{source}] {} {} ({})",
                    k.key_type, k.fingerprint_sha256, k.comment
                );
            }
            Ok(())
        }
        Commands::Run {
            config,
            agent_socket,
            ssh_keys,
            no_os_agent,
            force_active,
            auto_approve,
            zellij_port,
        } => {
            let mut cfg = ClientConfig::load(config.as_deref())?;
            if let Some(sock) = agent_socket {
                cfg.local_agent_socket = Some(sock);
            }
            if no_os_agent {
                cfg.disable_os_agent = true;
            }
            if force_active {
                cfg.force_active = true;
            }
            if let Some(zp) = zellij_port {
                cfg.zellij_listen_port = zp;
            }

            let local_agent = Arc::new(LocalAgentConnector::from_client_config(
                &cfg, &ssh_keys, true,
            )?);
            let policy = Arc::new(PolicyEngine::default());
            let prompter: Arc<dyn ApprovalPrompter> = if auto_approve {
                Arc::new(StaticPrompter::new(ApprovalDecision::ApproveOnce))
            } else {
                Arc::new(InteractivePrompter::new())
            };

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("Shutting down sshcast-client...");
                let _ = shutdown_tx.send(true);
            });

            let manager = WorkstationManager::new(cfg, local_agent, policy, prompter);
            manager.run(shutdown_rx).await
        }
        Commands::Zellij {
            host,
            session,
            config,
        } => {
            let port = ClientConfig::load(config.as_deref())
                .map(|c| c.zellij_listen_port)
                .unwrap_or(18080);
            let url = match (host, session) {
                (Some(h), Some(s)) => format!("http://{h}.localhost:{port}/{s}"),
                (Some(h), None) => format!("http://{h}.localhost:{port}/"),
                (None, _) => format!("http://localhost:{port}/"),
            };
            println!("Opening {url}");
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("cmd")
                    .args(["/C", "start", "", &url])
                    .spawn();
            }
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open").arg(&url).spawn();
            }
            #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
            {
                let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
            }
            Ok(())
        }
        Commands::Recovery { action } => run_recovery_command(action).await,
        Commands::InternalGuiPrompt { payload_json } => {
            let details: PromptDetails = serde_json::from_str(&payload_json)
                .context("failed to deserialize PromptDetails JSON")?;
            let decision = run_egui_modal_process(details)?;
            let token = match decision {
                ApprovalDecision::ApproveOnce => "ONCE",
                ApprovalDecision::ApproveToolOnHost15m => "TOOL_15M",
                ApprovalDecision::ApproveAllOnHost15m => "HOST_15M",
                ApprovalDecision::Deny => "DENY",
            };
            println!("{token}");
            Ok(())
        }
        Commands::InternalGuiPairingPrompt { payload_json } => {
            let details: PairingPromptDetails = serde_json::from_str(&payload_json)
                .context("failed to deserialize PairingPromptDetails JSON")?;
            let approved = run_egui_pairing_modal_process(details)?;
            println!("{}", if approved { "APPROVE" } else { "DENY" });
            Ok(())
        }
    }
}

#[cfg(unix)]
mod terminal_echo {
    use std::os::unix::io::AsRawFd;
    use std::sync::Mutex;

    static SAVED_TERMIOS: Mutex<Option<libc::termios>> = Mutex::new(None);

    pub struct TermiosRestoreGuard {
        active: bool,
    }

    impl TermiosRestoreGuard {
        pub fn disable_echo() -> Option<Self> {
            let fd = std::io::stdin().as_raw_fd();
            unsafe {
                if libc::isatty(fd) != 1 {
                    return None;
                }
                let mut orig: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut orig) != 0 {
                    return None;
                }
                if let Ok(mut saved) = SAVED_TERMIOS.lock() {
                    if saved.is_none() {
                        *saved = Some(orig);
                    }
                }
                let mut no_echo = orig;
                no_echo.c_lflag &= !libc::ECHO;
                if libc::tcsetattr(fd, libc::TCSANOW, &no_echo) != 0 {
                    if let Ok(mut saved) = SAVED_TERMIOS.lock() {
                        *saved = None;
                    }
                    return None;
                }
            }
            Some(Self { active: true })
        }
    }

    impl Drop for TermiosRestoreGuard {
        fn drop(&mut self) {
            if self.active {
                restore_terminal_echo();
            }
        }
    }

    pub fn restore_terminal_echo() {
        if let Ok(mut saved) = SAVED_TERMIOS.lock() {
            if let Some(orig) = saved.take() {
                let fd = std::io::stdin().as_raw_fd();
                unsafe {
                    let _ = libc::tcsetattr(fd, libc::TCSANOW, &orig);
                }
            }
        }
    }
}

#[cfg(not(unix))]
mod terminal_echo {
    pub struct TermiosRestoreGuard;

    impl TermiosRestoreGuard {
        pub fn disable_echo() -> Option<Self> {
            None
        }
    }

    pub fn restore_terminal_echo() {}
}

fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush().context("failed to flush stdout")?;

    let guard = terminal_echo::TermiosRestoreGuard::disable_echo();
    let mut line = Zeroizing::new(String::new());
    let n = std::io::stdin()
        .read_line(&mut line)
        .context("failed to read passphrase from stdin")?;
    let had_echo_disabled = guard.is_some();
    drop(guard);
    if had_echo_disabled {
        println!();
    }
    if n == 0 {
        anyhow::bail!("unexpected end of input while reading passphrase");
    }
    Ok(Zeroizing::new(
        line.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

async fn read_passphrase_cancellable<F>(prompt: &str, ctrl_c: &mut F) -> Result<Zeroizing<String>>
where
    F: Future<Output = std::io::Result<()>> + Unpin,
{
    let prompt_owned = prompt.to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_passphrase(&prompt_owned));
    });
    tokio::select! {
        _ = ctrl_c => {
            terminal_echo::restore_terminal_echo();
            println!();
            anyhow::bail!("canceled");
        }
        res = rx => res.context("passphrase input thread aborted")?,
    }
}

async fn read_line_cancellable<F>(prompt: &str, ctrl_c: &mut F) -> Result<String>
where
    F: Future<Output = std::io::Result<()>> + Unpin,
{
    let prompt_owned = prompt.to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        use std::io::Write;
        let res = (|| -> Result<String> {
            print!("{prompt_owned}");
            std::io::stdout().flush().context("failed to flush stdout")?;
            let mut line = String::new();
            let n = std::io::stdin()
                .read_line(&mut line)
                .context("failed to read input from stdin")?;
            if n == 0 {
                anyhow::bail!("unexpected end of input");
            }
            Ok(line)
        })();
        let _ = tx.send(res);
    });
    tokio::select! {
        _ = ctrl_c => {
            terminal_echo::restore_terminal_echo();
            println!();
            anyhow::bail!("canceled");
        }
        res = rx => res.context("input thread aborted")?,
    }
}

struct StdinCommandReader {
    line_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    next_tx: std::sync::mpsc::Sender<()>,
}

fn spawn_stdin_line_reader() -> StdinCommandReader {
    let (line_tx, line_rx) = tokio::sync::mpsc::unbounded_channel();
    let (next_tx, next_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || loop {
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line_tx.send(line).is_err() {
                    break;
                }
                if next_rx.recv().is_err() {
                    break;
                }
            }
        }
    });
    StdinCommandReader { line_rx, next_tx }
}

async fn next_stdin_line(reader: &mut Option<StdinCommandReader>) -> Option<String> {
    match reader {
        Some(r) => r.line_rx.recv().await,
        None => std::future::pending().await,
    }
}

fn print_login_success(outcome: &LoginOutcome, show_recovery_tip: bool) {
    println!("Authenticated Sshcast user '{}'!", outcome.user_id);
    println!("  Operator:          {}", outcome.operator_url);
    println!("  Root key:          {}", outcome.key_path.display());
    println!(
        "  Client config:     {}{}",
        outcome.config_path.display(),
        if outcome.enrolled_new_client {
            " (newly enrolled)"
        } else {
            ""
        }
    );
    if outcome.cert.expires_at_unix_sec > 0 {
        println!(
            "  Certificate exp:   unix {} (auto-renewed)",
            outcome.cert.expires_at_unix_sec
        );
    }
    if show_recovery_tip && outcome.enrolled_new_client {
        println!(
            "\nTip: run `sshcast-client recovery set` to set an optional recovery passphrase for offline device enrollment."
        );
    }
    println!("\nNext: start the workstation client (`sshcast-client run`) or tray app!");
}

fn is_wrong_passphrase_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<VaultDecryptError>(),
            Some(VaultDecryptError::WrongPassphrase)
        )
    })
}

async fn run_interactive_login(
    domain: &str,
    operator: Option<&str>,
    node: Option<&str>,
    key_file: Option<&std::path::Path>,
    config: Option<&std::path::Path>,
    open_browser: bool,
) -> Result<()> {
    let started = start_github_enrollment(
        &[domain.to_string()],
        operator,
        node,
        key_file,
        config,
        open_browser,
        |auth_url| {
            println!("Opening GitHub sign-in in your browser:");
            println!("  {auth_url}");
            println!("Waiting for authentication...");
        },
    )
    .await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());
    let mut poll_sleep = std::pin::pin!(tokio::time::sleep(Duration::from_secs(2)));
    let mut logged_awaiting = false;
    let mut displayed_pairing_id: Option<String> = None;
    let mut current_pairing_info: Option<PendingPairingInfo> = None;
    let mut stdin_reader: Option<StdinCommandReader> = None;

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                terminal_echo::restore_terminal_echo();
                println!("\nCanceling GitHub login...");
                let _ = cancel_enrollment_pairing(&started).await;
                anyhow::bail!("GitHub login canceled");
            }
            maybe_line = next_stdin_line(&mut stdin_reader) => {
                let Some(line) = maybe_line else {
                    stdin_reader = None;
                    continue;
                };
                let Some(ref info) = current_pairing_info else {
                    if let Some(ref reader) = stdin_reader {
                        let _ = reader.next_tx.send(());
                    }
                    continue;
                };

                let cmd = line.trim().to_ascii_lowercase();
                if cmd == "p" {
                    if !info.has_recovery_vault {
                        println!("No recovery passphrase is configured on this account.");
                    } else {
                        let passphrase = match read_passphrase_cancellable(
                            "Enter recovery passphrase: ",
                            &mut ctrl_c,
                        )
                        .await
                        {
                            Ok(p) => p,
                            Err(e) if e.to_string() == "canceled" => {
                                let _ = cancel_enrollment_pairing(&started).await;
                                anyhow::bail!("GitHub login canceled");
                            }
                            Err(e) => return Err(e),
                        };
                        match unlock_with_recovery_passphrase(&started, info, &passphrase).await {
                            Ok(outcome) => {
                                println!("Unlocked account root key using recovery passphrase!");
                                print_login_success(&outcome, false);
                                return Ok(());
                            }
                            Err(e) if is_wrong_passphrase_error(&e) => {
                                eprintln!("Incorrect recovery passphrase. Try again ('p'), reset ('r'), or approve on an existing workstation.");
                            }
                            Err(e) => return Err(e),
                        }
                    }
                } else if cmd == "r" {
                    let confirm = match read_line_cancellable(
                        "Type RESET to confirm replacing your root key (old workstations and relays will stop renewing): ",
                        &mut ctrl_c,
                    )
                    .await
                    {
                        Ok(c) => c,
                        Err(e) if e.to_string() == "canceled" => {
                            let _ = cancel_enrollment_pairing(&started).await;
                            anyhow::bail!("GitHub login canceled");
                        }
                        Err(e) => return Err(e),
                    };
                    if confirm.trim() == "RESET" {
                        let outcome = confirm_replace_lost_root_key(&started).await?;
                        println!("Replaced account root key and enrolled this workstation.");
                        print_login_success(&outcome, true);
                        return Ok(());
                    } else {
                        println!("Root key reset canceled. Waiting for pairing approval...");
                    }
                } else if !cmd.is_empty() {
                    println!(
                        "Unrecognized input. Enter 'p' for recovery passphrase, 'r' to reset root key, or approve on an existing workstation."
                    );
                }

                if let Some(ref reader) = stdin_reader {
                    let _ = reader.next_tx.send(());
                }
            }
            _ = &mut poll_sleep => {
                if tokio::time::Instant::now() >= deadline {
                    let _ = cancel_enrollment_pairing(&started).await;
                    anyhow::bail!("timed out waiting for GitHub OAuth enrollment completion");
                }
                poll_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + Duration::from_secs(2));

                let step_res = tokio::select! {
                    _ = &mut ctrl_c => {
                        terminal_echo::restore_terminal_echo();
                        println!("\nCanceling GitHub login...");
                        let _ = cancel_enrollment_pairing(&started).await;
                        anyhow::bail!("GitHub login canceled");
                    }
                    res = poll_enrollment_once(&started) => res,
                };

                let step = match step_res {
                    Ok(s) => s,
                    Err(e) if is_terminal_enroll_error(&e) => return Err(e),
                    Err(e) => {
                        tracing::debug!("Enrollment poll transient error: {e:#}");
                        continue;
                    }
                };

                match step {
                    EnrollPollStep::Pending => {}
                    EnrollPollStep::AwaitingApproval => {
                        if !logged_awaiting {
                            logged_awaiting = true;
                            println!(
                                "GitHub sign-in completed; waiting for operator approval in /console/..."
                            );
                        }
                    }
                    EnrollPollStep::Approved { cert_token } => {
                        let outcome = finalize_new_or_same_key_enrollment(&started, &cert_token)?;
                        print_login_success(&outcome, true);
                        return Ok(());
                    }
                    EnrollPollStep::Paired {
                        pairing_id,
                        existing_user_pubkey,
                        approver_node_id,
                        envelope,
                    } => {
                        if !approver_node_id.is_empty() {
                            println!("Pairing approved by workstation '{approver_node_id}'!");
                        } else {
                            println!("Pairing approved by existing workstation!");
                        }
                        let outcome = complete_paired_enrollment(
                            started,
                            &existing_user_pubkey,
                            &pairing_id,
                            &envelope,
                        )
                        .await?;
                        print_login_success(&outcome, false);
                        return Ok(());
                    }
                    EnrollPollStep::PairingRequired(info) => {
                        if displayed_pairing_id.as_deref() != Some(&info.pairing_id) {
                            displayed_pairing_id = Some(info.pairing_id.clone());
                            println!();
                            if info.github_login.is_empty() {
                                println!(
                                    "Existing Sshcast account detected ({}).",
                                    info.existing_user_pubkey_token
                                );
                            } else {
                                println!(
                                    "Existing account @{} detected ({}).",
                                    info.github_login, info.existing_user_pubkey_token
                                );
                            }
                            println!("  Verification Code: {}", info.sas_code);
                            println!(
                                "  Click Approve on an existing Sshcast workstation to pair this device."
                            );
                            if info.has_recovery_vault {
                                println!(
                                    "  [p] Or press 'p' + Enter to unlock with your recovery passphrase"
                                );
                            }
                            println!(
                                "  [r] Lost old devices? Type 'r' + Enter to reset account & replace root key"
                            );
                            if stdin_reader.is_none() {
                                stdin_reader = Some(spawn_stdin_line_reader());
                            }
                        }
                        current_pairing_info = Some(info);
                    }
                    EnrollPollStep::Denied(reason) => {
                        anyhow::bail!("enrollment rejected ({reason})");
                    }
                }
            }
        }
    }
}

async fn resolve_recovery_operator_url(
    cfg: &ClientConfig,
    operator_override: Option<&str>,
) -> Result<String> {
    let explicit = operator_override
        .map(str::to_string)
        .or_else(|| cfg.operator_url.clone());
    let servers = cfg.servers.clone();
    tokio::task::spawn_blocking(move || resolve_operator_url(explicit.as_deref(), &servers))
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "could not discover operator URL via _sshcast DNS TXT for {:?}; pass --operator https://...",
                cfg.servers
            )
        })
}

async fn run_recovery_command(action: RecoveryAction) -> Result<()> {
    match action {
        RecoveryAction::Set {
            config,
            key_file,
            operator,
            passphrase_stdin,
        } => {
            let cfg = ClientConfig::load(config.as_deref())?;
            let op_url = resolve_recovery_operator_url(&cfg, operator.as_deref()).await?;
            let user_sk = load_user_signing_key(key_file.as_deref())?;
            if user_sk.verifying_key().to_bytes().as_slice() != cfg.grant.user_pubkey.as_slice() {
                anyhow::bail!(
                    "local user_key.toml does not match this workstation's enrolled user ({}) in client.toml",
                    cfg.grant.user_id
                );
            }

            let passphrase = if passphrase_stdin {
                let mut line = Zeroizing::new(String::new());
                let n = std::io::stdin()
                    .read_line(&mut line)
                    .context("failed to read recovery passphrase from stdin")?;
                if n == 0 {
                    anyhow::bail!("failed to read recovery passphrase from stdin (empty input)");
                }
                Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string())
            } else {
                let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());
                let first = read_passphrase_cancellable(
                    "Enter new recovery passphrase (minimum 8 characters): ",
                    &mut ctrl_c,
                )
                .await?;
                if first.chars().count() < 8 {
                    anyhow::bail!("recovery passphrase must be at least 8 characters long");
                }
                let second =
                    read_passphrase_cancellable("Confirm recovery passphrase: ", &mut ctrl_c)
                        .await?;
                if *first != *second {
                    anyhow::bail!("recovery passphrases do not match");
                }
                first
            };

            if passphrase.chars().count() < 8 {
                anyhow::bail!("recovery passphrase must be at least 8 characters long");
            }

            let sk_clone = user_sk.clone();
            let vault = tokio::task::spawn_blocking(move || {
                encrypt_recovery_vault(&sk_clone, &passphrase, ScryptParams::default())
            })
            .await??;

            let updated_at =
                upload_recovery_vault_http(&op_url, &cfg.grant, &cfg.node_signing_key, &vault)
                    .await?;
            println!(
                "Recovery vault uploaded for '{}' (operator: {}, updated_at: unix {}).",
                cfg.grant.user_id, op_url, updated_at
            );
            println!(
                "Keep this passphrase safe — it allows enrolling new workstations when no existing device is online."
            );
            Ok(())
        }
        RecoveryAction::Status { config, operator } => {
            let cfg = ClientConfig::load(config.as_deref())?;
            let op_url = resolve_recovery_operator_url(&cfg, operator.as_deref()).await?;
            let (configured, updated_at) =
                get_recovery_vault_status_http(&op_url, &cfg.grant, &cfg.node_signing_key).await?;
            if configured {
                println!(
                    "Recovery vault: configured (updated_at: unix {}, operator: {})",
                    updated_at, op_url
                );
            } else {
                println!("Recovery vault: not configured (operator: {op_url})");
                println!(
                    "Run `sshcast-client recovery set` to configure an encrypted recovery passphrase."
                );
            }
            Ok(())
        }
        RecoveryAction::Remove { config, operator } => {
            let cfg = ClientConfig::load(config.as_deref())?;
            let op_url = resolve_recovery_operator_url(&cfg, operator.as_deref()).await?;
            delete_recovery_vault_http(&op_url, &cfg.grant, &cfg.node_signing_key).await?;
            println!(
                "Removed recovery vault from operator {op_url} for '{}'.",
                cfg.grant.user_id
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parses_login_and_recovery_subcommands() {
        let login = Cli::try_parse_from([
            "sshcast-client",
            "login",
            "--domain",
            "sshcast.net",
            "--operator",
            "https://op.sshcast.net",
            "--node",
            "my-laptop",
            "--no-browser",
        ])
        .unwrap();
        assert!(matches!(login.command, Some(Commands::Login { .. })));

        let rec_set = Cli::try_parse_from([
            "sshcast-client",
            "recovery",
            "set",
            "--passphrase-stdin",
            "--operator",
            "https://op.sshcast.net",
        ])
        .unwrap();
        assert!(matches!(
            rec_set.command,
            Some(Commands::Recovery {
                action: RecoveryAction::Set {
                    passphrase_stdin: true,
                    ..
                }
            })
        ));

        let rec_status = Cli::try_parse_from(["sshcast-client", "recovery", "status"]).unwrap();
        assert!(matches!(
            rec_status.command,
            Some(Commands::Recovery {
                action: RecoveryAction::Status { .. }
            })
        ));

        let rec_remove = Cli::try_parse_from(["sshcast-client", "recovery", "remove"]).unwrap();
        assert!(matches!(
            rec_remove.command,
            Some(Commands::Recovery {
                action: RecoveryAction::Remove { .. }
            })
        ));

        let pairing_gui = Cli::try_parse_from([
            "sshcast-client",
            "internal-gui-pairing-prompt",
            "--payload-json",
            "{}",
        ])
        .unwrap();
        assert!(matches!(
            pairing_gui.command,
            Some(Commands::InternalGuiPairingPrompt { .. })
        ));
    }
}
