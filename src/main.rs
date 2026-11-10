use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sshcast_client::config::{expand_tilde_path, ClientConfig, ClientConfigFile};
use sshcast_client::coordinator::WorkstationManager;
use sshcast_client::enroll::{
    decode_enrollment_bundle_token, encode_enrollment_bundle_token, export_user_root_key,
    import_user_root_key, load_user_signing_key, mint_enrollment_bundle, run_keygen,
    write_client_config_and_optional_root_key, write_client_config_from_bundle,
};
use sshcast_client::gui::run_egui_modal_process;
use sshcast_client::local_agent::LocalAgentConnector;
use sshcast_client::policy::{ApprovalDecision, PolicyEngine};
use sshcast_client::prompt::{ApprovalPrompter, InteractivePrompter, PromptDetails, StaticPrompter};
use sshcast_proto::v1::NodeRole;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

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
    /// Mint a signed `NodeGrant` (`NODE_ROLE_RELAY`) and output an `sc1_<base64>` bundle for `sshcast-relay init`
    GrantRelay {
        /// Target relay hostname (must match `/proc` hostname on the target server, e.g. `server-x.infra.local`)
        #[arg(long)]
        node: String,

        /// Coordinator server URL(s) (defaults to `servers` in `client.toml` if omitted)
        #[arg(long = "server")]
        servers: Vec<String>,

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

        /// Coordinator server URL(s) (defaults to `servers` in `client.toml` if omitted)
        #[arg(long = "server")]
        servers: Vec<String>,

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
    /// Internal helper subcommand that renders the native `eframe`/`egui` approval modal window
    #[command(hide = true)]
    InternalGuiPrompt {
        #[arg(long)]
        payload_json: String,
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
        Commands::GrantRelay {
            node,
            servers,
            expires_days,
            key_file,
        } => {
            let resolved_servers = if servers.is_empty() {
                ClientConfig::load(None)
                    .map(|c| c.servers)
                    .context("no --server provided and failed to load default servers from client.toml")?
            } else {
                servers
            };
            let user_sk = load_user_signing_key(key_file.as_deref())?;
            let bundle = mint_enrollment_bundle(
                &user_sk,
                &node,
                NodeRole::Relay,
                resolved_servers,
                expires_days,
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
            servers,
            expires_days,
            key_file,
            config,
            bundle_only,
            no_root_key,
            force,
        } => {
            let resolved_servers = if servers.is_empty() {
                ClientConfig::load(config.as_deref())
                    .map(|c| c.servers)
                    .context("no --server provided and failed to load default servers from client.toml")?
            } else {
                servers
            };
            let user_sk = load_user_signing_key(key_file.as_deref())?;
            let bundle = mint_enrollment_bundle(
                &user_sk,
                &node,
                NodeRole::Client,
                resolved_servers,
                expires_days,
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
            let keys = connector.list_filtered_keys().await?;
            println!("Exported local SSH keys ({}):", keys.len());
            for k in keys {
                let source = if connector.is_loaded_key(&k.key_blob) {
                    "built-in"
                } else {
                    "os-agent"
                };
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
    }
}
