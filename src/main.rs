use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sockcast_client::config::ClientConfig;
use sockcast_client::coordinator::WorkstationManager;
use sockcast_client::enroll::{
    load_user_signing_key, mint_enrollment_bundle, run_keygen, write_client_config_from_bundle,
};
use sockcast_client::local_agent::LocalAgentConnector;
use sockcast_client::policy::{ApprovalDecision, PolicyEngine};
use sockcast_client::prompt::{ApprovalPrompter, InteractivePrompter, StaticPrompter};
use sockcast_proto::bundle::EnrollmentBundle;
use sockcast_proto::v1::NodeRole;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sockcast-client",
    version,
    about = "Sockcast Roaming SSH Agent Workstation Client & Enrollment CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a new User Root Ed25519 keypair (`user_key.toml`)
    Keygen {
        /// Optional path for `user_key.toml` (defaults to `~/.config/sockcast/user_key.toml`)
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Overwrite existing root key if present
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Mint a signed `NodeGrant` (`NODE_ROLE_RELAY`) and output an `sc1_<base64>` bundle for `sockcast-relay init`
    GrantRelay {
        /// Target relay hostname (must match `/proc` hostname on the target server, e.g. `server-x.infra.local`)
        #[arg(long)]
        node: String,

        /// Coordinator server URL(s) (can be passed multiple times)
        #[arg(long = "server", required = true)]
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

        /// Coordinator server URL(s) (can be passed multiple times)
        #[arg(long = "server", required = true)]
        servers: Vec<String>,

        /// Optional grant expiration in days (0 = no expiration)
        #[arg(long, default_value_t = 0)]
        expires_days: u64,

        /// Optional path to `user_key.toml`
        #[arg(long)]
        key_file: Option<PathBuf>,

        /// Optional path to write `client.toml` (defaults to `~/.config/sockcast/client.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Only print the `sc1_<base64>` enrollment token instead of writing `client.toml` locally
        #[arg(long, default_value_t = false)]
        bundle_only: bool,
    },
    /// Initialize `client.toml` on a secondary workstation from an `sc1_<base64>` client bundle
    Init {
        /// Client enrollment bundle token (`sc1_<base64>`)
        #[arg(long)]
        bundle: String,

        /// Optional path to write `client.toml` (defaults to `~/.config/sockcast/client.toml`)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// List local OS SSH agent public keys (showing which keys pass `key_filter`)
    ListKeys {
        /// Optional path to `client.toml`
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional local SSH agent socket override
        #[arg(long)]
        agent_socket: Option<String>,
    },
    /// Run the workstation client daemon (connects to all coordinators, sends 25s heartbeats, prompts & bridges to local SSH agent)
    Run {
        /// Optional path to `client.toml` (defaults to `~/.config/sockcast/client.toml`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Optional local SSH agent socket override
        #[arg(long)]
        agent_socket: Option<String>,

        /// Force this workstation to be prioritized as active
        #[arg(long, default_value_t = false)]
        force_active: bool,

        /// Automatically approve all verified requests without interactive prompting (useful for testing)
        #[arg(long, default_value_t = false)]
        auto_approve: bool,
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
        force_active: false,
        auto_approve: false,
    }) {
        Commands::Keygen { key_file, force } => {
            let out = run_keygen(key_file.as_deref(), force)?;
            println!("Generated User Root Ed25519 keypair!");
            println!("  Saved to:          {}", out.key_path.display());
            println!("  User ID:           {}", out.user_id);
            println!("  Server Allowlist:  {}", out.user_pubkey_token);
            println!(
                "\nAdd the following to `/etc/sockcast/server.toml` on your coordinator(s):\n  allowed_user_pubkeys = [\"{}\"]",
                out.user_pubkey_token
            );
            Ok(())
        }
        Commands::GrantRelay {
            node,
            servers,
            expires_days,
            key_file,
        } => {
            let user_sk = load_user_signing_key(key_file.as_deref())?;
            let bundle =
                mint_enrollment_bundle(&user_sk, &node, NodeRole::Relay, servers, expires_days)?;
            let token = bundle.encode().context("failed to encode relay bundle")?;
            println!("Enrollment bundle for relay node '{node}':\n");
            println!("{token}\n");
            println!("Run this on '{node}':");
            println!("  sockcast-relay init --bundle {token}");
            Ok(())
        }
        Commands::GrantClient {
            node,
            servers,
            expires_days,
            key_file,
            config,
            bundle_only,
        } => {
            let user_sk = load_user_signing_key(key_file.as_deref())?;
            let bundle =
                mint_enrollment_bundle(&user_sk, &node, NodeRole::Client, servers, expires_days)?;
            let token = bundle.encode().context("failed to encode client bundle")?;
            if bundle_only {
                println!("{token}");
            } else {
                let path = write_client_config_from_bundle(&bundle, config.as_deref())?;
                println!(
                    "Enrolled workstation '{}' (user '{}')",
                    bundle.grant.node_id, bundle.grant.user_id
                );
                println!("  Client config written to: {}", path.display());
            }
            Ok(())
        }
        Commands::Init { bundle, config } => {
            let decoded =
                EnrollmentBundle::decode(&bundle).context("failed to decode client bundle")?;
            let path = write_client_config_from_bundle(&decoded, config.as_deref())?;
            println!(
                "Enrolled workstation '{}' (user '{}')",
                decoded.grant.node_id, decoded.grant.user_id
            );
            println!("  Client config written to: {}", path.display());
            Ok(())
        }
        Commands::ListKeys {
            config,
            agent_socket,
        } => {
            let (sock_override, filter) = match ClientConfig::load(config.as_deref()) {
                Ok(c) => (agent_socket.or(c.local_agent_socket), c.key_filter),
                Err(_) => (agent_socket, Default::default()),
            };
            let connector = LocalAgentConnector::new(sock_override, filter);
            let keys = connector.list_filtered_keys().await?;
            println!("Exported local SSH keys ({}):", keys.len());
            for k in keys {
                println!(
                    "  - {} {} ({})",
                    k.key_type, k.fingerprint_sha256, k.comment
                );
            }
            Ok(())
        }
        Commands::Run {
            config,
            agent_socket,
            force_active,
            auto_approve,
        } => {
            let mut cfg = ClientConfig::load(config.as_deref())?;
            if let Some(sock) = agent_socket {
                cfg.local_agent_socket = Some(sock);
            }
            if force_active {
                cfg.force_active = true;
            }

            let local_agent = Arc::new(LocalAgentConnector::new(
                cfg.local_agent_socket.clone(),
                cfg.key_filter.clone(),
            ));
            let policy = Arc::new(PolicyEngine::default());
            let prompter: Arc<dyn ApprovalPrompter> = if auto_approve {
                Arc::new(StaticPrompter::new(ApprovalDecision::ApproveOnce))
            } else {
                Arc::new(InteractivePrompter::new())
            };

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("Shutting down sockcast-client...");
                let _ = shutdown_tx.send(true);
            });

            let manager = WorkstationManager::new(cfg, local_agent, policy, prompter);
            manager.run(shutdown_rx).await
        }
    }
}
