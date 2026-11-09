#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::Result;
use clap::Parser;
use sockcast_client::config::ClientConfig;
use sockcast_client::coordinator::WorkstationManager;
use sockcast_client::local_agent::LocalAgentConnector;
use sockcast_client::policy::{ApprovalDecision, PolicyEngine};
use sockcast_client::prompt::{ApprovalPrompter, InteractivePrompter, StaticPrompter};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sockcast-tray",
    version,
    about = "Sockcast Roaming SSH Agent Windows System Tray Application (No Console Window)"
)]
struct TrayArgs {
    /// Optional path to `client.toml` (defaults to `~/.config/sockcast/client.toml`)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Optional local SSH agent socket override
    #[arg(long)]
    agent_socket: Option<String>,

    /// Force this workstation to be prioritized as active
    #[arg(long, default_value_t = false)]
    force_active: bool,

    /// Automatically approve all verified requests without interactive prompting
    #[arg(long, default_value_t = false)]
    auto_approve: bool,
}

fn main() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();

    let args = TrayArgs::parse();

    let mut cfg = match ClientConfig::load(args.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            #[cfg(target_os = "windows")]
            {
                sockcast_client::win_native::show_tray_error_dialog(
                    "Sockcast System Tray — Configuration Error",
                    "Failed to load Sockcast workstation configuration (client.toml)",
                    &format!(
                        "{e:#}\n\n\
                         Enroll this workstation first from a terminal using:\n\
                         • sockcast-client init --bundle sc1_...\n\
                         • or sockcast-client grant-client --node <name> --server https://...",
                    ),
                );
            }
            return Err(e);
        }
    };

    if let Some(sock) = args.agent_socket {
        cfg.local_agent_socket = Some(sock);
    }
    if args.force_active {
        cfg.force_active = true;
    }

    let local_agent = Arc::new(LocalAgentConnector::new(
        cfg.local_agent_socket.clone(),
        cfg.key_filter.clone(),
    ));
    let policy = Arc::new(PolicyEngine::default());
    let prompter: Arc<dyn ApprovalPrompter> = if args.auto_approve {
        Arc::new(StaticPrompter::new(ApprovalDecision::ApproveOnce))
    } else {
        Arc::new(InteractivePrompter::new())
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let manager = Arc::new(WorkstationManager::new(
        cfg.clone(),
        Arc::clone(&local_agent),
        policy,
        prompter,
    ));

    #[cfg(target_os = "windows")]
    {
        let force_active_flag = manager.force_active_flag();
        let connected_count = manager.connected_count();
        let manager_bg = Arc::clone(&manager);
        let shutdown_rx_bg = shutdown_rx.clone();
        let shutdown_tx_ctrlc = shutdown_tx.clone();

        let bg_handle = std::thread::spawn(move || -> Result<()> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                tokio::spawn(async move {
                    if tokio::signal::ctrl_c().await.is_ok() {
                        let _ = shutdown_tx_ctrlc.send(true);
                    }
                });
                manager_bg.run(shutdown_rx_bg).await
            })
        });

        sockcast_client::win_native::run_windows_tray_loop(
            &cfg,
            local_agent,
            force_active_flag,
            connected_count,
            shutdown_tx,
            shutdown_rx,
        )?;

        let _ = bg_handle.join();
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(async move {
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(true);
            });
            manager.run(shutdown_rx).await
        })
    }
}
