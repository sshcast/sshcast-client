#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::Result;
use clap::Parser;
use sshcast_client::config::ClientConfig;
use sshcast_client::coordinator::WorkstationManager;
use sshcast_client::local_agent::LocalAgentConnector;
use sshcast_client::policy::{ApprovalDecision, PolicyEngine};
use sshcast_client::prompt::{ApprovalPrompter, InteractivePrompter, StaticPrompter};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sshcast-tray",
    version,
    about = "Sshcast Roaming SSH Agent System Tray / Menu Bar Application"
)]
struct TrayArgs {
    /// Optional path to `client.toml` (defaults to `~/.config/sshcast/client.toml`)
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

    let mut initial_cfg = ClientConfig::load(args.config.as_deref()).ok();
    if let Some(ref mut cfg) = initial_cfg {
        if let Some(ref sock) = args.agent_socket {
            cfg.local_agent_socket = Some(sock.clone());
        }
        if args.force_active {
            cfg.force_active = true;
        }
    }

    let initial_force_active = initial_cfg
        .as_ref()
        .map(|c| c.force_active)
        .unwrap_or(args.force_active);

    let force_active_flag = Arc::new(AtomicBool::new(initial_force_active));
    let connected_count = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (reload_tx, mut reload_rx) = watch::channel(0u64);

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        let force_active_bg = Arc::clone(&force_active_flag);
        let connected_bg = Arc::clone(&connected_count);
        let mut shutdown_rx_bg = shutdown_rx.clone();
        let shutdown_tx_ctrlc = shutdown_tx.clone();
        let auto_approve = args.auto_approve;

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

                let policy = Arc::new(PolicyEngine::default());
                let prompter: Arc<dyn ApprovalPrompter> = if auto_approve {
                    Arc::new(StaticPrompter::new(ApprovalDecision::ApproveOnce))
                } else {
                    Arc::new(InteractivePrompter::new())
                };

                loop {
                    if *shutdown_rx_bg.borrow() {
                        break;
                    }

                    #[cfg(target_os = "windows")]
                    let maybe_ctx_and_cfg = sshcast_client::win_native::get_tray_context()
                        .and_then(|ctx| {
                            let cfg = ctx.current_config()?;
                            Some((Arc::clone(&ctx.local_agent), cfg))
                        });
                    #[cfg(target_os = "macos")]
                    let maybe_ctx_and_cfg = sshcast_client::mac_native::get_tray_context()
                        .and_then(|ctx| {
                            let cfg = ctx.current_config()?;
                            Some((Arc::clone(&ctx.local_agent), cfg))
                        });

                    if let Some((local_agent, cfg)) = maybe_ctx_and_cfg {
                        local_agent.sync_from_client_config(&cfg);
                        let manager = WorkstationManager::with_shared_state(
                            cfg,
                            local_agent,
                            Arc::clone(&policy),
                            Arc::clone(&prompter),
                            Arc::clone(&force_active_bg),
                            Arc::clone(&connected_bg),
                        );

                        let (mgr_stop_tx, mgr_stop_rx) = watch::channel(false);
                        let mut mgr_task = tokio::spawn(async move { manager.run(mgr_stop_rx).await });

                        tokio::select! {
                            _ = shutdown_rx_bg.changed() => {
                                let _ = mgr_stop_tx.send(true);
                                let _ = mgr_task.await;
                                break;
                            }
                            _ = reload_rx.changed() => {
                                tracing::info!("Reloading workstation configuration and reconnecting...");
                                let _ = mgr_stop_tx.send(true);
                                let _ = mgr_task.await;
                            }
                            _ = &mut mgr_task => {}
                        }
                    } else {
                        tokio::select! {
                            _ = shutdown_rx_bg.changed() => {
                                break;
                            }
                            _ = reload_rx.changed() => {}
                        }
                    }
                }
                Ok(())
            })
        });

        #[cfg(target_os = "windows")]
        sshcast_client::win_native::run_windows_tray_loop(
            args.config,
            args.agent_socket,
            initial_cfg,
            force_active_flag,
            connected_count,
            reload_tx,
            shutdown_tx,
            shutdown_rx,
        )?;

        #[cfg(target_os = "macos")]
        sshcast_client::mac_native::run_macos_tray_loop(
            args.config,
            args.agent_socket,
            initial_cfg,
            force_active_flag,
            connected_count,
            reload_tx,
            shutdown_tx,
            shutdown_rx,
        )?;

        let _ = bg_handle.join();
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = reload_tx;
        let _ = reload_rx.borrow_and_update();
        let cfg = initial_cfg.ok_or_else(|| {
            anyhow::anyhow!("failed to load client.toml (run `sshcast-client init` first)")
        })?;
        let local_agent = Arc::new(LocalAgentConnector::from_client_config(&cfg, &[], true)?);
        let policy = Arc::new(PolicyEngine::default());
        let prompter: Arc<dyn ApprovalPrompter> = if args.auto_approve {
            Arc::new(StaticPrompter::new(ApprovalDecision::ApproveOnce))
        } else {
            Arc::new(InteractivePrompter::new())
        };
        let manager = WorkstationManager::with_shared_state(
            cfg,
            local_agent,
            policy,
            prompter,
            force_active_flag,
            connected_count,
        );
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
