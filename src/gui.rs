#[cfg(all(feature = "gui", not(any(target_os = "windows", target_os = "macos"))))]
use eframe::egui;

use crate::policy::ApprovalDecision;
use crate::prompt::{PairingPromptDetails, PromptDetails};

/// Runs a native approval modal window in a fresh child process
/// (invoked via `sshcast-client internal-gui-prompt --payload-json <json>`),
/// printing the chosen `ApprovalDecision` token (`ONCE`, `TOOL_15M`, `HOST_15M`, `DENY`) to stdout.
#[cfg(target_os = "macos")]
pub fn run_egui_modal_process(details: PromptDetails) -> anyhow::Result<ApprovalDecision> {
    Ok(crate::mac_native::run_macos_modal_process(details))
}

#[cfg(all(feature = "gui", not(any(target_os = "windows", target_os = "macos"))))]
pub fn run_egui_modal_process(details: PromptDetails) -> anyhow::Result<ApprovalDecision> {
    use std::sync::{Arc, Mutex};

    let chosen = Arc::new(Mutex::new(ApprovalDecision::Deny));
    let chosen_clone = Arc::clone(&chosen);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Sshcast — Roaming SSH Agent Approval")
            .with_inner_size([620.0, 370.0])
            .with_min_inner_size([520.0, 320.0])
            .with_always_on_top()
            .with_resizable(true),
        ..Default::default()
    };

    let app = ApprovalModalApp {
        details,
        chosen: chosen_clone,
    };

    eframe::run_native(
        "Sshcast — SSH Agent Approval",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;

    let final_decision = *chosen.lock().unwrap();
    Ok(final_decision)
}

#[cfg(not(any(
    target_os = "macos",
    all(feature = "gui", not(target_os = "windows"))
)))]
pub fn run_egui_modal_process(_details: PromptDetails) -> anyhow::Result<ApprovalDecision> {
    anyhow::bail!("compiled without 'gui' (eframe/egui) feature")
}

/// Runs a native device pairing approval modal window in a fresh child process
/// (invoked via `sshcast-client internal-gui-pairing-prompt --payload-json <json>`),
/// returning `true` if approved or `false` if denied/closed.
#[cfg(target_os = "macos")]
pub fn run_egui_pairing_modal_process(details: PairingPromptDetails) -> anyhow::Result<bool> {
    Ok(crate::mac_native::run_macos_pairing_modal_process(details))
}

#[cfg(all(feature = "gui", not(any(target_os = "windows", target_os = "macos"))))]
pub fn run_egui_pairing_modal_process(details: PairingPromptDetails) -> anyhow::Result<bool> {
    use std::sync::{Arc, Mutex};

    let chosen = Arc::new(Mutex::new(false));
    let chosen_clone = Arc::clone(&chosen);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Sshcast — Device Pairing Request")
            .with_inner_size([540.0, 350.0])
            .with_min_inner_size([460.0, 300.0])
            .with_always_on_top()
            .with_resizable(true),
        ..Default::default()
    };

    let app = PairingModalApp {
        details,
        chosen: chosen_clone,
    };

    eframe::run_native(
        "Sshcast — Device Pairing Request",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;

    let approved = *chosen.lock().unwrap();
    Ok(approved)
}

#[cfg(not(any(
    target_os = "macos",
    all(feature = "gui", not(target_os = "windows"))
)))]
pub fn run_egui_pairing_modal_process(_details: PairingPromptDetails) -> anyhow::Result<bool> {
    anyhow::bail!("compiled without 'gui' (eframe/egui) feature")
}

#[cfg(all(feature = "gui", not(any(target_os = "windows", target_os = "macos"))))]
struct ApprovalModalApp {
    details: PromptDetails,
    chosen: std::sync::Arc<std::sync::Mutex<ApprovalDecision>>,
}

#[cfg(all(feature = "gui", not(any(target_os = "windows", target_os = "macos"))))]
impl eframe::App for ApprovalModalApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            *self.chosen.lock().unwrap() = ApprovalDecision::Deny;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("SSH Agent Signature Request");
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "Verify the cryptographically authenticated host, target user, and process ancestry before approving:",
                )
                .weak(),
            );
            ui.add_space(10.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("sshcast_approval_grid")
                    .num_columns(2)
                    .spacing([14.0, 8.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Verified Source Host:").strong());
                        ui.label(
                            egui::RichText::new(&self.details.verified_host)
                                .monospace()
                                .color(egui::Color32::from_rgb(80, 200, 120)),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Target SSH User:").strong());
                        ui.label(egui::RichText::new(&self.details.target_ssh_user).monospace());
                        ui.end_row();

                        ui.label(egui::RichText::new("Primary Tool & Command:").strong());
                        ui.label(egui::RichText::new(&self.details.primary_command).monospace());
                        ui.end_row();

                        ui.label(egui::RichText::new("Process Ancestry Tree:").strong());
                        ui.label(egui::RichText::new(&self.details.ancestry_chain).monospace());
                        ui.end_row();

                        ui.label(egui::RichText::new("Working Directory:").strong());
                        ui.label(egui::RichText::new(&self.details.cwd).monospace());
                        ui.end_row();

                        ui.label(egui::RichText::new("SSH Key:").strong());
                        ui.label(egui::RichText::new(&self.details.key_summary).monospace());
                        ui.end_row();
                    });
            });

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(10.0);

            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(egui::RichText::new("  Approve Once  ").strong())
                    .clicked()
                {
                    *self.chosen.lock().unwrap() = ApprovalDecision::ApproveOnce;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }

                let tool_label = format!(
                    "  Approve '{}' on '{}' for 15m  ",
                    self.details.primary_tool, self.details.verified_host
                );
                if ui.button(tool_label).clicked() {
                    *self.chosen.lock().unwrap() = ApprovalDecision::ApproveToolOnHost15m;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }

                let host_label = format!(
                    "  Approve all on '{}' for 15m  ",
                    self.details.verified_host
                );
                if ui.button(host_label).clicked() {
                    *self.chosen.lock().unwrap() = ApprovalDecision::ApproveAllOnHost15m;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }

                if ui
                    .button(
                        egui::RichText::new("  Deny (Esc)  ")
                            .color(egui::Color32::from_rgb(230, 80, 80)),
                    )
                    .clicked()
                {
                    *self.chosen.lock().unwrap() = ApprovalDecision::Deny;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    }
}

#[cfg(all(feature = "gui", not(any(target_os = "windows", target_os = "macos"))))]
struct PairingModalApp {
    details: PairingPromptDetails,
    chosen: std::sync::Arc<std::sync::Mutex<bool>>,
}

#[cfg(all(feature = "gui", not(any(target_os = "windows", target_os = "macos"))))]
impl eframe::App for PairingModalApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            *self.chosen.lock().unwrap() = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        let login_display = if self.details.github_login.is_empty() {
            "<unknown>".to_string()
        } else {
            format!("@{}", self.details.github_login)
        };

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Device Pairing Request");
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "Confirm the 6-digit verification code matches the new workstation before syncing your Sshcast root key:",
                )
                .weak(),
            );
            ui.add_space(10.0);

            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("sshcast_pairing_grid")
                    .num_columns(2)
                    .spacing([14.0, 8.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("New Workstation:").strong());
                        ui.label(
                            egui::RichText::new(&self.details.node_name)
                                .monospace()
                                .color(egui::Color32::from_rgb(80, 200, 120)),
                        );
                        ui.end_row();

                        ui.label(egui::RichText::new("Operating System:").strong());
                        ui.label(egui::RichText::new(&self.details.os_name).monospace());
                        ui.end_row();

                        ui.label(egui::RichText::new("GitHub Account:").strong());
                        ui.label(egui::RichText::new(&login_display).monospace());
                        ui.end_row();

                        ui.label(egui::RichText::new("Account ID:").strong());
                        ui.label(egui::RichText::new(&self.details.existing_user_id).monospace());
                        ui.end_row();

                        ui.label(egui::RichText::new("Verification Code:").strong());
                        ui.label(
                            egui::RichText::new(&self.details.sas_code)
                                .monospace()
                                .strong()
                                .size(26.0)
                                .color(egui::Color32::from_rgb(90, 180, 255)),
                        );
                        ui.end_row();
                    });
            });

            ui.add_space(16.0);
            ui.separator();
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                if ui
                    .button(egui::RichText::new("  Approve  ").strong())
                    .clicked()
                {
                    *self.chosen.lock().unwrap() = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }

                if ui
                    .button(
                        egui::RichText::new("  Deny (Esc)  ")
                            .color(egui::Color32::from_rgb(230, 80, 80)),
                    )
                    .clicked()
                {
                    *self.chosen.lock().unwrap() = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    }
}
