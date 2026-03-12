mod aef;
mod app;
mod auth;
mod delta_vault;
mod inter_layer_bus;
mod observation;
mod shanway;
mod state;
mod runtime_signal;
mod vault_access;

use app::AetherRustShell;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Aether")
            .with_inner_size([1560.0, 900.0])
            .with_min_inner_size([1260.0, 760.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Aether",
        native_options,
        Box::new(|cc| Ok(Box::new(AetherRustShell::new(cc)))),
    )
}
