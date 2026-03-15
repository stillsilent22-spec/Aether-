use aether_rust_shell::app::AetherRustShell;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Aether Legacy Shell")
            .with_inner_size([1560.0, 900.0])
            .with_min_inner_size([1260.0, 760.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Aether Legacy Shell",
        native_options,
        Box::new(|cc| Ok(Box::new(AetherRustShell::new(cc)))),
    )
}
