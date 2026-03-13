slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    let app = AetherModernWindow::new()?;
    app.run()
}
