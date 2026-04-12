use aether::system_service;

#[tokio::main]
async fn main() {
    if let Err(err) = system_service::run_system_service().await {
        eprintln!("Aether system service failed: {err}");
        std::process::exit(1);
    }
}
