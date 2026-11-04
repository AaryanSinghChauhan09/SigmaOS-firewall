use sigmaos_firewall::{Config, FirewallComponent, Component};
fn main() {
    env_logger::init();
    let mut component = FirewallComponent::new(Config::default());
    if let Err(e) = component.initialize() { eprintln!("Failed: {}", e); std::process::exit(1); }
    println!("SigmaOS firewall running");
    let _ = component.shutdown();
}
