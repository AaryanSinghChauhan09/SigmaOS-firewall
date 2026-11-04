pub mod config;
pub mod error;
pub mod rules;
pub mod service;

pub use config::Config;
pub use error::{ComponentError, Result};
pub use rules::{FirewallRule, RuleAction, RuleSet};
pub use service::{Service, ServiceStatus};

pub trait Component {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn initialize(&mut self) -> error::Result<()>;
    fn shutdown(&mut self) -> error::Result<()>;
    fn health_check(&self) -> error::Result<()>;
}

pub struct FirewallComponent {
    service: service::Service,
}

impl FirewallComponent {
    pub fn new(config: Config) -> Self {
        Self { service: service::Service::new(config) }
    }
}

impl Component for FirewallComponent {
    fn name(&self) -> &str { "sigmaos-firewall" }
    fn version(&self) -> &str { env!("CARGO_PKG_VERSION") }
    fn initialize(&mut self) -> error::Result<()> { self.service.start() }
    fn shutdown(&mut self) -> error::Result<()> { self.service.stop() }
    fn health_check(&self) -> error::Result<()> {
        if self.service.is_running() { Ok(()) }
        else { Err(error::ComponentError::Service("firewall not running".to_string())) }
    }
}
