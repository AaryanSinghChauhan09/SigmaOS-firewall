#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction { Allow, Deny, Log }

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub port: u16,
    pub protocol: String,
    pub action: RuleAction,
    pub description: String,
}

impl FirewallRule {
    pub fn allow(port: u16, protocol: &str) -> Self {
        Self { port, protocol: protocol.to_string(), action: RuleAction::Allow, description: String::new() }
    }
    pub fn deny(port: u16, protocol: &str) -> Self {
        Self { port, protocol: protocol.to_string(), action: RuleAction::Deny, description: String::new() }
    }
}

pub struct RuleSet {
    rules: Vec<FirewallRule>,
    default_action: RuleAction,
}

impl RuleSet {
    pub fn new_default_deny() -> Self {
        Self { rules: Vec::new(), default_action: RuleAction::Deny }
    }

    pub fn add_rule(&mut self, rule: FirewallRule) {
        self.rules.push(rule);
    }

    pub fn evaluate_port(&self, port: u16, protocol: &str) -> &RuleAction {
        for rule in &self.rules {
            if rule.port == port && rule.protocol == protocol {
                return &rule.action;
            }
        }
        &self.default_action
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }

    pub fn allow_count(&self) -> usize {
        self.rules.iter().filter(|r| r.action == RuleAction::Allow).count()
    }
}
