//! Firewall rule model.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction { Accept, Drop, Reject, Log }

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub source: Option<String>,
    pub dest: Option<String>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub action: RuleAction,
    pub match_expr: RuleMatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_rule() {
        let r = FirewallRule { action: RuleAction::Accept, match_expr: RuleMatch { source: None, dest: None, protocol: None, port: None } };
        assert_eq!(r.action, RuleAction::Accept);
    }
}
