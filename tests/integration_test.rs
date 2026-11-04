use sigmaos_firewall::{Config, FirewallComponent, FirewallRule, RuleAction, RuleSet, Component};

#[test]
fn test_config_default_aaa() {
    let config = Config::default();
    assert!(config.enabled);
    assert!(config.default_deny);
}

#[test]
fn test_ruleset_default_deny_aaa() {
    // Arrange
    let ruleset = RuleSet::new_default_deny();
    // Act
    let action = ruleset.evaluate_port(80, "tcp");
    // Assert
    assert_eq!(action, &RuleAction::Deny);
}

#[test]
fn test_ruleset_allow_rule_aaa() {
    // Arrange
    let mut ruleset = RuleSet::new_default_deny();
    ruleset.add_rule(FirewallRule::allow(443, "tcp"));
    // Act
    let action = ruleset.evaluate_port(443, "tcp");
    // Assert
    assert_eq!(action, &RuleAction::Allow);
}

#[test]
fn test_ruleset_deny_unmatched_port_aaa() {
    // Arrange
    let mut ruleset = RuleSet::new_default_deny();
    ruleset.add_rule(FirewallRule::allow(22, "tcp"));
    // Act
    let action = ruleset.evaluate_port(8080, "tcp");
    // Assert
    assert_eq!(action, &RuleAction::Deny);
}

#[test]
fn test_ruleset_rule_count_aaa() {
    // Arrange
    let mut ruleset = RuleSet::new_default_deny();
    // Act
    ruleset.add_rule(FirewallRule::allow(22, "tcp"));
    ruleset.add_rule(FirewallRule::allow(80, "tcp"));
    ruleset.add_rule(FirewallRule::deny(23, "tcp"));
    // Assert
    assert_eq!(ruleset.rule_count(), 3);
    assert_eq!(ruleset.allow_count(), 2);
}

#[test]
fn test_component_lifecycle_aaa() {
    let mut component = FirewallComponent::new(Config::default());
    assert!(component.initialize().is_ok());
    assert!(component.health_check().is_ok());
    assert!(component.shutdown().is_ok());
}

#[test]
fn test_component_name_aaa() {
    let component = FirewallComponent::new(Config::default());
    assert_eq!(component.name(), "sigmaos-firewall");
}
