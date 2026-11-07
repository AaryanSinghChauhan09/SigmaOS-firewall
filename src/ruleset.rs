//! Rule set model.
use crate::rule::{FirewallRule, RuleAction};
use crate::action::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType { Input, Output, Forward, Prerouting, Postrouting }

#[derive(Debug, Clone)]
pub struct Chain {
    pub ctype: ChainType,
    pub rules: Vec<FirewallRule>,
    pub policy: Policy,
}

#[derive(Debug, Default)]
pub struct RuleSet {
    pub chains: Vec<Chain>,
}

impl RuleSet {
    pub fn new() -> Self { Self::default() }
    pub fn add_chain(&mut self, c: Chain) { self.chains.push(c); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset() {
        let mut rs = RuleSet::new();
        rs.add_chain(Chain { ctype: ChainType::Input, rules: vec![], policy: Policy::Accept });
        assert_eq!(rs.chains.len(), 1);
    }
}
