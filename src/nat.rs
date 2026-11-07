//! NAT model.
use crate::rule::{FirewallRule, RuleAction};
use crate::action::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType { SourceNat, DestinationNat, Masquerade }

#[derive(Debug, Clone)]
pub struct NatRule {
    pub ntype: NatType,
    pub source: String,
    pub dest: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_rule() {
        let r = NatRule { ntype: NatType::Masquerade, source: "192.168.1.0/24".into(), dest: "eth0".into() };
        assert_eq!(r.ntype, NatType::Masquerade);
    }
}
