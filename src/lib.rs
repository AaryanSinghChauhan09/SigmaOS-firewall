//! SigmaOS-firewall — firewall model.
//!
//! Models firewall rules, rule sets, actions (accept/drop/reject),
//  NAT, and connection tracking. Deterministic and std-only.

pub mod rule;
pub mod ruleset;
pub mod action;
pub mod nat;
pub mod conntrack;

pub use rule::{FirewallRule, RuleMatch};
pub use ruleset::{RuleSet, Chain, ChainType};
pub use action::Policy;
pub use nat::{NatRule, NatType};
pub use conntrack::{ConntrackEntry, ConntrackState};
