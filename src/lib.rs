//! SigmaOS-firewall: netfilter-style packet filter — tables, chains,
//! rules with matches and targets, deterministic packet evaluation.
//! Replaces the earlier CLI-dispatch/`Plan` placeholder stubs.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

/// Packet direction relative to this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction { In, Out, Forward }

/// Conntrack states (simplified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnState { New, Established, Related, Invalid, Untracked }

/// A packet presented to the firewall for evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub direction: Direction,
    pub protocol: u8,            // IPPROTO_TCP=6, UDP=17, ICMP=1
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub in_iface: Option<String>,
    pub out_iface: Option<String>,
    pub conn_state: ConnState,
    pub tcp_flags: Option<u8>,   // for future flag matches
}

/// What a rule does when it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Accept,
    Drop,
    Reject { with: RejectType },
    Log { prefix: String },
    Masquerade,          // NAT table only
    Jump(String),        // jump to user chain
    Return,              // end of user chain
    Continue,            // keep evaluating rules in chain
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectType { TcpReset, IcmpNetUnreachable, IcmpHostUnreachable }

/// A single match clause: all present fields must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    pub protocol: Option<u8>,
    pub src: Option<String>,    // CIDR or bare IP
    pub dst: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub port_range: Option<(u16, u16)>, // matches src OR dst port in range
    pub in_iface: Option<String>,
    pub out_iface: Option<String>,
    pub conn_state: Option<ConnState>,
    pub negated: bool,          // '!' prefix semantics for the whole match
}

/// A rule = ordered list of matches + target. All matches must pass.
#[derive(Debug, Clone)]
pub struct Rule {
    pub matches: Vec<Match>,
    pub target: Target,
    pub description: String,
}

/// Built-in chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BuiltinChain {
    Prerouting, Input, Forward, Output, Postrouting,
}

impl BuiltinChain {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "prerouting" => Some(Self::Prerouting),
            "input" => Some(Self::Input),
            "forward" => Some(Self::Forward),
            "output" => Some(Self::Output),
            "postrouting" => Some(Self::Postrouting),
            _ => None,
        }
    }
}

/// Tables (netfilter has filter/nat/mangle/security/raw).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Table { Filter, Nat, Mangle, Raw }

impl Table {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "filter" => Some(Self::Filter),
            "nat" => Some(Self::Nat),
            "mangle" => Some(Self::Mangle),
            "raw" => Some(Self::Raw),
            _ => None,
        }
    }
    /// Chains valid in this table.
    pub fn chains(&self) -> &'static [BuiltinChain] {
        match self {
            Self::Filter => &[BuiltinChain::Input, BuiltinChain::Forward, BuiltinChain::Output],
            Self::Nat => &[BuiltinChain::Prerouting, BuiltinChain::Output, BuiltinChain::Postrouting],
            Self::Mangle => &[BuiltinChain::Prerouting, BuiltinChain::Input,
                             BuiltinChain::Forward, BuiltinChain::Output, BuiltinChain::Postrouting],
            Self::Raw => &[BuiltinChain::Prerouting, BuiltinChain::Output],
        }
    }
}

/// Final verdict for a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject(RejectType),
    /// Chain ended without a terminating target → policy applies.
    Policy(Table),
}

impl Default for Verdict {
    fn default() -> Self { Verdict::Drop }
}

/// A chain: builtin or user-defined, ordered rules.
#[derive(Debug, Default)]
pub struct Chain {
    pub name: String,
    pub builtin: Option<BuiltinChain>,
    pub policy: Verdict,
    pub rules: Vec<Rule>,
}

/// The firewall: tables -> chains -> rules.
#[derive(Debug, Default)]
pub struct Firewall {
    pub tables: BTreeMap<Table, BTreeMap<String, Chain>>,
    pub default_policy: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwError {
    UnknownTable(String),
    UnknownChain { table: Table, chain: String },
    ChainNotInTable { table: Table, chain: BuiltinChain },
    BadCidr(String),
    JumpLoop(String),
}

impl fmt::Display for FwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTable(t) => write!(f, "unknown table {}", t),
            Self::UnknownChain { table, chain } =>
                write!(f, "chain {} not found in {:?}", chain, table),
            Self::ChainNotInTable { table, chain } =>
                write!(f, "chain {:?} not valid in {:?}", chain, table),
            Self::BadCidr(c) => write!(f, "bad CIDR {}", c),
            Self::JumpLoop(c) => write!(f, "jump loop via chain {}", c),
        }
    }
}

impl std::error::Error for FwError {}

/// Does a CIDR spec ("10.0.0.0/8" or bare "10.0.0.1") contain `ip`?
fn cidr_contains(spec: &str, ip: &IpAddr) -> bool {
    let (net_s, prefix_s) = match spec.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (spec, None),
    };
    let net: IpAddr = match net_s.parse() { Ok(v) => v, Err(_) => return false };
    // family must match
    let v4 = |a: &IpAddr| matches!(a, IpAddr::V4(_));
    if v4(&net) != v4(ip) { return false; }
    let prefix: u8 = match prefix_s {
        Some(p) => match p.parse() { Ok(v) => v, Err(_) => return false },
        None => return net == *ip, // bare IP = exact match
    };
    match (net, *ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            if prefix > 32 { return false; }
            let shift = 32 - prefix;
            (u32::from(n) >> shift) == (u32::from(i) >> shift)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            if prefix > 128 { return false; }
            let shift = 128 - prefix;
            (u128::from(n) >> shift) == (u128::from(i) >> shift)
        }
        _ => false,
    }
}

/// Does a single match clause match the packet?
pub fn match_clause(m: &Match, p: &Packet) -> bool {
    let mut ok = true;
    if let Some(proto) = m.protocol { ok &= p.protocol == proto; }
    if let Some(src) = &m.src { ok &= cidr_contains(src, &p.src); }
    if let Some(dst) = &m.dst { ok &= cidr_contains(dst, &p.dst); }
    if let Some(sp) = m.src_port { ok &= p.src_port == Some(sp); }
    if let Some(dp) = m.dst_port { ok &= p.dst_port == Some(dp); }
    if let Some((lo, hi)) = m.port_range {
        let hit = |port: Option<u16>| port.map(|x| x >= lo && x <= hi).unwrap_or(false);
        ok &= hit(p.src_port) || hit(p.dst_port);
    }
    if let Some(i) = &m.in_iface { ok &= p.in_iface.as_deref() == Some(i.as_str()); }
    if let Some(o) = &m.out_iface { ok &= p.out_iface.as_deref() == Some(o.as_str()); }
    if let Some(cs) = m.conn_state { ok &= p.conn_state == cs; }
    if m.negated { !ok } else { ok }
}

impl Firewall {
    pub fn new() -> Self {
        let mut f = Self::default();
        // standard policy: filter default DROP, others ACCEPT
        f.default_policy = Verdict::Drop;
        // install builtin chains in filter table
        for &c in Table::Filter.chains() {
            f.ensure_builtin(Table::Filter, c);
        }
        for &c in Table::Nat.chains() {
            f.ensure_builtin(Table::Nat, c);
        }
        f
    }

    fn ensure_builtin(&mut self, table: Table, chain: BuiltinChain) {
        self.tables.entry(table).or_default().entry(chain_name(chain).to_string())
            .or_insert_with(|| Chain {
                name: chain_name(chain).to_string(),
                builtin: Some(chain),
                policy: if table == Table::Filter { Verdict::Drop } else { Verdict::Accept },
                rules: vec![],
            });
    }

    /// Get or create a user chain in a table.
    pub fn ensure_chain(&mut self, table: Table, name: &str) -> Result<(), FwError> {
        if BuiltinChain::parse(name).is_some() {
            // builtin names may only be used if valid for this table
            let b = BuiltinChain::parse(name).unwrap();
            if !table.chains().contains(&b) {
                return Err(FwError::ChainNotInTable { table, chain: b });
            }
            self.ensure_builtin(table, b);
            return Ok(());
        }
        self.tables.entry(table).or_default()
            .entry(name.to_string())
            .or_insert_with(|| Chain {
                name: name.to_string(), builtin: None,
                policy: Verdict::Accept, rules: vec![],
            });
        Ok(())
    }

    /// Append a rule to a chain.
    pub fn add_rule(&mut self, table: Table, chain: &str, rule: Rule) -> Result<(), FwError> {
        self.ensure_chain(table, chain)?;
        let chains = self.tables.get_mut(&table).unwrap();
        let c = chains.get_mut(chain)
            .ok_or_else(|| FwError::UnknownChain { table, chain: chain.into() })?;
        c.rules.push(rule);
        Ok(())
    }

    /// Evaluate a packet through the filter table for its direction.
    /// Returns the terminal verdict.
    pub fn evaluate(&self, p: &Packet) -> Verdict {
        let chain_name_for = match p.direction {
            Direction::In => "input",
            Direction::Out => "output",
            Direction::Forward => "forward",
        };
        self.eval_chain(Table::Filter, chain_name_for, p, 0)
            .unwrap_or_else(|| self.default_policy.clone())
    }

    fn eval_chain(&self, table: Table, chain: &str, p: &Packet, depth: u8)
        -> Option<Verdict>
    {
        if depth > 16 { return Some(Verdict::Drop); } // jump-loop guard
        let chains = self.tables.get(&table)?;
        let c = chains.get(chain)?;
        for rule in &c.rules {
            let matched = rule.matches.iter().all(|m| match_clause(m, p));
            if !matched { continue; }
            match &rule.target {
                Target::Accept => return Some(Verdict::Accept),
                Target::Drop => return Some(Verdict::Drop),
                Target::Reject { with } => return Some(Verdict::Reject(*with)),
                Target::Log { .. } => continue, // log-and-continue
                Target::Masquerade | Target::Continue => continue,
                Target::Return => return None,  // back to caller/policy
                Target::Jump(next) => {
                    if let Some(v) = self.eval_chain(table, next, p, depth + 1) {
                        // user-chain terminal verdict propagates only if it
                        // came from a real target; Return yields None →
                        // continue with remaining rules here
                        return Some(v);
                    }
                    // chain returned without verdict → keep evaluating
                }
            }
        }
        // end of chain: builtin → its policy; user chain → Return semantics
        match c.builtin {
            Some(_) => Some(c.policy.clone()),
            None => None,
        }
    }
}

fn chain_name(b: BuiltinChain) -> &'static str {
    match b {
        BuiltinChain::Prerouting => "prerouting",
        BuiltinChain::Input => "input",
        BuiltinChain::Forward => "forward",
        BuiltinChain::Output => "output",
        BuiltinChain::Postrouting => "postrouting",
    }
}

/// Convenience constructors for common rules.
pub mod prelude {
    use super::*;
    pub fn accept_all() -> Rule {
        Rule { matches: vec![], target: Target::Accept, description: "accept all".into() }
    }
    pub fn drop_all() -> Rule {
        Rule { matches: vec![], target: Target::Drop, description: "drop all".into() }
    }
    pub fn accept_established() -> Rule {
        Rule {
            matches: vec![Match { conn_state: Some(ConnState::Established), ..Default::default() }],
            target: Target::Accept,
            description: "accept established".into(),
        }
    }
    pub fn allow_tcp_port(port: u16) -> Rule {
        Rule {
            matches: vec![Match {
                protocol: Some(6), dst_port: Some(port), ..Default::default()
            }],
            target: Target::Accept,
            description: format!("allow tcp/{}", port),
        }
    }
    pub fn drop_invalid() -> Rule {
        Rule {
            matches: vec![Match { conn_state: Some(ConnState::Invalid), ..Default::default() }],
            target: Target::Drop,
            description: "drop invalid conntrack".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn pkt_in_tcp(dst_port: u16) -> Packet {
        Packet {
            direction: Direction::In, protocol: 6,
            src: IpAddr::V4(Ipv4Addr::new(8,8,8,8)),
            dst: IpAddr::V4(Ipv4Addr::new(192,168,1,5)),
            src_port: Some(12345), dst_port: Some(dst_port),
            in_iface: Some("eth0".into()), out_iface: None,
            conn_state: ConnState::New, tcp_flags: None,
        }
    }

    #[test]
    fn test_default_policy_drops_unsolicited_aaa() {
        // Arrange
        let fw = Firewall::new();
        // Act & Assert: no rules → filter policy DROP
        assert_eq!(fw.evaluate(&pkt_in_tcp(22)), Verdict::Drop);
    }

    #[test]
    fn test_accept_rule_short_circuits_aaa() {
        // Arrange
        let mut fw = Firewall::new();
        fw.add_rule(Table::Filter, "input", accept_established()).unwrap();
        let mut p = pkt_in_tcp(22);
        p.conn_state = ConnState::Established;
        // Act & Assert
        assert_eq!(fw.evaluate(&p), Verdict::Accept);
        // new conn still dropped
        p.conn_state = ConnState::New;
        assert_eq!(fw.evaluate(&p), Verdict::Drop);
    }

    #[test]
    fn test_port_match_and_protocol_match_aaa() {
        // Arrange
        let mut fw = Firewall::new();
        fw.add_rule(Table::Filter, "input", allow_tcp_port(443)).unwrap();
        fw.add_rule(Table::Filter, "input", allow_tcp_port(22)).unwrap();
        // Act & Assert
        assert_eq!(fw.evaluate(&pkt_in_tcp(443)), Verdict::Accept);
        assert_eq!(fw.evaluate(&pkt_in_tcp(22)), Verdict::Accept);
        assert_eq!(fw.evaluate(&pkt_in_tcp(23)), Verdict::Drop);
    }

    #[test]
    fn test_cidr_match_v4_and_v6_aaa() {
        // Arrange
        let m = Match { src: Some("10.0.0.0/8".into()), ..Default::default() };
        let mut p = pkt_in_tcp(80);
        p.src = IpAddr::V4(Ipv4Addr::new(10,1,2,3));
        assert!(match_clause(&m, &p));
        p.src = IpAddr::V4(Ipv4Addr::new(11,0,0,1));
        assert!(!match_clause(&m, &p));
        // v6 spec vs v4 packet → no match
        let m6 = Match { src: Some("fd00::/8".into()), ..Default::default() };
        assert!(!match_clause(&m6, &p));
        p.src = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(!match_clause(&m6, &p)); // ::1 not in fd00::/8
        p.src = IpAddr::V6("fd12::1".parse().unwrap());
        assert!(match_clause(&m6, &p));
    }

    #[test]
    fn test_bare_ip_match_is_exact_aaa() {
        // Arrange
        let m = Match { dst: Some("192.168.1.5".into()), ..Default::default() };
        assert!(match_clause(&m, &pkt_in_tcp(1)));
        let mut p = pkt_in_tcp(1);
        p.dst = IpAddr::V4(Ipv4Addr::new(192,168,1,6));
        assert!(!match_clause(&m, &p));
    }

    #[test]
    fn test_negated_match_aaa() {
        // Arrange: drop everything NOT from 10.0.0.0/8
        let m = Match { src: Some("10.0.0.0/8".into()), negated: true, ..Default::default() };
        let mut p = pkt_in_tcp(1);
        p.src = IpAddr::V4(Ipv4Addr::new(8,8,8,8));
        assert!(match_clause(&m, &p)); // 8.8.8.8 is not in 10/8 → negated true
        p.src = IpAddr::V4(Ipv4Addr::new(10,9,9,9));
        assert!(!match_clause(&m, &p));
    }

    #[test]
    fn test_jump_to_user_chain_aaa() {
        // Arrange: user chain "web" accepts 443, returns otherwise
        let mut fw = Firewall::new();
        fw.ensure_chain(Table::Filter, "web").unwrap();
        fw.add_rule(Table::Filter, "web", Rule {
            matches: vec![Match { dst_port: Some(443), ..Default::default() }],
            target: Target::Accept, description: "web 443".into(),
        }).unwrap();
        fw.add_rule(Table::Filter, "input", Rule {
            matches: vec![], target: Target::Jump("web".into()), description: "to web".into(),
        }).unwrap();
        // Act & Assert
        assert_eq!(fw.evaluate(&pkt_in_tcp(443)), Verdict::Accept);
        assert_eq!(fw.evaluate(&pkt_in_tcp(80)), Verdict::Drop); // fell through to policy
    }

    #[test]
    fn test_jump_depth_guard_aaa() {
        // Arrange: a->b->a loop
        let mut fw = Firewall::new();
        for c in ["a", "b"] {
            fw.ensure_chain(Table::Filter, c).unwrap();
            let next = if c == "a" { "b" } else { "a" };
            fw.add_rule(Table::Filter, c, Rule {
                matches: vec![], target: Target::Jump(next.into()), description: "loop".into(),
            }).unwrap();
        }
        fw.add_rule(Table::Filter, "input", Rule {
            matches: vec![], target: Target::Jump("a".into()), description: "enter".into(),
        }).unwrap();
        // Act & Assert: must terminate (Drop via depth guard)
        assert_eq!(fw.evaluate(&pkt_in_tcp(1)), Verdict::Drop);
    }

    #[test]
    fn test_reject_target_aaa() {
        // Arrange
        let mut fw = Firewall::new();
        fw.add_rule(Table::Filter, "input", Rule {
            matches: vec![Match { dst_port: Some(23), ..Default::default() }],
            target: Target::Reject { with: RejectType::TcpReset },
            description: "reject telnet".into(),
        }).unwrap();
        // Act & Assert
        assert_eq!(fw.evaluate(&pkt_in_tcp(23)), Verdict::Reject(RejectType::TcpReset));
    }

    #[test]
    fn test_builtin_chain_validity_per_table_aaa() {
        // Arrange
        let mut fw = Firewall::new();
        // Act & Assert: 'input' is not a nat chain
        assert!(fw.ensure_chain(Table::Nat, "input").is_err());
        assert!(fw.ensure_chain(Table::Nat, "prerouting").is_ok());
        assert!(fw.ensure_chain(Table::Filter, "forward").is_ok());
    }

    #[test]
    fn test_port_range_match_aaa() {
        // Arrange: ephemeral range 49152-65535 on dst port
        let m = Match { port_range: Some((49152, 65535)), ..Default::default() };
        let mut p = pkt_in_tcp(50000);
        assert!(match_clause(&m, &p));
        p.dst_port = Some(80);
        p.src_port = Some(50001); // src in range still matches (OR semantics)
        assert!(match_clause(&m, &p));
        p.src_port = Some(1234);
        assert!(!match_clause(&m, &p));
    }

    #[test]
    fn test_direction_selects_chain_aaa() {
        // Arrange: output chain allows tcp/25; input drops by policy
        let mut fw = Firewall::new();
        fw.add_rule(Table::Filter, "output", allow_tcp_port(25)).unwrap();
        // Act: outbound smtp accepted
        let mut p = pkt_in_tcp(25);
        p.direction = Direction::Out;
        assert_eq!(fw.evaluate(&p), Verdict::Accept);
        // inbound smtp dropped (no input rule)
        p.direction = Direction::In;
        assert_eq!(fw.evaluate(&p), Verdict::Drop);
    }

    #[test]
    fn test_conn_state_matching_aaa() {
        // Arrange
        let m = Match { conn_state: Some(ConnState::Established), ..Default::default() };
        let mut p = pkt_in_tcp(1);
        p.conn_state = ConnState::Established;
        assert!(match_clause(&m, &p));
        p.conn_state = ConnState::New;
        assert!(!match_clause(&m, &p));
    }
}
