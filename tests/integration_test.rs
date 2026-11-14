use sigmaos_firewall::{prelude::*, Direction, Firewall, Packet, Table, Verdict, ConnState};
use std::net::IpAddr;
use std::str::FromStr;

#[test]
fn component_constructs_and_evaluates() {
    let mut fw = Firewall::new();
    fw.add_rule(Table::Filter, "input", allow_tcp_port(443)).unwrap();
    let p = Packet {
        direction: Direction::In, protocol: 6,
        src: IpAddr::from_str("1.2.3.4").unwrap(),
        dst: IpAddr::from_str("10.0.0.1").unwrap(),
        src_port: Some(1), dst_port: Some(443),
        in_iface: None, out_iface: None,
        conn_state: ConnState::New, tcp_flags: None,
    };
    assert_eq!(fw.evaluate(&p), Verdict::Accept);
}
