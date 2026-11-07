//! Connection tracking model.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConntrackState { New, Established, Related, Invalid }

#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    pub source: String,
    pub dest: String,
    pub protocol: String,
    pub state: ConntrackState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack() {
        let e = ConntrackEntry { source: "192.168.1.5".into(), dest: "8.8.8.8".into(), protocol: "tcp".into(), state: ConntrackState::New };
        assert_eq!(e.state, ConntrackState::New);
    }
}
