//! Action model.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy { Accept, Drop, Reject }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy() {
        assert_eq!(Policy::Accept, Policy::Accept);
    }
}
