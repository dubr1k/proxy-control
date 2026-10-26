//! The parts of `panel/fleet.py` that outlive fleet v1.
//!
//! The v1 transport (typed commands, the mTLS ingress, certificate issuance, `FleetStore`'s command
//! registry) is retired. What remains is what the node registry, fleet v2 and the node views still
//! use: the node-id grammar, the inventory allow-list a `fleet_nodes` row is read through, and the
//! pending-command count the view shows for v1 rows left in a database (`fleet_commands.status`
//! compared as plain strings, exactly as `fleet.py:320`/`:361` and `nodes/registry.py` did).

/// `fleet.NODE_RE` as a pattern string (what the request models and OpenAPI quote).
pub const NODE_PATTERN: &str = "^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$";

/// `fleet.INVENTORY_KEYS`: what a node's stored inventory may say.
pub const INVENTORY_KEYS: [&str; 6] =
    ["agent_version", "telemt_version", "region", "hostname", "platform", "capabilities"];

/// `fleet.OPERATIONS`: the five Telemt operations a v1 node could advertise as capabilities.
pub const OPERATIONS: [&str; 5] = [
    "telemt.inventory.refresh",
    "telemt.user.enable",
    "telemt.user.disable",
    "telemt.user.update_limits",
    "telemt.user.reset_quota",
];

/// The `fleet_commands.status` values that count as still pending.
pub const PENDING_COMMAND_STATUSES: [&str; 2] = ["queued", "dispatched"];

/// `NODE_RE.fullmatch(node_id)`: 1 to 64 characters of `a-z 0-9 . -`, starting and ending with a
/// letter or digit (no trailing newline sneaks through `fullmatch`).
pub fn valid_node_id(node_id: &str) -> bool {
    let bytes = node_id.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let inner = |byte: u8| edge(byte) || byte == b'.' || byte == b'-';
    match bytes {
        [] => false,
        [only] => edge(*only),
        [first, middle @ .., last] => {
            middle.len() <= 62 && edge(*first) && edge(*last) && middle.iter().all(|b| inner(*b))
        }
    }
}

/// True for an operation name in [`OPERATIONS`].
pub fn is_operation(name: &str) -> bool {
    OPERATIONS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_grammar_matches_the_python_pattern() {
        for good in ["a", "0", "edge-01", "edge.07-b", "a1b2c3d4-0000-4000-8000-000000000001", &"a".repeat(64)] {
            assert!(valid_node_id(good), "{good}");
        }
        for bad in ["", "-edge", "edge-", "edge.", "Edge", "edge_01", "edge 01", "edge-07\n", "ëdge", &"a".repeat(65)]
        {
            assert!(!valid_node_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn fleet_v1_allowlist_is_exactly_the_five_telemt_operations() {
        let mut operations = OPERATIONS.to_vec();
        operations.sort_unstable();
        assert_eq!(
            operations,
            [
                "telemt.inventory.refresh",
                "telemt.user.disable",
                "telemt.user.enable",
                "telemt.user.reset_quota",
                "telemt.user.update_limits"
            ]
        );
        assert!(is_operation("telemt.user.enable"));
        assert!(!is_operation("mieru.inspect"));
    }
}
