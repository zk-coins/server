// Compile-fail: AccountNode::receive_coin_into is private (not pub / not
// pub(crate)). One expected error only (Stage 3 Runde 5 / R1).
// External crates must not bypass the gated receive_coin entry.

fn main() {
    let _ = node::account_node::AccountNode::receive_coin_into;
}
