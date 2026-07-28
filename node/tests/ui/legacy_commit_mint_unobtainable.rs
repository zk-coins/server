// Compile-fail: AccountNode::commit_mint is pub(crate) only.
// One expected error only (Stage 3 Runde 5 / R1).

fn main() {
    let _ = node::account_node::AccountNode::commit_mint;
}
