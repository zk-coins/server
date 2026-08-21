// Stage 3 Runde 6 counter-probe: the former downstream path
//   AccountNode::import_account → state() → persist_account → accounts table
// must not compile outside the `node` crate. Visibility is the gate
// (positive list default = closed), not a runtime check.
//
// Driven by `stage3_legacy_unreachable_compile_fail`.

fn main() {
    // Mutative install of an arbitrary legacy ledger row.
    let _ = node::account_node::AccountNode::import_account;

    // Mutable Arc<Mutex<State>> was handed out despite a "read-only" comment.
    let _ = node::account_node::AccountNode::state;

    // Free-standing write into the legacy `accounts` table.
    let _ = node::account_node::persist_account;

    // SQL sinks for legacy durable state (also gated in-tx when reachable).
    let _ = node::db::upsert_account;
    let _ = node::db::upsert_account_with_source;
    let _ = node::db::insert_account_history;
    let _ = node::db::commit_mint_tx;
    let _ = node::db::register_asset_creator;
    let _ = node::db::insert_pending_inscription;
    let _ = node::db::update_pending_status;
    let _ = node::db::update_pending_failure_reason;
}
