// Compile-fail: `nav_rand` is not a field of `ReceiveRequest`.
// Callers cannot supply commitment randomness; the engine derives it from
// `op_secret ‖ u64-be(send_counter)` (§1.4).

fn main() {
    use shared::spec_v1::Address;
    use zkcoins_prover_plonky2::state_engine::{OpSecret, ReceiveRequest};

    let _ = ReceiveRequest {
        owner: Address([0u8; 32]),
        nk: [0u8; 32],
        op_secret: OpSecret([0u8; 32]),
        current_pubkey: [0u8; 32],
        received_coins: Vec::new(),
        received_auth: Vec::new(),
        next_pubkey: [0u8; 32],
        // Intentional: field removed — must not compile.
        nav_rand: [0u8; 32],
        npk_rand: [0u8; 32],
    };
}
