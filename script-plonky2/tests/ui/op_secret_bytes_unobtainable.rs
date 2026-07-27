// Compile-fail: OpSecret raw bytes are unreachable outside the defining module.
// No public field, no as_bytes, no Serialize — including through containing
// types' general-purpose serialisation.
//
// Driven by trybuild (`tests/proved_envelope_compile_fail.rs`).

fn main() {
    use zkcoins_prover_plonky2::state_engine::{
        FinalisationCapability, MintRequest, OpSecret, PendingTransition,
    };

    let secret = OpSecret::new([0xAB; 32]);

    // 1. Public tuple field is private — cannot project or Debug-print it.
    let _ = secret.0;
    let _ = format!("{:?}", secret.0);

    // 2. Former public accessor is gone.
    let _ = secret.as_bytes();

    // 3. OpSecret itself is not Serializable.
    fn needs_serialize<T: serde::Serialize>(_: &T) {}
    needs_serialize(&secret);

    // 4. Containing request type has no Serialize (secret not reachable that way).
    let mint = MintRequest {
        owner: shared::spec_v1::Address([0u8; 32]),
        nk: [0u8; 32],
        op_secret: secret,
        current_pubkey: [0u8; 32],
        next_pubkey: [0u8; 32],
        name: Vec::new(),
        decimals: 0,
        amount: 0,
        issuance_version: 1,
        cap_total: 0,
        terms_salt: [0u8; 32],
        npk_rand: [0u8; 32],
    };
    needs_serialize(&mint);

    // 5. PendingTransition / FinalisationCapability: no general-purpose Serialize.
    //    Durable path is FinalisationCapability::{to,from}_durable_bytes only.
    //    These lines force a trait-bound check that must fail to compile.
    let _pending: Option<&PendingTransition> = None;
    let _cap: Option<&FinalisationCapability> = None;
    if let Some(p) = _pending {
        needs_serialize(p);
    }
    if let Some(c) = _cap {
        needs_serialize(c);
    }
}
