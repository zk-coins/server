//! Spec-v1.1 history-private balance-attestation circuit `C_balance`.
//!
//! This circuit is deliberately non-cyclic. It verifies exactly one proof
//! from the compliance circuit `C` using `C`'s constant verifier data and has
//! no self-recursion targets, cyclic CommonCircuitData fixed point, or dummy
//! proof machinery.

mod targets;

use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData,
};

use crate::circuit::compliance::{Network, SkeletonCircuit};
use crate::{C, D, F};

pub use targets::{
    BalancePublicInputsTarget, BalanceTargets, BalanceWitnessTargets, SpendRecordTarget,
};

/// A built `C_balance` circuit and all targets needed by its prover.
pub struct BalanceCircuit {
    pub data: CircuitData<F, C, D>,
    pub targets: BalanceTargets,
    /// Gate count immediately before Plonky2 finalizes/pads the circuit.
    pub gate_count: usize,
}

fn build_c_balance_circuit_inner(
    compliance_common: CommonCircuitData<F, D>,
    compliance_verifier: VerifierOnlyCircuitData<C, D>,
    network: Network,
) -> BalanceCircuit {
    let config = CircuitConfig::standard_recursion_zk_config();
    assert!(
        config.zero_knowledge,
        "C_balance requires standard_recursion_zk_config"
    );
    assert!(
        compliance_common.config.zero_knowledge,
        "C_balance may only pin the production ZK compliance circuit"
    );

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let targets = targets::add_balance_statement(
        &mut builder,
        &compliance_common,
        &compliance_verifier,
        network,
    );
    let gate_count = builder.num_gates();
    let data = builder.build::<C>();
    BalanceCircuit {
        data,
        targets,
        gate_count,
    }
}

/// Builds the non-cyclic balance-attestation circuit against one canonical
/// compliance-circuit build.
///
/// The explicitly sized worker stack matches the production compliance build
/// discipline and avoids depending on a caller/test-runner's stack size.
pub fn build_c_balance_circuit(compliance: &SkeletonCircuit, network: Network) -> BalanceCircuit {
    assert_eq!(
        compliance.network, network,
        "C_balance network must match the pinned compliance verifier data"
    );
    let compliance_common = compliance.data.common.clone();
    let compliance_verifier = compliance.data.verifier_only.clone();
    std::thread::Builder::new()
        .name("zkcoins-balance-build".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            build_c_balance_circuit_inner(compliance_common, compliance_verifier, network)
        })
        .expect("C_balance build worker must spawn")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

#[cfg(test)]
mod tests;
