use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::Secp256K1;
use crate::circuit::gadgets::nflog_consistency::H_MAX;
use crate::circuit::gadgets::u128_arith::U128Target;
use crate::{D, F};

/// Maximum number of distinct non-zero balances in a spec-v1.1 account.
pub const MAX_ACCOUNT_ASSETS: usize = 32;

/// Coin-history updates in this increment: eight spends plus eight self admissions.
///
/// P1-D.5 extends this fixed array to the normative 20 slots when the four
/// clause-10 received-coin admissions are introduced.
pub const MAX_HISTORY_UPDATES_D3: usize = 16;

/// One witnessed 256-level CoinHist sibling path.
#[derive(Clone, Copy, Debug)]
pub struct HistoryUpdatePathTarget {
    pub siblings: [HashOutTarget; crate::circuit::gadgets::coinhist::COINHIST_DEPTH],
}

impl HistoryUpdatePathTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            siblings: std::array::from_fn(|_| builder.add_virtual_hash()),
        }
    }
}

/// Optional v1/v2 issuance witness.
#[derive(Clone, Copy, Debug)]
pub struct AssetIssuanceTarget {
    pub present: BoolTarget,
    pub asset_id: HashOutTarget,
    pub creator_pubkey: [Target; 32],
    pub issuance_version: Target,
    pub name_hash: [Target; 32],
    pub decimals: Target,
    pub amount: U128Target,
    pub terms_hash: HashOutTarget,
    pub cap_total: U128Target,
    pub terms_salt: [Target; 32],
}

impl AssetIssuanceTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        let issuance_version = builder.add_virtual_target();
        builder.range_check(issuance_version, 8);
        let decimals = builder.add_virtual_target();
        builder.range_check(decimals, 8);
        Self {
            present: builder.add_virtual_bool_target_safe(),
            asset_id: builder.add_virtual_hash(),
            creator_pubkey: virtual_bytes(builder),
            issuance_version,
            name_hash: virtual_bytes(builder),
            decimals,
            amount: U128Target::new_virtual(builder),
            terms_hash: builder.add_virtual_hash(),
            cap_total: U128Target::new_virtual(builder),
            terms_salt: virtual_bytes(builder),
        }
    }
}

/// One fixed-array balance slot.
#[derive(Clone, Copy, Debug)]
pub struct BalanceSlotTarget {
    pub active: BoolTarget,
    pub asset_id: HashOutTarget,
    pub amount: U128Target,
}

impl BalanceSlotTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            active: builder.add_virtual_bool_target_safe(),
            asset_id: builder.add_virtual_hash(),
            amount: U128Target::new_virtual(builder),
        }
    }
}

/// In-circuit form of spec-v1.1 `AccountState`.
#[derive(Clone, Copy, Debug)]
pub struct AccountStateTarget {
    pub owner: [Target; 32],
    pub nk_commit: HashOutTarget,
    pub balances: [BalanceSlotTarget; MAX_ACCOUNT_ASSETS],
    pub current_pubkey: [Target; 32],
    pub send_counter: Target,
    pub coin_history_root: HashOutTarget,
}

impl AccountStateTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        let owner = virtual_bytes(builder);
        let nk_commit = builder.add_virtual_hash();
        let balances = std::array::from_fn(|_| BalanceSlotTarget::new_virtual(builder));
        let current_pubkey = virtual_bytes(builder);
        let send_counter = builder.add_virtual_target();
        builder.split_le(send_counter, 64);
        let coin_history_root = builder.add_virtual_hash();
        Self {
            owner,
            nk_commit,
            balances,
            current_pubkey,
            send_counter,
            coin_history_root,
        }
    }
}

/// Private output-template slot used by the skeleton.
#[derive(Clone, Copy, Debug)]
pub struct OutputTemplateTarget {
    pub active: BoolTarget,
    pub recipient: [Target; 32],
    pub amount: U128Target,
    pub asset_id: HashOutTarget,
}

impl OutputTemplateTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            active: builder.add_virtual_bool_target_safe(),
            recipient: virtual_bytes(builder),
            amount: U128Target::new_virtual(builder),
            asset_id: builder.add_virtual_hash(),
        }
    }
}

/// One fixed-array input-coin slot.
#[derive(Clone, Copy, Debug)]
pub struct InputCoinTarget {
    pub active: BoolTarget,
    pub identifier: HashOutTarget,
    pub recipient: [Target; 32],
    pub amount: U128Target,
    pub asset_id: HashOutTarget,
}

impl InputCoinTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            active: builder.add_virtual_bool_target_safe(),
            identifier: builder.add_virtual_hash(),
            recipient: virtual_bytes(builder),
            amount: U128Target::new_virtual(builder),
            asset_id: builder.add_virtual_hash(),
        }
    }
}

/// Clause-2 authorization data needed to recompute an input coin identifier.
#[derive(Clone, Copy, Debug)]
pub struct InputAuthTarget {
    pub creating_prev_ash: HashOutTarget,
    pub coin_index: Target,
}

impl InputAuthTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        let coin_index = builder.add_virtual_target();
        builder.range_check(coin_index, 32);
        Self {
            creating_prev_ash: builder.add_virtual_hash(),
            coin_index,
        }
    }
}

/// In-circuit form of spec-v1.1 `Coin`.
#[derive(Clone, Copy, Debug)]
pub struct CoinTarget {
    pub identifier: HashOutTarget,
    pub recipient: [Target; 32],
    pub amount: U128Target,
    pub asset_id: HashOutTarget,
}

/// The six public `ProofData` fields.
#[derive(Clone, Copy, Debug)]
pub struct ProofDataTarget {
    pub new_account_state_hash: HashOutTarget,
    pub output_coins_root: HashOutTarget,
    pub input_nullifiers_root: HashOutTarget,
    pub coin_history_root: HashOutTarget,
    pub nav_commitment: HashOutTarget,
    pub npk_commit: [Target; 32],
}

/// A witnessed conditional NfLog accumulator value.
#[derive(Clone, Copy, Debug)]
pub struct NavTarget {
    pub size: Target,
    pub mth: HashOutTarget,
}

impl NavTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        let size = builder.add_virtual_target();
        builder.split_le(size, 64);
        Self {
            size,
            mth: builder.add_virtual_hash(),
        }
    }
}

/// Opening of a predecessor proof's hidden conditional NAV.
#[derive(Clone, Copy, Debug)]
pub struct NavOpeningTarget {
    pub nav: NavTarget,
    pub nav_rand: [Target; 32],
}

impl NavOpeningTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            nav: NavTarget::new_virtual(builder),
            nav_rand: virtual_bytes(builder),
        }
    }
}

/// Clause-1 predecessor-nullifier anchoring witness.
#[derive(Clone, Debug)]
pub struct PrevStateNullifierTarget {
    pub pk_prev: [Target; 32],
    pub r_prev: [Target; 32],
    pub r_prime_prev: AffinePointTarget<Secp256K1>,
    pub nav_inclusion: [HashOutTarget; H_MAX],
    pub pos_prev: Target,
}

impl PrevStateNullifierTarget {
    pub(crate) fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        let pos_prev = builder.add_virtual_target();
        builder.split_le(pos_prev, 64);
        Self {
            pk_prev: virtual_bytes(builder),
            r_prev: virtual_bytes(builder),
            r_prime_prev: builder.add_virtual_affine_point_target(),
            nav_inclusion: std::array::from_fn(|_| builder.add_virtual_hash()),
            pos_prev,
        }
    }
}

/// Handles needed to assign cyclic and explicit zk-safe base proofs.
#[derive(Clone, Debug)]
pub struct PrevProofTargets {
    pub is_account_update: BoolTarget,
    pub prev_proof: ProofWithPublicInputsTarget<D>,
    pub base_proof: ProofWithPublicInputsTarget<D>,
    pub base_verifier_data: VerifierCircuitTarget,
    pub own_verifier_data: VerifierCircuitTarget,
}

pub(crate) fn virtual_bytes(builder: &mut CircuitBuilder<F, D>) -> [Target; 32] {
    let bytes = builder.add_virtual_target_arr();
    for byte in bytes {
        builder.range_check(byte, 8);
    }
    bytes
}
