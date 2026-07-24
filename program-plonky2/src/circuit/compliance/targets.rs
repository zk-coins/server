use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

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

pub(crate) fn virtual_bytes(builder: &mut CircuitBuilder<F, D>) -> [Target; 32] {
    let bytes = builder.add_virtual_target_arr();
    for byte in bytes {
        builder.range_check(byte, 8);
    }
    bytes
}
