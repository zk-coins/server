use bitcoin::{
    bip32::{ChildNumber, Xpriv, Xpub},
    key::{
        rand::{rngs::OsRng, RngCore},
        Secp256k1,
    },
    secp256k1::{All, PublicKey, SecretKey},
    Network,
};
use commitment::Commitment;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use zkcoins_program::hash::{digest_to_bytes, hash_concat, HashDigest, ZERO_HASH};
use zkcoins_program::types::{AccountState, Amount};

pub mod commitment;
pub mod spec_v1;
pub use zkcoins_program::types::ProofData;

lazy_static! {
    pub static ref SECP256K1: Secp256k1<All> = Secp256k1::new();
}

pub type Address = HashDigest;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Invoice {
    pub amount: Amount,
    pub recipient: Address,
    /// The asset this invoice requests. There is no native/default
    /// asset any more — callers must always specify which asset they
    /// want to be paid in.
    pub asset_id: zkcoins_program::hash::HashDigest,
}

impl Invoice {
    pub fn new(
        amount: Amount,
        recipient: HashDigest,
        asset_id: zkcoins_program::hash::HashDigest,
    ) -> Self {
        Invoice {
            amount,
            recipient,
            asset_id,
        }
    }
}

// Design note: this account representation may eventually live in the client.
pub struct ClientAccount {
    pub address: Address,
    pub num_pubkeys: u32,
    pub private_key: Xpriv,
}

pub fn new_master_private_key() -> Xpriv {
    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create private key.")
}

impl ClientAccount {
    fn current_private_key(&self) -> SecretKey {
        self.private_key
            .derive_priv(
                &SECP256K1,
                &[ChildNumber::Normal {
                    index: self
                        .num_pubkeys
                        .checked_sub(1)
                        .expect("This account was never commited to."),
                }],
            )
            .expect("Unable to derive private key for account")
            .private_key
    }

    /// Compute the BIP-340 Schnorr commitment over the canonical
    /// `(account_state_hash || output_coins_root)` digest. The digest
    /// is Poseidon, serialised to 32 bytes via `digest_to_bytes` for
    /// signing; Schnorr signing itself remains SHA256-based per BIP-340.
    pub fn create_commitment(
        &self,
        account_state_hash: &HashDigest,
        output_coins_root: &HashDigest,
    ) -> Commitment {
        let combined = hash_concat(account_state_hash, output_coins_root);
        Commitment::new(
            &self.current_private_key(),
            digest_to_bytes(&combined).to_vec(),
        )
        .expect("Should be able to create commitment")
    }

    pub fn generate_public_key(&self, index: u32) -> PublicKey {
        // WARNING: LEAKING THE MASTER PUBLIC KEY IS EQUIVALENT TO LEAKING THE PRIVATE KEY!
        Xpub::from_priv(&SECP256K1, &self.private_key)
            .derive_pub(&SECP256K1, &[ChildNumber::Normal { index }])
            .expect("Failed to derive first pubkey")
            .public_key
    }

    pub fn new(private_key: Xpriv) -> Self {
        let mut client_account = ClientAccount {
            address: ZERO_HASH,
            num_pubkeys: 0,
            private_key,
        };
        // The address is `H(initial_public_key)` and does not depend on
        // the asset; a placeholder asset_id is fine here because only
        // `account.owner` is read out.
        let account =
            AccountState::new(client_account.generate_public_key(0).serialize(), ZERO_HASH);
        client_account.address = account.owner;
        client_account
    }
}
