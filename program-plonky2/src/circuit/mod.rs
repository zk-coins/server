//! Plonky2 circuit gadgets for the zkCoins state-transition predicate.
//!
//! Circuit **C** lives under [`compliance`]; **C_balance** under [`balance`].
//! The legacy Poseidon monolithic circuit body that used to live in
//! [`main`] has been deleted (Stage 4); [`main`] retains residual host
//! constants and the `InCoinSourceWitness` type path only.

pub mod balance;
pub mod compliance;
pub mod gadgets;
pub mod main;
pub mod util;
