//! Plonky2 circuit gadgets for the zkCoins state-transition predicate.
//!
//! Each gadget in [`mmr`] / [`smt`] mirrors a piece of off-circuit logic
//! in this crate (see `hash`, `merkle`, `types`) and adds the
//! constraints required to prove the same invariant in-circuit. The
//! [`main`] module composes those gadgets into the monolithic
//! state-transition circuit per the protocol specification §8
//! (<https://docs.zkcoins.com/specification>).

pub mod balance;
pub mod compliance;
pub mod gadgets;
pub mod main;
pub mod mmr;
#[cfg(test)]
mod recursion_shape_probe;
pub mod smt;
pub mod source_aggregator;
mod util;
