use alloc::vec;
use alloc::vec::Vec;

use plonky2::field::extension::Extendable;
use plonky2::gates::gate::Gate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::u32_lib::gadgets::arithmetic_u32::U32Target;
use crate::u32_lib::gates::range_check_u32::U32RangeCheckGate;

pub fn range_check_u32_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    vals: Vec<U32Target>,
) {
    let num_input_limbs = vals.len();
    let wires_per_limb = U32RangeCheckGate::<F, D>::new(1).num_wires();
    let max_limbs_per_gate = (builder.config.num_wires / wires_per_limb).max(1);

    if num_input_limbs <= max_limbs_per_gate {
        let gate = U32RangeCheckGate::<F, D>::new(num_input_limbs);
        let row = builder.add_gate(gate, vec![]);

        for i in 0..num_input_limbs {
            builder.connect(Target::wire(row, gate.wire_ith_input_limb(i)), vals[i].0);
        }
        return;
    }

    for chunk in vals.chunks(max_limbs_per_gate) {
        let gate = U32RangeCheckGate::<F, D>::new(chunk.len());
        let row = builder.add_gate(gate, vec![]);

        for (i, val) in chunk.iter().enumerate() {
            builder.connect(Target::wire(row, gate.wire_ith_input_limb(i)), val.0);
        }
    }
}
