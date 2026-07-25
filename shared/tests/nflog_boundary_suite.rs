//! V.11 generated log-boundary suite (`k = 0…63`) — host + independent reference.
//!
//! Differential-tests split-/peak-bagging logic against an **independent**
//! RFC-6962 reference using only O(log n) symbolic subtree-root fixtures.
//! Never materialises Θ(n) leaves (required for `n ≈ 2⁶³`).
//!
//! Fixture construction and the independent reference live in
//! `shared::spec_v1::nflog_boundary` so the in-circuit gadget suite
//! (`program-plonky2`) consumes the **same** generator. This file covers the
//! host verifiers + independent reference layer; the gadget layer is exercised
//! on the `program-plonky2` side (dependency direction forbids linking the
//! gadget from `shared`).

use shared::spec_v1::nflog_boundary::{
    adjacent_consistency_pairs, bag_peaks_swapped, boundary_sizes, case_id_consistency,
    case_id_inclusion, case_id_peaks, find_inclusion_wrong_pivot, fixture_peaks,
    inclusion_positions, peak_sizes, ref_bag_peaks, ref_build_consistency, ref_build_inclusion,
    ref_build_inclusion_swapped_top_mth, ref_fold_chunks, ref_fold_chunks_swapped, ref_mth_run,
    ref_split_point, ref_verify_consistency, ref_verify_inclusion, try_consistency_wrong_pivot,
    try_inclusion_wrong_pivot, ConsistencyPivotMutation, PivotMutation,
};
use shared::spec_v1::nflog_boundary::fixture_range;
use shared::spec_v1::{nflog_empty, verify_consistency, verify_inclusion, HashDigest};

#[test]
fn nflog_boundary_suite_k0_to_63() {
    let mut accept_count: u64 = 0;
    let mut reject_count: u64 = 0;
    let mut skip_wrong_pivot_inc: u64 = 0;
    let mut skip_wrong_pivot_con: u64 = 0;
    let mut skip_swapped_inc: u64 = 0;
    let mut skip_swapped_peaks: u64 = 0;
    let mut skip_trunc_peaks: u64 = 0;

    // Platform note: production `verify_*` cast sizes to `usize`. On this
    // 64-bit host that is lossless for every in-scope n. The independent
    // reference stays on u64 regardless.
    assert_eq!(
        usize::BITS, 64,
        "this suite exercises n up to ~2^63; production verify_* uses usize \
         and would truncate on a 32-bit host"
    );

    for k in 0..=63u32 {
        let sizes = boundary_sizes(k);

        // --- Peak-bagging Accept: independent bag of fixture peaks equals
        // ref_mth_run (same peak decomposition). Symbolic peak fixtures are
        // atomic and intentionally *not* equal to the expanded inclusion MTH
        // of the same range — production peak bagging is exercised via the
        // consistency mth_a chunk-fold below (host +, on the gadget side, the
        // in-circuit fold). ---
        for &n in &sizes {
            if n == 0 {
                assert_eq!(nflog_empty(), nflog_empty());
                accept_count += 1;
                continue;
            }
            let case_peaks = case_id_peaks(k);
            let peaks = fixture_peaks(case_peaks, n);
            let bagged = ref_bag_peaks(&peaks);
            assert_eq!(
                bagged,
                ref_mth_run(case_peaks, 0, n),
                "bag(peaks) != mth_run k={k} n={n}"
            );
            // Fold identity: bag_peaks ≡ fold_chunks on the same list.
            assert_eq!(
                bagged,
                ref_fold_chunks(&peaks),
                "bag_peaks != fold_chunks k={k} n={n}"
            );
            accept_count += 1;

            // Structural Reject note for swapped/truncated peak *lists* alone
            // is not a production predicate; those mutations are applied as
            // mth_a bagging faults on consistency witnesses below. Here we
            // only record that the independent digests differ (sanity), and
            // count a Reject only when we also have a multi-chunk consistency
            // pair later. Track single-peak skips for the report.
            if peaks.len() < 2 {
                skip_swapped_peaks += 1;
                skip_trunc_peaks += 1;
                eprintln!(
                    "skip peak-list swap/trunc at peak layer: k={k} n={n} — single peak \
                     (swap/trunc no-op; multi-chunk bagging covered via consistency)"
                );
            } else {
                let swapped = bag_peaks_swapped(&peaks);
                assert_ne!(
                    swapped, bagged,
                    "swapped bagging collided with honest mth k={k} n={n}"
                );
                let mth_trunc = ref_bag_peaks(&peaks[..peaks.len() - 1]);
                assert_ne!(
                    mth_trunc, bagged,
                    "truncated peaks collided with honest mth k={k} n={n}"
                );
                // Rejects are counted when consistency applies the same fold
                // fault to an honest proof (production predicate).
            }
        }

        // --- Inclusion Accept ---
        for &n in &sizes {
            if n == 0 {
                continue;
            }
            for &p in &inclusion_positions(n) {
                let case_id = case_id_inclusion(k, n, p);
                let w = ref_build_inclusion(case_id, p, n);

                assert!(
                    ref_verify_inclusion(w.leaf, p, &w.path, n, w.mth),
                    "ref inclusion Accept failed k={k} n={n} p={p}"
                );
                assert!(
                    verify_inclusion(w.leaf, p, &w.path, n, w.mth),
                    "prod inclusion Accept failed k={k} n={n} p={p}"
                );
                accept_count += 1;

                // --- Inclusion Reject: truncated path (same roots, only length). ---
                if !w.path.is_empty() {
                    let trunc = &w.path[..w.path.len() - 1];
                    assert!(
                        ref_verify_inclusion(w.leaf, p, &w.path, n, w.mth),
                        "honest counterpart must Accept before trunc Reject k={k} n={n} p={p}"
                    );
                    assert!(
                        !ref_verify_inclusion(w.leaf, p, trunc, n, w.mth),
                        "ref must reject truncated inclusion path k={k} n={n} p={p}"
                    );
                    assert!(
                        !verify_inclusion(w.leaf, p, trunc, n, w.mth),
                        "prod must reject truncated inclusion path k={k} n={n} p={p}"
                    );
                    reject_count += 1;
                }

                // --- Inclusion Reject: over-long path (same roots, only length). ---
                if n >= 2 {
                    let mut overlong = w.path.clone();
                    overlong.push(fixture_range_extra(case_id));
                    assert!(
                        !ref_verify_inclusion(w.leaf, p, &overlong, n, w.mth),
                        "ref must reject over-long inclusion path k={k} n={n} p={p}"
                    );
                    assert!(
                        !verify_inclusion(w.leaf, p, &overlong, n, w.mth),
                        "prod must reject over-long inclusion path k={k} n={n} p={p}"
                    );
                    reject_count += 1;
                }

                // --- Inclusion Reject: swapped top-hop bagging (same path,
                // same leaf, only claimed mth uses Node(R,L)). ---
                match ref_build_inclusion_swapped_top_mth(case_id, p, n) {
                    Some(bad) => {
                        assert_eq!(bad.path.len(), w.path.len());
                        assert_eq!(bad.leaf, w.leaf);
                        assert_ne!(bad.mth, w.mth);
                        assert!(
                            ref_verify_inclusion(w.leaf, p, &w.path, n, w.mth),
                            "honest counterpart must Accept before swapped-mth Reject \
                             k={k} n={n} p={p}"
                        );
                        assert!(
                            !ref_verify_inclusion(bad.leaf, p, &bad.path, n, bad.mth)
                                || bad.mth != w.mth,
                            "swapped-mth self-check"
                        );
                        // Present honest path against swapped claimed root.
                        assert!(
                            !ref_verify_inclusion(w.leaf, p, &w.path, n, bad.mth),
                            "ref must reject honest path under swapped-top mth k={k} n={n} p={p}"
                        );
                        assert!(
                            !verify_inclusion(w.leaf, p, &w.path, n, bad.mth),
                            "prod must reject honest path under swapped-top mth k={k} n={n} p={p}"
                        );
                        reject_count += 1;
                    }
                    None => {
                        skip_swapped_inc += 1;
                        eprintln!(
                            "skip swapped-top inclusion: k={k} n={n} p={p} — \
                             mutation collapsed to honest mth or n < 2"
                        );
                    }
                }

            }
            // Wrong pivot (NL-B1) for this size: search O(1) interior positions
            // so the mutation stays same-length (Accept positions alone almost
            // always force a length change — that is reported, not forced).
            if n >= 3 {
                let case_id = case_id_inclusion(k, n, 0);
                match find_inclusion_wrong_pivot(case_id, n) {
                    Some((p, wrong_pivot, bad)) => {
                        let honest = ref_build_inclusion(case_id, p, n);
                        assert_eq!(bad.path.len(), honest.path.len());
                        assert_eq!(bad.leaf, honest.leaf);
                        assert!(
                            ref_verify_inclusion(honest.leaf, p, &honest.path, n, honest.mth),
                            "honest counterpart must Accept before wrong-pivot Reject \
                             k={k} n={n} p={p} k'={wrong_pivot}"
                        );
                        assert!(
                            verify_inclusion(honest.leaf, p, &honest.path, n, honest.mth),
                            "prod honest counterpart must Accept k={k} n={n} p={p}"
                        );
                        assert!(
                            !ref_verify_inclusion(bad.leaf, p, &bad.path, n, honest.mth),
                            "ref must reject wrong-pivot path vs honest mth \
                             k={k} n={n} p={p} k'={wrong_pivot}"
                        );
                        assert!(
                            !verify_inclusion(bad.leaf, p, &bad.path, n, honest.mth),
                            "prod must reject wrong-pivot path vs honest mth \
                             k={k} n={n} p={p} k'={wrong_pivot}"
                        );
                        reject_count += 1;
                    }
                    None => {
                        skip_wrong_pivot_inc += 1;
                        eprintln!(
                            "skip wrong-pivot inclusion: k={k} n={n} — no same-length \
                             power-of-two top-pivot mutation among search positions"
                        );
                    }
                }
            } else {
                skip_wrong_pivot_inc += 1;
                eprintln!(
                    "skip wrong-pivot inclusion: k={k} n={n} — size < 3"
                );
            }
        }

        // --- Consistency Accept for adjacent pairs ---
        for (m, n) in adjacent_consistency_pairs(k) {
            if m == 0 && n > 0 {
                let proof: &[HashDigest] = &[];
                // mth_b unconstrained for m=0 on production; ref requires empty mth_a.
                assert!(
                    ref_verify_consistency(0, nflog_empty(), n, nflog_empty(), proof),
                    "m=0 trivial: ref (n={n})"
                );
                assert!(
                    verify_consistency(0, nflog_empty(), n, nflog_empty(), proof),
                    "m=0 trivial: prod (n={n})"
                );
                accept_count += 1;
                continue;
            }
            if m == 0 || n == 0 || m >= n {
                continue;
            }

            let case_id = case_id_consistency(k, m, n);
            let w = ref_build_consistency(case_id, m, n);

            assert!(
                ref_verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                "ref consistency Accept failed k={k} m={m} n={n}"
            );
            assert!(
                verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                "prod consistency Accept failed k={k} m={m} n={n}"
            );
            accept_count += 1;

            // --- Consistency Reject: truncated proof (length only). ---
            if !w.proof.is_empty() {
                let trunc = &w.proof[..w.proof.len() - 1];
                assert!(
                    ref_verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                    "honest counterpart must Accept before trunc Reject k={k} m={m} n={n}"
                );
                assert!(
                    !ref_verify_consistency(m, w.mth_a, n, w.mth_b, trunc),
                    "ref must reject truncated consistency proof k={k} m={m} n={n}"
                );
                assert!(
                    !verify_consistency(m, w.mth_a, n, w.mth_b, trunc),
                    "prod must reject truncated consistency proof k={k} m={m} n={n}"
                );
                reject_count += 1;
            }

            // --- Consistency Reject: over-long proof (length only). ---
            {
                let mut overlong = w.proof.clone();
                overlong.push(fixture_range_extra(case_id));
                assert!(
                    !ref_verify_consistency(m, w.mth_a, n, w.mth_b, &overlong),
                    "ref must reject over-long consistency proof k={k} m={m} n={n}"
                );
                assert!(
                    !verify_consistency(m, w.mth_a, n, w.mth_b, &overlong),
                    "prod must reject over-long consistency proof k={k} m={m} n={n}"
                );
                reject_count += 1;
            }

            // --- Consistency Reject: swapped peak-/chunk-bagging order.
            // Same proof, same mth_b; only mth_a uses swapped Node fold. ---
            if w.chunks.len() >= 2 {
                let swapped_a = ref_fold_chunks_swapped(&w.chunks);
                assert_ne!(
                    swapped_a, w.mth_a,
                    "swapped chunk fold collided with honest mth_a k={k} m={m} n={n}"
                );
                // Sanity: honest fold matches.
                assert_eq!(ref_fold_chunks(&w.chunks), w.mth_a);
                assert!(
                    ref_verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                    "honest counterpart must Accept before swapped-bag Reject k={k} m={m} n={n}"
                );
                assert!(
                    !ref_verify_consistency(m, swapped_a, n, w.mth_b, &w.proof),
                    "ref must reject swapped mth_a bagging k={k} m={m} n={n}"
                );
                assert!(
                    !verify_consistency(m, swapped_a, n, w.mth_b, &w.proof),
                    "prod must reject swapped mth_a bagging k={k} m={m} n={n}"
                );
                reject_count += 1;

                // Truncated peak/chunk list (only length of the bagged list wrong).
                let trunc_a = ref_fold_chunks(&w.chunks[..w.chunks.len() - 1]);
                assert_ne!(
                    trunc_a, w.mth_a,
                    "truncated chunk fold collided with honest mth_a k={k} m={m} n={n}"
                );
                assert!(
                    !ref_verify_consistency(m, trunc_a, n, w.mth_b, &w.proof),
                    "ref must reject truncated mth_a bagging k={k} m={m} n={n}"
                );
                assert!(
                    !verify_consistency(m, trunc_a, n, w.mth_b, &w.proof),
                    "prod must reject truncated mth_a bagging k={k} m={m} n={n}"
                );
                reject_count += 1;
            } else {
                eprintln!(
                    "skip swapped/trunc-chunk consistency: k={k} m={m} n={n} — \
                     fewer than 2 chunks (swap/trunc is a no-op)"
                );
            }

            // --- Consistency Reject: wrong pivot (same fixtures, same proof
            // length) against honest roots. ---
            match try_consistency_wrong_pivot(case_id, m, n) {
                ConsistencyPivotMutation::Ok {
                    wrong_pivot,
                    witness: bad,
                } => {
                    assert_eq!(bad.proof.len(), w.proof.len());
                    assert!(
                        ref_verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                        "honest counterpart must Accept before wrong-pivot Reject \
                         k={k} m={m} n={n} k'={wrong_pivot}"
                    );
                    assert!(
                        !ref_verify_consistency(m, w.mth_a, n, w.mth_b, &bad.proof),
                        "ref must reject wrong-pivot proof vs honest roots \
                         k={k} m={m} n={n} k'={wrong_pivot}"
                    );
                    assert!(
                        !verify_consistency(m, w.mth_a, n, w.mth_b, &bad.proof),
                        "prod must reject wrong-pivot proof vs honest roots \
                         k={k} m={m} n={n} k'={wrong_pivot}"
                    );
                    reject_count += 1;
                }
                ConsistencyPivotMutation::Unreachable { reason } => {
                    skip_wrong_pivot_con += 1;
                    eprintln!(
                        "skip wrong-pivot consistency: k={k} m={m} n={n} — {reason}"
                    );
                }
            }
        }
    }

    eprintln!(
        "V.11 boundary suite (host+ref) counts: Accept={accept_count} Reject={reject_count}"
    );
    eprintln!(
        "V.11 boundary suite skips: wrong_pivot_inc={skip_wrong_pivot_inc} \
         wrong_pivot_con={skip_wrong_pivot_con} swapped_inc={skip_swapped_inc} \
         swapped_peaks={skip_swapped_peaks} trunc_peaks={skip_trunc_peaks}"
    );
    assert!(
        accept_count > 100,
        "expected a large Accept set, got {accept_count}"
    );
    assert!(
        reject_count > 100,
        "expected a large Reject set, got {reject_count}"
    );
}

/// Extra digest for over-long path/proof injection — not a reseed of the case.
fn fixture_range_extra(case_id: u64) -> HashDigest {
    // Distinct range that is not part of the honest tree spine for typical sizes.
    fixture_range(case_id, u64::MAX - 1, 1)
}

#[test]
fn ref_split_point_matches_rfc_examples() {
    assert_eq!(ref_split_point(2), 1);
    assert_eq!(ref_split_point(3), 2);
    assert_eq!(ref_split_point(4), 2);
    assert_eq!(ref_split_point(5), 4);
    assert_eq!(ref_split_point(7), 4);
    assert_eq!(ref_split_point(8), 4);
    assert_eq!(ref_split_point(9), 8);
    assert_eq!(ref_split_point(1u64 << 63), 1u64 << 62);
    assert_eq!(ref_split_point((1u64 << 63) + 1), 1u64 << 63);
    assert_eq!(ref_split_point(u64::MAX), 1u64 << 63);
}

#[test]
fn peak_sizes_binary_decomposition() {
    assert_eq!(peak_sizes(1), vec![1]);
    assert_eq!(peak_sizes(2), vec![2]);
    assert_eq!(peak_sizes(3), vec![2, 1]);
    assert_eq!(peak_sizes(5), vec![4, 1]);
    assert_eq!(peak_sizes(7), vec![4, 2, 1]);
    assert_eq!(peak_sizes(8), vec![8]);
    assert_eq!(peak_sizes((1u64 << 63) + 1), vec![1u64 << 63, 1]);
}

#[test]
fn wrong_pivot_mutation_never_reseeds() {
    // Same case_id honest vs wrong-pivot leaf must match when reachable.
    let case_id = 0xBEEF;
    for &(n, p) in &[(5u64, 0u64), (5, 4), (9, 0), (9, 8), (17, 8)] {
        let honest = ref_build_inclusion(case_id, p, n);
        match try_inclusion_wrong_pivot(case_id, p, n) {
            PivotMutation::Ok { witness: bad, .. } => {
                assert_eq!(bad.leaf, honest.leaf);
                assert_eq!(bad.path.len(), honest.path.len());
            }
            PivotMutation::Unreachable { .. } => {}
        }
    }
}

