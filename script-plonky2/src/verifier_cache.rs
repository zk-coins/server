//! Trustless, digest- and full-blob-pinned on-disk verifier data for `C` and `C_balance`.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::lookup::LookupGate;
use plonky2::gates::lookup_table::LookupTableGate;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::Hasher;
use plonky2::util::serialization::GateSerializer;
use plonky2::{get_gate_tag_impl, impl_gate_serializer, read_gate_impl};
use sha2::{Digest, Sha256};
use shared::spec_v1::digest_to_bytes;
use zkcoins_program_plonky2::circuit::compliance::Network;
use zkcoins_program_plonky2::u32_lib::gates::add_many_u32::U32AddManyGate;
use zkcoins_program_plonky2::u32_lib::gates::arithmetic_u32::U32ArithmeticGate;
use zkcoins_program_plonky2::u32_lib::gates::comparison::ComparisonGate;
use zkcoins_program_plonky2::u32_lib::gates::range_check_u32::U32RangeCheckGate;
use zkcoins_program_plonky2::u32_lib::gates::subtraction_u32::U32SubtractionGate;
use zkcoins_program_plonky2::{C, D as PROGRAM_D, F as PROGRAM_F};

use crate::prover_bridge::{BalanceProof, BalancePublicStatement};

const MAGIC: &[u8; 4] = b"ZKVC";
const SCHEMA_VERSION: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 2;
const CACHE_FILE_NAME: &str = "c_balance_verifier.bin";
const CACHE_TMP_FILE_NAME: &str = ".c_balance_verifier.bin.tmp";
const COMPLIANCE_CACHE_FILE_NAME: &str = "c_verifier.bin";
const COMPLIANCE_CACHE_TMP_FILE_NAME: &str = ".c_verifier.bin.tmp";

/// Fixed-order gate serializer for the on-disk `C_balance` verifier cache: the 16 plonky2
/// `DefaultGateSerializer` gates (same order plonky2 itself uses) followed by the 5 zkCoins custom
/// u32 gates. Positional index = on-disk tag value — NEVER reorder existing entries; only ever
/// append. Plonky2 1.1.0 encodes that value with `write_u32`.
#[derive(Debug)]
pub struct ZkCoinsGateSerializer;

impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for ZkCoinsGateSerializer {
    impl_gate_serializer! {
        ZkCoinsGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        BaseSumGate<4>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        U32ArithmeticGate<F, D>,
        U32SubtractionGate<F, D>,
        U32RangeCheckGate<F, D>,
        ComparisonGate<F, D>,
        U32AddManyGate<F, D>
    }
}

/// A checked, verifier-only `C_balance` circuit loaded from disk.
pub struct CachedBalanceVerifier {
    network: Network,
    data: VerifierCircuitData<PROGRAM_F, C, PROGRAM_D>,
}

impl CachedBalanceVerifier {
    pub fn network(&self) -> Network {
        self.network
    }

    pub fn balance_circuit_digest_bytes(&self) -> [u8; 32] {
        digest_to_bytes(&self.data.verifier_only.circuit_digest)
    }

    pub fn load_balance_proof_bytes(&self, bytes: &[u8]) -> Result<BalanceProof> {
        BalanceProof::from_bytes(bytes.to_vec(), &self.data.common).context(
            "native Plonky2 proof bytes rejected by from_bytes (C_balance attestation proof)",
        )
    }

    pub fn verify_attestation(&self, proof: &BalanceProof) -> Result<BalancePublicStatement> {
        self.data
            .verify(proof.clone())
            .context("balance-attestation proof verification failed")?;
        crate::prover_bridge::extract_balance_public_inputs(proof)
    }
}

/// Writes `MAGIC || version || network-id || VerifierCircuitData`, where network ids are
/// `Mainnet=0`, `Testnet=1`, and `Regtest=2`.
pub fn write_balance_verifier_cache(network: Network, dir: &Path) -> Result<PathBuf> {
    let circuit = crate::prover_bridge::balance_circuit(network)?;
    let verifier_data = circuit.data.verifier_data();
    let serialized = verifier_data
        .to_bytes(&ZkCoinsGateSerializer)
        .map_err(|e| anyhow!("VerifierCircuitData::to_bytes failed: {e:?}"))?;

    let network_dir = dir.join(crate::circuit_identity::network_label(network));
    fs::create_dir_all(&network_dir).with_context(|| {
        format!(
            "create C_balance verifier-cache directory {}",
            network_dir.display()
        )
    })?;

    let final_path = network_dir.join(CACHE_FILE_NAME);
    let tmp_path = network_dir.join(CACHE_TMP_FILE_NAME);
    let mut blob = Vec::with_capacity(HEADER_LEN + serialized.len());
    blob.extend_from_slice(MAGIC);
    blob.push(SCHEMA_VERSION);
    blob.push(network_id(network));
    blob.extend_from_slice(&serialized);

    write_atomic(&tmp_path, &final_path, &blob)?;
    Ok(final_path)
}

/// Loads a verifier cache without constructing a circuit, authenticates the full serialized
/// `VerifierCircuitData` blob (SHA-256 over everything after the 6-byte header — this is what
/// actually covers `common: CommonCircuitData`), recomputes its circuit digest from the
/// independently serialized verifier inputs, and then checks that digest against `pinned_digest`.
/// The digest triple-check alone is **not** cryptographically equivalent to a local build: it only
/// covers `(constants_sigmas_cap, domain_separator, degree_bits)`. Only the full-blob-hash check
/// against `pinned_verifier_blob_hash` makes the local-build equivalence claim true.
pub fn load_balance_verifier_cache_checked(
    network: Network,
    dir: &Path,
    pinned_digest: &[u8; 32],
    pinned_verifier_blob_hash: &[u8; 32],
) -> Result<CachedBalanceVerifier> {
    let path = dir
        .join(crate::circuit_identity::network_label(network))
        .join(CACHE_FILE_NAME);
    let blob = fs::read(&path)
        .with_context(|| format!("read C_balance verifier cache {}", path.display()))?;

    ensure!(
        blob.len() >= HEADER_LEN,
        "C_balance verifier cache {} is truncated: expected at least {HEADER_LEN} header bytes, got {}",
        path.display(),
        blob.len()
    );
    ensure!(
        &blob[..MAGIC.len()] == MAGIC,
        "C_balance verifier cache {} has wrong magic",
        path.display()
    );
    ensure!(
        blob[MAGIC.len()] == SCHEMA_VERSION,
        "C_balance verifier cache {} has unsupported schema version {} (expected {})",
        path.display(),
        blob[MAGIC.len()],
        SCHEMA_VERSION
    );
    ensure!(
        blob[MAGIC.len() + 1] == network_id(network),
        "C_balance verifier cache {} has network id {} but {} requires {}",
        path.display(),
        blob[MAGIC.len() + 1],
        crate::circuit_identity::network_label(network),
        network_id(network)
    );

    let full_blob_hash = verifier_blob_hash(&blob[HEADER_LEN..]);
    ensure!(
        &full_blob_hash == pinned_verifier_blob_hash,
        "C_balance verifier cache full-blob hash does not match the pinned full-VerifierCircuitData \
         blob hash for this network (fail-closed) — the digest triple-check alone does not \
         authenticate CommonCircuitData (gate constraints/selectors/FRI params/LUTs); this \
         check does"
    );

    let vd = VerifierCircuitData::<PROGRAM_F, C, PROGRAM_D>::from_bytes(
        blob[HEADER_LEN..].to_vec(),
        &ZkCoinsGateSerializer,
    )
    .map_err(|e| {
        anyhow!(
            "VerifierCircuitData::from_bytes failed for {}: {e:?}",
            path.display()
        )
    })?;

    let recomputed = recompute_circuit_digest(&vd);
    ensure!(
        recomputed == vd.verifier_only.circuit_digest,
        "verifier cache self-inconsistent: recomputed circuit_digest != the digest stored in the cache file (constants_sigmas_cap/common do not match the file's own circuit_digest field — refusing a self-inconsistent cache, never trust the stored field alone)"
    );
    ensure!(
        &digest_to_bytes(&recomputed) == pinned_digest,
        "verifier cache digest does not match the §3.6 pinned C_balance digest for this network (fail-closed)"
    );

    Ok(CachedBalanceVerifier { network, data: vd })
}

/// A checked, verifier-only `C` circuit loaded from disk.
pub struct CachedComplianceVerifier {
    network: Network,
    data: VerifierCircuitData<PROGRAM_F, C, PROGRAM_D>,
}

impl CachedComplianceVerifier {
    pub fn network(&self) -> Network {
        self.network
    }

    pub fn compliance_circuit_digest_bytes(&self) -> [u8; 32] {
        digest_to_bytes(&self.data.verifier_only.circuit_digest)
    }

    /// Consumes the wrapper and hands back the raw verifier data so the caller can install it
    /// into `ProverBridge`'s process-global compliance-verifier slot via
    /// `ProverBridge::mark_compliance_verifier_from_cache`.
    pub fn into_verifier_data(self) -> VerifierCircuitData<PROGRAM_F, C, PROGRAM_D> {
        self.data
    }
}

/// Writes `MAGIC || version || network-id || VerifierCircuitData` for circuit `C`, mirroring
/// `write_balance_verifier_cache` for `C_balance`. Network ids are `Mainnet=0`, `Testnet=1`,
/// `Regtest=2`.
pub fn write_compliance_verifier_cache(network: Network, dir: &Path) -> Result<PathBuf> {
    let circuit = crate::prover_bridge::compliance_circuit(network)?;
    let verifier_data = circuit.data.verifier_data();
    let serialized = verifier_data
        .to_bytes(&ZkCoinsGateSerializer)
        .map_err(|e| anyhow!("VerifierCircuitData::to_bytes failed: {e:?}"))?;

    let network_dir = dir.join(crate::circuit_identity::network_label(network));
    fs::create_dir_all(&network_dir).with_context(|| {
        format!(
            "create C verifier-cache directory {}",
            network_dir.display()
        )
    })?;

    let final_path = network_dir.join(COMPLIANCE_CACHE_FILE_NAME);
    let tmp_path = network_dir.join(COMPLIANCE_CACHE_TMP_FILE_NAME);
    let mut blob = Vec::with_capacity(HEADER_LEN + serialized.len());
    blob.extend_from_slice(MAGIC);
    blob.push(SCHEMA_VERSION);
    blob.push(network_id(network));
    blob.extend_from_slice(&serialized);

    write_atomic(&tmp_path, &final_path, &blob)?;
    Ok(final_path)
}

/// Loads a `C` verifier cache without constructing a circuit, authenticates the full serialized
/// `VerifierCircuitData` blob (SHA-256 over everything after the 6-byte header — this is what
/// actually covers `common: CommonCircuitData`), recomputes its circuit digest from the
/// independently serialized verifier inputs, and then checks that digest against `pinned_digest`.
/// Mirrors `load_balance_verifier_cache_checked` for `C_balance`. The digest triple-check alone is
/// **not** cryptographically equivalent to a local build: it only covers
/// `(constants_sigmas_cap, domain_separator, degree_bits)`. Only the full-blob-hash check against
/// `pinned_verifier_blob_hash` makes the local-build equivalence claim true.
pub fn load_compliance_verifier_cache_checked(
    network: Network,
    dir: &Path,
    pinned_digest: &[u8; 32],
    pinned_verifier_blob_hash: &[u8; 32],
) -> Result<CachedComplianceVerifier> {
    let path = dir
        .join(crate::circuit_identity::network_label(network))
        .join(COMPLIANCE_CACHE_FILE_NAME);
    let blob =
        fs::read(&path).with_context(|| format!("read C verifier cache {}", path.display()))?;

    ensure!(
        blob.len() >= HEADER_LEN,
        "C verifier cache {} is truncated: expected at least {HEADER_LEN} header bytes, got {}",
        path.display(),
        blob.len()
    );
    ensure!(
        &blob[..MAGIC.len()] == MAGIC,
        "C verifier cache {} has wrong magic",
        path.display()
    );
    ensure!(
        blob[MAGIC.len()] == SCHEMA_VERSION,
        "C verifier cache {} has unsupported schema version {} (expected {})",
        path.display(),
        blob[MAGIC.len()],
        SCHEMA_VERSION
    );
    ensure!(
        blob[MAGIC.len() + 1] == network_id(network),
        "C verifier cache {} has network id {} but {} requires {}",
        path.display(),
        blob[MAGIC.len() + 1],
        crate::circuit_identity::network_label(network),
        network_id(network)
    );

    let full_blob_hash = verifier_blob_hash(&blob[HEADER_LEN..]);
    ensure!(
        &full_blob_hash == pinned_verifier_blob_hash,
        "C verifier cache full-blob hash does not match the pinned full-VerifierCircuitData \
         blob hash for this network (fail-closed) — the digest triple-check alone does not \
         authenticate CommonCircuitData (gate constraints/selectors/FRI params/LUTs); this \
         check does"
    );

    let vd = VerifierCircuitData::<PROGRAM_F, C, PROGRAM_D>::from_bytes(
        blob[HEADER_LEN..].to_vec(),
        &ZkCoinsGateSerializer,
    )
    .map_err(|e| {
        anyhow!(
            "VerifierCircuitData::from_bytes failed for {}: {e:?}",
            path.display()
        )
    })?;

    let recomputed = recompute_circuit_digest(&vd);
    ensure!(
        recomputed == vd.verifier_only.circuit_digest,
        "verifier cache self-inconsistent: recomputed circuit_digest != the digest stored in the cache file (constants_sigmas_cap/common do not match the file's own circuit_digest field — refusing a self-inconsistent cache, never trust the stored field alone)"
    );
    ensure!(
        &digest_to_bytes(&recomputed) == pinned_digest,
        "verifier cache digest does not match the §3.6 pinned C digest for this network (fail-closed)"
    );

    Ok(CachedComplianceVerifier { network, data: vd })
}

/// `Sha256` over the exact bytes written by `write_balance_verifier_cache` /
/// `write_compliance_verifier_cache` for one circuit's serialized
/// `VerifierCircuitData` — i.e. everything AFTER the 6-byte
/// `MAGIC || version || network-id` header. This is what the full-blob
/// authentication check authenticates: the circuit_digest triple-check alone
/// only covers `(constants_sigmas_cap, domain_separator, degree_bits)`, never
/// the separately-deserialized `common: CommonCircuitData` (gate
/// constraints, selectors, FRI parameters, lookup tables). Shared by both
/// `load_balance_verifier_cache_checked` / `load_compliance_verifier_cache_checked`
/// and by the `print_canonical_verifier_blob_hash` generation helper below so
/// every caller hashes the identical byte range with the identical formula.
fn verifier_blob_hash(serialized_verifier_circuit_data: &[u8]) -> [u8; 32] {
    Sha256::digest(serialized_verifier_circuit_data).into()
}

/// Per-network pin for FIX2's full-`VerifierCircuitData`-blob authentication,
/// for circuit `C` (compliance). Generated from a real canonical build via
/// `print_canonical_verifier_blob_hash` (below, `#[ignore]`) — never hand-typed
/// from anything other than that helper's printed output. **Fails loud** for
/// any network whose value has not yet been generated and filled in here.
pub fn compliance_verifier_blob_hash_for_network(network: Network) -> Result<[u8; 32]> {
    match network {
        // Canonical full-VerifierCircuitData blob hash for C/regtest, generated 2026-08-06 from a
        // real node1 (primary) build via write_compliance_verifier_cache (sha256 of the serialized
        // VerifierCircuitData). Authenticates the whole `common` (gate constraints etc.), not just
        // circuit_digest, against a cache-dir tamper (Spec-1-FIX CRIT2).
        Network::Regtest => Ok([
            0x24, 0x08, 0xd0, 0x5a, 0x63, 0xb7, 0x39, 0x65, 0xb1, 0xaa, 0x00, 0xa7, 0x3b, 0xa1,
            0x1d, 0xb9, 0xf7, 0xd2, 0x1a, 0xd0, 0xcb, 0x9f, 0x11, 0x05, 0x5e, 0x90, 0x2c, 0x67,
            0x14, 0x24, 0xf0, 0x3a,
        ]),
        Network::Testnet => Err(anyhow!(
            "no canonical full-VerifierCircuitData blob hash generated yet for C/testnet — \
             see the Regtest arm's doc comment for the generation procedure (use \
             ZKCOINS_BLOB_HASH_NETWORK=testnet)"
        )),
        Network::Mainnet => Err(anyhow!(
            "no canonical full-VerifierCircuitData blob hash generated yet for C/mainnet — \
             see the Regtest arm's doc comment for the generation procedure (use \
             ZKCOINS_BLOB_HASH_NETWORK=mainnet)"
        )),
    }
}

/// Per-network pin for FIX2's full-`VerifierCircuitData`-blob authentication,
/// for circuit `C_balance`. Mirrors
/// [`compliance_verifier_blob_hash_for_network`] — see its doc comment.
pub fn balance_verifier_blob_hash_for_network(network: Network) -> Result<[u8; 32]> {
    match network {
        // Canonical C_balance/regtest blob hash — see compliance fn above (generated 2026-08-06).
        Network::Regtest => Ok([
            0xc9, 0xaa, 0x4f, 0x6e, 0xa8, 0x29, 0xe4, 0x76, 0x1a, 0x06, 0x76, 0x7f, 0x57, 0xc1,
            0xf6, 0x10, 0x11, 0xe6, 0xd1, 0x62, 0x9d, 0x58, 0xcb, 0xfb, 0x87, 0x8a, 0x01, 0xd5,
            0x2c, 0xb2, 0x6d, 0x3f,
        ]),
        Network::Testnet => Err(anyhow!(
            "no canonical full-VerifierCircuitData blob hash generated yet for C_balance/testnet \
             — see the Regtest arm's doc comment for the generation procedure (use \
             ZKCOINS_BLOB_HASH_NETWORK=testnet)"
        )),
        Network::Mainnet => Err(anyhow!(
            "no canonical full-VerifierCircuitData blob hash generated yet for C_balance/mainnet \
             — see the Regtest arm's doc comment for the generation procedure (use \
             ZKCOINS_BLOB_HASH_NETWORK=mainnet)"
        )),
    }
}

fn recompute_circuit_digest(
    vd: &VerifierCircuitData<PROGRAM_F, C, PROGRAM_D>,
) -> HashOut<PROGRAM_F> {
    // Neither `C` nor `C_balance` ever calls `CircuitBuilder::set_domain_separator`, so
    // `build()` hashes the default empty separator with pad10*1 before assembling the outer
    // circuit digest — this recompute is shared by both cache paths.
    let domain_separator_digest: HashOut<PROGRAM_F> =
        <PoseidonHash as Hasher<PROGRAM_F>>::hash_pad(&[]);
    let circuit_digest_parts = [
        vd.verifier_only.constants_sigmas_cap.flatten(),
        domain_separator_digest.elements.to_vec(),
        vec![PROGRAM_F::from_canonical_usize(vd.common.degree_bits())],
    ];
    <PoseidonHash as Hasher<PROGRAM_F>>::hash_no_pad(&circuit_digest_parts.concat())
}

const fn network_id(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Regtest => 2,
    }
}

fn write_atomic(tmp_path: &Path, final_path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = File::create(tmp_path)
        .with_context(|| format!("create temporary verifier cache {}", tmp_path.display()))?;
    if let Err(error) = tmp.write_all(bytes) {
        drop(tmp);
        let cleanup = fs::remove_file(tmp_path);
        if let Err(cleanup_error) = cleanup {
            bail!(
                "write temporary verifier cache {} failed: {error}; cleanup failed: {cleanup_error}",
                tmp_path.display()
            );
        }
        return Err(error)
            .with_context(|| format!("write temporary verifier cache {}", tmp_path.display()));
    }
    if let Err(error) = tmp.sync_all() {
        drop(tmp);
        let cleanup = fs::remove_file(tmp_path);
        if let Err(cleanup_error) = cleanup {
            bail!(
                "sync temporary verifier cache {} failed: {error}; cleanup failed: {cleanup_error}",
                tmp_path.display()
            );
        }
        return Err(error)
            .with_context(|| format!("sync temporary verifier cache {}", tmp_path.display()));
    }
    drop(tmp);

    if let Err(error) = fs::rename(tmp_path, final_path) {
        let cleanup = fs::remove_file(tmp_path);
        if let Err(cleanup_error) = cleanup {
            bail!(
                "rename verifier cache {} to {} failed: {error}; cleanup failed: {cleanup_error}",
                tmp_path.display(),
                final_path.display()
            );
        }
        return Err(error).with_context(|| {
            format!(
                "rename verifier cache {} to {}",
                tmp_path.display(),
                final_path.display()
            )
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, VerifierOnlyCircuitData};
    use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
    use shared::spec_v1::digest_from_bytes;

    use super::*;

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after UNIX_EPOCH")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "zkcoins-verifier-cache-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn pinned_digest(key: &str) -> [u8; 32] {
        const PINNED_DIGESTS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/generated_circuit_digests.txt"
        ));
        let value = match PINNED_DIGESTS.lines().find_map(|line| {
            let (candidate, value) = line.split_once(" = ")?;
            (candidate == key).then_some(value)
        }) {
            Some(value) => value,
            None => panic!("pinned digests file missing required key `{key}`"),
        };
        let hex = match value.strip_prefix("0x") {
            Some(hex) => hex,
            None => panic!("pinned digest `{key}` lacks 0x prefix"),
        };
        assert_eq!(hex.len(), 64, "pinned digest `{key}` must contain 32 bytes");
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = match u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16) {
                Ok(byte) => byte,
                Err(error) => panic!("pinned digest `{key}` has invalid hex: {error}"),
            };
        }
        out
    }

    fn dummy_verifier_data() -> VerifierCircuitData<PROGRAM_F, C, PROGRAM_D> {
        let mut builder =
            CircuitBuilder::<PROGRAM_F, PROGRAM_D>::new(CircuitConfig::standard_recursion_config());
        let target = builder.add_virtual_target();
        builder.register_public_input(target);
        builder.build::<C>().verifier_data()
    }

    fn write_test_blob(
        network: Network,
        dir: &Path,
        verifier_data: &VerifierCircuitData<PROGRAM_F, C, PROGRAM_D>,
        magic: &[u8; 4],
        version: u8,
        header_network_id: u8,
        file_name: &str,
    ) -> PathBuf {
        let network_dir = dir.join(crate::circuit_identity::network_label(network));
        fs::create_dir_all(&network_dir).expect("create test verifier-cache directory");
        let path = network_dir.join(file_name);
        let serialized = verifier_data
            .to_bytes(&ZkCoinsGateSerializer)
            .map_err(|e| anyhow!("VerifierCircuitData::to_bytes failed: {e:?}"))
            .expect("serialize test verifier data");
        let mut blob = Vec::with_capacity(HEADER_LEN + serialized.len());
        blob.extend_from_slice(magic);
        blob.push(version);
        blob.push(header_network_id);
        blob.extend_from_slice(&serialized);
        fs::write(&path, blob).expect("write test verifier-cache file");
        path
    }

    fn test_blob_hash(vd: &VerifierCircuitData<PROGRAM_F, C, PROGRAM_D>) -> [u8; 32] {
        let serialized = vd
            .to_bytes(&ZkCoinsGateSerializer)
            .map_err(|e| anyhow!("serialize verifier data for test: {e:?}"))
            .expect("serialize test verifier data");
        verifier_blob_hash(&serialized)
    }

    #[test]
    fn rejects_forged_stored_digest_even_when_it_matches_pin() {
        let network = Network::Regtest;
        let dir = test_dir("forged-digest");
        let dummy = dummy_verifier_data();
        let fake_pin = [0x5au8; 32];
        let forged = VerifierCircuitData {
            verifier_only: VerifierOnlyCircuitData {
                constants_sigmas_cap: dummy.verifier_only.constants_sigmas_cap.clone(),
                circuit_digest: digest_from_bytes(&fake_pin)
                    .expect("fake pin uses canonical Goldilocks limbs"),
            },
            common: dummy.common.clone(),
        };
        write_test_blob(
            network,
            &dir,
            &forged,
            MAGIC,
            SCHEMA_VERSION,
            network_id(network),
            CACHE_FILE_NAME,
        );

        let blob_hash = test_blob_hash(&forged);
        let error = match load_balance_verifier_cache_checked(network, &dir, &fake_pin, &blob_hash)
        {
            Ok(_) => panic!("a forged stored digest must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("self-inconsistent"),
            "unexpected error: {error:#}"
        );
        fs::remove_dir_all(&dir).expect("remove forged-digest test directory");
    }

    #[test]
    fn rejects_wrong_magic_version_and_network_id() {
        let network = Network::Mainnet;
        let dir = test_dir("bad-header");
        let dummy = dummy_verifier_data();
        let pin = digest_to_bytes(&dummy.verifier_only.circuit_digest);
        let blob_hash = test_blob_hash(&dummy);

        write_test_blob(
            network,
            &dir,
            &dummy,
            b"BAD!",
            SCHEMA_VERSION,
            network_id(network),
            CACHE_FILE_NAME,
        );
        assert!(load_balance_verifier_cache_checked(network, &dir, &pin, &blob_hash).is_err());

        write_test_blob(
            network,
            &dir,
            &dummy,
            MAGIC,
            SCHEMA_VERSION + 1,
            network_id(network),
            CACHE_FILE_NAME,
        );
        assert!(load_balance_verifier_cache_checked(network, &dir, &pin, &blob_hash).is_err());

        write_test_blob(
            network,
            &dir,
            &dummy,
            MAGIC,
            SCHEMA_VERSION,
            network_id(Network::Testnet),
            CACHE_FILE_NAME,
        );
        assert!(load_balance_verifier_cache_checked(network, &dir, &pin, &blob_hash).is_err());

        fs::remove_dir_all(&dir).expect("remove bad-header test directory");
    }

    #[test]
    fn rejects_wrong_full_blob_hash_even_when_digest_matches_pin() {
        let network = Network::Regtest;
        let dir = test_dir("wrong-blob-hash");
        let dummy = dummy_verifier_data();
        let pin = digest_to_bytes(&dummy.verifier_only.circuit_digest);
        write_test_blob(
            network,
            &dir,
            &dummy,
            MAGIC,
            SCHEMA_VERSION,
            network_id(network),
            CACHE_FILE_NAME,
        );

        let mut wrong_blob_hash = test_blob_hash(&dummy);
        wrong_blob_hash[0] ^= 0xFF;
        let error = match load_balance_verifier_cache_checked(network, &dir, &pin, &wrong_blob_hash)
        {
            Ok(_) => panic!(
                "a wrong full-blob hash must be rejected even when circuit_digest matches its pin"
            ),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("full-blob hash"),
            "unexpected error: {error:#}"
        );
        fs::remove_dir_all(&dir).expect("remove wrong-blob-hash test directory");
    }

    #[test]
    #[ignore = "builds and proves with the real C_balance circuit (2^18, minutes to build)"]
    fn real_balance_verifier_cache_round_trip_and_digest_recompute() {
        let network = Network::Testnet;
        let dir = test_dir("real-round-trip");
        let pin_c = pinned_digest("circuit_digest_c_testnet");
        let pin_c_balance = pinned_digest("circuit_digest_c_balance_testnet");
        crate::prover_bridge::ProverBridge::install_network_pins(network, pin_c, pin_c_balance)
            .expect("install matching testnet circuit pins before construction");

        let (bridge, proved_attestation, expected_statement) =
            crate::prover_bridge::tests::real_balance_attestation_fixture();
        let circuit = crate::prover_bridge::balance_circuit(network)
            .expect("build the real pinned C_balance circuit");
        let real = circuit.data.verifier_data();
        let real_digest = digest_to_bytes(&real.verifier_only.circuit_digest);
        assert_eq!(real_digest, pin_c_balance);

        assert_eq!(
            recompute_circuit_digest(&real),
            real.verifier_only.circuit_digest,
            "the cache recompute formula must reproduce CircuitBuilder::build()"
        );
        write_balance_verifier_cache(network, &dir).expect("write real verifier cache");
        let blob_hash = test_blob_hash(&real);
        let cached = load_balance_verifier_cache_checked(network, &dir, &real_digest, &blob_hash)
            .expect("load and check real verifier cache");
        assert_eq!(cached.network(), network);
        assert_eq!(cached.balance_circuit_digest_bytes(), real_digest);

        let proof_bytes = proved_attestation.proof.to_bytes();
        let loaded_proof = cached
            .load_balance_proof_bytes(&proof_bytes)
            .expect("load a genuine C_balance proof through cached common data");
        let extracted = cached
            .verify_attestation(&loaded_proof)
            .expect("verify a genuine C_balance proof through cached verifier data");
        let bridge_extracted = bridge
            .verify_attestation(&proved_attestation.proof)
            .expect("verify fixture proof through the warm real circuit");
        assert_eq!(extracted.subject, expected_statement.subject);
        assert_eq!(extracted.asset_id, expected_statement.asset_id);
        assert_eq!(extracted.balance, expected_statement.balance);
        assert_eq!(extracted.nav_ceiling, expected_statement.nav_ceiling.root());
        assert_eq!(extracted.size_ceiling, expected_statement.nav_ceiling.size);
        assert_eq!(extracted.anchor, expected_statement.anchor);
        assert_eq!(extracted.network_id, bridge_extracted.network_id);

        fs::remove_dir_all(&dir).expect("remove real-round-trip test directory");
    }

    #[test]
    fn compliance_cache_rejects_forged_stored_digest_even_when_it_matches_pin() {
        let network = Network::Regtest;
        let dir = test_dir("compliance-forged-digest");
        let dummy = dummy_verifier_data();
        let fake_pin = [0x5au8; 32];
        let forged = VerifierCircuitData {
            verifier_only: VerifierOnlyCircuitData {
                constants_sigmas_cap: dummy.verifier_only.constants_sigmas_cap.clone(),
                circuit_digest: digest_from_bytes(&fake_pin)
                    .expect("fake pin uses canonical Goldilocks limbs"),
            },
            common: dummy.common.clone(),
        };
        write_test_blob(
            network,
            &dir,
            &forged,
            MAGIC,
            SCHEMA_VERSION,
            network_id(network),
            COMPLIANCE_CACHE_FILE_NAME,
        );

        let blob_hash = test_blob_hash(&forged);
        let error =
            match load_compliance_verifier_cache_checked(network, &dir, &fake_pin, &blob_hash) {
                Ok(_) => panic!("a forged stored digest must be rejected"),
                Err(error) => error,
            };
        assert!(
            error.to_string().contains("self-inconsistent"),
            "unexpected error: {error:#}"
        );
        fs::remove_dir_all(&dir).expect("remove compliance-forged-digest test directory");
    }

    #[test]
    fn compliance_cache_rejects_wrong_magic_version_and_network_id() {
        let network = Network::Mainnet;
        let dir = test_dir("compliance-bad-header");
        let dummy = dummy_verifier_data();
        let pin = digest_to_bytes(&dummy.verifier_only.circuit_digest);
        let blob_hash = test_blob_hash(&dummy);

        write_test_blob(
            network,
            &dir,
            &dummy,
            b"BAD!",
            SCHEMA_VERSION,
            network_id(network),
            COMPLIANCE_CACHE_FILE_NAME,
        );
        assert!(load_compliance_verifier_cache_checked(network, &dir, &pin, &blob_hash).is_err());

        write_test_blob(
            network,
            &dir,
            &dummy,
            MAGIC,
            SCHEMA_VERSION + 1,
            network_id(network),
            COMPLIANCE_CACHE_FILE_NAME,
        );
        assert!(load_compliance_verifier_cache_checked(network, &dir, &pin, &blob_hash).is_err());

        write_test_blob(
            network,
            &dir,
            &dummy,
            MAGIC,
            SCHEMA_VERSION,
            network_id(Network::Testnet),
            COMPLIANCE_CACHE_FILE_NAME,
        );
        assert!(load_compliance_verifier_cache_checked(network, &dir, &pin, &blob_hash).is_err());

        fs::remove_dir_all(&dir).expect("remove compliance-bad-header test directory");
    }

    #[test]
    fn compliance_cache_rejects_wrong_full_blob_hash_even_when_digest_matches_pin() {
        let network = Network::Mainnet;
        let dir = test_dir("compliance-wrong-blob-hash");
        let dummy = dummy_verifier_data();
        let pin = digest_to_bytes(&dummy.verifier_only.circuit_digest);
        write_test_blob(
            network,
            &dir,
            &dummy,
            MAGIC,
            SCHEMA_VERSION,
            network_id(network),
            COMPLIANCE_CACHE_FILE_NAME,
        );

        let mut wrong_blob_hash = test_blob_hash(&dummy);
        wrong_blob_hash[0] ^= 0xFF;
        let error = match load_compliance_verifier_cache_checked(
            network,
            &dir,
            &pin,
            &wrong_blob_hash,
        ) {
            Ok(_) => panic!(
                "a wrong full-blob hash must be rejected even when circuit_digest matches its pin"
            ),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("full-blob hash"),
            "unexpected error: {error:#}"
        );
        fs::remove_dir_all(&dir).expect("remove compliance-wrong-blob-hash test directory");
    }

    #[test]
    #[ignore = "builds and proves with the real ~90-100 GiB C circuit (2^21)"]
    fn real_compliance_verifier_cache_round_trip_and_digest_recompute() {
        let network = Network::Testnet;
        let dir = test_dir("real-compliance-round-trip");
        let pin_c = pinned_digest("circuit_digest_c_testnet");
        let pin_c_balance = pinned_digest("circuit_digest_c_balance_testnet");
        crate::prover_bridge::ProverBridge::install_network_pins(network, pin_c, pin_c_balance)
            .expect("install matching testnet circuit pins before construction");

        let (bridge, proved_genesis) = crate::prover_bridge::tests::real_transition_fixture();
        let circuit = crate::prover_bridge::compliance_circuit(network)
            .expect("build the real pinned C circuit");
        let real = circuit.data.verifier_data();
        let real_digest = digest_to_bytes(&real.verifier_only.circuit_digest);
        assert_eq!(real_digest, pin_c);

        assert_eq!(
            recompute_circuit_digest(&real),
            real.verifier_only.circuit_digest,
            "the cache recompute formula must reproduce CircuitBuilder::build() for C"
        );
        write_compliance_verifier_cache(network, &dir).expect("write real C verifier cache");
        let blob_hash = test_blob_hash(&real);
        let cached =
            load_compliance_verifier_cache_checked(network, &dir, &real_digest, &blob_hash)
                .expect("load and check real C verifier cache");
        assert_eq!(cached.network(), network);
        assert_eq!(cached.compliance_circuit_digest_bytes(), real_digest);

        let vd = cached.into_verifier_data();
        vd.verify(proved_genesis.proof.clone())
            .expect("cached C verifier must accept a genuine transition proof");
        check_cyclic_proof_verifier_data(&proved_genesis.proof, &vd.verifier_only, &vd.common)
            .expect(
                "cached C verifier's cyclic verifier-data tail check must accept a genuine proof",
            );

        let bridge_check = bridge.verify_transition(&proved_genesis.proof);
        assert!(
            bridge_check.is_ok(),
            "the same proof must also verify through the warm real ProverBridge"
        );

        let mut tampered = proved_genesis.proof.clone();
        tampered.public_inputs[40] += PROGRAM_F::ONE;
        let tampered_verify_err = vd.verify(tampered.clone()).is_err();
        let tampered_cyclic_err =
            check_cyclic_proof_verifier_data(&tampered, &vd.verifier_only, &vd.common).is_err();
        assert!(
            tampered_verify_err || tampered_cyclic_err,
            "cached C verifier must reject a tampered proof"
        );

        fs::remove_dir_all(&dir).expect("remove real-compliance-round-trip test directory");
    }

    #[test]
    #[ignore = "prints the canonical full-VerifierCircuitData blob hash for FIX2 pin \
                generation (multi-minute real circuit build); run with --ignored \
                --nocapture, e.g. ZKCOINS_BLOB_HASH_NETWORK=regtest cargo test -p \
                zkcoins-prover-plonky2 --lib verifier_cache::tests::print_canonical_verifier_blob_hash \
                -- --ignored --nocapture — then fill the printed values into \
                compliance_verifier_blob_hash_for_network / \
                balance_verifier_blob_hash_for_network for that network"]
    fn print_canonical_verifier_blob_hash() {
        let network = match std::env::var("ZKCOINS_BLOB_HASH_NETWORK").as_deref() {
            Ok("mainnet") => Network::Mainnet,
            Ok("testnet") => Network::Testnet,
            Ok("regtest") | Err(_) => Network::Regtest,
            Ok(other) => panic!(
                "ZKCOINS_BLOB_HASH_NETWORK={other:?} must be one of mainnet|testnet|regtest \
                 (unset defaults to regtest)"
            ),
        };
        let label = crate::circuit_identity::network_label(network);
        let pin_c = pinned_digest(&format!("circuit_digest_c_{label}"));
        let pin_c_balance = pinned_digest(&format!("circuit_digest_c_balance_{label}"));
        crate::prover_bridge::ProverBridge::install_network_pins(network, pin_c, pin_c_balance)
            .expect("install matching circuit pins before construction");

        let c_circuit = crate::prover_bridge::compliance_circuit(network)
            .expect("build the real pinned C circuit");
        let c_serialized = c_circuit
            .data
            .verifier_data()
            .to_bytes(&ZkCoinsGateSerializer)
            .map_err(|e| anyhow!("C VerifierCircuitData::to_bytes failed: {e:?}"))
            .expect("serialize C verifier data");
        let c_blob_hash = verifier_blob_hash(&c_serialized);

        let balance_circuit = crate::prover_bridge::balance_circuit(network)
            .expect("build the real pinned C_balance circuit");
        let b_serialized = balance_circuit
            .data
            .verifier_data()
            .to_bytes(&ZkCoinsGateSerializer)
            .map_err(|e| anyhow!("C_balance VerifierCircuitData::to_bytes failed: {e:?}"))
            .expect("serialize C_balance verifier data");
        let b_blob_hash = verifier_blob_hash(&b_serialized);

        fn hex32(bytes: &[u8; 32]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        println!("network = {label}");
        println!(
            "compliance_verifier_blob_hash (C)         = {}",
            hex32(&c_blob_hash)
        );
        println!(
            "balance_verifier_blob_hash    (C_balance) = {}",
            hex32(&b_blob_hash)
        );
    }
}
