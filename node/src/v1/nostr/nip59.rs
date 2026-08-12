//! NIP-59 seal (kind 13) and gift-wrap (kind 1059).
//!
//! # Layering
//!
//! ```text
//! Rumor  (unsigned; has id, no sig)
//!   └─ NIP-44 under conversation_key(sender_op, recipient_op)
//!      └─ Seal (kind 13, signed by real sender)
//!           └─ NIP-44 under conversation_key(fresh_ephemeral, recipient_op)
//!              └─ Gift-Wrap (kind 1059, signed by ephemeral)
//! ```
//!
//! # Authenticity
//!
//! Unwrap fails closed unless `seal.pubkey == rumor.pubkey`. Without that
//! check any party can seal a rumor that claims a foreign author.
//!
//! # Randomness
//!
//! Production encrypt paths take an explicit [`SecureRandom`] source for the
//! ephemeral secret, both NIP-44 nonces, and the independent `created_at`
//! jitter on seal and wrap. There is no default RNG, no default clock, and
//! no zero-filled nonce path.

use std::fmt;

use bitcoin::key::rand::{rngs::OsRng, RngCore};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use super::event::{compute_event_id, Event, EventError, EventParts};
use super::nip44::{self, Nip44Error};

/// NIP-59 seal event kind.
pub(crate) const KIND_SEAL: u32 = 13;
/// NIP-59 gift-wrap event kind.
pub(crate) const KIND_GIFT_WRAP: u32 = 1059;

/// Maximum seal/wrap `created_at` skew into the past (two days, NIP-59).
pub(crate) const MAX_CREATED_AT_PAST_SECS: u64 = 2 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Secure random source — explicit, never a silent default
// ---------------------------------------------------------------------------

/// Cryptographically secure byte source required by NIP-59 production paths.
///
/// Callers must construct and pass an implementation. There is no default
/// parameter and no "use zeros if missing" branch on any encrypt path.
///
/// # `Send`
///
/// The trait requires [`Send`] because production encrypt sites hold the
/// source across `.await` points that must run under `tokio::spawn` (e.g.
/// §4.4 receive: gift-wrap a kind-1421 ACK after durable persist and relay
/// publish). A non-`Send` trait object would make those tasks unschedulable.
/// Sync pure helpers (`seal`, `gift_wrap`, `build_coin_delivery`) do not
/// need the bound themselves; they inherit it so one type serves both.
///
/// Mutex-backed sharing (`MeshDeliveryPort`) still **must** drop the guard
/// before any network await — `Send` does not license holding a
/// `MutexGuard` across I/O.
pub(crate) trait SecureRandom: Send {
    /// Fill `dest` completely with CSPRNG bytes. On failure the implementation
    /// **MUST** return an error rather than leave zeros or partial data.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Nip59Error>;
}

/// Operating-system CSPRNG for production seal/wrap.
///
/// Must be passed explicitly — functions never invent one.
#[derive(Debug, Default)]
pub(crate) struct OsSecureRandom;

impl SecureRandom for OsSecureRandom {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Nip59Error> {
        // `try_fill_bytes` surfaces entropy failure; `fill_bytes` would panic.
        OsRng
            .try_fill_bytes(dest)
            .map_err(|_| Nip59Error::RandomSourceFailed)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Fail-closed reasons for NIP-59 seal, wrap, and unwrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Nip59Error {
    /// CSPRNG refused to provide entropy.
    RandomSourceFailed,
    /// Secret scalar is not a valid secp256k1 key.
    InvalidSecretKey,
    /// Rumor `pubkey` does not match the sealer's real key.
    RumorAuthorMismatch {
        rumor_pubkey: [u8; 32],
        sealer_pubkey: [u8; 32],
    },
    /// After unwrap, `seal.pubkey != rumor.pubkey` — forged sender claim.
    SealAuthorMismatch {
        seal_pubkey: [u8; 32],
        rumor_pubkey: [u8; 32],
    },
    /// Outer event is not kind 1059.
    WrongWrapKind { kind: u32 },
    /// Inner seal is not kind 13.
    WrongSealKind { kind: u32 },
    /// Seal carries tags (NIP-59/NIP-17: seal tags must be empty).
    SealTagsNotEmpty,
    /// Rumor JSON carried a `sig` field (must be absent).
    RumorHasSignature,
    /// Claimed rumor `id` does not match the NIP-01 hash of its fields.
    RumorIdMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
    /// Decrypted payload is not valid JSON for the expected layer.
    InvalidInnerJson { layer: &'static str },
    /// Hex field width or alphabet is wrong inside an inner JSON event.
    InvalidInnerHex { field: &'static str },
    /// NIP-01 event construction / verification failed.
    Event(EventError),
    /// NIP-44 encrypt / decrypt failed.
    Nip44(Nip44Error),
}

impl fmt::Display for Nip59Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Nip59Error::RandomSourceFailed => write!(f, "secure random source failed"),
            Nip59Error::InvalidSecretKey => write!(f, "invalid secp256k1 secret key"),
            Nip59Error::RumorAuthorMismatch {
                rumor_pubkey,
                sealer_pubkey,
            } => write!(
                f,
                "rumor pubkey {} does not match sealer {}",
                hex::encode(rumor_pubkey),
                hex::encode(sealer_pubkey)
            ),
            Nip59Error::SealAuthorMismatch {
                seal_pubkey,
                rumor_pubkey,
            } => write!(
                f,
                "seal author {} does not match rumor pubkey {} (forged sender)",
                hex::encode(seal_pubkey),
                hex::encode(rumor_pubkey)
            ),
            Nip59Error::WrongWrapKind { kind } => {
                write!(f, "expected gift-wrap kind {KIND_GIFT_WRAP}, got {kind}")
            }
            Nip59Error::WrongSealKind { kind } => {
                write!(f, "expected seal kind {KIND_SEAL}, got {kind}")
            }
            Nip59Error::SealTagsNotEmpty => write!(f, "seal tags must be empty"),
            Nip59Error::RumorHasSignature => {
                write!(f, "rumor must not carry a signature field")
            }
            Nip59Error::RumorIdMismatch { claimed, computed } => write!(
                f,
                "rumor id mismatch: claimed={}, computed={}",
                hex::encode(claimed),
                hex::encode(computed)
            ),
            Nip59Error::InvalidInnerJson { layer } => {
                write!(f, "invalid JSON for NIP-59 {layer}")
            }
            Nip59Error::InvalidInnerHex { field } => {
                write!(f, "invalid hex for NIP-59 field {field}")
            }
            Nip59Error::Event(e) => write!(f, "event error: {e}"),
            Nip59Error::Nip44(e) => write!(f, "nip44 error: {e}"),
        }
    }
}

impl std::error::Error for Nip59Error {}

impl From<EventError> for Nip59Error {
    fn from(value: EventError) -> Self {
        Nip59Error::Event(value)
    }
}

impl From<Nip44Error> for Nip59Error {
    fn from(value: Nip44Error) -> Self {
        Nip59Error::Nip44(value)
    }
}

// ---------------------------------------------------------------------------
// Rumor — unsigned by type
// ---------------------------------------------------------------------------

/// An unsigned NIP-59 rumor.
///
/// Has a computed `id` but **no** `sig` field. There is no conversion into
/// [`Event`]: a signed event can only be produced by [`Event::sign`] /
/// [`Event::verify_parts`], both of which require a BIP-340 signature. A
/// rumor therefore cannot be treated as a signed event without an explicit
/// seal/wrap construction that encrypts it rather than signing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rumor {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl Rumor {
    /// Build a rumor and compute its NIP-01 `id` from the fields.
    ///
    /// `pubkey` is the claimed author (must equal the sealer when sealed).
    pub(crate) fn create(
        pubkey: [u8; 32],
        created_at: u64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Self {
        let id = compute_event_id(&pubkey, created_at, kind, &tags, &content);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        }
    }

    /// Recompute `id` and reject a mismatch.
    pub(crate) fn verify_id(&self) -> Result<(), Nip59Error> {
        let computed = compute_event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if computed != self.id {
            return Err(Nip59Error::RumorIdMismatch {
                claimed: self.id,
                computed,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unwrapped result
// ---------------------------------------------------------------------------

/// Successfully unwrapped NIP-59 payload (seal author bound to rumor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unwrapped {
    pub rumor: Rumor,
    pub seal: Event,
}

// ---------------------------------------------------------------------------
// JSON wire shapes for encrypted interiors
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct RumorJson {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    /// Must be absent on a true rumor. Present ⇒ reject.
    #[serde(default, skip_serializing)]
    sig: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedEventJson {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u32,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn xonly_from_sk(secret_key: &[u8; 32]) -> Result<[u8; 32], Nip59Error> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret_key).map_err(|_| Nip59Error::InvalidSecretKey)?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    Ok(xonly.serialize())
}

fn parse_hex32(s: &str, field: &'static str) -> Result<[u8; 32], Nip59Error> {
    parse_hex_exact::<32>(s, field)
}

fn parse_hex64(s: &str, field: &'static str) -> Result<[u8; 64], Nip59Error> {
    parse_hex_exact::<64>(s, field)
}

fn parse_hex_exact<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], Nip59Error> {
    if s.len() != N * 2 {
        return Err(Nip59Error::InvalidInnerHex { field });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        // Reject uppercase and non-hex — lowercase only.
        return Err(Nip59Error::InvalidInnerHex { field });
    }
    let bytes = hex::decode(s).map_err(|_| Nip59Error::InvalidInnerHex { field })?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Draw `created_at` uniformly from `[now.saturating_sub(MAX), now]`.
///
/// Independent draws for seal and wrap prevent correlating the three layers.
fn random_past_created_at(now: u64, rng: &mut dyn SecureRandom) -> Result<u64, Nip59Error> {
    let mut raw = [0u8; 8];
    rng.fill_bytes(&mut raw)?;
    let r = u64::from_le_bytes(raw);
    // Inclusive range of length MAX+1: skew ∈ [0, MAX].
    let skew = r % (MAX_CREATED_AT_PAST_SECS.saturating_add(1));
    Ok(now.saturating_sub(skew))
}

/// Fresh secp256k1 secret from CSPRNG (retry invalid scalars).
fn fresh_secret_key(rng: &mut dyn SecureRandom) -> Result<[u8; 32], Nip59Error> {
    // Bounded retries: a working CSPRNG produces a valid scalar almost always.
    for _ in 0..64 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes)?;
        if SecretKey::from_slice(&bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err(Nip59Error::RandomSourceFailed)
}

fn fill_nonce(rng: &mut dyn SecureRandom) -> Result<[u8; 32], Nip59Error> {
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce)?;
    Ok(nonce)
}

fn rumor_to_json(rumor: &Rumor) -> Result<String, Nip59Error> {
    let j = RumorJson {
        id: hex::encode(rumor.id),
        pubkey: hex::encode(rumor.pubkey),
        created_at: rumor.created_at,
        kind: rumor.kind,
        tags: rumor.tags.clone(),
        content: rumor.content.clone(),
        sig: None,
    };
    // Compact JSON — field order is the struct declaration order.
    serde_json::to_string(&j).map_err(|_| Nip59Error::InvalidInnerJson { layer: "rumor" })
}

fn event_to_json(event: &Event) -> Result<String, Nip59Error> {
    let j = SignedEventJson {
        id: hex::encode(event.id),
        pubkey: hex::encode(event.pubkey),
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags.clone(),
        content: event.content.clone(),
        sig: hex::encode(event.sig),
    };
    serde_json::to_string(&j).map_err(|_| Nip59Error::InvalidInnerJson { layer: "seal" })
}

fn rumor_from_json(s: &str) -> Result<Rumor, Nip59Error> {
    let j: RumorJson =
        serde_json::from_str(s).map_err(|_| Nip59Error::InvalidInnerJson { layer: "rumor" })?;
    if j.sig.is_some() {
        return Err(Nip59Error::RumorHasSignature);
    }
    let id = parse_hex32(&j.id, "rumor.id")?;
    let pubkey = parse_hex32(&j.pubkey, "rumor.pubkey")?;
    let rumor = Rumor {
        id,
        pubkey,
        created_at: j.created_at,
        kind: j.kind,
        tags: j.tags,
        content: j.content,
    };
    rumor.verify_id()?;
    Ok(rumor)
}

fn event_from_json(s: &str) -> Result<Event, Nip59Error> {
    let j: SignedEventJson =
        serde_json::from_str(s).map_err(|_| Nip59Error::InvalidInnerJson { layer: "seal" })?;
    let parts = EventParts {
        id: parse_hex32(&j.id, "seal.id")?,
        pubkey: parse_hex32(&j.pubkey, "seal.pubkey")?,
        created_at: j.created_at,
        kind: j.kind,
        tags: j.tags,
        content: j.content,
        sig: parse_hex64(&j.sig, "seal.sig")?,
    };
    Event::verify_parts(parts).map_err(Nip59Error::from)
}

// ---------------------------------------------------------------------------
// Seal
// ---------------------------------------------------------------------------

/// Seal a rumor: NIP-44-encrypt under `conversation_key(sender_sk, recipient_pk)`,
/// sign kind-13 with the real sender key, empty tags, randomized `created_at`.
///
/// `now` is the wall-clock upper bound for seal `created_at` (no silent clock).
/// `rng` supplies the NIP-44 nonce and the past-timestamp draw.
pub(crate) fn seal(
    rumor: &Rumor,
    sender_sk: &[u8; 32],
    recipient_pk: &[u8; 32],
    now: u64,
    rng: &mut dyn SecureRandom,
) -> Result<Event, Nip59Error> {
    rumor.verify_id()?;
    let sealer_pk = xonly_from_sk(sender_sk)?;
    if rumor.pubkey != sealer_pk {
        return Err(Nip59Error::RumorAuthorMismatch {
            rumor_pubkey: rumor.pubkey,
            sealer_pubkey: sealer_pk,
        });
    }

    let conversation_key = nip44::get_conversation_key(sender_sk, recipient_pk)?;
    let plaintext = rumor_to_json(rumor)?;
    let nonce = fill_nonce(rng)?;
    let content = nip44::encrypt(&conversation_key, &plaintext, &nonce)?;

    let created_at = random_past_created_at(now, rng)?;
    // NIP-59: seal carries no tags.
    Event::sign(sender_sk, created_at, KIND_SEAL, vec![], content).map_err(Nip59Error::from)
}

// ---------------------------------------------------------------------------
// Gift-wrap
// ---------------------------------------------------------------------------

/// Gift-wrap a seal under a **fresh** ephemeral key.
///
/// - Ephemeral secret from `rng` (never reused across calls).
/// - NIP-44 under `conversation_key(ephemeral, recipient_pk)`.
/// - Signed by the ephemeral key.
/// - `created_at` independently randomized from `now`.
/// - Outer `tags` are exactly what the caller passes (zkCoins delivery:
///   `zkdt`/`zkepk` only; NIP-17: a single `p` tag — caller responsibility).
pub(crate) fn gift_wrap(
    seal_event: &Event,
    recipient_pk: &[u8; 32],
    outer_tags: Vec<Vec<String>>,
    now: u64,
    rng: &mut dyn SecureRandom,
) -> Result<Event, Nip59Error> {
    if seal_event.kind != KIND_SEAL {
        return Err(Nip59Error::WrongSealKind {
            kind: seal_event.kind,
        });
    }
    if !seal_event.tags.is_empty() {
        return Err(Nip59Error::SealTagsNotEmpty);
    }
    // Ensure the seal itself verifies before wrapping.
    seal_event.verify()?;

    let ephemeral_sk = fresh_secret_key(rng)?;
    let conversation_key = nip44::get_conversation_key(&ephemeral_sk, recipient_pk)?;
    let plaintext = event_to_json(seal_event)?;
    let nonce = fill_nonce(rng)?;
    let content = nip44::encrypt(&conversation_key, &plaintext, &nonce)?;

    let created_at = random_past_created_at(now, rng)?;
    Event::sign(
        &ephemeral_sk,
        created_at,
        KIND_GIFT_WRAP,
        outer_tags,
        content,
    )
    .map_err(Nip59Error::from)
}

/// Seal then gift-wrap in one shot (independent `created_at` and nonces).
pub(crate) fn seal_and_wrap(
    rumor: &Rumor,
    sender_sk: &[u8; 32],
    recipient_pk: &[u8; 32],
    outer_tags: Vec<Vec<String>>,
    now: u64,
    rng: &mut dyn SecureRandom,
) -> Result<Event, Nip59Error> {
    let seal_event = seal(rumor, sender_sk, recipient_pk, now, rng)?;
    gift_wrap(&seal_event, recipient_pk, outer_tags, now, rng)
}

// ---------------------------------------------------------------------------
// Outer scan tags for zkCoins delivery (§4.2 step 4 / §7.3)
// ---------------------------------------------------------------------------

/// Exactly the two cleartext outer tags allowed on a zkCoins delivery wrap:
/// `["zkdt", detect_tag_hex]` and `["zkepk", epk_hex]`.
///
/// Spec: §4.2 step 4, §7.3 delivery rumor — **MUST NOT** carry any other
/// cleartext field (`blob_id`, holders, `record_kind`, coin ids, …).
pub(crate) fn delivery_scan_tags(detect_tag: &[u8; 32], epk: &[u8; 32]) -> Vec<Vec<String>> {
    vec![
        vec!["zkdt".to_string(), hex::encode(detect_tag)],
        vec!["zkepk".to_string(), hex::encode(epk)],
    ]
}

// ---------------------------------------------------------------------------
// Unwrap (fail-closed)
// ---------------------------------------------------------------------------

/// Unwrap a gift-wrap: verify wrap → decrypt → verify seal → decrypt → rumor,
/// then require `seal.pubkey == rumor.pubkey`.
pub(crate) fn unwrap_gift(wrap: &Event, recipient_sk: &[u8; 32]) -> Result<Unwrapped, Nip59Error> {
    // Re-verify the outer event (id + BIP-340 under ephemeral pubkey).
    wrap.verify()?;
    if wrap.kind != KIND_GIFT_WRAP {
        return Err(Nip59Error::WrongWrapKind { kind: wrap.kind });
    }

    let wrap_ck = nip44::get_conversation_key(recipient_sk, &wrap.pubkey)?;
    let seal_json = nip44::decrypt(&wrap_ck, &wrap.content)?;
    let seal_event = event_from_json(&seal_json)?;

    if seal_event.kind != KIND_SEAL {
        return Err(Nip59Error::WrongSealKind {
            kind: seal_event.kind,
        });
    }
    if !seal_event.tags.is_empty() {
        return Err(Nip59Error::SealTagsNotEmpty);
    }

    let seal_ck = nip44::get_conversation_key(recipient_sk, &seal_event.pubkey)?;
    let rumor_json = nip44::decrypt(&seal_ck, &seal_event.content)?;
    let rumor = rumor_from_json(&rumor_json)?;

    // THE authenticity check: rumor must not claim a foreign author.
    if seal_event.pubkey != rumor.pubkey {
        return Err(Nip59Error::SealAuthorMismatch {
            seal_pubkey: seal_event.pubkey,
            rumor_pubkey: rumor.pubkey,
        });
    }

    Ok(Unwrapped {
        rumor,
        seal: seal_event,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    /// Deterministic CSPRNG stand-in: SHA-256 chain. Explicit test fixture —
    /// not a production default.
    struct ChainRng {
        state: [u8; 32],
    }

    impl ChainRng {
        fn new(seed_label: &[u8]) -> Self {
            Self {
                state: Sha256::digest(seed_label).into(),
            }
        }
    }

    impl SecureRandom for ChainRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Nip59Error> {
            let mut filled = 0;
            while filled < dest.len() {
                self.state = Sha256::digest(self.state).into();
                let n = (dest.len() - filled).min(32);
                dest[filled..filled + n].copy_from_slice(&self.state[..n]);
                filled += n;
            }
            Ok(())
        }
    }

    fn fixture_sk(label: &[u8]) -> [u8; 32] {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let _ = Keypair::from_secret_key(&secp, &sk);
                return sk_bytes;
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    fn fixture_pk(sk: &[u8; 32]) -> [u8; 32] {
        xonly_from_sk(sk).expect("fixture sk")
    }

    fn sample_rumor(author_pk: [u8; 32]) -> Rumor {
        Rumor::create(
            author_pk,
            1_700_000_000,
            1420,
            vec![],
            r#"{"blob_id":"aa","blob_locators":"AQ","ack_nonce":"bb"}"#.to_string(),
        )
    }

    #[test]
    fn rumor_has_id_and_no_sig_field() {
        let sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let pk = fixture_pk(&sk);
        let rumor = sample_rumor(pk);
        // Type: Rumor has no `sig`. Id is the NIP-01 hash.
        assert_eq!(
            rumor.id,
            compute_event_id(
                &rumor.pubkey,
                rumor.created_at,
                rumor.kind,
                &rumor.tags,
                &rumor.content
            )
        );
        // JSON for encryption omits sig (serde skip_serializing + None).
        let json = rumor_to_json(&rumor).expect("json");
        assert!(
            !json.contains("\"sig\""),
            "rumor JSON must not include sig: {json}"
        );
    }

    #[test]
    fn seal_and_wrap_roundtrip() {
        let alice_sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let bob_sk = fixture_sk(b"zkCoins/v1/test/nip59/bob");
        let alice_pk = fixture_pk(&alice_sk);
        let bob_pk = fixture_pk(&bob_sk);
        let rumor = sample_rumor(alice_pk);

        let mut rng = ChainRng::new(b"zkCoins/v1/test/nip59/rng-roundtrip");
        let now = 1_800_000_000u64;
        let detect = [0x11u8; 32];
        let epk = [0x22u8; 32];
        let tags = delivery_scan_tags(&detect, &epk);

        let wrap = seal_and_wrap(&rumor, &alice_sk, &bob_pk, tags.clone(), now, &mut rng)
            .expect("seal_and_wrap");

        assert_eq!(wrap.kind, KIND_GIFT_WRAP);
        assert_eq!(wrap.tags, tags);
        // Wrap author is ephemeral — not Alice, not Bob.
        assert_ne!(wrap.pubkey, alice_pk);
        assert_ne!(wrap.pubkey, bob_pk);
        assert!(wrap.created_at <= now);
        assert!(now - wrap.created_at <= MAX_CREATED_AT_PAST_SECS);

        let unwrapped = unwrap_gift(&wrap, &bob_sk).expect("unwrap");
        assert_eq!(unwrapped.rumor, rumor);
        assert_eq!(unwrapped.seal.pubkey, alice_pk);
        assert_eq!(unwrapped.seal.kind, KIND_SEAL);
        assert!(unwrapped.seal.tags.is_empty());
        assert!(unwrapped.seal.created_at <= now);
    }

    #[test]
    fn forged_rumor_author_is_rejected() {
        // Mallory seals a rumor that claims Alice as author.
        let alice_sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let mallory_sk = fixture_sk(b"zkCoins/v1/test/nip59/mallory");
        let bob_sk = fixture_sk(b"zkCoins/v1/test/nip59/bob");
        let alice_pk = fixture_pk(&alice_sk);
        let mallory_pk = fixture_pk(&mallory_sk);
        let bob_pk = fixture_pk(&bob_sk);

        // Rumor claims Alice; Mallory would have to seal it. seal() rejects
        // the author mismatch at seal time — build a forged path by sealing
        // with a rumor that has Mallory as author, then manually constructing
        // a mismatched inner after... That is blocked at seal.
        //
        // The authenticity check that NIP-59 depends on is exercised by
        // building a seal whose JSON-decrypted rumor has a different pubkey:
        // seal with Mallory over a Mallory-authored rumor, then craft a wrap
        // is fine; to forge Alice we must bypass seal()'s author check and
        // inject a foreign rumor into a Mallory-signed seal ciphertext.
        //
        // Simulate the attack at the unwrap boundary: take a valid Mallory
        // seal, replace its NIP-44 content with encryption of an Alice-claim
        // rumor under Mallory's conversation key with Bob, and re-sign the
        // seal as Mallory. Unwrap must then hit SealAuthorMismatch.

        let alice_claim = Rumor::create(
            alice_pk,
            1_700_000_000,
            1420,
            vec![],
            "forged-as-alice".to_string(),
        );
        // Direct seal of alice_claim under mallory must fail at seal time.
        let mut rng = ChainRng::new(b"zkCoins/v1/test/nip59/rng-forge");
        let seal_err = seal(&alice_claim, &mallory_sk, &bob_pk, 1_800_000_000, &mut rng)
            .expect_err("seal must refuse rumor that claims a foreign author");
        match seal_err {
            Nip59Error::RumorAuthorMismatch {
                rumor_pubkey,
                sealer_pubkey,
            } => {
                assert_eq!(rumor_pubkey, alice_pk);
                assert_eq!(sealer_pubkey, mallory_pk);
            }
            other => panic!("expected RumorAuthorMismatch, got {other:?}"),
        }

        // Bypass seal-time check: encrypt alice-claim rumor under
        // conversation_key(mallory, bob), sign seal as Mallory.
        let ck = nip44::get_conversation_key(&mallory_sk, &bob_pk).expect("ck");
        let plain = rumor_to_json(&alice_claim).expect("json");
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce).expect("nonce");
        let content = nip44::encrypt(&ck, &plain, &nonce).expect("encrypt");
        let forged_seal = Event::sign(&mallory_sk, 1_799_000_000, KIND_SEAL, vec![], content)
            .expect("sign seal as mallory");
        assert_eq!(forged_seal.pubkey, mallory_pk);

        let wrap = gift_wrap(
            &forged_seal,
            &bob_pk,
            delivery_scan_tags(&[0x33; 32], &[0x44; 32]),
            1_800_000_000,
            &mut rng,
        )
        .expect("wrap forged seal");

        let err = unwrap_gift(&wrap, &bob_sk).expect_err("forged author must fail");
        match err {
            Nip59Error::SealAuthorMismatch {
                seal_pubkey,
                rumor_pubkey,
            } => {
                assert_eq!(seal_pubkey, mallory_pk, "seal is signed by Mallory");
                assert_eq!(rumor_pubkey, alice_pk, "rumor falsely claims Alice");
            }
            other => panic!("expected SealAuthorMismatch, got {other:?}"),
        }
    }

    #[test]
    fn wrap_carries_exactly_delivery_scan_tags() {
        let alice_sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let bob_sk = fixture_sk(b"zkCoins/v1/test/nip59/bob");
        let alice_pk = fixture_pk(&alice_sk);
        let bob_pk = fixture_pk(&bob_sk);
        let detect = {
            let mut d = [0u8; 32];
            d[0] = 0xab;
            d
        };
        let epk = {
            let mut e = [0u8; 32];
            e[0] = 0xcd;
            e
        };
        let tags = delivery_scan_tags(&detect, &epk);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0][0], "zkdt");
        assert_eq!(tags[0][1], hex::encode(detect));
        assert_eq!(tags[1][0], "zkepk");
        assert_eq!(tags[1][1], hex::encode(epk));

        let mut rng = ChainRng::new(b"zkCoins/v1/test/nip59/rng-tags");
        let wrap = seal_and_wrap(
            &sample_rumor(alice_pk),
            &alice_sk,
            &bob_pk,
            tags.clone(),
            1_800_000_000,
            &mut rng,
        )
        .expect("wrap");
        assert_eq!(wrap.tags, tags);
        // No `p` tag, no blob_id, no extra metadata on the outer event.
        assert!(wrap.tags.iter().all(|t| t[0] == "zkdt" || t[0] == "zkepk"));
        assert!(!wrap.tags.iter().any(|t| t[0] == "p"));
        assert!(!wrap.tags.iter().any(|t| t[0] == "blob_id"));
    }

    #[test]
    fn seal_and_wrap_created_at_are_independently_drawn() {
        let alice_sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let bob_sk = fixture_sk(b"zkCoins/v1/test/nip59/bob");
        let alice_pk = fixture_pk(&alice_sk);
        let bob_pk = fixture_pk(&bob_sk);
        let mut rng = ChainRng::new(b"zkCoins/v1/test/nip59/rng-time");
        let now = 1_800_000_000u64;
        let seal_event =
            seal(&sample_rumor(alice_pk), &alice_sk, &bob_pk, now, &mut rng).expect("seal");
        let wrap = gift_wrap(&seal_event, &bob_pk, vec![], now, &mut rng).expect("wrap");
        // Both in the allowed window; with a non-degenerate RNG they almost
        // always differ — pin that the draws are separate values of the chain.
        assert!(seal_event.created_at <= now);
        assert!(wrap.created_at <= now);
        // ChainRng advances: consecutive draws yield different timestamps
        // except on a modular collision (astronomically rare for 8-byte mod).
        // Assert only the normative bound, and that they are not both forced
        // to `now` (which a silent default clock+zero-skew would produce).
        let seal_skew = now - seal_event.created_at;
        let wrap_skew = now - wrap.created_at;
        assert!(seal_skew <= MAX_CREATED_AT_PAST_SECS);
        assert!(wrap_skew <= MAX_CREATED_AT_PAST_SECS);
        // At least one of the two is non-zero with this seed (deterministic).
        assert!(
            seal_skew != 0 || wrap_skew != 0,
            "timestamp jitter must not be stuck at zero"
        );
    }

    #[test]
    fn ephemeral_key_is_fresh_per_wrap() {
        let alice_sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let bob_sk = fixture_sk(b"zkCoins/v1/test/nip59/bob");
        let alice_pk = fixture_pk(&alice_sk);
        let bob_pk = fixture_pk(&bob_sk);
        let mut rng = ChainRng::new(b"zkCoins/v1/test/nip59/rng-eph");
        let now = 1_800_000_000u64;
        let seal_event =
            seal(&sample_rumor(alice_pk), &alice_sk, &bob_pk, now, &mut rng).expect("seal");
        let w1 = gift_wrap(&seal_event, &bob_pk, vec![], now, &mut rng).expect("w1");
        let w2 = gift_wrap(&seal_event, &bob_pk, vec![], now, &mut rng).expect("w2");
        assert_ne!(
            w1.pubkey, w2.pubkey,
            "each wrap must use a fresh ephemeral key"
        );
        assert_ne!(w1.id, w2.id);
    }

    #[test]
    fn rumor_with_sig_field_in_json_is_rejected() {
        let alice_sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let bob_sk = fixture_sk(b"zkCoins/v1/test/nip59/bob");
        let bob_pk = fixture_pk(&bob_sk);
        let alice_pk = fixture_pk(&alice_sk);
        let mut rng = ChainRng::new(b"zkCoins/v1/test/nip59/rng-sigfield");

        // Build a seal whose plaintext is a rumor JSON with a sig field.
        let rumor = sample_rumor(alice_pk);
        let signed_looking = serde_json::json!({
            "id": hex::encode(rumor.id),
            "pubkey": hex::encode(rumor.pubkey),
            "created_at": rumor.created_at,
            "kind": rumor.kind,
            "tags": rumor.tags,
            "content": rumor.content,
            "sig": hex::encode([0x55u8; 64]),
        });
        let plain = signed_looking.to_string();
        let ck = nip44::get_conversation_key(&alice_sk, &bob_pk).expect("ck");
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce).expect("nonce");
        let content = nip44::encrypt(&ck, &plain, &nonce).expect("enc");
        let seal_event =
            Event::sign(&alice_sk, 1_799_000_000, KIND_SEAL, vec![], content).expect("sign");
        let wrap = gift_wrap(&seal_event, &bob_pk, vec![], 1_800_000_000, &mut rng).expect("wrap");

        let err = unwrap_gift(&wrap, &bob_sk).expect_err("signed rumor JSON must fail");
        assert_eq!(err, Nip59Error::RumorHasSignature);
    }

    #[test]
    fn wrong_recipient_cannot_decrypt() {
        let alice_sk = fixture_sk(b"zkCoins/v1/test/nip59/alice");
        let bob_sk = fixture_sk(b"zkCoins/v1/test/nip59/bob");
        let eve_sk = fixture_sk(b"zkCoins/v1/test/nip59/eve");
        let alice_pk = fixture_pk(&alice_sk);
        let bob_pk = fixture_pk(&bob_sk);
        let mut rng = ChainRng::new(b"zkCoins/v1/test/nip59/rng-wrong-rx");
        let wrap = seal_and_wrap(
            &sample_rumor(alice_pk),
            &alice_sk,
            &bob_pk,
            vec![],
            1_800_000_000,
            &mut rng,
        )
        .expect("wrap");
        let err = unwrap_gift(&wrap, &eve_sk).expect_err("eve must not decrypt");
        match err {
            Nip59Error::Nip44(Nip44Error::MacMismatch) => {}
            other => panic!("expected Nip44 MacMismatch, got {other:?}"),
        }
    }
}
