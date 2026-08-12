//! §7.5 `OutputTemplate.delivery` — presence rule and both credential checklists.
//!
//! # Where this runs
//!
//! Kernel-only (§6.1 / §7.5 / §7.8). The API layer forwards `delivery`
//! unchanged and must not mark it verified. Failures surface as
//! [`KernelErrorCode::MalformedRequest`] (`ErrorInfo.reason` =
//! `"malformed_request"`) **before** a job is admitted when the check is
//! structural, and as the same machine code when a supplied credential
//! fails its checklist prior to prove.
//!
//! # Reuse
//!
//! Invoice checklist (i)–(iii) and the profile payment-object chain live in
//! [`crate::v1::nostr::profile`]. This module only adds the §7.5 binding
//! (output field equality / address pin), presence, self-output narrowness,
//! profile freshness (relay-relative high-water + clock window), store fill
//! via the existing verified insert paths, and retention hygiene on errors
//! (never quote `pk0` / `nk_commit` / `memo` / signatures in public messages).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::kernel::bootstrap::BundleStore;
use crate::kernel::chain::KernelNetwork;
use crate::kernel::types::{DeliveryCredential, OutputTemplate, SubjectAddress, TransitionCommand};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult};
use crate::v1::delivery::DeliveryTargetStore;
use crate::v1::nostr::event::Event;
use crate::v1::nostr::profile::{
    newer_replaceable, verify_invoice, verify_payment_profile, InvoiceCheckError, ProfileCheckError,
};
use crate::v1::PaymentInvoice;
use shared::spec_v1::{Address, ManifestClock};

/// Maximum future skew for a profile `created_at` relative to the kernel clock
/// (implementation-defined window, §7.5 profile freshness).
pub(crate) const PROFILE_CREATED_AT_FUTURE_SKEW_SECS: u64 = 15 * 60;

/// Maximum age of a profile `created_at` relative to the kernel clock
/// (implementation-defined window, §7.5 profile freshness).
pub(crate) const PROFILE_CREATED_AT_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;

/// Resolve a usable unix-seconds value from the injected kernel clock.
///
/// Bootstrap-manifest verification treats [`ManifestClock::Unavailable`] as
/// "skip the expiry leg only" (signature + network still run). Profile
/// freshness is different: without a clock there is no bound on
/// `created_at`, so admitting the credential would be an unbounded skip of
/// the age window. That is not fail-closed — we refuse with a named reason.
fn require_kernel_now(clock: ManifestClock, index: usize) -> KernelResult<u64> {
    match clock {
        ManifestClock::UnixSeconds(now) => Ok(now),
        ManifestClock::Unavailable => Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Kernel clock unavailable",
            format!(
                "output_templates[{index}].delivery: ManifestClock::Unavailable — \
                 refuse profile age / delivery TTL (bootstrap expiry may skip the \
                 time leg; profile freshness must not)"
            ),
        )),
    }
}

/// NIP-01 replaceable high-water for one author: `(created_at, event_id)`.
type ProfileHighWaterMark = (u64, [u8; 32]);

/// Process-local map of kind-0 high-water marks, keyed by author `op_pubkey`.
type ProfileHighWaterByAuthor = HashMap<[u8; 32], ProfileHighWaterMark>;

/// Process-local high-water mark of kind-0 events accepted as delivery
/// credentials, keyed by author `op_pubkey`.
///
/// Freshness is **relay-relative**: only events this node has already
/// accepted raise the watermark. A withheld newer profile is an availability
/// limit no signature closes (§7.5 / §4.3).
#[derive(Debug, Default)]
pub(crate) struct ProfileHighWaterStore {
    by_author: Mutex<ProfileHighWaterByAuthor>,
}

impl ProfileHighWaterStore {
    pub(crate) fn new() -> Self {
        Self {
            by_author: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn shared() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::new())
    }

    /// Known high-water `(created_at, id)` for `author`, if any.
    pub(crate) fn get(&self, author: &[u8; 32]) -> Option<ProfileHighWaterMark> {
        self.by_author
            .lock()
            .expect("ProfileHighWaterStore mutex poisoned")
            .get(author)
            .copied()
    }

    /// Raise the watermark when `event` is strictly newer under NIP-01 order.
    pub(crate) fn observe(&self, event: &Event) {
        let mut guard = self
            .by_author
            .lock()
            .expect("ProfileHighWaterStore mutex poisoned");
        match guard.get(&event.pubkey) {
            None => {
                guard.insert(event.pubkey, (event.created_at, event.id));
            }
            Some(&(created_at, id)) => {
                let known = Event {
                    id,
                    pubkey: event.pubkey,
                    created_at,
                    kind: 0,
                    tags: Vec::new(),
                    content: String::new(),
                    sig: [0u8; 64],
                };
                if newer_replaceable(event, &known) {
                    guard.insert(event.pubkey, (event.created_at, event.id));
                }
            }
        }
    }
}

/// Inputs for the §7.5 delivery presence + checklist pass.
pub(crate) struct DeliveryCheckDeps<'a> {
    pub bundles: &'a BundleStore,
    pub delivery_targets: &'a DeliveryTargetStore,
    pub profile_high_water: &'a ProfileHighWaterStore,
    /// Persisted `AccountState.owner` for the request subject, when known.
    /// Absence means the owner equality leg of self-output cannot hold.
    pub subject_owner: Option<[u8; 32]>,
    pub network: KernelNetwork,
    /// Injected wall clock for profile age windows and delivery-target TTL.
    ///
    /// Production passes [`ManifestClock::UnixSeconds`] from the system clock;
    /// tests pass a fixed instant. See [`require_kernel_now`] for the
    /// fail-closed treatment of [`ManifestClock::Unavailable`].
    pub clock: ManifestClock,
}

/// Self-output (§7.5, narrow):
/// `decoded(recipient) == decoded(subject) == AccountState.owner`
/// **and** an active operational bundle under **exactly** that subject.
///
/// A hit in the delivery-target store or "ivpk known" never discharges this.
pub(crate) fn is_self_output(
    recipient: &SubjectAddress,
    subject: &SubjectAddress,
    subject_owner: Option<[u8; 32]>,
    bundles: &BundleStore,
) -> bool {
    if recipient.0 != subject.0 {
        return false;
    }
    match subject_owner {
        Some(owner) if owner == subject.0 => {}
        _ => return false,
    }
    bundles.is_active(subject)
}

/// Presence rule + both checklists for every output of a mint/send command.
///
/// On success every verified non-self (and every present self) credential has
/// been inserted into [`DeliveryTargetStore`] via the verified paths; only
/// `{ivpk, op_pubkey, relays}` (+ TTL) remain. Credential secrets never enter
/// the public error string.
pub(crate) fn check_and_store_delivery_credentials(
    command: &TransitionCommand,
    deps: &DeliveryCheckDeps<'_>,
) -> KernelResult<()> {
    let (subject, templates) = match command {
        TransitionCommand::Mint {
            common,
            output_templates,
            ..
        }
        | TransitionCommand::Send {
            common,
            output_templates,
            ..
        } => (common.subject, output_templates.as_slice()),
        TransitionCommand::Receive { .. } => return Ok(()),
    };

    for (i, template) in templates.iter().enumerate() {
        let self_out = is_self_output(
            &template.recipient,
            &subject,
            deps.subject_owner,
            deps.bundles,
        );
        match (&template.delivery, self_out) {
            (None, true) => {
                // Self-output may omit delivery.
            }
            (None, false) => {
                return Err(KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    format!(
                        "output_templates[{i}].delivery is required for non-self outputs \
                         (kind ∈ {{send,mint}})"
                    ),
                ));
            }
            (Some(cred), _) => {
                verify_and_store_one(i, template, cred, deps)?;
            }
        }
    }
    Ok(())
}

fn verify_and_store_one(
    index: usize,
    template: &OutputTemplate,
    cred: &DeliveryCredential,
    deps: &DeliveryCheckDeps<'_>,
) -> KernelResult<()> {
    // TTL + profile age both need a concrete instant; resolve once per credential.
    let now = require_kernel_now(deps.clock, index)?;
    match cred {
        DeliveryCredential::Invoice(invoice) => {
            verify_invoice_against_output(index, template, invoice)?;
            // Insert only after the full checklist — store retains {ivpk,op,relays}.
            deps.delivery_targets
                .insert_verified_invoice_inner(invoice, now)
                .map_err(|e| {
                    // Named class only; DeliveryError Display must not carry secrets.
                    KernelError::new(
                        KernelErrorCode::MalformedRequest,
                        format!(
                            "output_templates[{index}].delivery invoice rejected at store insert: {e}"
                        ),
                    )
                })?;
        }
        DeliveryCredential::Profile(event) => {
            let profile = verify_profile_against_output(index, template, event, now, deps)?;
            deps.delivery_targets
                .insert_verified_profile(&profile, now)
                .map_err(|e| {
                    KernelError::new(
                        KernelErrorCode::MalformedRequest,
                        format!(
                            "output_templates[{index}].delivery profile rejected at store insert: {e}"
                        ),
                    )
                })?;
            // Raise high-water only after acceptance (relay-relative).
            deps.profile_high_water.observe(event);
        }
    }
    Ok(())
}

fn verify_invoice_against_output(
    index: usize,
    template: &OutputTemplate,
    invoice: &PaymentInvoice,
) -> KernelResult<()> {
    // §4.3 (i)–(iii) in order — public messages name the check step only.
    verify_invoice(invoice).map_err(|e| map_invoice_check(index, e))?;

    // Byte-exact equality with the enclosing OutputTemplate.
    if invoice.recipient != template.recipient.0 {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "output_templates[{index}].delivery invoice.recipient does not equal \
                 output_templates[{index}].recipient"
            ),
        ));
    }
    if invoice.asset_id != template.asset_id.0 {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "output_templates[{index}].delivery invoice.asset_id does not equal \
                 output_templates[{index}].asset_id"
            ),
        ));
    }
    if invoice.amount != template.amount {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "output_templates[{index}].delivery invoice.amount does not equal \
                 output_templates[{index}].amount"
            ),
        ));
    }
    Ok(())
}

fn map_invoice_check(index: usize, e: InvoiceCheckError) -> KernelError {
    // Step labels only — never echo pk0 / nk_commit / memo / sig bytes.
    let step = match &e {
        InvoiceCheckError::Check1AddressMismatch { .. } => "check (i) address preimage",
        InvoiceCheckError::Check2BadAddrSig | InvoiceCheckError::Check2Malformed { .. } => {
            "check (ii) addr_sig"
        }
        InvoiceCheckError::Check3BadOpSig | InvoiceCheckError::Check3Malformed { .. } => {
            "check (iii) op sig"
        }
        InvoiceCheckError::InvalidRelays { .. } | InvoiceCheckError::InvalidRelayUrl { .. } => {
            "relay list"
        }
    };
    KernelError::new(
        KernelErrorCode::MalformedRequest,
        format!("output_templates[{index}].delivery invoice failed {step}"),
    )
}

fn verify_profile_against_output(
    index: usize,
    template: &OutputTemplate,
    event: &Event,
    now: u64,
    deps: &DeliveryCheckDeps<'_>,
) -> KernelResult<crate::v1::nostr::profile::VerifiedPaymentProfile> {
    // Clock window (implementation-defined) against the injected `now` —
    // never `SystemTime::now` here (tests pin the instant; production
    // resolves the wall clock at the service edge into `ManifestClock`).
    if event.created_at > now.saturating_add(PROFILE_CREATED_AT_FUTURE_SKEW_SECS) {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "output_templates[{index}].delivery profile created_at is too far in the future"
            ),
        ));
    }
    if now.saturating_sub(event.created_at) > PROFILE_CREATED_AT_MAX_AGE_SECS {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("output_templates[{index}].delivery profile created_at is outside the allowed age window"),
        ));
    }

    // Relay-relative high-water: reject strictly older than a known event.
    if let Some((hw_created, hw_id)) = deps.profile_high_water.get(&event.pubkey) {
        let known = Event {
            id: hw_id,
            pubkey: event.pubkey,
            created_at: hw_created,
            kind: 0,
            tags: Vec::new(),
            content: String::new(),
            sig: [0u8; 64],
        };
        if newer_replaceable(&known, event) {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                format!(
                    "output_templates[{index}].delivery profile is older than the node's \
                     high-water mark for this author (NIP-01 replaceable order)"
                ),
            ));
        }
    }

    let network = deps.network.as_str();
    let profile = verify_payment_profile(event, &event.pubkey, network, None)
        .map_err(|e| map_profile_check(index, e))?;

    // zkcoins.address == output.recipient (decoded 32-byte compare).
    if profile.address != template.recipient.0 {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "output_templates[{index}].delivery profile zkcoins.address does not equal \
                 output_templates[{index}].recipient"
            ),
        ));
    }
    // Bech32m spelling is irrelevant; also refuse a mismatched bech32 string
    // that somehow decoded differently (belt-and-braces via Address encode).
    let _ = Address(profile.address).to_bech32m();

    Ok(profile)
}

fn map_profile_check(index: usize, e: ProfileCheckError) -> KernelError {
    let step = match &e {
        ProfileCheckError::Check1WrongKind { .. }
        | ProfileCheckError::Check1AuthorMismatch { .. }
        | ProfileCheckError::Check1BadSignature(_) => "check (i) kind-0 event signature",
        ProfileCheckError::Check2InvalidContentJson { .. }
        | ProfileCheckError::Check2MissingZkcoins
        | ProfileCheckError::Check2ZkcoinsNotObject
        | ProfileCheckError::Check2ExtraField { .. }
        | ProfileCheckError::Check2OpPubkeyDuplicated
        | ProfileCheckError::Check2MissingField { .. }
        | ProfileCheckError::Check2Version { .. }
        | ProfileCheckError::Check2Network { .. }
        | ProfileCheckError::Check2InvalidHex { .. }
        | ProfileCheckError::Check2InvalidAddress { .. }
        | ProfileCheckError::Check2InvalidRelays { .. }
        | ProfileCheckError::Check2InvalidRelayUrl { .. } => "check (iv) zkcoins object shape",
        ProfileCheckError::Check3AddressMismatch { .. } => "check (ii) address preimage",
        ProfileCheckError::Check4BadAddrSig | ProfileCheckError::Check4Malformed { .. } => {
            "check (iii) addr_sig"
        }
        ProfileCheckError::NameReverseMismatch { .. }
        | ProfileCheckError::Check5NameMessage { .. }
        | ProfileCheckError::Check5BadNameSig
        | ProfileCheckError::Check5Malformed { .. } => "name checklist",
    };
    KernelError::new(
        KernelErrorCode::MalformedRequest,
        format!("output_templates[{index}].delivery profile failed {step}"),
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::types::{
        Digest32, IdempotencyKey, PublisherChoice, TransitionCommon, XOnlyKey,
    };
    use crate::v1::nostr::profile::{
        address_from_parts, invoice_message, sign_bip340, InvoiceMessageParts,
    };
    use sha2::{Digest, Sha256};
    use shared::spec_v1::{Address, ManifestClock};

    fn fixture_sk(label: &[u8]) -> ([u8; 32], [u8; 32]) {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let mut seed = Sha256::digest(label).to_vec();
        loop {
            if let Ok(sk) = SecretKey::from_slice(&seed[..32]) {
                let secp = Secp256k1::new();
                let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
                let (xonly, _) = keypair.x_only_public_key();
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&seed[..32]);
                return (secret, xonly.serialize());
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    struct Acct {
        sk0: [u8; 32],
        pk0: [u8; 32],
        op_sk: [u8; 32],
        op_pk: [u8; 32],
        nk_commit: [u8; 32],
        ivpk: [u8; 32],
        address: [u8; 32],
        address_bech32: String,
    }

    fn sample_acct(label: &str) -> Acct {
        let (sk0, pk0) =
            fixture_sk(format!("zkCoins/v1/test/delivery_cred/{label}/sk0").as_bytes());
        let (op_sk, op_pk) =
            fixture_sk(format!("zkCoins/v1/test/delivery_cred/{label}/op").as_bytes());
        let nk_commit: [u8; 32] = Sha256::digest(format!("nk-{label}").as_bytes()).into();
        let (_, ivpk) = fixture_sk(format!("zkCoins/v1/test/delivery_cred/{label}/ivk").as_bytes());
        let address = address_from_parts(&pk0, &nk_commit);
        Acct {
            sk0,
            pk0,
            op_sk,
            op_pk,
            nk_commit,
            ivpk,
            address,
            address_bech32: Address(address).to_bech32m(),
        }
    }

    fn signed_invoice(acct: &Acct, amount: u128, asset_id: [u8; 32]) -> PaymentInvoice {
        let relays = vec!["wss://relay.example.com".to_string()];
        let msg = invoice_message(InvoiceMessageParts {
            amount,
            recipient: &acct.address,
            pk0: &acct.pk0,
            nk_commit: &acct.nk_commit,
            asset_id: &asset_id,
            memo: None,
            ivpk: &acct.ivpk,
            op_pubkey: &acct.op_pk,
            relays: &relays,
        });
        let addr_sig = sign_bip340(&acct.sk0, &msg).expect("addr_sig");
        let sig = sign_bip340(&acct.op_sk, &msg).expect("op sig");
        PaymentInvoice {
            amount,
            recipient: acct.address,
            asset_id,
            memo: None,
            pk0: acct.pk0,
            nk_commit: acct.nk_commit,
            ivpk: acct.ivpk,
            op_pubkey: acct.op_pk,
            relays,
            addr_sig,
            sig,
        }
    }

    /// Fixed test clock — never the wall clock. All fixture `created_at`
    /// values are relative to this instant so the suite is not time-dependent.
    const TEST_NOW: u64 = 1_700_000_000;

    fn empty_deps<'a>(
        bundles: &'a BundleStore,
        targets: &'a DeliveryTargetStore,
        hw: &'a ProfileHighWaterStore,
        owner: Option<[u8; 32]>,
    ) -> DeliveryCheckDeps<'a> {
        DeliveryCheckDeps {
            bundles,
            delivery_targets: targets,
            profile_high_water: hw,
            subject_owner: owner,
            network: KernelNetwork::Regtest,
            clock: ManifestClock::UnixSeconds(TEST_NOW),
        }
    }

    fn deps_with_clock<'a>(
        bundles: &'a BundleStore,
        targets: &'a DeliveryTargetStore,
        hw: &'a ProfileHighWaterStore,
        owner: Option<[u8; 32]>,
        clock: ManifestClock,
    ) -> DeliveryCheckDeps<'a> {
        DeliveryCheckDeps {
            bundles,
            delivery_targets: targets,
            profile_high_water: hw,
            subject_owner: owner,
            network: KernelNetwork::Regtest,
            clock,
        }
    }

    fn send_with(subject: [u8; 32], template: OutputTemplate) -> TransitionCommand {
        TransitionCommand::Send {
            common: TransitionCommon {
                subject: SubjectAddress(subject),
                next_pubkey: XOnlyKey([0xB2; 32]),
                npk_rand: Digest32([0xC3; 32]),
                publisher: PublisherChoice::SelfPublish,
                idempotency_key: IdempotencyKey::from_validated("k".into()),
            },
            input_coins: vec![Digest32([0x11; 32])],
            output_templates: vec![template],
        }
    }

    #[test]
    fn missing_delivery_on_foreign_output_is_malformed() {
        let payee = sample_acct("payee");
        let subject = sample_acct("subject");
        let bundles = BundleStore::new();
        // Even with the payee's bundle held, a foreign recipient is not self.
        bundles.install_for_test(
            &SubjectAddress(payee.address),
            crate::kernel::bootstrap::OperationalBundle {
                ivk: [1; 32],
                ovk: [2; 32],
                op: [3; 32],
                nk: [4; 32],
                op_secret: [5; 32],
            },
        );
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32([0xE5; 32]),
                amount: 10,
                delivery: None,
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("missing delivery");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("delivery is required"),
            "{}",
            err.public_message
        );
        assert!(
            targets.get(&payee.address).is_none(),
            "store must stay empty on presence failure"
        );
    }

    #[test]
    fn holding_foreign_bundle_does_not_make_self_output() {
        // Self-Output-Erschleichung: recipient is foreign; node holds *their*
        // bundle and knows their owner — still not self for *this* subject.
        let payee = sample_acct("foreign");
        let subject = sample_acct("me");
        let bundles = BundleStore::new();
        bundles.install_for_test(
            &SubjectAddress(payee.address),
            crate::kernel::bootstrap::OperationalBundle {
                ivk: [1; 32],
                ovk: [2; 32],
                op: [3; 32],
                nk: [4; 32],
                op_secret: [5; 32],
            },
        );
        assert!(!is_self_output(
            &SubjectAddress(payee.address),
            &SubjectAddress(subject.address),
            Some(payee.address),
            &bundles,
        ));
    }

    #[test]
    fn invoice_amount_mismatch_is_malformed_and_not_stored() {
        let payee = sample_acct("amt");
        let subject = sample_acct("payer");
        let asset = [0xAAu8; 32];
        let inv = signed_invoice(&payee, 10, asset);
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32(asset),
                amount: 11, // ≠ invoice.amount
                delivery: Some(DeliveryCredential::Invoice(inv)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("amount mismatch");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("amount"),
            "{}",
            err.public_message
        );
        assert!(targets.get(&payee.address).is_none());
        // Retention: public message must not quote credential secrets.
        assert!(!err.public_message.contains(&hex::encode(payee.pk0)));
        assert!(!err.public_message.contains(&hex::encode(payee.nk_commit)));
    }

    #[test]
    fn forged_addr_sig_is_malformed() {
        let payee = sample_acct("addr");
        let subject = sample_acct("payer2");
        let asset = [0xBBu8; 32];
        let mut inv = signed_invoice(&payee, 5, asset);
        inv.addr_sig[0] ^= 0xFF;
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32(asset),
                amount: 5,
                delivery: Some(DeliveryCredential::Invoice(inv)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("bad addr_sig");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("addr_sig"),
            "{}",
            err.public_message
        );
        assert!(targets.get(&payee.address).is_none());
    }

    #[test]
    fn swapped_ivpk_is_malformed() {
        let payee = sample_acct("ivpk");
        let attacker = sample_acct("attacker");
        let subject = sample_acct("payer3");
        let asset = [0xCCu8; 32];
        let mut inv = signed_invoice(&payee, 7, asset);
        // Swap ivpk but keep original signatures → check (ii) fails (message covered real ivpk).
        inv.ivpk = attacker.ivpk;
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32(asset),
                amount: 7,
                delivery: Some(DeliveryCredential::Invoice(inv)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("ivpk swap");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(targets.get(&payee.address).is_none());
    }

    #[test]
    fn honest_invoice_fills_store_without_secrets() {
        let payee = sample_acct("ok");
        let subject = sample_acct("payer4");
        let asset = [0xDDu8; 32];
        let inv = signed_invoice(&payee, 42, asset);
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32(asset),
                amount: 42,
                delivery: Some(DeliveryCredential::Invoice(inv.clone())),
            },
        );
        check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect("honest invoice");
        let stored = targets.get(&payee.address).expect("store filled");
        assert_eq!(stored.ivpk, payee.ivpk);
        assert_eq!(stored.op_pk, payee.op_pk);
        assert_eq!(stored.relays, inv.relays);
        // Retention: pk0 / nk_commit / memo / signatures are not on the target.
        let debug = format!("{stored:?}");
        assert!(!debug.contains(&hex::encode(payee.pk0)));
        assert!(!debug.contains(&hex::encode(payee.nk_commit)));
        assert!(!debug.contains(&hex::encode(inv.addr_sig)));
        assert!(!debug.contains(&hex::encode(inv.sig)));
    }

    fn signed_kind0(acct: &Acct, network: &str, created_at: u64) -> Event {
        use crate::v1::nostr::event::Event;
        use crate::v1::nostr::profile::{profile_invoice_message, KIND_METADATA};
        use serde_json::json;
        use shared::spec_v1::hashes::name_message;

        let relays = vec!["wss://relay.example.com".to_string()];
        let inv_msg = profile_invoice_message(
            &acct.address,
            &acct.pk0,
            &acct.nk_commit,
            &acct.ivpk,
            &acct.op_pk,
            &relays,
        );
        let addr_sig = sign_bip340(&acct.sk0, &inv_msg).expect("addr_sig");
        let name = "alice@example.com";
        let nm = name_message(network, name, &acct.op_pk).expect("name_message");
        let name_sig = sign_bip340(&acct.sk0, &nm).expect("name_sig");
        let content = json!({
            "name": "Alice",
            "nip05": name,
            "zkcoins": {
                "version": 1,
                "network": network,
                "address": acct.address_bech32,
                "pk0": hex::encode(acct.pk0),
                "nk_commit": hex::encode(acct.nk_commit),
                "ivpk": hex::encode(acct.ivpk),
                "relays": relays,
                "addr_sig": hex::encode(addr_sig),
                "name_sig": hex::encode(name_sig),
            }
        })
        .to_string();
        Event::sign(&acct.op_sk, created_at, KIND_METADATA, vec![], content).expect("sign")
    }

    #[test]
    fn profile_address_mismatch_is_malformed() {
        let payee = sample_acct("prof-mismatch");
        let other = sample_acct("other-recip");
        let subject = sample_acct("payer-prof");
        let event = signed_kind0(&payee, "regtest", TEST_NOW);
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(other.address), // ≠ profile.address
                asset_id: Digest32([0x11; 32]),
                amount: 1,
                delivery: Some(DeliveryCredential::Profile(event)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("address mismatch");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("zkcoins.address")
                || err.public_message.contains("recipient"),
            "{}",
            err.public_message
        );
        assert!(targets.get(&payee.address).is_none());
        assert!(targets.get(&other.address).is_none());
    }

    #[test]
    fn profile_bad_event_signature_is_malformed() {
        let payee = sample_acct("prof-badsig");
        let subject = sample_acct("payer-badsig");
        let mut event = signed_kind0(&payee, "regtest", TEST_NOW);
        event.sig[0] ^= 0xFF;
        // Re-wrap as DeliveryCredential::Profile — verify_payment_profile
        // re-checks the event signature (check i).
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32([0x22; 32]),
                amount: 1,
                delivery: Some(DeliveryCredential::Profile(event)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("bad event sig");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("kind-0") || err.public_message.contains("signature"),
            "{}",
            err.public_message
        );
        assert!(targets.get(&payee.address).is_none());
    }

    #[test]
    fn honest_profile_fills_store_and_raises_high_water() {
        let payee = sample_acct("prof-ok");
        let subject = sample_acct("payer-prof-ok");
        // `created_at` is relative to the injected clock, not the wall clock.
        let event = signed_kind0(&payee, "regtest", TEST_NOW);
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32([0x33; 32]),
                amount: 99,
                delivery: Some(DeliveryCredential::Profile(event.clone())),
            },
        );
        check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect("honest profile");
        let stored = targets.get(&payee.address).expect("store filled");
        assert_eq!(stored.ivpk, payee.ivpk);
        assert_eq!(stored.op_pk, payee.op_pk);
        let debug = format!("{stored:?}");
        assert!(!debug.contains(&hex::encode(payee.pk0)));
        assert!(!debug.contains(&hex::encode(payee.nk_commit)));
        assert!(!debug.contains(&hex::encode(event.sig)));
        let hw_mark = hw.get(&payee.op_pk).expect("high-water raised");
        assert_eq!(hw_mark.0, event.created_at);
        assert_eq!(hw_mark.1, event.id);

        // Strictly older under NIP-01 order, but still inside the age window
        // so the high-water leg is what rejects (not the clock window).
        let older_at = TEST_NOW.saturating_sub(3_600); // 1h older
        assert!(
            TEST_NOW.saturating_sub(older_at) <= PROFILE_CREATED_AT_MAX_AGE_SECS,
            "fixture must stay inside the age window so high-water is the failing leg"
        );
        let older = signed_kind0(&payee, "regtest", older_at);
        let cmd2 = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32([0x33; 32]),
                amount: 1,
                delivery: Some(DeliveryCredential::Profile(older)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd2,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("stale profile");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("high-water"),
            "{}",
            err.public_message
        );
    }

    #[test]
    fn profile_created_at_outside_age_window_is_malformed() {
        let payee = sample_acct("prof-old");
        let subject = sample_acct("payer-old");
        // One second past the max-age bound relative to TEST_NOW.
        let too_old_at = TEST_NOW
            .saturating_sub(PROFILE_CREATED_AT_MAX_AGE_SECS)
            .saturating_sub(1);
        let event = signed_kind0(&payee, "regtest", too_old_at);
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32([0x55; 32]),
                amount: 1,
                delivery: Some(DeliveryCredential::Profile(event)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(subject.address)),
        )
        .expect_err("outside age window");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("age window"),
            "{}",
            err.public_message
        );
        assert!(targets.get(&payee.address).is_none());
        assert!(hw.get(&payee.op_pk).is_none());
    }

    #[test]
    fn profile_clock_unavailable_is_rejected() {
        // ManifestClock::Unavailable skips bootstrap expiry; profile freshness
        // must not inherit that skip — refuse with a named internal error.
        let payee = sample_acct("prof-noclock");
        let subject = sample_acct("payer-noclock");
        let event = signed_kind0(&payee, "regtest", TEST_NOW);
        let bundles = BundleStore::new();
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            subject.address,
            OutputTemplate {
                recipient: SubjectAddress(payee.address),
                asset_id: Digest32([0x66; 32]),
                amount: 1,
                delivery: Some(DeliveryCredential::Profile(event)),
            },
        );
        let err = check_and_store_delivery_credentials(
            &cmd,
            &deps_with_clock(
                &bundles,
                &targets,
                &hw,
                Some(subject.address),
                ManifestClock::Unavailable,
            ),
        )
        .expect_err("unavailable clock");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            err.public_message.contains("clock unavailable")
                || err.public_message.to_ascii_lowercase().contains("clock"),
            "{}",
            err.public_message
        );
        assert!(targets.get(&payee.address).is_none());
    }

    #[test]
    fn self_output_may_omit_delivery() {
        let me = sample_acct("self");
        let bundles = BundleStore::new();
        bundles.install_for_test(
            &SubjectAddress(me.address),
            crate::kernel::bootstrap::OperationalBundle {
                ivk: [1; 32],
                ovk: [2; 32],
                op: [3; 32],
                nk: [4; 32],
                op_secret: [5; 32],
            },
        );
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let cmd = send_with(
            me.address,
            OutputTemplate {
                recipient: SubjectAddress(me.address),
                asset_id: Digest32([0x44; 32]),
                amount: 1,
                delivery: None,
            },
        );
        check_and_store_delivery_credentials(
            &cmd,
            &empty_deps(&bundles, &targets, &hw, Some(me.address)),
        )
        .expect("self may omit delivery");
    }
}
