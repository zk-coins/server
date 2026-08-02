#!/usr/bin/env node
/**
 * A-to-Z local-e2e journey — machine-evaluable pass/fail (mandate §3).
 *
 * No mocks on the protocol path. Fail-closed: first red assertion aborts with
 * a named stage. Custody: this process holds keys and signs via @zkcoins/sdk;
 * the stack never signs.
 *
 * Fixtures (normative mandate §3):
 *   mnemonic V.2-ext, Alice account'=0, Bob=1, Carol=2
 *   USD-Demo, decimals=2, issuance_version=1, supply 1_000_000_000
 *   fee-less (D9); every confirmation wait = 6 mined blocks
 *
 * Default run: stages 1–2 (hard). Stages 2b–11 are named controls that fail
 * with an honest TODO when the surrounding mechanics are not yet operable.
 */

import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { HDKey } from '@scure/bip32';
import { schnorr } from '@noble/curves/secp256k1.js';

import {
  GENESIS_TAG,
  assetIdV1,
  addressFromParts,
  bip340NormaliseSecret,
  canonicalHostFromApiUrl,
  chanBindForHost,
  decodeHexExact,
  decodeZkAddress,
  deriveSk0,
  deriveSpendKey,
  digestToBytes,
  encodeHexLower,
  encodeZkAddress,
  freshNpkRand,
  nkCommit,
  parseExpiryDecimal,
  pullChallengeMessage,
  seedFromMnemonicV1,
  ZkCoinsV1Client,
} from '@zkcoins/sdk';

// ---------------------------------------------------------------------------
// Constants (mandate §3 + circuit bounds + V.2-ext)
// ---------------------------------------------------------------------------

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const PINNED_DIGEST_C =
  process.env.ZKCOINS_CIRCUIT_DIGEST_C ??
  '9d256e8c828f531fc6cf9ffd4fa1ca9480473d00a99f92ea535912daa34e8352';
const PINNED_DIGEST_C_BALANCE =
  process.env.ZKCOINS_CIRCUIT_DIGEST_C_BALANCE ??
  'bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d';

/** Circuit dimensioning (node program-plonky2 / shared). */
const BOUNDS = {
  finality_confirmations: 6,
  max_tx_inputs: 8,
  max_tx_outputs: 8,
  max_rx_coins: 4,
  max_account_assets: 32,
  activation_height: 0,
};

const USD_DEMO = {
  name: 'USD-Demo',
  decimals: 2,
  issuance_version: 1,
  amount: '1000000000',
};
const SEND_AMOUNT = '250000';

const API_URL = (process.env.ZKCOINS_API_URL ?? 'http://127.0.0.1:8080').replace(/\/+$/, '');
const COMPOSE_FILE =
  process.env.COMPOSE_FILE ??
  resolve(dirname(fileURLToPath(import.meta.url)), '../../compose.yaml');
const WALLET = process.env.ZKCOINS_V1_BITCOIND_WALLET ?? 'zkcoins';

const JOB_WAIT_MS = Number(process.env.ZKCOINS_E2E_JOB_TIMEOUT_MS ?? 30 * 60 * 1000);
const POLL_CAP_MS = 15_000;

// ---------------------------------------------------------------------------
// Fail-closed harness
// ---------------------------------------------------------------------------

function fail(stage, message) {
  console.error(`journey FAIL [stage ${stage}]: ${message}`);
  process.exit(1);
}

function pass(stage, message) {
  console.log(`journey PASS [stage ${stage}]: ${message}`);
}

function log(msg) {
  console.error(`journey: ${msg}`);
}

// ---------------------------------------------------------------------------
// HTTP helpers (raw surfaces not on ZkCoinsV1Client)
// ---------------------------------------------------------------------------

async function httpJson(method, url, body, headers = {}) {
  const init = {
    method,
    headers: { Accept: 'application/json', ...headers },
  };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  const text = await res.text();
  let json = null;
  if (text.length > 0) {
    try {
      json = JSON.parse(text);
    } catch {
      /* non-JSON */
    }
  }
  return { status: res.status, json, text, headers: res.headers };
}

async function sleep(ms) {
  await new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// bitcoind mining via compose
// ---------------------------------------------------------------------------

function btcCli(args) {
  const r = spawnSync(
    'docker',
    [
      'compose',
      '-f',
      COMPOSE_FILE,
      'exec',
      '-T',
      'bitcoind',
      'bitcoin-cli',
      '-regtest',
      '-datadir=/home/bitcoin/.bitcoin',
      ...args,
    ],
    { encoding: 'utf8' },
  );
  if (r.status !== 0) {
    fail(
      'mine',
      `bitcoin-cli ${args.join(' ')} failed (exit ${r.status}): ${r.stderr || r.stdout}`,
    );
  }
  return (r.stdout || '').trim().replace(/\r/g, '');
}

function mineBlocks(n, stage) {
  log(`mining ${n} regtest block(s)…`);
  const addr = btcCli([`-rpcwallet=${WALLET}`, 'getnewaddress']);
  btcCli([`-rpcwallet=${WALLET}`, 'generatetoaddress', String(n), addr]);
  pass(stage, `mined ${n} block(s)`);
}

// ---------------------------------------------------------------------------
// Wallet material (V.2-ext accounts)
// ---------------------------------------------------------------------------

function deriveBranch(seed, account, pathSuffix) {
  const master = HDKey.fromMasterSeed(seed);
  const path = `m/1798'/${account}'/${pathSuffix}`;
  const child = master.derive(path);
  if (!child.privateKey) {
    fail('keys', `no private key at ${path}`);
  }
  return child.privateKey.slice();
}

function buildAccount(seed, accountIndex) {
  const sk0 = deriveSk0(seed, accountIndex);
  const nk = deriveBranch(seed, accountIndex, "3'");
  const ivk = deriveBranch(seed, accountIndex, "1'/0'");
  const ovk = deriveBranch(seed, accountIndex, "1'/1'");
  const op = deriveBranch(seed, accountIndex, "2'");
  const opSecret = deriveBranch(seed, accountIndex, "4'");
  const nkCommitBytes = digestToBytes(nkCommit(nk));
  const addressRaw = addressFromParts(sk0.publicKey, nkCommitBytes);
  const subject = encodeZkAddress(addressRaw);
  const bundle = new Uint8Array(161);
  bundle[0] = 0x01;
  bundle.set(ivk, 1);
  bundle.set(ovk, 33);
  bundle.set(op, 65);
  bundle.set(nk, 97);
  bundle.set(opSecret, 129);
  const { pkBytes: opPubkey } = bip340NormaliseSecret(op);
  return {
    accountIndex,
    sk0,
    nk,
    nkCommit: nkCommitBytes,
    subject,
    bundleHex: encodeHexLower(bundle),
    op,
    opPubkey,
    sendCounter: 0,
  };
}

function spendAt(seed, account, index) {
  return deriveSpendKey(seed, account, index);
}

/** OwnershipProof for a challenge domain other than PullChallenge (e.g. Entrust). */
function buildDomainOwnershipProof({
  subject,
  sk0Secret,
  nkCommitBytes,
  challenge,
  host,
  expectedDomain,
}) {
  if (challenge.domain !== expectedDomain) {
    fail(
      'ownership',
      `challenge domain ${JSON.stringify(challenge.domain)} ≠ ${JSON.stringify(expectedDomain)}`,
    );
  }
  const subjectRaw = decodeZkAddress(subject);
  const nonce = decodeHexExact(challenge.nonce, 32, 'challenge.nonce');
  const expiry = parseExpiryDecimal(String(challenge.expiry));
  const chanBind = chanBindForHost(host);
  const chal = pullChallengeMessage({
    domain: expectedDomain,
    nonce,
    chanBind,
    subjectRaw,
    expiry,
  });
  const { pkBytes } = bip340NormaliseSecret(sk0Secret);
  const signature = schnorr.sign(chal, sk0Secret, new Uint8Array(32));
  return {
    type: 'ownership',
    subject,
    public_key: encodeHexLower(pkBytes),
    nk_commit: encodeHexLower(nkCommitBytes),
    signature: encodeHexLower(signature),
  };
}

// ---------------------------------------------------------------------------
// AccountState balances parser (V.3 / serialize.rs — 140 B prefix + 48 B/entry)
// ---------------------------------------------------------------------------

function parseBalancesMap(accountStateHex) {
  const byteLen = accountStateHex.length / 2;
  const bytes = decodeHexExact(accountStateHex, byteLen, 'account_state');
  if (bytes.length < 140) {
    fail('balance', `account_state shorter than 140-byte prefix (${bytes.length})`);
  }
  const count = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(
    136,
    false,
  );
  const expected = 140 + 48 * count;
  if (bytes.length !== expected) {
    fail(
      'balance',
      `account_state length ${bytes.length} ≠ expected ${expected} for ${count} balances`,
    );
  }
  /** @type {Map<string, string>} */
  const map = new Map();
  let off = 140;
  for (let i = 0; i < count; i++) {
    const aid = encodeHexLower(bytes.subarray(off, off + 32));
    off += 32;
    let amount = 0n;
    for (let j = 0; j < 16; j++) {
      amount = (amount << 8n) | BigInt(bytes[off + j]);
    }
    off += 16;
    map.set(aid, amount.toString(10));
  }
  return map;
}

function assertBalancesExact(stage, map, expected) {
  const expKeys = Object.keys(expected).sort();
  const gotKeys = [...map.keys()].sort();
  if (expKeys.length !== gotKeys.length || expKeys.some((k, i) => k !== gotKeys[i])) {
    fail(
      stage,
      `balances map keys mismatch: expected [${expKeys.join(',')}] got [${gotKeys.join(',')}]`,
    );
  }
  for (const k of expKeys) {
    if (map.get(k) !== expected[k]) {
      fail(stage, `balance for ${k}: expected ${expected[k]}, got ${map.get(k)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Job lifecycle
// ---------------------------------------------------------------------------

async function waitJobStatus(client, jobId, want, stage) {
  const deadline = Date.now() + JOB_WAIT_MS;
  while (Date.now() < deadline) {
    const { job, retryAfterMs } = await client.getJob(jobId);
    if (job.status === want) return job;
    if (job.status === 'failed' || job.status === 'cancelled') {
      fail(
        stage,
        `job ${jobId} terminal ${job.status}: ${JSON.stringify(job.error ?? job)}`,
      );
    }
    const wait = retryAfterMs ?? 2000;
    await sleep(Math.min(wait, POLL_CAP_MS));
  }
  fail(stage, `timeout waiting for job ${jobId} status ${JSON.stringify(want)}`);
}

async function runSignedTransition(client, seed, acct, request, stage) {
  const spend = spendAt(seed, acct.accountIndex, acct.sendCounter);
  const next = spendAt(seed, acct.accountIndex, acct.sendCounter + 1);
  const npkRand = freshNpkRand();

  const body = {
    ...request,
    subject: acct.subject,
    next_pubkey: encodeHexLower(next.publicKey),
    npk_rand: encodeHexLower(npkRand),
  };

  const accepted = await client.submitTransition(body, {
    idempotencyKey: `e2e-${stage}-${randomBytes(8).toString('hex')}`,
  });
  log(`[${stage}] job accepted ${accepted.job_id}`);

  const awaiting = await waitJobStatus(client, accepted.job_id, 'awaiting_signature', stage);
  if (!awaiting.awaiting_signature) {
    fail(stage, `job ${accepted.job_id} status awaiting_signature but payload absent`);
  }

  // Wallet-side recomputation of ProofData + three refusals (mandate step 3/§7.5).
  const accountState = {
    current_pubkey: encodeHexLower(spend.publicKey),
    send_counter: acct.sendCounter,
  };

  const { job: postSign } = await client.refuseOrSignAndSubmit({
    jobId: accepted.job_id,
    localPubkey: spend.publicKey,
    secretKey: spend.secretKey,
    accountState,
    awaiting: awaiting.awaiting_signature,
    nextPubkey: next.publicKey,
    npkRand,
    nodeNetwork: 'regtest',
  });
  log(`[${stage}] signed; status=${postSign.status}`);

  const completed = await waitJobStatus(client, accepted.job_id, 'completed', stage);
  acct.sendCounter += 1;
  return { jobId: accepted.job_id, job: completed, spendPubkey: spend.publicKey };
}

// ---------------------------------------------------------------------------
// Entrust + pull balances
// ---------------------------------------------------------------------------

async function entrustBundle(acct, host) {
  const ch = await httpJson('POST', `${API_URL}/v1/bootstrap/challenge`, {
    subject: acct.subject,
    action: 'entrust',
  });
  if (ch.status !== 200 || !ch.json) {
    fail('entrust', `bootstrap/challenge HTTP ${ch.status}: ${ch.text}`);
  }
  const proof = buildDomainOwnershipProof({
    subject: acct.subject,
    sk0Secret: acct.sk0.secretKey,
    nkCommitBytes: acct.nkCommit,
    challenge: {
      nonce: ch.json.nonce,
      expiry: String(ch.json.expiry),
      domain: ch.json.domain,
    },
    host,
    expectedDomain: 'zkCoins/v1/EntrustChallenge',
  });
  const en = await httpJson('POST', `${API_URL}/v1/bootstrap/entrust`, {
    challenge: { nonce: ch.json.nonce, expiry: String(ch.json.expiry) },
    ownership_proof: proof,
    bundle: acct.bundleHex,
  });
  if (en.status !== 200 || !en.json?.accepted) {
    fail('entrust', `bootstrap/entrust HTTP ${en.status}: ${en.text}`);
  }
  pass('entrust', `operational bundle accepted for account'=${acct.accountIndex}`);
}

async function pullBalances(client, acct) {
  const pull = await client.openOwnershipPullSession({
    subject: acct.subject,
    sk0: acct.sk0.secretKey,
    nkCommit: acct.nkCommit,
  });
  const state = await client.getAccountState(pull.session);
  return parseBalancesMap(state.account_state);
}

// ---------------------------------------------------------------------------
// Nullifier / inscription §3.10
// ---------------------------------------------------------------------------

async function waitNullifierCompleted(pubkeyHex, stage) {
  const deadline = Date.now() + JOB_WAIT_MS;
  while (Date.now() < deadline) {
    const res = await httpJson('GET', `${API_URL}/v1/chain/nullifier/${pubkeyHex}`);
    if (res.status === 200 && res.json?.present === true) {
      return res.json;
    }
    await sleep(2000);
  }
  fail(stage, `nullifier for ${pubkeyHex} never present on /v1/chain/nullifier after timeout`);
}

async function waitInscriptionCompletedForPubkey(pubkeyHex, stage) {
  const deadline = Date.now() + JOB_WAIT_MS;
  while (Date.now() < deadline) {
    const res = await httpJson('GET', `${API_URL}/v1/chain/inscriptions?limit=50`);
    if (res.status === 200 && Array.isArray(res.json?.inscriptions)) {
      for (const ins of res.json.inscriptions) {
        const members = ins.nullifiers ?? ins.members ?? [];
        for (const m of members) {
          const pk = m.pubkey ?? m.pk ?? m.public_key;
          if (typeof pk === 'string' && pk.toLowerCase() === pubkeyHex.toLowerCase()) {
            const memberState = m.state;
            if (
              ins.confirmation_state === 'completed' &&
              (memberState === 'completed' || memberState === undefined)
            ) {
              return { inscription: ins, member: m };
            }
          }
        }
      }
    }
    await sleep(3000);
  }
  fail(stage, `no inscription with confirmation_state=completed for pubkey ${pubkeyHex}`);
}

function publisherPubkeyHex() {
  const skHex = process.env.PUBLISHER_KEY;
  if (!skHex || skHex.startsWith('REPLACE_ME_')) {
    return null;
  }
  try {
    const sk = decodeHexExact(skHex, 32, 'PUBLISHER_KEY');
    const { pkBytes } = bip340NormaliseSecret(sk);
    return encodeHexLower(pkBytes);
  } catch (e) {
    fail('publisher', `cannot derive publisher pubkey from PUBLISHER_KEY: ${e}`);
  }
}

function usdDemoAssetId(alicePk0) {
  const nameHash = createHash('sha256').update(USD_DEMO.name, 'utf8').digest();
  const aidDigest = assetIdV1(
    GENESIS_TAG,
    alicePk0,
    nameHash,
    USD_DEMO.decimals,
    USD_DEMO.issuance_version,
  );
  return encodeHexLower(digestToBytes(aidDigest));
}

// ---------------------------------------------------------------------------
// Stages
// ---------------------------------------------------------------------------

async function stage1_info(client) {
  const info = await client.info();
  if (info.network !== 'regtest') {
    fail(1, `network: expected regtest, got ${JSON.stringify(info.network)}`);
  }
  if (info.protocol_version !== 'v1') {
    fail(1, `protocol_version: expected v1, got ${JSON.stringify(info.protocol_version)}`);
  }
  const digests = info.circuit_digests;
  if (!digests || typeof digests !== 'object') {
    fail(1, 'circuit_digests missing on /v1/info');
  }
  const c = digests.C ?? digests.c;
  const cb = digests.C_balance ?? digests.c_balance;
  if (c !== PINNED_DIGEST_C) {
    fail(1, `circuit_digests.C: expected ${PINNED_DIGEST_C}, got ${c}`);
  }
  if (cb !== PINNED_DIGEST_C_BALANCE) {
    fail(1, `circuit_digests.C_balance: expected ${PINNED_DIGEST_C_BALANCE}, got ${cb}`);
  }
  for (const [k, v] of Object.entries(BOUNDS)) {
    if (info[k] !== v) {
      fail(1, `bound ${k}: expected ${v}, got ${JSON.stringify(info[k])}`);
    }
  }
  pass(1, 'GET /v1/info matches pinned regtest digests + bounds');
  return info;
}

async function stage2_alice_mint(client, seed, alice, host) {
  await entrustBundle(alice, host);

  const assetIdHex = usdDemoAssetId(alice.sk0.publicKey);
  const pub = publisherPubkeyHex();
  const request = {
    kind: 'mint',
    output_templates: [
      {
        recipient: alice.subject,
        asset_id: assetIdHex,
        amount: USD_DEMO.amount,
      },
    ],
    issuance: {
      name: USD_DEMO.name,
      decimals: USD_DEMO.decimals,
      issuance_version: 1,
      amount: USD_DEMO.amount,
    },
  };
  if (pub) {
    request.publisher_pubkey = pub;
  }

  const { job, spendPubkey } = await runSignedTransition(
    client,
    seed,
    alice,
    request,
    '2-mint',
  );
  pass(2, `Alice mint job completed (${job.job_id}); awaiting_signature recompute ok`);

  mineBlocks(1, '2-include');
  await waitNullifierCompleted(encodeHexLower(spendPubkey), '2-nullifier-present');
  mineBlocks(BOUNDS.finality_confirmations, '2-finality');
  await waitInscriptionCompletedForPubkey(encodeHexLower(spendPubkey), '2-§3.10');
  pass(2, 'mint nullifier inscribed; §3.10 completed after finality blocks');

  const balances = await pullBalances(client, alice);
  assertBalancesExact(2, balances, { [assetIdHex]: USD_DEMO.amount });
  pass(2, `Alice balance USD-Demo == ${USD_DEMO.amount}`);

  return { assetIdHex, mintJob: job, mintSpendPubkey: spendPubkey };
}

async function stage2b_carol_eur() {
  fail(
    '2b',
    'TODO: Carol EUR-Demo token-standard-2 genesis (issuance_version=2, amount=500_000_000, ' +
      'cap_total=500_000_000, terms_salt=terms_salt_fixture, explicit outputs to Alice) + ' +
      "Alice's clause-10 receive → two-asset balances map. Blocked on complete Nostr/Blossom " +
      'delivery for non-self mint outputs (docs/local-stack.md gaps 5–6). Not pretended.',
  );
}

async function stage3_4_alice_send(client, seed, alice, bob, assetIdHex) {
  const pub = publisherPubkeyHex();
  if (!pub) {
    fail(3, 'PUBLISHER_KEY required to assert fee-less case (c) with publisher_pubkey');
  }

  // Negative control: fee_address MUST be rejected (presence matrix).
  const feeReject = await httpJson('POST', `${API_URL}/v1/tx`, {
    kind: 'send',
    subject: alice.subject,
    next_pubkey: encodeHexLower(
      spendAt(seed, alice.accountIndex, alice.sendCounter + 1).publicKey,
    ),
    npk_rand: encodeHexLower(freshNpkRand()),
    publisher_pubkey: pub,
    fee_address: alice.subject,
    input_coins: ['00'.repeat(32)],
    output_templates: [
      { recipient: bob.subject, asset_id: assetIdHex, amount: SEND_AMOUNT },
    ],
  });
  if (feeReject.status < 400) {
    fail(3, `fee_address request MUST be rejected; got HTTP ${feeReject.status}`);
  }
  pass(3, 'fee_address on send is rejected (presence matrix case (c) negative)');

  // Positive path needs Invoice delivery + live Nostr gift-wrap / Blossom.
  fail(
    3,
    'TODO: Alice→Bob fee-less send with real Invoice delivery + AggregateStateNullifierV3 ' +
      'inscription + Alice balance 999_750_000. Shell ready (fee_address negative control ' +
      `passed; publisher_pubkey=${pub.slice(0, 16)}…). Blocked on operable private delivery ` +
      '(IVPK/Invoice + Nostr/Blossom; docs/local-stack.md gaps 5–6). ' +
      'awaiting_signature recompute is hard-exercised on mint (stage 2) via refuseOrSignAndSubmit.',
  );
}

async function stage5_bob_receive() {
  fail(
    5,
    'TODO: Bob receive (kind=receive, fold) self-published → completed; balance == 250_000 — ' +
      'depends on stage 3–4 delivery + discoverable fold_coin_ids.',
  );
}

async function stage6_confirmation_link() {
  fail(
    6,
    'TODO: confirmation link for the Alice→Bob payment reporting §3.10 completed — ' +
      'depends on stages 3–5. Mint path (stage 2) already hard-checks ' +
      '/v1/chain/inscriptions confirmation_state=completed for the mint nullifier.',
  );
}

async function stage7_reorg() {
  fail(
    7,
    'TODO: Reorg control (V.9 N-09) — force a 3-block regtest reorg spanning a pending ' +
      'nullifier; assert both nodes\' (size, mth) and nav_root equal a fresh full rescan. ' +
      'Needs: second node, reorg mining recipe, pending-nullifier harness.',
  );
}

async function stage8_recovery() {
  fail(
    8,
    'TODO: Recovery control (Requirement 6) — destroy Bob node state; restore from seed + ' +
      'regtest chain + replicated blobs; balance and coin set equal pre-destruction. ' +
      'Needs: durable blob replication (k=3), volume wipe + restore procedure.',
  );
}

async function stage9_portability() {
  fail(
    9,
    'TODO: Portability control (Requirement 10) — repoint Alice wallet to a freshly synced ' +
      'second node by configuration only; balances identical; send from new node succeeds. ' +
      'Needs: second node+api compose service and wallet config switch.',
  );
}

async function stage10_attestation(alice) {
  const ch = await httpJson('POST', `${API_URL}/v1/attest/balance/challenge`, {
    subject: alice.subject,
  });
  if (ch.status >= 500) {
    fail(10, `attest challenge hard-failed HTTP ${ch.status}: ${ch.text}`);
  }
  fail(
    10,
    'TODO: Attestation control (Requirement 9(b)) — Alice POST /v1/attest/balance for ' +
      'USD-Demo; fresh verifier validates proof, host-side anchors, nav_ceiling against own scan. ' +
      `Challenge endpoint responded HTTP ${ch.status} (surface present). Full verify path not automated.`,
  );
}

async function stage11_grants(alice) {
  const ch = await httpJson('POST', `${API_URL}/v1/grants/challenge`, {
    subject: alice.subject,
  });
  if (ch.status >= 500) {
    fail(11, `grants challenge hard-failed HTTP ${ch.status}: ${ch.text}`);
  }
  fail(
    11,
    'TODO: Grant control (Requirement 9(c)) — Alice issues USD-Demo-scoped view grant; ' +
      'grantee pulls in-scope records only and cannot pull EUR-Demo (scope clamp). ' +
      `Challenge endpoint responded HTTP ${ch.status}. Needs EUR-Demo (stage 2b) + grant pull harness.`,
  );
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const STAGES = {
  1: 'info digests + bounds',
  2: 'Alice mint USD-Demo → completed + §3.10 + balance',
  '2b': 'Carol EUR-Demo genesis + Alice receive (TODO)',
  3: 'Alice send fee-less to Bob + awaiting_signature recompute',
  4: 'Alice balance after send (paired with 3)',
  5: 'Bob receive fold + balance',
  6: 'confirmation link §3.10 completed',
  7: 'reorg control N-09 (TODO)',
  8: 'recovery control Req 6 (TODO)',
  9: 'portability control Req 10 (TODO)',
  10: 'attestation control Req 9(b) (TODO)',
  11: 'grant control Req 9(c) (TODO)',
};

function parseArgs(argv) {
  /** @type {{ list: boolean, stages: string[] }} */
  const out = { list: false, stages: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--list') out.list = true;
    else if (a === '--stage') {
      const v = argv[++i];
      if (!v) fail('cli', '--stage requires a value');
      out.stages.push(v);
    } else if (a === '-h' || a === '--help') {
      console.log(`Usage: journey.mjs [--stage N]… [--list]
Default: stages 1 and 2 (hard core that this tree can drive unmocked).
Stages 2b–11 are named and fail with TODO until their mechanics are operable.
`);
      process.exit(0);
    } else {
      fail('cli', `unknown argument: ${a}`);
    }
  }
  if (out.stages.length === 0 && !out.list) {
    out.stages = ['1', '2'];
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.list) {
    for (const [k, v] of Object.entries(STAGES)) {
      console.log(`  ${String(k).padStart(3)}  ${v}`);
    }
    process.exit(0);
  }

  const health = await httpJson('GET', `${API_URL}/health`);
  if (health.status !== 200 || (health.text || '').trim() !== 'ok') {
    fail(
      'preflight',
      `api /health not ok (HTTP ${health.status}: ${health.text}) — run up.sh first`,
    );
  }

  const client = new ZkCoinsV1Client({
    apiUrl: API_URL,
    network: 'regtest',
    requestTimeoutMs: 120_000,
  });
  const host = canonicalHostFromApiUrl(API_URL);
  const seed = seedFromMnemonicV1(MNEMONIC);
  const alice = buildAccount(seed, 0);
  const bob = buildAccount(seed, 1);
  const carol = buildAccount(seed, 2);
  void carol;

  log(`API ${API_URL}`);
  log(`Alice ${alice.subject}`);
  log(`Bob   ${bob.subject}`);

  /** @type {{ assetIdHex?: string }} */
  let ctx = {};

  for (const s of args.stages) {
    switch (s) {
      case '1':
        await stage1_info(client);
        break;
      case '2':
        ctx = { ...ctx, ...(await stage2_alice_mint(client, seed, alice, host)) };
        break;
      case '2b':
        await stage2b_carol_eur();
        break;
      case '3':
      case '4':
        if (!ctx.assetIdHex) {
          fail(s, 'stage 3/4 require stage 2 in the same run (asset id + Alice head)');
        }
        await stage3_4_alice_send(client, seed, alice, bob, ctx.assetIdHex);
        break;
      case '5':
        await stage5_bob_receive();
        break;
      case '6':
        await stage6_confirmation_link();
        break;
      case '7':
        await stage7_reorg();
        break;
      case '8':
        await stage8_recovery();
        break;
      case '9':
        await stage9_portability();
        break;
      case '10':
        await stage10_attestation(alice);
        break;
      case '11':
        await stage11_grants(alice);
        break;
      default:
        fail('cli', `unknown stage ${s}; use --list`);
    }
  }

  console.log('journey: all requested stages passed.');
  process.exit(0);
}

main().catch((err) => {
  console.error('journey FAIL [uncaught]:', err);
  process.exit(1);
});
