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
  assetIdV2,
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
  issueInvoice,
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
/** Token-standard-2 EUR-Demo fixture (mandate §3 stage 2b / spec V.4). */
const EUR_DEMO = {
  name: 'EUR-Demo',
  decimals: 2,
  issuance_version: 2,
  amount: '500000000',
  cap_total: '500000000',
};
/** `terms_salt_fixture = H("zkCoins/v1/test-vector/terms_salt")` (SHA-256). */
const TERMS_SALT_FIXTURE_HEX = createHash('sha256')
  .update('zkCoins/v1/test-vector/terms_salt', 'utf8')
  .digest('hex');
const SEND_AMOUNT = '250000';
/** Alice balance after fee-less send of SEND_AMOUNT from USD_DEMO.amount. */
const ALICE_AFTER_SEND = '999750000';

const API_URL = (process.env.ZKCOINS_API_URL ?? 'http://127.0.0.1:8080').replace(/\/+$/, '');
/** Compose-internal relay advertised on invoices (node-reachable). */
const RELAY_URL = process.env.ZKCOINS_RELAY_URL ?? 'ws://nostr-relay:8080/';
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
  const { pkBytes: ivpk } = bip340NormaliseSecret(ivk);
  return {
    accountIndex,
    sk0,
    nk,
    nkCommit: nkCommitBytes,
    subject,
    bundleHex: encodeHexLower(bundle),
    op,
    opPubkey,
    ivk,
    ivpk,
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

function eurDemoAssetId(carolPk0) {
  const nameHash = createHash('sha256').update(EUR_DEMO.name, 'utf8').digest();
  const termsSalt = decodeHexExact(TERMS_SALT_FIXTURE_HEX, 32, 'terms_salt_fixture');
  const aidDigest = assetIdV2(
    GENESIS_TAG,
    carolPk0,
    nameHash,
    EUR_DEMO.decimals,
    EUR_DEMO.issuance_version,
    BigInt(EUR_DEMO.cap_total),
    termsSalt,
  );
  return encodeHexLower(digestToBytes(aidDigest));
}

/**
 * Subscribe to GET /v1/receipts/stream and wait for a receipt with
 * state === 'completed' (optionally matching asset_id). SSE framing is
 * axum-style: `event: receipt\ndata: <json>\n\n` (api/src/routes.rs tests;
 * receipt_to_json fields: coin_id, asset_id, amount, state, credited_at).
 *
 * The hub is push-only with no catch-up replay (receipts.rs): open the
 * stream before the credit is published, or the event is missed.
 */
async function waitForCompletedReceipt(sessionToken, assetIdHex, stage) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), JOB_WAIT_MS);
  try {
    const res = await fetch(`${API_URL}/v1/receipts/stream`, {
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        Accept: 'text/event-stream',
      },
      signal: controller.signal,
    });
    if (!res.ok) {
      const body = await res.text();
      fail(stage, `receipts/stream HTTP ${res.status}: ${body}`);
    }
    if (!res.body) {
      fail(stage, 'receipts/stream response has no body');
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        fail(stage, 'receipts/stream ended before a completed receipt arrived');
      }
      buffer += decoder.decode(value, { stream: true });
      // SSE frames are delimited by a blank line (\n\n).
      let sep;
      while ((sep = buffer.indexOf('\n\n')) !== -1) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        const lines = frame.split(/\r?\n/);
        let eventName = 'message';
        const dataParts = [];
        for (const line of lines) {
          if (line.startsWith('event:')) {
            eventName = line.slice('event:'.length).trim();
          } else if (line.startsWith('data:')) {
            dataParts.push(line.slice('data:'.length).trimStart());
          }
        }
        if (eventName === 'error') {
          fail(stage, `receipts/stream error frame: ${dataParts.join('\n')}`);
        }
        if (eventName !== 'receipt' || dataParts.length === 0) {
          continue;
        }
        let receipt;
        try {
          receipt = JSON.parse(dataParts.join('\n'));
        } catch (e) {
          fail(stage, `receipts/stream data is not JSON: ${e}`);
        }
        if (receipt && typeof receipt === 'object') {
          if (receipt.state === 'failed') {
            fail(
              stage,
              `receipt state=failed for coin_id=${receipt.coin_id ?? '?'}`,
            );
          }
          if (receipt.state === 'completed') {
            if (
              assetIdHex !== undefined &&
              typeof receipt.asset_id === 'string' &&
              receipt.asset_id.toLowerCase() !== assetIdHex.toLowerCase()
            ) {
              continue;
            }
            if (typeof receipt.coin_id !== 'string' || receipt.coin_id.length === 0) {
              fail(stage, 'completed receipt missing coin_id');
            }
            try {
              await reader.cancel();
            } catch {
              /* stream already closing */
            }
            return receipt;
          }
          // pending — keep waiting for completed
        }
      }
    }
  } catch (e) {
    if (e && e.name === 'AbortError') {
      fail(stage, `timeout waiting for completed receipt on /v1/receipts/stream`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** Mine 1 inclusion block + finality, then assert §3.10 completed for spend pubkey. */
async function postTransitionOnChain(spendPubkey, stagePrefix) {
  mineBlocks(1, `${stagePrefix}-include`);
  await waitNullifierCompleted(encodeHexLower(spendPubkey), `${stagePrefix}-nullifier-present`);
  mineBlocks(BOUNDS.finality_confirmations, `${stagePrefix}-finality`);
  await waitInscriptionCompletedForPubkey(
    encodeHexLower(spendPubkey),
    `${stagePrefix}-§3.10`,
  );
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

  // First mint has no AccountState yet → self-output exemption fails; every
  // mint/send output (including Alice's self-mint) needs a real Invoice.
  const selfInvoice = await issueInvoice({
    amount: USD_DEMO.amount,
    assetId: assetIdHex,
    relays: [RELAY_URL],
    sk0Secret: alice.sk0.secretKey,
    nkCommit: alice.nkCommit,
    ivpk: alice.ivpk,
    opSecret: alice.op,
  });

  const request = {
    kind: 'mint',
    output_templates: [
      {
        recipient: alice.subject,
        asset_id: assetIdHex,
        amount: USD_DEMO.amount,
        delivery: { type: 'invoice', invoice: selfInvoice },
      },
    ],
    issuance: {
      name: USD_DEMO.name,
      decimals: USD_DEMO.decimals,
      issuance_version: 1,
      amount: USD_DEMO.amount,
      creator_pubkey: encodeHexLower(alice.sk0.publicKey),
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

  await postTransitionOnChain(spendPubkey, '2');
  pass(2, 'mint nullifier inscribed; §3.10 completed after finality blocks');

  const balances = await pullBalances(client, alice);
  assertBalancesExact(2, balances, { [assetIdHex]: USD_DEMO.amount });
  pass(2, `Alice balance USD-Demo == ${USD_DEMO.amount}`);

  return { assetIdHex, mintJob: job, mintSpendPubkey: spendPubkey };
}

async function stage2b_carol_eur(client, seed, alice, carol, host, usdAssetIdHex) {
  await entrustBundle(carol, host);

  const eurAssetIdHex = eurDemoAssetId(carol.sk0.publicKey);
  const pub = publisherPubkeyHex();

  // Token-standard-2 forbids self-credit: mint explicitly to Alice. Alice's
  // Invoice is the delivery credential (non-self output).
  const aliceInvoice = await issueInvoice({
    amount: EUR_DEMO.amount,
    assetId: eurAssetIdHex,
    relays: [RELAY_URL],
    sk0Secret: alice.sk0.secretKey,
    nkCommit: alice.nkCommit,
    ivpk: alice.ivpk,
    opSecret: alice.op,
  });

  // Open Alice's receipts stream before the mint so the credit is not missed
  // (SSE is push-only; no catch-up replay).
  const aliceSession = await client.openOwnershipPullSession({
    subject: alice.subject,
    sk0: alice.sk0.secretKey,
    nkCommit: alice.nkCommit,
  });
  const receiptWait = waitForCompletedReceipt(
    aliceSession.session,
    eurAssetIdHex,
    '2b-receipt',
  );

  const mintRequest = {
    kind: 'mint',
    output_templates: [
      {
        recipient: alice.subject,
        asset_id: eurAssetIdHex,
        amount: EUR_DEMO.amount,
        delivery: { type: 'invoice', invoice: aliceInvoice },
      },
    ],
    issuance: {
      name: EUR_DEMO.name,
      decimals: EUR_DEMO.decimals,
      issuance_version: 2,
      amount: EUR_DEMO.amount,
      cap_total: EUR_DEMO.cap_total,
      terms_salt: TERMS_SALT_FIXTURE_HEX,
      creator_pubkey: encodeHexLower(carol.sk0.publicKey),
    },
  };
  if (pub) {
    mintRequest.publisher_pubkey = pub;
  }

  const { job: mintJob, spendPubkey: mintSpend } = await runSignedTransition(
    client,
    seed,
    carol,
    mintRequest,
    '2b-mint',
  );
  pass('2b', `Carol EUR-Demo mint job completed (${mintJob.job_id})`);

  await postTransitionOnChain(mintSpend, '2b-mint');

  const eurReceipt = await receiptWait;
  const foldCoinId = eurReceipt.coin_id;
  pass('2b', `Alice discovered EUR-Demo coin_id via receipts stream`);

  const receiveRequest = {
    kind: 'receive',
    fold_coin_ids: [foldCoinId],
  };
  const { job: rxJob, spendPubkey: rxSpend } = await runSignedTransition(
    client,
    seed,
    alice,
    receiveRequest,
    '2b-receive',
  );
  pass('2b', `Alice EUR-Demo receive completed (${rxJob.job_id})`);

  await postTransitionOnChain(rxSpend, '2b-receive');

  // After stage 4 Alice holds ALICE_AFTER_SEND USD; if stage 4 has not run,
  // she still holds the full mint. Require usdAssetIdHex for the map key;
  // amount is whatever pull reports for USD plus exact EUR.
  const balances = await pullBalances(client, alice);
  const usdBal = balances.get(usdAssetIdHex);
  if (usdBal === undefined) {
    fail('2b', `Alice missing USD-Demo balance after EUR receive`);
  }
  assertBalancesExact('2b', balances, {
    [usdAssetIdHex]: usdBal,
    [eurAssetIdHex]: EUR_DEMO.amount,
  });
  pass(
    '2b',
    `Alice two-asset balances: USD-Demo=${usdBal}, EUR-Demo=${EUR_DEMO.amount}`,
  );

  return { eurAssetIdHex, carolMintJob: mintJob };
}

async function stage3_4_alice_send(client, seed, alice, bob, host, assetIdHex, aliceMintCoinId) {
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

  // Bob must entrust before Alice delivers so the node holds his ivk/nk for
  // the incoming scanner and any later receive he proves himself.
  await entrustBundle(bob, host);

  if (typeof aliceMintCoinId !== 'string' || aliceMintCoinId.length === 0) {
    fail(3, 'aliceMintCoinId required (stage 2 mintJob.result.output_coin_ids[0])');
  }

  const bobInvoice = await issueInvoice({
    amount: SEND_AMOUNT,
    assetId: assetIdHex,
    relays: [RELAY_URL],
    sk0Secret: bob.sk0.secretKey,
    nkCommit: bob.nkCommit,
    ivpk: bob.ivpk,
    opSecret: bob.op,
  });

  // Open Bob's receipts stream before the send so the credit push is observed
  // (SubscribeReceipts is push-only; no historical replay).
  const bobSession = await client.openOwnershipPullSession({
    subject: bob.subject,
    sk0: bob.sk0.secretKey,
    nkCommit: bob.nkCommit,
  });
  const receiptWait = waitForCompletedReceipt(bobSession.session, assetIdHex, '3-receipt');

  const request = {
    kind: 'send',
    publisher_pubkey: pub,
    input_coins: [aliceMintCoinId],
    output_templates: [
      {
        recipient: bob.subject,
        asset_id: assetIdHex,
        amount: SEND_AMOUNT,
        delivery: { type: 'invoice', invoice: bobInvoice },
      },
    ],
  };
  const { job, spendPubkey } = await runSignedTransition(
    client,
    seed,
    alice,
    request,
    '3-send',
  );
  pass(3, `Alice→Bob send job completed (${job.job_id}); awaiting_signature recompute ok`);

  await postTransitionOnChain(spendPubkey, '3');
  pass(3, 'send nullifier inscribed; §3.10 completed after finality blocks');

  const bobReceipt = await receiptWait;
  pass(3, `Bob receipt discovered coin_id=${bobReceipt.coin_id.slice(0, 16)}…`);

  const balances = await pullBalances(client, alice);
  assertBalancesExact(4, balances, { [assetIdHex]: ALICE_AFTER_SEND });
  pass(4, `Alice balance USD-Demo == ${ALICE_AFTER_SEND} after send of ${SEND_AMOUNT}`);

  return {
    assetIdHex,
    sendJob: job,
    sendSpendPubkey: spendPubkey,
    bobCoinId: bobReceipt.coin_id,
  };
}

async function stage5_bob_receive(client, seed, bob, assetIdHex, bobCoinId) {
  let discoveredCoinId = bobCoinId;

  // Prefer the coin_id discovered during stage 3/4 (stream opened before
  // delivery). If missing (stage 5 run alone after a prior delivery), try
  // a fresh stream wait — this will only succeed if a new credit is still
  // pending; the hub does not replay already-published receipts.
  if (typeof discoveredCoinId !== 'string' || discoveredCoinId.length === 0) {
    const bobSession = await client.openOwnershipPullSession({
      subject: bob.subject,
      sk0: bob.sk0.secretKey,
      nkCommit: bob.nkCommit,
    });
    const receipt = await waitForCompletedReceipt(
      bobSession.session,
      assetIdHex,
      '5-receipt',
    );
    discoveredCoinId = receipt.coin_id;
  }
  pass(5, `Bob fold coin_id ready (${discoveredCoinId.slice(0, 16)}…)`);

  // Self-published receive: omit publisher_pubkey so the kernel default path runs.
  const request = {
    kind: 'receive',
    fold_coin_ids: [discoveredCoinId],
    genesis_pubkey: encodeHexLower(bob.sk0.publicKey),
  };
  const { job, spendPubkey } = await runSignedTransition(
    client,
    seed,
    bob,
    request,
    '5-receive',
  );
  pass(5, `Bob receive job completed (${job.job_id})`);

  // Same on-chain wait pattern as mint/send (header mandate: every
  // confirmation wait = 6 mined blocks). Self-published receive still
  // consumes Bob's spend key and publishes a nullifier.
  await postTransitionOnChain(spendPubkey, '5');
  pass(5, 'Bob receive nullifier inscribed; §3.10 completed after finality blocks');

  const balances = await pullBalances(client, bob);
  assertBalancesExact(5, balances, { [assetIdHex]: SEND_AMOUNT });
  pass(5, `Bob balance USD-Demo == ${SEND_AMOUNT}`);

  return { bobReceiveJob: job, bobReceiveSpendPubkey: spendPubkey };
}

async function stage6_confirmation_link(sendSpendPubkey) {
  if (typeof sendSpendPubkey !== 'string' && !(sendSpendPubkey instanceof Uint8Array)) {
    fail(6, 'stage 6 requires sendSpendPubkey from stage 3/4 (Alice→Bob payment)');
  }
  const pubkeyHex =
    typeof sendSpendPubkey === 'string'
      ? sendSpendPubkey
      : encodeHexLower(sendSpendPubkey);
  const hit = await waitInscriptionCompletedForPubkey(pubkeyHex, '6');
  if (hit.inscription.confirmation_state !== 'completed') {
    fail(
      6,
      `confirmation link expected confirmation_state=completed, got ${JSON.stringify(hit.inscription.confirmation_state)}`,
    );
  }
  pass(
    6,
    `confirmation link for Alice→Bob payment reports §3.10 completed (pubkey ${pubkeyHex.slice(0, 16)}…)`,
  );
  return hit;
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
  '2b': 'Carol EUR-Demo genesis + Alice receive',
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

  log(`API ${API_URL}`);
  log(`Alice ${alice.subject}`);
  log(`Bob   ${bob.subject}`);
  log(`Carol ${carol.subject}`);

  /**
   * @type {{
   *   assetIdHex?: string,
   *   mintJob?: object,
   *   mintSpendPubkey?: Uint8Array,
   *   sendJob?: object,
   *   sendSpendPubkey?: Uint8Array,
   *   bobCoinId?: string,
   *   eurAssetIdHex?: string,
   * }}
   */
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
        if (!ctx.assetIdHex) {
          fail('2b', 'stage 2b requires stage 2 in the same run (Alice USD asset id)');
        }
        ctx = {
          ...ctx,
          ...(await stage2b_carol_eur(
            client,
            seed,
            alice,
            carol,
            host,
            ctx.assetIdHex,
          )),
        };
        break;
      case '3':
      case '4': {
        // Stages 3 and 4 share one function; run only once if both are listed.
        if (ctx.sendJob) {
          break;
        }
        if (!ctx.assetIdHex || !ctx.mintJob) {
          fail(s, 'stage 3/4 require stage 2 in the same run (asset id + mint job)');
        }
        const aliceMintCoinId = ctx.mintJob?.result?.output_coin_ids?.[0];
        if (typeof aliceMintCoinId !== 'string') {
          fail(s, 'stage 2 mintJob.result.output_coin_ids[0] missing');
        }
        ctx = {
          ...ctx,
          ...(await stage3_4_alice_send(
            client,
            seed,
            alice,
            bob,
            host,
            ctx.assetIdHex,
            aliceMintCoinId,
          )),
        };
        break;
      }
      case '5':
        if (!ctx.assetIdHex) {
          fail(5, 'stage 5 requires stage 2 in the same run (asset id)');
        }
        ctx = {
          ...ctx,
          ...(await stage5_bob_receive(
            client,
            seed,
            bob,
            ctx.assetIdHex,
            ctx.bobCoinId,
          )),
        };
        break;
      case '6':
        if (!ctx.sendSpendPubkey) {
          fail(6, 'stage 6 requires stage 3/4 in the same run (sendSpendPubkey)');
        }
        await stage6_confirmation_link(ctx.sendSpendPubkey);
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
