// node --test coordinator/test
//
// logic.js is pure: storage, verifier, clock and uuid source are all injected, so
// every branch is reachable without wrangler, kv or a network. worker.js is not
// covered here (see README status).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import {
  handleRequest,
  buildSignedMessage,
  canonicalJson,
  verifyCardDocument,
  decodeCardHeader,
  queueKey,
  PROTOCOL_PREFIX,
  MAX_SKEW_S,
  NONCE_TTL_S,
  PULL_MAX,
  LEASE_MS,
  MAX_ATTEMPTS,
  MAX_BODY_BYTES,
  MAX_BLOB_B64,
  MAX_QUEUED_PER_NODE,
  MAX_RECEIPT_BYTES,
  STALE_MS,
  NODES_LIMIT_DEFAULT,
  DONE_TTL_S,
  NODE_TTL_S,
  CORS_HEADERS,
  PUBLIC_CACHE_HEADERS,
  STATS_JOBS_DONE_KEY,
  STATS_MAX_GETS,
  DEFAULT_NEIGHBORHOOD,
} from '../src/logic.js';

// ------------------------------------------------------------------- fixtures

const HOST = 'grid.example.com';
const T0 = 1_777_000_000_000; // fixed epoch ms so every assertion is deterministic

function key32(fill) {
  return Buffer.alloc(32, fill).toString('base64');
}

const A_BOX = key32(0x11);
const A_VERIFY = key32(0x12);
const A_VERIFY_NEW = key32(0x13);
const B_BOX = key32(0x21);
const B_VERIFY = key32(0x22);
const REPLY_PUB = key32(0x31);
const CLUB_VERIFY = key32(0x41);
const CLUB_IMPOSTOR = key32(0x42);
const MEMBER_VERIFY = key32(0x51);
const MEMBER_OTHER = key32(0x52);

function blob(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

// in-memory kv. get() deep-copies like kv's json decode, so a handler that mutates
// a record and forgets to put it back fails here exactly as it would in production.
function makeStorage() {
  const map = new Map();
  const ttls = new Map();
  return {
    map,
    ttls,
    async get(key) {
      const v = map.get(key);
      return v === undefined ? null : JSON.parse(v);
    },
    async put(key, value, opts) {
      map.set(key, JSON.stringify(value));
      ttls.set(key, opts && opts.expirationTtl);
    },
    async delete(key) {
      map.delete(key);
      ttls.delete(key);
    },
    async list({ prefix, limit, cursor }) {
      const names = [...map.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0;
      const lim = limit || 1000;
      const page = names.slice(start, start + lim);
      const next = start + page.length;
      const complete = next >= names.length;
      return {
        keys: page.map((name) => ({ name })),
        list_complete: complete,
        cursor: complete ? undefined : String(next),
      };
    },
  };
}

// fake signature scheme: tag = "<verify_key>|<base64 of signed message>". binds the
// signature to both the key and the exact bytes, which is all the logic layer cares
// about, and needs no real crypto. real ed25519 lives in worker.js and pygrid.
function fakeSig(verifyKeyB64, msgBytes) {
  const tag = `${verifyKeyB64}|${Buffer.from(msgBytes).toString('base64')}`;
  return Buffer.from(tag, 'utf8').toString('base64');
}

function makeVerifier() {
  const calls = [];
  return {
    calls,
    async verify(verifyKeyB64, msg, sig) {
      calls.push({ verifyKeyB64, msg: Buffer.from(msg), sig: Buffer.from(sig) });
      const got = Buffer.from(sig).toString('utf8');
      return got === `${verifyKeyB64}|${Buffer.from(msg).toString('base64')}`;
    },
  };
}

// a verifier that throws: checkSignature must turn that into 401, never a 500.
const throwingVerifier = {
  calls: [],
  async verify() {
    throw new Error('boom');
  },
};

// clubVerifyKey defaults to '' so every v1 test runs against the open-submission
// coordinator that is actually deployed today.
function setup(opts = {}) {
  const storage = makeStorage();
  const verifier = opts.verifier || makeVerifier();
  const clock = { ms: T0 };
  let n = 0;
  const env = {
    storage,
    verifier,
    now: () => clock.ms,
    randomUUID: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
    clubVerifyKey: opts.clubVerifyKey === undefined ? '' : opts.clubVerifyKey,
  };
  return { storage, verifier, clock, env };
}

function bodyBytes(body) {
  if (body === null || body === undefined) return new Uint8Array(0);
  const s = typeof body === 'string' ? body : JSON.stringify(body);
  return new Uint8Array(Buffer.from(s, 'utf8'));
}

function makeReq(method, path, { body = null, headers = {}, host = HOST } = {}) {
  const qmark = path.indexOf('?');
  const pathname = qmark === -1 ? path : path.slice(0, qmark);
  const search = qmark === -1 ? '' : path.slice(qmark + 1);
  const query = {};
  if (search) {
    for (const [k, v] of new URLSearchParams(search)) if (!(k in query)) query[k] = v;
  }
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return { method, pathname, path, host, headers: lower, query, bodyBytes: bodyBytes(body) };
}

// signs with `verifyKey` unless `signWith` overrides it, so wrong-key cases are one arg.
function signReq(env, method, path, opts = {}) {
  const {
    body = null,
    nodeId = 'alpha',
    verifyKey = A_VERIFY,
    signWith = null,
    host = HOST,
    timestamp = null,
    nonce = randomBytes(16).toString('base64'),
    mutateSig = null,
    dropHeaders = [],
  } = opts;

  const ts = timestamp === null ? String(Math.floor(env.now() / 1000)) : String(timestamp);
  const raw = bodyBytes(body);
  const msg = buildSignedMessage({ host, method, path, timestamp: ts, nonce, body: raw });
  let sig = fakeSig(signWith || verifyKey, msg);
  if (mutateSig) sig = mutateSig(sig);

  const headers = {
    'X-NYCC-Node-Id': nodeId,
    'X-NYCC-Timestamp': ts,
    'X-NYCC-Nonce': nonce,
    'X-NYCC-Signature': sig,
  };
  for (const h of dropHeaders) delete headers[h];
  return makeReq(method, path, { body, headers, host });
}

async function registerNode(
  env,
  {
    nodeId = 'alpha',
    pubkey = A_BOX,
    verifyKey = A_VERIFY,
    wattage = 300,
    neighborhood = undefined,
    wattsSource = undefined,
  } = {},
) {
  const body = { node_id: nodeId, pubkey, verify_key: verifyKey, wattage };
  if (neighborhood !== undefined) body.neighborhood = neighborhood;
  if (wattsSource !== undefined) body.watts_source = wattsSource;
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/register', { body, nodeId, verifyKey }),
    env,
  );
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res;
}

async function submitJob(env, { toNode = 'alpha', text = 'ciphertext', idem = null } = {}) {
  const body = { to_node: toNode, blob_b64: blob(text), reply_pubkey: REPLY_PUB };
  if (idem) body.idempotency_key = idem;
  const res = await handleRequest(makeReq('POST', '/v1/jobs', { body }), env);
  return res;
}

// ------------------------------------------------------------- card fixtures

function makeCard(over = {}) {
  return {
    member: 'jimmy baker',
    member_verify_key: MEMBER_VERIFY,
    issued: '2026-08-19T12:00:00+00:00',
    serial: 1755600000,
    ...over,
  };
}

// signs the canonical bytes with the fake scheme, same as a real club key would sign
// the bytes canonicalJson produces.
function cardDoc(card = makeCard(), signWith = CLUB_VERIFY) {
  // the fallback only matters for cards this canonicalizer refuses (a float serial);
  // those are rejected on shape before any signature is checked.
  const bytes = Buffer.from(canonicalJson(card) ?? JSON.stringify(card), 'utf8');
  return { card, sig: fakeSig(signWith, bytes) };
}

function cardHeader(doc = cardDoc()) {
  return Buffer.from(JSON.stringify(doc), 'utf8').toString('base64');
}

// a member-signed POST /v1/jobs. the member signature covers the same canonical string
// as node signing, just under the member header names.
function memberSubmit(env, opts = {}) {
  const {
    body = { to_node: 'alpha', blob_b64: blob('sealed'), reply_pubkey: REPLY_PUB },
    card = makeCard(),
    doc = null,
    header = null,
    signWith = MEMBER_VERIFY,
    timestamp = null,
    nonce = randomBytes(16).toString('base64'),
    dropHeaders = [],
    host = HOST,
  } = opts;

  const ts = timestamp === null ? String(Math.floor(env.now() / 1000)) : String(timestamp);
  const msg = buildSignedMessage({
    host,
    method: 'POST',
    path: '/v1/jobs',
    timestamp: ts,
    nonce,
    body: bodyBytes(body),
  });
  const headers = {
    'X-NYCC-Card': header === null ? cardHeader(doc || cardDoc(card)) : header,
    'X-NYCC-Member-Ts': ts,
    'X-NYCC-Member-Nonce': nonce,
    'X-NYCC-Member-Sig': fakeSig(signWith, msg),
  };
  for (const h of dropHeaders) delete headers[h];
  return makeReq('POST', '/v1/jobs', { body, headers, host });
}

// a job posted through the gate, for tests that need a running job to finish
async function gatedSubmit(env, opts = {}) {
  return handleRequest(memberSubmit(env, opts), env);
}

async function postResult(env, jobId, { text = 'sealed-result', receipt = undefined } = {}) {
  const body = { job_id: jobId, blob_b64: blob(text) };
  if (receipt !== undefined) body.receipt = receipt;
  return handleRequest(signReq(env, 'POST', '/v1/jobs/result', { body }), env);
}

// register, submit, pull, post the result. returns the job id.
async function runOneJob(env, { receipt = undefined, text = 'sealed-result' } = {}) {
  const job = await submitJob(env);
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  const res = await postResult(env, job.body.job_id, { text, receipt });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return job.body.job_id;
}

// --------------------------------------------------------------- canonical bytes

test('signed message is the pinned byte string, path with query included', () => {
  const msg = buildSignedMessage({
    host: HOST,
    method: 'POST',
    path: '/v1/jobs/result?x=1',
    timestamp: '1777000000',
    nonce: 'bm9uY2U=',
    body: new Uint8Array(Buffer.from('{"a":1}', 'utf8')),
  });
  const expected = `${PROTOCOL_PREFIX}${HOST}\nPOST\n/v1/jobs/result?x=1\n1777000000\nbm9uY2U=\n{"a":1}`;
  assert.equal(Buffer.from(msg).toString('utf8'), expected);
  assert.equal(PROTOCOL_PREFIX, 'nycc-grid-v1|');
});

test('verifier receives the exact canonical bytes for a signed GET', async () => {
  const { env, verifier } = setup();
  await registerNode(env);
  const nonce = 'AAAAAAAAAAAAAAAAAAAAAA==';
  const ts = String(Math.floor(T0 / 1000));
  const req = signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { nonce, timestamp: ts });
  const before = verifier.calls.length;
  const res = await handleRequest(req, env);
  assert.equal(res.status, 200);
  const call = verifier.calls[before];
  assert.equal(call.verifyKeyB64, A_VERIFY);
  assert.equal(
    call.msg.toString('utf8'),
    `nycc-grid-v1|${HOST}\nGET\n/v1/jobs/pull?node_id=alpha\n${ts}\n${nonce}\n`,
  );
});

test('verifier receives the raw received body, not a re-serialization', async () => {
  const { env, verifier } = setup();
  await registerNode(env);
  // deliberately odd spacing and key order: a canonicalizing verifier would break here.
  const raw = '{ "node_id" :"alpha",   "wattage": 42 }';
  const req = signReq(env, 'POST', '/v1/nodes/heartbeat', { body: raw });
  const before = verifier.calls.length;
  const res = await handleRequest(req, env);
  assert.equal(res.status, 200);
  const call = verifier.calls[before];
  assert.ok(call.msg.toString('utf8').endsWith(`\n${raw}`));
});

// ------------------------------------------------------------------ registration

test('register stores a new node id and proves possession of the submitted key', async () => {
  const { env, storage } = setup();
  await registerNode(env, { wattage: 350 });
  const rec = JSON.parse(storage.map.get('node:alpha'));
  assert.equal(rec.node_id, 'alpha');
  assert.equal(rec.pubkey, A_BOX);
  assert.equal(rec.verify_key, A_VERIFY);
  assert.equal(rec.wattage, 350);
  assert.equal(rec.last_seen, T0);
});

test('register with a signature from another key is rejected and stores nothing', async () => {
  const { env, storage } = setup();
  const body = { node_id: 'alpha', pubkey: A_BOX, verify_key: A_VERIFY, wattage: 0 };
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/register', { body, verifyKey: A_VERIFY, signWith: B_VERIFY }),
    env,
  );
  assert.equal(res.status, 401);
  assert.equal(storage.map.has('node:alpha'), false);
});

test('re-register cannot overwrite another members verify key', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  // attacker holds B's keys and signs with them, hoping to take over "alpha"
  const body = { node_id: 'alpha', pubkey: B_BOX, verify_key: B_VERIFY, wattage: 0 };
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/register', { body, verifyKey: B_VERIFY }),
    env,
  );
  assert.equal(res.status, 401);
  const rec = JSON.parse(storage.map.get('node:alpha'));
  assert.equal(rec.verify_key, A_VERIFY);
  assert.equal(rec.pubkey, A_BOX);
});

test('re-register signed by the current key rotates keys and wattage', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const body = { node_id: 'alpha', pubkey: B_BOX, verify_key: A_VERIFY_NEW, wattage: 120 };
  const res = await handleRequest(
    // signed by the CURRENTLY registered key, carrying the new key in the body
    signReq(env, 'POST', '/v1/nodes/register', { body, signWith: A_VERIFY }),
    env,
  );
  assert.equal(res.status, 200);
  assert.equal(res.body.rotated, true);
  const rec = JSON.parse(storage.map.get('node:alpha'));
  assert.equal(rec.verify_key, A_VERIFY_NEW);
  assert.equal(rec.pubkey, B_BOX);
  assert.equal(rec.wattage, 120);
  assert.equal(rec.registered_ms, T0);
});

test('register rejects a node id header that disagrees with the body', async () => {
  const { env } = setup();
  const body = { node_id: 'alpha', pubkey: A_BOX, verify_key: A_VERIFY, wattage: 0 };
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/register', { body, nodeId: 'bravo' }),
    env,
  );
  assert.equal(res.status, 400);
});

test('register rejects malformed ids, keys and wattage', async () => {
  const { env } = setup();
  const bad = [
    { node_id: 'has:colon', pubkey: A_BOX, verify_key: A_VERIFY, wattage: 0 },
    { node_id: 'alpha', pubkey: 'short', verify_key: A_VERIFY, wattage: 0 },
    { node_id: 'alpha', pubkey: A_BOX, verify_key: Buffer.alloc(31, 7).toString('base64'), wattage: 0 },
    { node_id: 'alpha', pubkey: A_BOX, verify_key: A_VERIFY, wattage: -1 },
    { node_id: 'alpha', pubkey: A_BOX, verify_key: A_VERIFY, wattage: 'lots' },
  ];
  for (const body of bad) {
    const res = await handleRequest(
      signReq(env, 'POST', '/v1/nodes/register', { body, nodeId: body.node_id }),
      env,
    );
    assert.equal(res.status, 400, JSON.stringify(body));
  }
});

test('register rejects a body that is not a json object', async () => {
  const { env } = setup();
  for (const raw of ['[]', 'null', 'not json']) {
    const res = await handleRequest(signReq(env, 'POST', '/v1/nodes/register', { body: raw }), env);
    assert.equal(res.status, 400);
  }
});

// -------------------------------------------------------------------- heartbeat

test('heartbeat for an unknown node is 404 so the agent re-registers', async () => {
  const { env } = setup();
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/heartbeat', { body: { node_id: 'alpha', wattage: 10 } }),
    env,
  );
  assert.equal(res.status, 404);
});

test('heartbeat updates wattage and last_seen', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env, { wattage: 300 });
  clock.ms = T0 + 45_000;
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/heartbeat', { body: { node_id: 'alpha', wattage: 275.5 } }),
    env,
  );
  assert.equal(res.status, 200);
  const rec = JSON.parse(storage.map.get('node:alpha'));
  assert.equal(rec.wattage, 275.5);
  assert.equal(rec.last_seen, T0 + 45_000);
  assert.equal(rec.verify_key, A_VERIFY);
});

test('heartbeat with a bad signature does not touch last_seen', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  clock.ms = T0 + 45_000;
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/heartbeat', {
      body: { node_id: 'alpha', wattage: 1 },
      signWith: B_VERIFY,
    }),
    env,
  );
  assert.equal(res.status, 401);
  assert.equal(JSON.parse(storage.map.get('node:alpha')).last_seen, T0);
});

test('node records expire, and every heartbeat pushes the expiry out again', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  assert.equal(storage.ttls.get('node:alpha'), NODE_TTL_S);
  assert.equal(NODE_TTL_S, 7 * 24 * 60 * 60);
  assert.ok(NODE_TTL_S * 1000 > STALE_MS * 100, 'a ttl near STALE_MS would evict live nodes');

  // a v1 record written with no ttl gets one from the next beat
  storage.ttls.set('node:alpha', undefined);
  clock.ms = T0 + 45_000;
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/heartbeat', { body: { node_id: 'alpha', wattage: 10 } }),
    env,
  );
  assert.equal(res.status, 200);
  assert.equal(storage.ttls.get('node:alpha'), NODE_TTL_S);
});

// ------------------------------------------------------------------- node list

test('nodes list reports alive from last_seen and three heartbeat intervals', async () => {
  const { env, clock } = setup();
  await registerNode(env, { nodeId: 'alpha' });
  clock.ms = T0 + STALE_MS + 1;
  await registerNode(env, { nodeId: 'bravo', pubkey: B_BOX, verifyKey: B_VERIFY });

  const res = await handleRequest(makeReq('GET', '/v1/nodes'), env);
  assert.equal(res.status, 200);
  const byId = Object.fromEntries(res.body.nodes.map((n) => [n.node_id, n]));
  assert.equal(byId.alpha.alive, false);
  assert.equal(byId.bravo.alive, true);
  assert.equal(byId.alpha.pubkey, A_BOX);
  assert.equal(byId.alpha.wattage, 300);
  assert.equal(byId.alpha.last_seen, T0);
  assert.equal('blob_b64' in byId.alpha, false);
});

test('nodes list is bounded by limit and pages with a cursor', async () => {
  const { env } = setup();
  for (const id of ['n1', 'n2', 'n3']) {
    await registerNode(env, { nodeId: id });
  }
  const first = await handleRequest(makeReq('GET', '/v1/nodes?limit=2'), env);
  assert.equal(first.body.nodes.length, 2);
  assert.ok(first.body.cursor);

  const second = await handleRequest(
    makeReq('GET', `/v1/nodes?limit=2&cursor=${encodeURIComponent(first.body.cursor)}`),
    env,
  );
  assert.equal(second.body.nodes.length, 1);
  assert.equal(second.body.cursor, undefined);

  const seen = [...first.body.nodes, ...second.body.nodes].map((n) => n.node_id).sort();
  assert.deepEqual(seen, ['n1', 'n2', 'n3']);
  assert.equal(NODES_LIMIT_DEFAULT, 50);
});

test('nodes list rejects a nonsense limit', async () => {
  const { env } = setup();
  for (const q of ['limit=0', 'limit=-3', 'limit=abc', 'limit=1.5']) {
    const res = await handleRequest(makeReq('GET', `/v1/nodes?${q}`), env);
    assert.equal(res.status, 400, q);
  }
});

// ---------------------------------------------------------------------- submit

test('submit stores the job and one queue index entry', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const res = await submitJob(env, { text: 'sealed-job' });
  assert.equal(res.status, 200);
  const jobId = res.body.job_id;
  assert.ok(jobId);

  const job = JSON.parse(storage.map.get(`job:${jobId}`));
  assert.equal(job.status, 'queued');
  assert.equal(job.attempts, 0);
  assert.equal(job.to_node, 'alpha');
  assert.equal(job.blob_b64, blob('sealed-job'));
  assert.equal(job.result_b64, null);

  const qkeys = [...storage.map.keys()].filter((k) => k.startsWith('queue:alpha:'));
  assert.deepEqual(qkeys, [queueKey('alpha', T0, jobId)]);
});

test('submit to an unknown node is 404', async () => {
  const { env } = setup();
  const res = await submitJob(env);
  assert.equal(res.status, 404);
});

test('submit rejects a bad reply pubkey and a non base64 blob', async () => {
  const { env } = setup();
  await registerNode(env);
  const bad = [
    { to_node: 'alpha', blob_b64: blob('x'), reply_pubkey: 'nope' },
    { to_node: 'alpha', blob_b64: 'not base64!!', reply_pubkey: REPLY_PUB },
    { to_node: 'alpha', blob_b64: '', reply_pubkey: REPLY_PUB },
    { to_node: 'has:colon', blob_b64: blob('x'), reply_pubkey: REPLY_PUB },
  ];
  for (const body of bad) {
    const res = await handleRequest(makeReq('POST', '/v1/jobs', { body }), env);
    assert.equal(res.status, 400, JSON.stringify(body).slice(0, 80));
  }
});

test('replaying an idempotency key returns the first job id and enqueues once', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const first = await submitJob(env, { idem: 'client-retry-1' });
  const second = await submitJob(env, { idem: 'client-retry-1' });
  assert.equal(second.status, 200);
  assert.equal(second.body.job_id, first.body.job_id);
  assert.equal(second.body.duplicate, true);
  const qkeys = [...storage.map.keys()].filter((k) => k.startsWith('queue:alpha:'));
  assert.equal(qkeys.length, 1);
});

test('idempotency keys are scoped per target node', async () => {
  const { env } = setup();
  await registerNode(env, { nodeId: 'alpha' });
  await registerNode(env, { nodeId: 'bravo', pubkey: B_BOX, verifyKey: B_VERIFY });
  const a = await submitJob(env, { toNode: 'alpha', idem: 'same' });
  const b = await submitJob(env, { toNode: 'bravo', idem: 'same' });
  assert.notEqual(a.body.job_id, b.body.job_id);
});

test('oversize blob is 413 and oversize body is 413', async () => {
  const { env } = setup();
  await registerNode(env);

  const bigBlob = 'A'.repeat(MAX_BLOB_B64 + 1);
  const r1 = await handleRequest(
    makeReq('POST', '/v1/jobs', {
      body: { to_node: 'alpha', blob_b64: bigBlob, reply_pubkey: REPLY_PUB },
    }),
    env,
  );
  assert.equal(r1.status, 413);

  const r2 = await handleRequest(
    makeReq('POST', '/v1/jobs', { body: 'x'.repeat(MAX_BODY_BYTES + 1) }),
    env,
  );
  assert.equal(r2.status, 413);
});

test('per node queue cap returns 429', async () => {
  const { env } = setup();
  await registerNode(env);
  for (let i = 0; i < MAX_QUEUED_PER_NODE; i++) {
    const res = await submitJob(env, { text: `job-${i}` });
    assert.equal(res.status, 200, `job ${i}`);
  }
  const over = await submitJob(env, { text: 'one too many' });
  assert.equal(over.status, 429);
});

// ------------------------------------------------------------------------ pull

test('pull delivers oldest first, marks running and leases', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  const older = await submitJob(env, { text: 'first' });
  clock.ms = T0 + 5;
  const newer = await submitJob(env, { text: 'second' });
  clock.ms = T0 + 10;

  const res = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.equal(res.status, 200);
  assert.deepEqual(
    res.body.jobs.map((j) => j.job_id),
    [older.body.job_id, newer.body.job_id],
  );
  const first = res.body.jobs[0];
  assert.equal(first.blob_b64, blob('first')); // JOB ciphertext, never the result
  assert.equal(first.reply_pubkey, REPLY_PUB);
  assert.equal(first.status, 'running');
  assert.equal(first.to_node, 'alpha');

  const rec = JSON.parse(storage.map.get(`job:${older.body.job_id}`));
  assert.equal(rec.status, 'running');
  assert.equal(rec.attempts, 1);
  assert.equal(rec.lease_until, T0 + 10 + LEASE_MS);
});

test('pull never returns more than PULL_MAX jobs in one call', async () => {
  const { env, clock } = setup();
  await registerNode(env);
  for (let i = 0; i < PULL_MAX + 3; i++) {
    clock.ms = T0 + i;
    const res = await submitJob(env, { text: `j${i}` });
    assert.equal(res.status, 200);
  }
  clock.ms = T0 + 1000;
  const res = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.equal(res.body.jobs.length, PULL_MAX);
});

test('a leased job is not redelivered before the lease expires', async () => {
  const { env, clock } = setup();
  await registerNode(env);
  await submitJob(env);
  const first = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.equal(first.body.jobs.length, 1);

  clock.ms = T0 + LEASE_MS - 1;
  const second = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.deepEqual(second.body.jobs, []);
});

test('lease expiry redelivers, keeps status running and increments attempts', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);

  clock.ms = T0 + LEASE_MS + 1;
  const again = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.equal(again.body.jobs.length, 1);
  assert.equal(again.body.jobs[0].job_id, job.body.job_id);

  const rec = JSON.parse(storage.map.get(`job:${job.body.job_id}`));
  assert.equal(rec.status, 'running');
  assert.equal(rec.attempts, 2);
  assert.equal(rec.lease_until, clock.ms + LEASE_MS);
});

test('a poison job fails terminally after MAX_ATTEMPTS lease expiries', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const jobId = job.body.job_id;

  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    clock.ms = T0 + i * (LEASE_MS + 1);
    const res = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
    assert.equal(res.body.jobs.length, 1, `delivery ${i + 1}`);
  }
  assert.equal(JSON.parse(storage.map.get(`job:${jobId}`)).attempts, MAX_ATTEMPTS);

  clock.ms = T0 + MAX_ATTEMPTS * (LEASE_MS + 1);
  const dead = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.deepEqual(dead.body.jobs, []);

  const rec = JSON.parse(storage.map.get(`job:${jobId}`));
  assert.equal(rec.status, 'failed');
  assert.equal(storage.ttls.get(`job:${jobId}`), DONE_TTL_S);
  assert.equal([...storage.map.keys()].some((k) => k.startsWith('queue:alpha:')), false);

  const status = await handleRequest(makeReq('GET', `/v1/jobs/${jobId}`), env);
  assert.equal(status.body.status, 'failed');
  assert.equal('blob_b64' in status.body, false);
});

test('pull for an unknown node is 404 and a mismatched node id is 403', async () => {
  const { env } = setup();
  const missing = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=ghost', { nodeId: 'ghost' }), env);
  assert.equal(missing.status, 404);

  await registerNode(env);
  await registerNode(env, { nodeId: 'bravo', pubkey: B_BOX, verifyKey: B_VERIFY });
  // bravo signs, but asks to drain alpha's queue
  const stolen = await handleRequest(
    signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { nodeId: 'bravo', verifyKey: B_VERIFY }),
    env,
  );
  assert.equal(stolen.status, 403);
});

test('pull with a bad signature leaves the queue untouched', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const res = await handleRequest(
    signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { signWith: B_VERIFY }),
    env,
  );
  assert.equal(res.status, 401);
  assert.equal(JSON.parse(storage.map.get(`job:${job.body.job_id}`)).status, 'queued');
});

test('pull drops index entries whose job record is gone', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  storage.map.delete(`job:${job.body.job_id}`); // kv ttl expiry, seen from the index side

  const res = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.deepEqual(res.body.jobs, []);
  assert.equal([...storage.map.keys()].some((k) => k.startsWith('queue:alpha:')), false);
});

// ---------------------------------------------------------------------- result

test('running to done stores the result and only the result comes back out', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  const job = await submitJob(env, { text: 'sealed-job' });
  const jobId = job.body.job_id;
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);

  clock.ms = T0 + 2000;
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', { body: { job_id: jobId, blob_b64: blob('sealed-result') } }),
    env,
  );
  assert.equal(res.status, 200);

  const rec = JSON.parse(storage.map.get(`job:${jobId}`));
  assert.equal(rec.status, 'done');
  assert.equal(rec.result_b64, blob('sealed-result'));
  assert.equal(rec.blob_b64, blob('sealed-job'));
  assert.equal(storage.ttls.get(`job:${jobId}`), DONE_TTL_S);
  assert.equal([...storage.map.keys()].some((k) => k.startsWith('queue:alpha:')), false);

  const status = await handleRequest(makeReq('GET', `/v1/jobs/${jobId}`), env);
  assert.equal(status.body.status, 'done');
  assert.equal(status.body.blob_b64, blob('sealed-result'));
});

test('a retried result is accepted once and never overwrites', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const jobId = job.body.job_id;
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);

  await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', { body: { job_id: jobId, blob_b64: blob('first') } }),
    env,
  );
  const retry = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', { body: { job_id: jobId, blob_b64: blob('second') } }),
    env,
  );
  assert.equal(retry.status, 200);
  assert.equal(retry.body.duplicate, true);
  assert.equal(JSON.parse(storage.map.get(`job:${jobId}`)).result_b64, blob('first'));
});

test('a node cannot post a result for a job addressed to someone else', async () => {
  const { env, storage } = setup();
  await registerNode(env, { nodeId: 'alpha' });
  await registerNode(env, { nodeId: 'bravo', pubkey: B_BOX, verifyKey: B_VERIFY });
  const job = await submitJob(env, { toNode: 'alpha' });
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);

  const res = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', {
      body: { job_id: job.body.job_id, blob_b64: blob('forged') },
      nodeId: 'bravo',
      verifyKey: B_VERIFY,
    }),
    env,
  );
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(storage.map.get(`job:${job.body.job_id}`)).result_b64, null);
});

test('a result for a job that was never pulled is refused', async () => {
  const { env } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', {
      body: { job_id: job.body.job_id, blob_b64: blob('early') },
    }),
    env,
  );
  assert.equal(res.status, 409);
  assert.equal(res.body.status, 'queued');
});

test('failed is terminal: a late result cannot revive it', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const jobId = job.body.job_id;
  for (let i = 0; i <= MAX_ATTEMPTS; i++) {
    clock.ms = T0 + i * (LEASE_MS + 1);
    await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  }
  assert.equal(JSON.parse(storage.map.get(`job:${jobId}`)).status, 'failed');

  const res = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', { body: { job_id: jobId, blob_b64: blob('too late') } }),
    env,
  );
  assert.equal(res.status, 409);
  assert.equal(JSON.parse(storage.map.get(`job:${jobId}`)).result_b64, null);
});

test('result for an unknown job or an unregistered signer', async () => {
  const { env } = setup();
  const unknownSigner = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', { body: { job_id: 'nope', blob_b64: blob('x') } }),
    env,
  );
  assert.equal(unknownSigner.status, 404);

  await registerNode(env);
  const unknownJob = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', { body: { job_id: 'nope', blob_b64: blob('x') } }),
    env,
  );
  assert.equal(unknownJob.status, 404);
});

test('result rejects an oversize blob before touching the job', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', {
      body: { job_id: job.body.job_id, blob_b64: 'A'.repeat(MAX_BLOB_B64 + 1) },
    }),
    env,
  );
  assert.equal(res.status, 413);
  assert.equal(JSON.parse(storage.map.get(`job:${job.body.job_id}`)).status, 'running');
});

// --------------------------------------------------------- monotonic transitions

test('a replayed queue index entry never drags a done job back to running', async () => {
  const { env, storage, clock } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const jobId = job.body.job_id;
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  await handleRequest(
    signReq(env, 'POST', '/v1/jobs/result', { body: { job_id: jobId, blob_b64: blob('done') } }),
    env,
  );

  // stale index write resurfacing from another edge under kv eventual consistency
  await storage.put(queueKey('alpha', T0, jobId), { job_id: jobId });
  clock.ms = T0 + LEASE_MS * 10;
  const res = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);

  assert.deepEqual(res.body.jobs, []);
  const rec = JSON.parse(storage.map.get(`job:${jobId}`));
  assert.equal(rec.status, 'done');
  assert.equal(rec.result_b64, blob('done'));
  assert.equal([...storage.map.keys()].some((k) => k.startsWith('queue:alpha:')), false);
});

test('job status while queued and running never carries a blob', async () => {
  const { env } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const queued = await handleRequest(makeReq('GET', `/v1/jobs/${job.body.job_id}`), env);
  assert.deepEqual(queued.body, { status: 'queued' });

  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  const running = await handleRequest(makeReq('GET', `/v1/jobs/${job.body.job_id}`), env);
  assert.deepEqual(running.body, { status: 'running' });
});

test('unknown job id is 404', async () => {
  const { env } = setup();
  const res = await handleRequest(makeReq('GET', '/v1/jobs/00000000-0000-4000-8000-000000000009'), env);
  assert.equal(res.status, 404);
});

// ------------------------------------------------------------ replay protection

test('a stale timestamp is refused without ever calling the verifier', async () => {
  const { env, verifier } = setup();
  await registerNode(env);
  const before = verifier.calls.length;
  const old = Math.floor(T0 / 1000) - (MAX_SKEW_S + 1);
  const res = await handleRequest(
    signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { timestamp: old }),
    env,
  );
  assert.equal(res.status, 401);
  assert.equal(verifier.calls.length, before);
});

test('a timestamp from the future is refused too', async () => {
  const { env } = setup();
  await registerNode(env);
  const ahead = Math.floor(T0 / 1000) + MAX_SKEW_S + 1;
  const res = await handleRequest(
    signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { timestamp: ahead }),
    env,
  );
  assert.equal(res.status, 401);
});

test('a replayed nonce inside the window is refused and the nonce is stored with a ttl', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const nonce = 'ZmFrZS1ub25jZS0wMDAwMDA=';
  const first = signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { nonce });
  assert.equal((await handleRequest(first, env)).status, 200);
  assert.equal(storage.ttls.get(`nonce:alpha:${nonce}`), NONCE_TTL_S);

  const replay = await handleRequest(first, env);
  assert.equal(replay.status, 401);
  assert.equal(replay.body.error, 'nonce replay');
});

test('nonces are scoped per node id', async () => {
  const { env } = setup();
  await registerNode(env, { nodeId: 'alpha' });
  await registerNode(env, { nodeId: 'bravo', pubkey: B_BOX, verifyKey: B_VERIFY });
  const nonce = 'c2hhcmVkLW5vbmNlLTAwMDA=';
  const a = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { nonce }), env);
  const b = await handleRequest(
    signReq(env, 'GET', '/v1/jobs/pull?node_id=bravo', { nodeId: 'bravo', verifyKey: B_VERIFY, nonce }),
    env,
  );
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
});

test('an unauthenticated caller cannot burn a nodes nonce space', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const nonce = 'YnVybi10aGlzLW5vbmNlLTAw';
  const forged = await handleRequest(
    signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { nonce, signWith: B_VERIFY }),
    env,
  );
  assert.equal(forged.status, 401);
  assert.equal(storage.map.has(`nonce:alpha:${nonce}`), false);

  const real = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { nonce }), env);
  assert.equal(real.status, 200);
});

// ------------------------------------------------------------- signature shapes

test('tampering with the body after signing invalidates the signature', async () => {
  const { env } = setup();
  await registerNode(env);
  const req = signReq(env, 'POST', '/v1/nodes/heartbeat', { body: { node_id: 'alpha', wattage: 1 } });
  req.bodyBytes = bodyBytes({ node_id: 'alpha', wattage: 9999 });
  const res = await handleRequest(req, env);
  assert.equal(res.status, 401);
});

test('re-targeting a signed pull to another queue invalidates the signature', async () => {
  const { env } = setup();
  await registerNode(env, { nodeId: 'alpha' });
  // signed for alpha's queue, then the path is rewritten in flight
  const req = signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha');
  req.path = '/v1/jobs/pull?node_id=alpha&extra=1';
  const res = await handleRequest(req, env);
  assert.equal(res.status, 401);
});

test('a signature captured from another deployment does not verify here', async () => {
  const { env } = setup();
  await registerNode(env);
  const req = signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { host: 'other.example.com' });
  req.host = HOST; // replayed against this coordinator
  const res = await handleRequest(req, env);
  assert.equal(res.status, 401);
});

test('truncated, empty and non base64 signatures are refused, never thrown', async () => {
  const { env } = setup();
  await registerNode(env);
  const mutations = [
    (s) => s.slice(0, 8),
    (s) => '',
    (s) => 'not base64 at all',
    (s) => `${s.slice(0, -1)}%`,
  ];
  for (const mutateSig of mutations) {
    const res = await handleRequest(
      signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { mutateSig }),
      env,
    );
    assert.equal(res.status, 401);
  }
});

test('missing signature headers are refused one by one', async () => {
  const { env } = setup();
  await registerNode(env);
  for (const h of ['X-NYCC-Timestamp', 'X-NYCC-Nonce', 'X-NYCC-Signature']) {
    const res = await handleRequest(
      signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { dropHeaders: [h] }),
      env,
    );
    assert.equal(res.status, 401, h);
  }
});

test('malformed timestamp and nonce headers are refused', async () => {
  const { env } = setup();
  await registerNode(env);
  const ts = await handleRequest(
    signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha', { timestamp: 'now-ish' }),
    env,
  );
  assert.equal(ts.status, 401);

  const bad = signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha');
  bad.headers['x-nycc-nonce'] = 'line\nbreak'; // would shift the signed framing
  assert.equal((await handleRequest(bad, env)).status, 401);
});

test('a verifier that throws becomes a 401, not a 500', async () => {
  const { env } = setup({ verifier: throwingVerifier });
  // seed the node record directly: register itself needs a working verifier
  await env.storage.put('node:alpha', {
    node_id: 'alpha',
    pubkey: A_BOX,
    verify_key: A_VERIFY,
    wattage: 0,
    last_seen: T0,
    registered_ms: T0,
  });
  const res = await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  assert.equal(res.status, 401);
});

// -------------------------------------------------------------------- routing

test('healthz, unknown paths and wrong methods', async () => {
  const { env } = setup();
  assert.equal((await handleRequest(makeReq('GET', '/healthz'), env)).status, 200);
  assert.equal((await handleRequest(makeReq('GET', '/nope'), env)).status, 404);
  assert.equal((await handleRequest(makeReq('GET', '/v1/nodes/register'), env)).status, 405);
  assert.equal((await handleRequest(makeReq('POST', '/v1/nodes'), env)).status, 405);
  assert.equal((await handleRequest(makeReq('POST', '/v1/stats'), env)).status, 405);
});

// ============================================================================ v2
// neighborhood, measured watts, member cards, receipts, stats and cors.
// ============================================================================

// --------------------------------------------------------------- neighborhood

test('register stores a neighborhood and the node list echoes it', async () => {
  const { env, storage } = setup();
  await registerNode(env, { neighborhood: "hell's kitchen" });
  assert.equal(JSON.parse(storage.map.get('node:alpha')).neighborhood, "hell's kitchen");

  const res = await handleRequest(makeReq('GET', '/v1/nodes'), env);
  assert.equal(res.body.nodes[0].neighborhood, "hell's kitchen");
});

test('a node that names no neighborhood is filed as undisclosed', async () => {
  const { env } = setup();
  await registerNode(env);
  const res = await handleRequest(makeReq('GET', '/v1/nodes'), env);
  assert.equal(res.body.nodes[0].neighborhood, DEFAULT_NEIGHBORHOOD);
  assert.equal(DEFAULT_NEIGHBORHOOD, 'undisclosed');
});

test('a v1 node record with no neighborhood field still lists as undisclosed', async () => {
  const { env } = setup();
  // exactly what v1 wrote: no neighborhood, no watts_source
  await env.storage.put('node:legacy', {
    node_id: 'legacy',
    pubkey: A_BOX,
    verify_key: A_VERIFY,
    wattage: 42,
    last_seen: T0,
    registered_ms: T0,
  });
  const res = await handleRequest(makeReq('GET', '/v1/nodes'), env);
  assert.equal(res.body.nodes[0].neighborhood, 'undisclosed');
  assert.equal(res.body.nodes[0].watts_source, 'claimed');
});

test('register rejects a neighborhood that is not the pinned lowercase shape', async () => {
  const { env, storage } = setup();
  const bad = [
    'Bed-Stuy', // uppercase would split one neighborhood into two pins
    '',
    ' leading space',
    '-leading dash',
    'ridgewood!',
    'a'.repeat(33),
    'bed\nstuy',
    42,
  ];
  for (const neighborhood of bad) {
    const body = { node_id: 'alpha', pubkey: A_BOX, verify_key: A_VERIFY, wattage: 0, neighborhood };
    const res = await handleRequest(signReq(env, 'POST', '/v1/nodes/register', { body }), env);
    assert.equal(res.status, 400, JSON.stringify(neighborhood));
    assert.equal(res.body.error, 'invalid neighborhood');
  }
  assert.equal(storage.map.has('node:alpha'), false);
});

test('register accepts the full pinned neighborhood charset', async () => {
  const { env } = setup();
  for (const neighborhood of ['bed-stuy', "hell's kitchen", '5 pointz', 'a', 'a'.repeat(32)]) {
    const body = { node_id: 'alpha', pubkey: A_BOX, verify_key: A_VERIFY, wattage: 0, neighborhood };
    const res = await handleRequest(signReq(env, 'POST', '/v1/nodes/register', { body }), env);
    assert.equal(res.status, 200, neighborhood);
  }
});

// -------------------------------------------------------------- watts_source

test('register stores watts_source and the node list echoes it', async () => {
  const { env, storage } = setup();
  await registerNode(env, { wattage: 65.4, wattsSource: 'measured' });
  assert.equal(JSON.parse(storage.map.get('node:alpha')).watts_source, 'measured');
  const res = await handleRequest(makeReq('GET', '/v1/nodes'), env);
  assert.equal(res.body.nodes[0].watts_source, 'measured');
  assert.equal(res.body.nodes[0].wattage, 65.4);
});

test('heartbeat can flip watts_source when the gpu goes away', async () => {
  const { env, storage } = setup();
  await registerNode(env, { wattage: 65.4, wattsSource: 'measured' });
  const res = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/heartbeat', {
      body: { node_id: 'alpha', wattage: 300, watts_source: 'claimed' },
    }),
    env,
  );
  assert.equal(res.status, 200);
  const rec = JSON.parse(storage.map.get('node:alpha'));
  assert.equal(rec.watts_source, 'claimed');
  assert.equal(rec.wattage, 300);
});

test('watts_source outside the two known values is refused on both routes', async () => {
  const { env } = setup();
  const reg = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/register', {
      body: { node_id: 'alpha', pubkey: A_BOX, verify_key: A_VERIFY, wattage: 0, watts_source: 'guessed' },
    }),
    env,
  );
  assert.equal(reg.status, 400);
  assert.equal(reg.body.error, 'invalid watts_source');

  await registerNode(env);
  const hb = await handleRequest(
    signReq(env, 'POST', '/v1/nodes/heartbeat', {
      body: { node_id: 'alpha', wattage: 1, watts_source: 'vibes' },
    }),
    env,
  );
  assert.equal(hb.status, 400);
});

// ------------------------------------------------------ canonical card bytes

test('canonicalJson is byte for byte python json.dumps(sort_keys, separators)', () => {
  const card = {
    member: 'jimmy',
    member_verify_key: A_VERIFY,
    issued: '2026-08-19T12:00:00+00:00',
    serial: 1755600000,
  };
  assert.equal(
    canonicalJson(card),
    '{"issued":"2026-08-19T12:00:00+00:00","member":"jimmy",' +
      `"member_verify_key":"${A_VERIFY}","serial":1755600000}`,
  );
  // key order comes from the sort, not from insertion order
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson({ x: -3, y: null, z: true }), '{"x":-3,"y":null,"z":true}');
});

test('canonicalJson escapes exactly what python ensure_ascii escapes', () => {
  // every code point outside 0x20..0x7e is escaped \uXXXX, lowercase hex, del too
  assert.equal(
    canonicalJson({ a: 'q"b\\c\td\ne\u0001f\u007f\u2014' }),
    '{"a":"q\\"b\\\\c\\td\\ne\\u0001f\\u007f\\u2014"}',
  );
  assert.equal(canonicalJson({ m: 'caf\u00e9' }), '{"m":"caf\\u00e9"}');
  // non-bmp comes out as the surrogate pair, which is what python emits too
  assert.equal(canonicalJson({ m: '\u{1F600}' }), '{"m":"\\ud83d\\ude00"}');
  assert.equal(canonicalJson({ m: '' }), '{"m":""}');
});

test('canonicalJson refuses anything python would not have produced here', () => {
  assert.equal(canonicalJson({ n: 1.5 }), null);
  assert.equal(canonicalJson({ n: Number.NaN }), null);
  assert.equal(canonicalJson({ n: Infinity }), null);
  assert.equal(canonicalJson(undefined), null);
});

test('canonicalJson writes an integral number the way python now writes it', () => {
  // javascript has one number type, so 65.0 and 65 are the same value here and there is
  // nothing to choose between them. pygrid.crypto.canonical_json collapses integral
  // floats for exactly this reason: a receipt the node signed over "watts":65 has to
  // canonicalize to the same bytes once it has been through this worker's JSON.parse.
  assert.equal(canonicalJson({ watts: 65.0 }), '{"watts":65}');
  assert.equal(canonicalJson({ watts: 65 }), canonicalJson({ watts: 65.0 }));
});

test('decodeCardHeader takes base64 utf8 json and nothing else', () => {
  const doc = cardDoc();
  assert.deepEqual(decodeCardHeader(cardHeader(doc)), doc);
  for (const junk of ['', 'not base64!!', Buffer.from('{nope', 'utf8').toString('base64'), null, 7]) {
    assert.equal(decodeCardHeader(junk), null, String(junk));
  }
});

// ------------------------------------------------- card verification, in pure

test('verifyCardDocument accepts a club signed card and names every failure', async () => {
  const verifier = makeVerifier();
  const good = await verifyCardDocument(cardDoc(), CLUB_VERIFY, verifier);
  assert.equal(good.ok, true);
  assert.equal(good.card.member, 'jimmy baker');

  const cases = [
    [null, 'card_malformed'],
    ['a string', 'card_malformed'],
    [{ card: makeCard() }, 'card_malformed'],
    [{ card: makeCard(), sig: 'not base64!!' }, 'card_malformed'],
    [{ card: 'nope', sig: 'AAAA' }, 'card_malformed'],
    [cardDoc(makeCard({ member: '' })), 'card_invalid'],
    [cardDoc(makeCard({ member: 'x'.repeat(65) })), 'card_invalid'],
    [cardDoc(makeCard({ member: 7 })), 'card_invalid'],
    [cardDoc(makeCard({ member_verify_key: 'short' })), 'card_invalid'],
    [cardDoc(makeCard({ issued: 'yesterday' })), 'card_invalid'],
    [cardDoc(makeCard({ issued: '19/08/2026' })), 'card_invalid'],
    [cardDoc(makeCard({ issued: 7 })), 'card_invalid'],
    [cardDoc(makeCard({ serial: 1.5 })), 'card_invalid'],
    [cardDoc(makeCard({ serial: '1755600000' })), 'card_invalid'],
    [cardDoc(makeCard(), CLUB_IMPOSTOR), 'card_not_signed_by_club'],
  ];
  for (const [doc, code] of cases) {
    const res = await verifyCardDocument(doc, CLUB_VERIFY, verifier);
    assert.equal(res.ok, false, JSON.stringify(doc));
    assert.equal(res.code, code, JSON.stringify(doc));
  }
});

test('issued is accepted as a date or as a full timestamp', async () => {
  for (const issued of ['2026-08-19', '2026-08-19T12:00:00+00:00', '2026-08-19 12:00', '2026-08-19T12:00:00.123456Z']) {
    const res = await verifyCardDocument(cardDoc(makeCard({ issued })), CLUB_VERIFY, makeVerifier());
    assert.equal(res.ok, true, issued);
  }
});

test('a card field edited after issue no longer verifies', async () => {
  const doc = cardDoc(makeCard({ member: 'a guest' }));
  doc.card.member = 'jimmy baker'; // promotion by text editor
  const res = await verifyCardDocument(doc, CLUB_VERIFY, makeVerifier());
  assert.equal(res.code, 'card_not_signed_by_club');
});

test('a field bolted onto a signed card breaks the signature', async () => {
  const doc = cardDoc();
  doc.card.tier = 'founder';
  const res = await verifyCardDocument(doc, CLUB_VERIFY, makeVerifier());
  assert.equal(res.code, 'card_not_signed_by_club');
});

test('a card the club signed with an extra field still verifies', async () => {
  // forward compatibility: the canonical form covers every key on the card, so a v3
  // field the club signed does not have to be known here to check out.
  const card = makeCard({ tier: 'founder' });
  const res = await verifyCardDocument(cardDoc(card), CLUB_VERIFY, makeVerifier());
  assert.equal(res.ok, true);
});

test('a card verifier that throws is a failure, not an exception', async () => {
  const res = await verifyCardDocument(cardDoc(), CLUB_VERIFY, throwingVerifier);
  assert.equal(res.ok, false);
  assert.equal(res.code, 'card_not_signed_by_club');
});

// ----------------------------------------------------------- the submit gate

test('with no club key configured submission is open exactly as v1', async () => {
  const { env } = setup(); // clubVerifyKey ''
  await registerNode(env);
  const res = await submitJob(env);
  assert.equal(res.status, 200);

  // a card sent to a coordinator that has no club key is ignored, not rejected
  const carded = await handleRequest(memberSubmit(env), env);
  assert.equal(carded.status, 200);
});

test('with a club key configured an uncarded submit is 403 and queues nothing', async () => {
  const { env, storage } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  const res = await submitJob(env);
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'card_required');
  assert.equal([...storage.map.keys()].some((k) => k.startsWith('job:')), false);
  assert.equal([...storage.map.keys()].some((k) => k.startsWith('queue:')), false);
});

test('a carded and member signed submit is accepted and queued', async () => {
  const { env, storage } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  const res = await gatedSubmit(env);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.ok(res.body.job_id);
  assert.equal(JSON.parse(storage.map.get(`job:${res.body.job_id}`)).status, 'queued');
});

test('the gate answers before the body is read, so probing tells an outsider nothing', async () => {
  const { env } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  for (const body of ['not json', '[]', { to_node: 'ghost' }]) {
    const res = await handleRequest(makeReq('POST', '/v1/jobs', { body }), env);
    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'card_required');
  }
});

test('every gate failure is a 403 with its own code', async () => {
  const { env } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  const nowS = Math.floor(T0 / 1000);

  const cases = [
    ['card_malformed', { header: 'not base64!!' }],
    ['card_invalid', { card: makeCard({ member: '' }) }],
    ['card_not_signed_by_club', { doc: cardDoc(makeCard(), CLUB_IMPOSTOR) }],
    ['member_sig_missing', { dropHeaders: ['X-NYCC-Member-Sig'] }],
    ['member_sig_missing', { dropHeaders: ['X-NYCC-Member-Nonce'] }],
    ['member_sig_missing', { dropHeaders: ['X-NYCC-Member-Ts'] }],
    ['member_sig_expired', { timestamp: nowS - (MAX_SKEW_S + 1) }],
    ['member_sig_expired', { timestamp: nowS + MAX_SKEW_S + 1 }],
    ['member_sig_invalid', { signWith: MEMBER_OTHER }],
  ];
  for (const [code, opts] of cases) {
    const res = await handleRequest(memberSubmit(env, opts), env);
    assert.equal(res.status, 403, code);
    assert.equal(res.body.code, code, JSON.stringify(opts));
  }
});

test('a malformed member timestamp or nonce header is refused', async () => {
  const { env } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);

  const badTs = await handleRequest(memberSubmit(env, { timestamp: 'now-ish' }), env);
  assert.equal(badTs.body.code, 'member_sig_malformed');

  const req = memberSubmit(env);
  req.headers['x-nycc-member-nonce'] = 'line\nbreak'; // would shift the signed framing
  assert.equal((await handleRequest(req, env)).body.code, 'member_sig_malformed');

  const badSig = memberSubmit(env);
  badSig.headers['x-nycc-member-sig'] = 'not base64!!';
  assert.equal((await handleRequest(badSig, env)).body.code, 'member_sig_malformed');
});

test('the member signature covers the body, so a rewritten job is refused', async () => {
  const { env, storage } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  await registerNode(env, { nodeId: 'bravo', pubkey: B_BOX, verifyKey: B_VERIFY });

  const req = memberSubmit(env);
  // re-pointed at another member's gpu after the member signed it
  req.bodyBytes = bodyBytes({ to_node: 'bravo', blob_b64: blob('sealed'), reply_pubkey: REPLY_PUB });
  const res = await handleRequest(req, env);
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'member_sig_invalid');
  assert.equal([...storage.map.keys()].some((k) => k.startsWith('job:')), false);
});

test('a member signature captured from another deployment does not verify here', async () => {
  const { env } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  const req = memberSubmit(env, { host: 'other.example.com' });
  req.host = HOST;
  assert.equal((await handleRequest(req, env)).body.code, 'member_sig_invalid');
});

test('a replayed member nonce is refused and the nonce is stored per member key', async () => {
  const { env, storage } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  const nonce = 'bWVtYmVyLW5vbmNlLTAwMDE=';

  const first = await handleRequest(memberSubmit(env, { nonce }), env);
  assert.equal(first.status, 200);
  assert.equal(storage.ttls.get(`mnonce:${MEMBER_VERIFY}:${nonce}`), NONCE_TTL_S);

  const replay = await handleRequest(memberSubmit(env, { nonce }), env);
  assert.equal(replay.status, 403);
  assert.equal(replay.body.code, 'member_sig_replay');

  // the same nonce under a different member key is a different nonce
  const other = makeCard({ member: 'someone else', member_verify_key: MEMBER_OTHER });
  const shared = await handleRequest(
    memberSubmit(env, { card: other, signWith: MEMBER_OTHER, nonce }),
    env,
  );
  assert.equal(shared.status, 200);
});

test('a forged member signature cannot burn a members nonce space', async () => {
  const { env, storage } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  const nonce = 'YnVybi1tZW1iZXItbm9uYw==';

  const forged = await handleRequest(memberSubmit(env, { nonce, signWith: MEMBER_OTHER }), env);
  assert.equal(forged.status, 403);
  assert.equal(storage.map.has(`mnonce:${MEMBER_VERIFY}:${nonce}`), false);

  const real = await handleRequest(memberSubmit(env, { nonce }), env);
  assert.equal(real.status, 200);
});

test('the gate does not change any other route', async () => {
  const { env } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env); // signed by the node key, no card anywhere
  assert.equal((await handleRequest(makeReq('GET', '/v1/nodes'), env)).status, 200);
  assert.equal((await handleRequest(makeReq('GET', '/v1/stats'), env)).status, 200);
  assert.equal(
    (await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env)).status,
    200,
  );
});

test('an oversize body is 413 before the gate does any crypto', async () => {
  const { env, verifier } = setup({ clubVerifyKey: CLUB_VERIFY });
  await registerNode(env);
  const before = verifier.calls.length;
  const res = await handleRequest(
    makeReq('POST', '/v1/jobs', { body: 'x'.repeat(MAX_BODY_BYTES + 1) }),
    env,
  );
  assert.equal(res.status, 413);
  assert.equal(verifier.calls.length, before);
});

// ---------------------------------------------------------------- receipts

test('a result receipt is stored and handed back with the finished job', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const receipt = {
    receipt: {
      job_id: 'j1',
      node_id: 'alpha',
      duration_ms: 812,
      watts: 65.0,
      watts_source: 'measured',
      request_sha256: 'aa'.repeat(32),
      result_sha256: 'bb'.repeat(32),
    },
    sig: 'c2ln',
  };
  const jobId = await runOneJob(env, { receipt });

  assert.deepEqual(JSON.parse(storage.map.get(`job:${jobId}`)).receipt, receipt);
  const status = await handleRequest(makeReq('GET', `/v1/jobs/${jobId}`), env);
  assert.equal(status.body.status, 'done');
  assert.equal(status.body.blob_b64, blob('sealed-result'));
  // opaque: stored and returned untouched, the coordinator verifies nothing in it
  assert.deepEqual(status.body.receipt, receipt);
});

test('a v1 result with no receipt is still accepted and carries no receipt key', async () => {
  const { env } = setup();
  await registerNode(env);
  const jobId = await runOneJob(env);
  const status = await handleRequest(makeReq('GET', `/v1/jobs/${jobId}`), env);
  assert.deepEqual(status.body, { status: 'done', blob_b64: blob('sealed-result') });
});

test('a receipt that is not a json object is refused, an oversize one is 413', async () => {
  const { env, storage } = setup();
  await registerNode(env);

  for (const receipt of ['a string', [1, 2], 7]) {
    const job = await submitJob(env);
    await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
    const res = await postResult(env, job.body.job_id, { receipt });
    assert.equal(res.status, 400, JSON.stringify(receipt));
    assert.equal(JSON.parse(storage.map.get(`job:${job.body.job_id}`)).status, 'running');
  }

  const job = await submitJob(env);
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);
  const big = await postResult(env, job.body.job_id, {
    receipt: { pad: 'x'.repeat(MAX_RECEIPT_BYTES + 1) },
  });
  assert.equal(big.status, 413);
});

test('a retried result never replaces the first receipt', async () => {
  const { env, storage } = setup();
  await registerNode(env);
  const job = await submitJob(env);
  const jobId = job.body.job_id;
  await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env);

  await postResult(env, jobId, { text: 'first', receipt: { n: 1 } });
  const retry = await postResult(env, jobId, { text: 'second', receipt: { n: 2 } });
  assert.equal(retry.body.duplicate, true);
  assert.deepEqual(JSON.parse(storage.map.get(`job:${jobId}`)).receipt, { n: 1 });
});

// ------------------------------------------------------------------- stats

test('stats on an empty grid is all zeros', async () => {
  const { env } = setup();
  const res = await handleRequest(makeReq('GET', '/v1/stats'), env);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, {
    ok: true,
    nodes_alive: 0,
    watts: 0,
    watts_measured: 0,
    jobs_done: 0,
    neighborhoods: [],
  });
});

test('stats sums alive nodes only and splits measured from claimed', async () => {
  const { env } = setup();
  await registerNode(env, { nodeId: 'a1', wattage: 65.1, wattsSource: 'measured', neighborhood: 'bed-stuy' });
  await registerNode(env, {
    nodeId: 'a2',
    pubkey: B_BOX,
    verifyKey: B_VERIFY,
    wattage: 30.2,
    wattsSource: 'claimed',
    neighborhood: 'bed-stuy',
  });
  await registerNode(env, { nodeId: 'a3', wattage: 10, wattsSource: 'measured', neighborhood: 'ridgewood' });
  // a4 went quiet three heartbeats ago: it must drop out of every total, including
  // its neighborhood, so the map shows watts that are actually plugged in
  await env.storage.put('node:a4', {
    node_id: 'a4',
    pubkey: A_BOX,
    verify_key: A_VERIFY,
    wattage: 1000,
    watts_source: 'measured',
    neighborhood: 'ridgewood',
    last_seen: T0 - STALE_MS - 1,
    registered_ms: T0,
  });

  const res = await handleRequest(makeReq('GET', '/v1/stats'), env);
  assert.equal(res.body.nodes_alive, 3);
  assert.equal(res.body.watts, 105.3);
  assert.equal(res.body.watts_measured, 75.1);
  assert.deepEqual(res.body.neighborhoods, [
    { name: 'bed-stuy', nodes: 2, watts: 95.3 },
    { name: 'ridgewood', nodes: 1, watts: 10 },
  ]);
});

test('stats files nodes with no neighborhood under undisclosed', async () => {
  const { env } = setup();
  await registerNode(env, { nodeId: 'a1', wattage: 5 });
  const res = await handleRequest(makeReq('GET', '/v1/stats'), env);
  assert.deepEqual(res.body.neighborhoods, [{ name: 'undisclosed', nodes: 1, watts: 5 }]);
});

test('jobs_done counts accepted results once each', async () => {
  const { env, storage } = setup();
  await registerNode(env);

  const first = await runOneJob(env);
  assert.equal((await handleRequest(makeReq('GET', '/v1/stats'), env)).body.jobs_done, 1);

  await runOneJob(env);
  assert.equal(storage.map.get(STATS_JOBS_DONE_KEY), '2');

  // a retry of an already accepted result must not count twice
  await postResult(env, first, { text: 'again' });
  assert.equal((await handleRequest(makeReq('GET', '/v1/stats'), env)).body.jobs_done, 2);

  // a refused result does not count either
  await submitJob(env);
  assert.equal((await handleRequest(makeReq('GET', '/v1/stats'), env)).body.jobs_done, 2);
});

test('a junk counter value reads as zero rather than breaking stats', async () => {
  const { env } = setup();
  await env.storage.put(STATS_JOBS_DONE_KEY, 'seventeen');
  const res = await handleRequest(makeReq('GET', '/v1/stats'), env);
  assert.equal(res.status, 200);
  assert.equal(res.body.jobs_done, 0);
});

test('stats pages through every node record, not just the first page', async () => {
  const { env, storage } = setup();
  for (let i = 0; i < 12; i++) {
    await storage.put(`node:n${String(i).padStart(3, '0')}`, {
      node_id: `n${i}`,
      pubkey: A_BOX,
      verify_key: A_VERIFY,
      wattage: 1,
      watts_source: 'claimed',
      neighborhood: 'bed-stuy',
      last_seen: T0,
      registered_ms: T0,
    });
  }
  const listSpy = storage.list.bind(storage);
  let pages = 0;
  storage.list = async (opts) => {
    pages += 1;
    // a kv page smaller than the namespace, which is what the cursor loop is for
    return listSpy({ ...opts, limit: 5 });
  };
  const res = await handleRequest(makeReq('GET', '/v1/stats'), env);
  assert.equal(res.body.nodes_alive, 12);
  assert.ok(pages > 1, 'expected the cursor loop to run');
});

test('stats stops at the kv get budget and reports a partial answer', async () => {
  const { env, storage } = setup();
  // more node records than one invocation is allowed to read. the platform kills the
  // invocation at 1000 kv operations, so the honest answer is a short one, not a 500.
  for (let i = 0; i < STATS_MAX_GETS + 5; i++) {
    await storage.put(`node:n${String(i).padStart(4, '0')}`, {
      node_id: `n${i}`,
      pubkey: A_BOX,
      verify_key: A_VERIFY,
      wattage: 1,
      watts_source: 'claimed',
      neighborhood: 'bed-stuy',
      last_seen: T0,
      registered_ms: T0,
    });
  }
  const res = await handleRequest(makeReq('GET', '/v1/stats'), env);
  assert.equal(res.status, 200);
  assert.equal(res.body.partial, true);
  assert.equal(res.body.nodes_alive, STATS_MAX_GETS);
  assert.equal(res.body.watts, STATS_MAX_GETS);
});

// -------------------------------------------------------------------- cors

test('every v1 response carries the cors headers, including errors', async () => {
  const { env } = setup();
  const responses = [
    await handleRequest(makeReq('GET', '/v1/nodes'), env),
    await handleRequest(makeReq('GET', '/v1/stats'), env),
    await handleRequest(makeReq('GET', '/v1/jobs/nope'), env),
    await handleRequest(makeReq('POST', '/v1/nodes'), env),
    await handleRequest(makeReq('GET', '/v1/does-not-exist'), env),
  ];
  for (const res of responses) {
    assert.equal(res.headers['access-control-allow-origin'], '*');
    assert.equal(res.headers['access-control-allow-methods'], 'GET, POST, OPTIONS');
    assert.equal(res.headers['access-control-max-age'], '86400');
  }
});

test('the two public read routes are cacheable and every other route is not', async () => {
  const { env } = setup();
  await registerNode(env);
  const job = await submitJob(env);

  for (const path of ['/v1/nodes', '/v1/stats']) {
    const res = await handleRequest(makeReq('GET', path), env);
    assert.equal(res.headers['cache-control'], PUBLIC_CACHE_HEADERS['cache-control'], path);
    // the cache header rides on top of cors, it does not replace it
    assert.equal(res.headers['access-control-allow-origin'], '*', path);
    assert.ok(res.headers['access-control-allow-headers'], path);
  }
  assert.equal(PUBLIC_CACHE_HEADERS['cache-control'], 'public, max-age=15');

  // everything else sets nothing here and keeps the no-store default worker.js applies.
  // job status is per caller and the signed routes must never come out of a cache.
  const uncacheable = [
    await handleRequest(makeReq('GET', `/v1/jobs/${job.body.job_id}`), env),
    await handleRequest(signReq(env, 'GET', '/v1/jobs/pull?node_id=alpha'), env),
    await handleRequest(makeReq('POST', '/v1/jobs', { body: { to_node: 'alpha' } }), env),
    await handleRequest(makeReq('GET', '/healthz'), env),
  ];
  for (const res of uncacheable) {
    assert.equal(res.headers && res.headers['cache-control'], undefined);
  }
});

test('allow-headers names content-type and every x-nycc header in use', () => {
  const allowed = CORS_HEADERS['access-control-allow-headers'].split(',').map((s) => s.trim());
  assert.deepEqual(allowed.slice(0, 1), ['content-type']);
  for (const h of [
    'x-nycc-node-id',
    'x-nycc-timestamp',
    'x-nycc-nonce',
    'x-nycc-signature',
    'x-nycc-card',
    'x-nycc-member-ts',
    'x-nycc-member-nonce',
    'x-nycc-member-sig',
  ]) {
    assert.ok(allowed.includes(h), h);
  }
});

test('preflight anywhere under /v1/ is 204 with the headers and no body', async () => {
  const { env } = setup();
  for (const p of ['/v1/jobs', '/v1/nodes/register', '/v1/stats', '/v1/whatever']) {
    const res = await handleRequest(makeReq('OPTIONS', p), env);
    assert.equal(res.status, 204, p);
    assert.equal(res.body, null);
    assert.equal(res.headers['access-control-allow-origin'], '*');
  }
});

test('routes outside /v1/ get no cors headers', async () => {
  const { env } = setup();
  assert.equal((await handleRequest(makeReq('GET', '/healthz'), env)).headers, undefined);
  assert.equal((await handleRequest(makeReq('GET', '/nope'), env)).headers, undefined);
  // preflight is a /v1/ affair; /healthz keeps the v1 405 for a method it does not have
  assert.equal((await handleRequest(makeReq('OPTIONS', '/healthz'), env)).status, 405);
});
