// pure coordinator logic. no cloudflare globals, no network, no kv imports.
// storage and verifier are injected so node --test can exercise every branch.
//
// storage interface (see worker.js for the kv adapter):
//   get(key)                    -> Promise<object|null>   (json-decoded)
//   put(key, value, opts?)      -> Promise<void>          (opts: {expirationTtl} seconds)
//   delete(key)                 -> Promise<void>
//   list({prefix, limit, cursor}) -> Promise<{keys:[{name}], list_complete, cursor}>
// verifier interface:
//   verify(verifyKeyB64:string, msg:Uint8Array, sig:Uint8Array) -> Promise<boolean>
//   must return false on malformed/truncated/forged input, never throw.
// env also carries now() -> ms epoch, randomUUID() -> string, and clubVerifyKey, the
// b64 ed25519 key that member cards are checked against. empty string means the club
// gate is off and POST /v1/jobs stays open, exactly as v1 shipped.

// the signing domain is unchanged from v1 on purpose: v2 adds endpoints and fields, it
// does not move a byte of the canonical string, so v1 nodes keep verifying.
export const PROTOCOL_PREFIX = 'nycc-grid-v1|';

// replay window. hard bound on signature reuse; nonce dedup is best effort on top.
export const MAX_SKEW_S = 300;
export const NONCE_TTL_S = 600;

export const PULL_MAX = 10;
export const LEASE_MS = 10 * 60 * 1000;
export const MAX_ATTEMPTS = 5;

// body cap sits above the blob cap so a max blob plus json framing still fits.
export const MAX_BODY_BYTES = 2 * 1024 * 1024;
export const MAX_BLOB_B64 = 1024 * 1024;
export const MAX_QUEUED_PER_NODE = 100;

export const HEARTBEAT_S = 30;
export const STALE_MS = 3 * HEARTBEAT_S * 1000;

export const NODES_LIMIT_DEFAULT = 50;
export const NODES_LIMIT_MAX = 200;

// job records are garbage collected: terminal jobs 24h, never-pulled jobs 7d.
export const DONE_TTL_S = 24 * 60 * 60;
export const QUEUED_TTL_S = 7 * 24 * 60 * 60;

// node records expire too, or a namespace collects every one-off registration forever
// and the stats scan pays for all of them. 7 days is many multiples of STALE_MS, so a
// record only lapses long after the node stopped counting as alive, and a node that is
// still running re-registers on the first heartbeat 404 (see handleHeartbeat) and gets
// its record back. a live node therefore never notices this.
export const NODE_TTL_S = 7 * 24 * 60 * 60;

// a node that sends no neighborhood is filed here rather than dropped from the map.
export const DEFAULT_NEIGHBORHOOD = 'undisclosed';
export const WATTS_SOURCES = ['measured', 'claimed'];

// receipts are stored opaquely, so the only thing checked is that one cannot be used
// to stuff a job record. a real receipt is a few hundred bytes.
export const MAX_RECEIPT_BYTES = 8 * 1024;
// the card travels in a header, and headers are not the place for a megabyte.
export const MAX_CARD_HEADER = 8 * 1024;
export const CARD_MEMBER_MAX = 64;

export const STATS_JOBS_DONE_KEY = '__stats__:jobs_done';
// bounded so a namespace with a runaway number of node records cannot hang the edge.
const STATS_PAGE = 1000;
const STATS_MAX_PAGES = 20;
// a worker invocation is capped at 1000 kv operations, and this route spends one get
// per node record. stop under the cap and say the answer is short: the alternative is
// a namespace that grows past it and turns /v1/stats into a permanent 500.
export const STATS_MAX_GETS = 800;

export const CORS_HEADERS = Object.freeze({
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers':
    'content-type, x-nycc-node-id, x-nycc-timestamp, x-nycc-nonce, x-nycc-signature, ' +
    'x-nycc-card, x-nycc-member-ts, x-nycc-member-nonce, x-nycc-member-sig',
  'access-control-max-age': '86400',
});

// the two public read routes, and only those, are cacheable. they take no credentials,
// answer the same thing to everyone, and are what the site polls; 15 seconds is half a
// heartbeat interval, so a node still appears promptly. every other route keeps the
// no-store default worker.js applies, which matters because job status is a per-caller
// secret and the signed routes must never be served from a cache.
export const PUBLIC_CACHE_HEADERS = Object.freeze({ 'cache-control': 'public, max-age=15' });

const KEY_BYTES = 32;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------- primitives

export function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// the one canonical byte string. every signer and verifier in the grid cites this.
// header values (timestamp, nonce) are signed verbatim: no normalization anywhere.
// body is the raw received bytes: no re-serialization, no json canonicalization.
export function buildSignedMessage({ host, method, path, timestamp, nonce, body }) {
  const head = `${PROTOCOL_PREFIX}${host}\n${method}\n${path}\n${timestamp}\n${nonce}\n`;
  return concatBytes(enc.encode(head), body && body.length ? body : new Uint8Array(0));
}

export function b64ToBytes(s) {
  if (typeof s !== 'string' || s.length === 0) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

// ':' is excluded: node ids are kv key segments and ':' would let "a" list "a:b" queues.
const NODE_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const JOB_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const IDEM_RE = /^[A-Za-z0-9._:-]{1,128}$/;
// base64 charset only: a newline in a header value would shift the signed framing.
const HEADER_TOKEN_RE = /^[A-Za-z0-9+/=]{1,128}$/;
const TIMESTAMP_RE = /^\d{1,15}$/;
// lowercase only, so "Bed-Stuy" and "bed-stuy" cannot become two pins on the same map.
const NEIGHBORHOOD_RE = /^[a-z0-9][a-z0-9 \-']{0,31}$/;
// loose on purpose: a date alone is iso8601 and so is a full timestamp with an offset.
// this only has to reject junk, the club signature decides everything that matters.
const ISSUED_RE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?/;

export function isNodeId(v) {
  return typeof v === 'string' && NODE_ID_RE.test(v);
}

function isJobId(v) {
  return typeof v === 'string' && JOB_ID_RE.test(v);
}

function isKey32(v) {
  const raw = b64ToBytes(v);
  return raw !== null && raw.length === KEY_BYTES;
}

// headers is optional and carries only what a route needs for itself. cors is added
// later, in handleRequest, for every /v1 path, and worker.js spreads whatever lands
// here over its own no-store default.
function json(status, body, headers) {
  return headers ? { status, body, headers } : { status, body };
}

// 403 plus a stable machine readable code. the message is for humans reading logs,
// the code is what a client branches on.
function forbid(code, message) {
  return { status: 403, body: { error: message, code } };
}

// display and grouping value only. it is self reported like wattage, nothing verifies
// that a node is anywhere near the neighborhood it names.
function readNeighborhood(rec) {
  const v = rec && rec.neighborhood;
  return typeof v === 'string' && v ? v : DEFAULT_NEIGHBORHOOD;
}

// records written by v1 nodes have no watts_source; they were all claimed numbers.
function readWattsSource(rec) {
  const v = rec && rec.watts_source;
  return v === 'measured' ? 'measured' : 'claimed';
}

// watt sums are floats added in a loop, so 0.1 + 0.2 shows up unless it is rounded.
// one decimal is what nodes report anyway.
function round1(n) {
  return Math.round(n * 10) / 10;
}

function nodeKey(nodeId) {
  return `node:${nodeId}`;
}

function jobKey(jobId) {
  return `job:${jobId}`;
}

// zero padded so lexicographic prefix listing is oldest first.
export function queueKey(toNode, createdMs, jobId) {
  return `queue:${toNode}:${String(createdMs).padStart(16, '0')}:${jobId}`;
}

function queuePrefix(toNode) {
  return `queue:${toNode}:`;
}

function readJsonBody(req) {
  const bytes = req.bodyBytes || new Uint8Array(0);
  if (bytes.length > MAX_BODY_BYTES) return { err: json(413, { error: 'body too large' }) };
  let obj;
  try {
    obj = JSON.parse(dec.decode(bytes));
  } catch {
    return { err: json(400, { error: 'invalid json' }) };
  }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
    return { err: json(400, { error: 'body must be a json object' }) };
  }
  return { value: obj };
}

// blob checks in cap order: 413 for oversize, 400 for malformed.
function checkBlob(v) {
  if (typeof v !== 'string' || v.length === 0) return json(400, { error: 'blob_b64 required' });
  if (v.length > MAX_BLOB_B64) return json(413, { error: 'blob_b64 too large' });
  if (b64ToBytes(v) === null) return json(400, { error: 'blob_b64 is not base64' });
  return null;
}

// ------------------------------------------------------------- signature path

// returns null when the request is authentic, otherwise the error response.
// order is deliberate: signature is checked before the nonce is stored, so an
// unauthenticated caller cannot write kv or burn another node's nonce space.
export async function checkSignature(req, env, verifyKeyB64) {
  const h = req.headers || {};
  const nodeId = h['x-nycc-node-id'];
  const ts = h['x-nycc-timestamp'];
  const nonce = h['x-nycc-nonce'];
  const sigB64 = h['x-nycc-signature'];

  if (!nodeId || !ts || !nonce || !sigB64) return json(401, { error: 'missing signature headers' });
  if (!isNodeId(nodeId)) return json(401, { error: 'invalid node id header' });
  if (!TIMESTAMP_RE.test(ts)) return json(401, { error: 'invalid timestamp header' });
  if (!HEADER_TOKEN_RE.test(nonce)) return json(401, { error: 'invalid nonce header' });

  const nowS = Math.floor(env.now() / 1000);
  if (Math.abs(nowS - Number(ts)) > MAX_SKEW_S) return json(401, { error: 'timestamp outside window' });

  const sig = b64ToBytes(sigB64);
  if (sig === null) return json(401, { error: 'bad signature encoding' });

  const msg = buildSignedMessage({
    host: req.host,
    method: req.method,
    path: req.path,
    timestamp: ts,
    nonce,
    body: req.bodyBytes,
  });

  let ok = false;
  try {
    ok = await env.verifier.verify(verifyKeyB64, msg, sig);
  } catch {
    ok = false;
  }
  if (ok !== true) return json(401, { error: 'bad signature' });

  const nk = `nonce:${nodeId}:${nonce}`;
  if (await env.storage.get(nk)) return json(401, { error: 'nonce replay' });
  await env.storage.put(nk, { t: nowS }, { expirationTtl: NONCE_TTL_S });
  return null;
}

// --------------------------------------------------------------- member cards

// the club signs a card as python bytes:
//   json.dumps(card, sort_keys=True, separators=(",", ":")).encode("utf-8")
// so this has to reproduce that encoder exactly, ensure_ascii included: every code
// point outside 0x20..0x7e is escaped \uXXXX with lowercase hex, and non-bmp code
// points come out as the two surrogate escapes, which is what iterating utf-16 code
// units gives for free. JSON.stringify does NOT do this, hence the hand rolled walk.
// returns null for anything python would not have produced from a decoded card.
export function canonicalJson(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'string') return canonicalString(value);
  if (typeof value === 'number') {
    // floats are refused rather than guessed at: python repr and javascript
    // Number#toString disagree on shapes like 1e-07, and a signature check is not
    // the place to find out. cards carry an integer serial.
    if (!Number.isSafeInteger(value)) return null;
    return String(value);
  }
  if (Array.isArray(value)) {
    const parts = [];
    for (const item of value) {
      const s = canonicalJson(item);
      if (s === null) return null;
      parts.push(s);
    }
    return '[' + parts.join(',') + ']';
  }
  if (typeof value === 'object') {
    const parts = [];
    for (const key of Object.keys(value).sort()) {
      const s = canonicalJson(value[key]);
      if (s === null) return null;
      parts.push(canonicalString(key) + ':' + s);
    }
    return '{' + parts.join(',') + '}';
  }
  return null;
}

function canonicalString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const c = s.charCodeAt(i);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (c === 0x08) out += '\\b';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0d) out += '\\r';
    else if (c < 0x20 || c > 0x7e) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

// x-nycc-card is b64 of the utf-8 json {"card":{...},"sig":"..."}. null on anything
// that is not that, with no distinction between the ways it can be junk.
export function decodeCardHeader(headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return null;
  if (headerValue.length > MAX_CARD_HEADER) return null;
  const raw = b64ToBytes(headerValue);
  if (raw === null) return null;
  try {
    return JSON.parse(dec.decode(raw));
  } catch {
    return null;
  }
}

// pure: takes the decoded document, the club key and a verifier, returns
// {ok:true, card} or {ok:false, code}. no storage, no clock, no headers.
//
// every key present on the card is canonicalized, not just the four this checks, so a
// card the club signed with a field added later still verifies and a field an attacker
// bolted on does not.
export async function verifyCardDocument(doc, clubVerifyKeyB64, verifier) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return { ok: false, code: 'card_malformed' };
  }
  const card = doc.card;
  if (card === null || typeof card !== 'object' || Array.isArray(card)) {
    return { ok: false, code: 'card_malformed' };
  }
  const sig = b64ToBytes(doc.sig);
  if (sig === null) return { ok: false, code: 'card_malformed' };

  if (typeof card.member !== 'string') return { ok: false, code: 'card_invalid' };
  // code points, not utf-16 units, so the bound means the same thing here and in python
  const memberLen = Array.from(card.member).length;
  if (memberLen < 1 || memberLen > CARD_MEMBER_MAX) return { ok: false, code: 'card_invalid' };
  if (!isKey32(card.member_verify_key)) return { ok: false, code: 'card_invalid' };
  if (typeof card.issued !== 'string' || card.issued.length > 64 || !ISSUED_RE.test(card.issued)) {
    return { ok: false, code: 'card_invalid' };
  }
  if (typeof card.serial !== 'number' || !Number.isSafeInteger(card.serial)) {
    return { ok: false, code: 'card_invalid' };
  }

  const canonical = canonicalJson(card);
  if (canonical === null) return { ok: false, code: 'card_invalid' };

  let ok = false;
  try {
    ok = await verifier.verify(clubVerifyKeyB64, enc.encode(canonical), sig);
  } catch {
    ok = false;
  }
  if (ok !== true) return { ok: false, code: 'card_not_signed_by_club' };
  return { ok: true, card };
}

// the member half of the gate: same canonical byte string as node signing, same skew
// window, same nonce dedup, different header names and a different nonce namespace.
async function checkMemberSignature(req, env, card) {
  const h = req.headers || {};
  const ts = h['x-nycc-member-ts'];
  const nonce = h['x-nycc-member-nonce'];
  const sigB64 = h['x-nycc-member-sig'];

  if (!ts || !nonce || !sigB64) return forbid('member_sig_missing', 'missing member signature headers');
  if (!TIMESTAMP_RE.test(ts)) return forbid('member_sig_malformed', 'invalid member timestamp header');
  if (!HEADER_TOKEN_RE.test(nonce)) return forbid('member_sig_malformed', 'invalid member nonce header');

  const nowS = Math.floor(env.now() / 1000);
  if (Math.abs(nowS - Number(ts)) > MAX_SKEW_S) {
    return forbid('member_sig_expired', 'member timestamp outside window');
  }

  const sig = b64ToBytes(sigB64);
  if (sig === null) return forbid('member_sig_malformed', 'bad member signature encoding');

  const msg = buildSignedMessage({
    host: req.host,
    method: req.method,
    path: req.path,
    timestamp: ts,
    nonce,
    body: req.bodyBytes,
  });

  let ok = false;
  try {
    ok = await env.verifier.verify(card.member_verify_key, msg, sig);
  } catch {
    ok = false;
  }
  if (ok !== true) return forbid('member_sig_invalid', 'bad member signature');

  // scoped to the member key, so one member cannot burn another member's nonce space,
  // and never to the member NAME, which is not unique and not authenticated on its own.
  const nk = `mnonce:${card.member_verify_key}:${nonce}`;
  if (await env.storage.get(nk)) return forbid('member_sig_replay', 'member nonce replay');
  await env.storage.put(nk, { t: nowS }, { expirationTtl: NONCE_TTL_S });
  return null;
}

// returns null when submission is allowed, otherwise the 403. with no club key
// configured this returns null immediately and POST /v1/jobs behaves exactly as v1.
export async function checkMemberCard(req, env) {
  const club = env.clubVerifyKey;
  if (typeof club !== 'string' || club === '') return null;

  const header = (req.headers || {})['x-nycc-card'];
  if (!header) return forbid('card_required', 'member card required');

  const doc = decodeCardHeader(header);
  if (doc === null) return forbid('card_malformed', 'card header is not base64 json');

  const res = await verifyCardDocument(doc, club, env.verifier);
  if (!res.ok) {
    if (res.code === 'card_malformed') return forbid(res.code, 'card document is malformed');
    if (res.code === 'card_invalid') return forbid(res.code, 'card fields are invalid');
    return forbid(res.code, 'card is not signed by the club');
  }
  return checkMemberSignature(req, env, res.card);
}

// ------------------------------------------------------------------- handlers

async function handleRegister(req, env) {
  const { err, value: body } = readJsonBody(req);
  if (err) return err;

  const nodeId = body.node_id;
  if (!isNodeId(nodeId)) return json(400, { error: 'invalid node_id' });
  if (req.headers['x-nycc-node-id'] !== nodeId) {
    return json(400, { error: 'node_id header does not match body' });
  }
  if (!isKey32(body.pubkey)) return json(400, { error: 'pubkey must be 32 base64 bytes' });
  if (!isKey32(body.verify_key)) return json(400, { error: 'verify_key must be 32 base64 bytes' });

  const wattage = body.wattage === undefined || body.wattage === null ? 0 : Number(body.wattage);
  if (!Number.isFinite(wattage) || wattage < 0) return json(400, { error: 'invalid wattage' });

  let neighborhood = DEFAULT_NEIGHBORHOOD;
  if (body.neighborhood !== undefined && body.neighborhood !== null) {
    if (typeof body.neighborhood !== 'string' || !NEIGHBORHOOD_RE.test(body.neighborhood)) {
      return json(400, { error: 'invalid neighborhood' });
    }
    neighborhood = body.neighborhood;
  }

  let wattsSource = 'claimed';
  if (body.watts_source !== undefined && body.watts_source !== null) {
    if (!WATTS_SOURCES.includes(body.watts_source)) {
      return json(400, { error: 'invalid watts_source' });
    }
    wattsSource = body.watts_source;
  }

  const existing = await env.storage.get(nodeKey(nodeId));
  // proof of possession for a new id; for an existing id the CURRENT key must sign,
  // so rotation works but nobody can overwrite another member's pubkey.
  const verifyKeyB64 = existing ? existing.verify_key : body.verify_key;
  const sigErr = await checkSignature(req, env, verifyKeyB64);
  if (sigErr) return sigErr;

  const now = env.now();
  // register is a full upsert: re-registering without a neighborhood files the node
  // back under "undisclosed" rather than silently keeping the old pin.
  await env.storage.put(
    nodeKey(nodeId),
    {
      node_id: nodeId,
      pubkey: body.pubkey,
      verify_key: body.verify_key,
      wattage,
      watts_source: wattsSource,
      neighborhood,
      last_seen: now,
      registered_ms: existing ? existing.registered_ms : now,
    },
    { expirationTtl: NODE_TTL_S },
  );
  return json(200, { ok: true, node_id: nodeId, rotated: Boolean(existing) });
}

async function handleHeartbeat(req, env) {
  const { err, value: body } = readJsonBody(req);
  if (err) return err;

  const nodeId = body.node_id;
  if (!isNodeId(nodeId)) return json(400, { error: 'invalid node_id' });
  if (req.headers['x-nycc-node-id'] !== nodeId) {
    return json(400, { error: 'node_id header does not match body' });
  }

  // 404 before the signature check is unavoidable: the verify key lives in the record.
  // it is also the signal NodeAgent needs to re-register after coordinator state loss.
  const node = await env.storage.get(nodeKey(nodeId));
  if (!node) return json(404, { error: 'unknown node' });

  const sigErr = await checkSignature(req, env, node.verify_key);
  if (sigErr) return sigErr;

  if (body.wattage !== undefined && body.wattage !== null) {
    const w = Number(body.wattage);
    if (!Number.isFinite(w) || w < 0) return json(400, { error: 'invalid wattage' });
    node.wattage = w;
  }
  // a node that loses its gpu mid-run flips back to claimed on the next beat.
  if (body.watts_source !== undefined && body.watts_source !== null) {
    if (!WATTS_SOURCES.includes(body.watts_source)) {
      return json(400, { error: 'invalid watts_source' });
    }
    node.watts_source = body.watts_source;
  }
  node.last_seen = env.now();
  // every beat pushes the expiry out again, so the ttl only ever catches a node that
  // stopped talking a week ago, not one that is quietly idle.
  await env.storage.put(nodeKey(nodeId), node, { expirationTtl: NODE_TTL_S });
  return json(200, { ok: true, node_id: nodeId });
}

async function handleListNodes(req, env) {
  let limit = NODES_LIMIT_DEFAULT;
  if (req.query.limit !== undefined) {
    const n = Number(req.query.limit);
    if (!Number.isInteger(n) || n < 1) return json(400, { error: 'invalid limit' });
    limit = Math.min(n, NODES_LIMIT_MAX);
  }
  const listed = await env.storage.list({
    prefix: 'node:',
    limit,
    cursor: req.query.cursor || undefined,
  });

  const now = env.now();
  const nodes = [];
  for (const k of listed.keys) {
    const rec = await env.storage.get(k.name);
    if (!rec) continue;
    nodes.push({
      node_id: rec.node_id,
      pubkey: rec.pubkey,
      verify_key: rec.verify_key,
      wattage: rec.wattage,
      watts_source: readWattsSource(rec),
      neighborhood: readNeighborhood(rec),
      last_seen: rec.last_seen,
      alive: now - rec.last_seen <= STALE_MS,
    });
  }
  const out = { nodes };
  if (!listed.list_complete && listed.cursor) out.cursor = listed.cursor;
  return json(200, out, PUBLIC_CACHE_HEADERS);
}

// counter reads are defensive: a hand edited or half written kv value reads as zero
// rather than poisoning the whole stats response.
async function readCounter(env, key) {
  const v = await env.storage.get(key);
  if (typeof v === 'number' && Number.isFinite(v) && v > 0) return Math.floor(v);
  return 0;
}

// read-modify-write with no compare-and-swap under it, so two results landing at the
// same instant can collapse into one increment. it is a counter for a wall display,
// not an invoice. a failure here must never cost a member their result, so it is
// swallowed: the result is already durable by the time this runs.
async function bumpJobsDone(env) {
  try {
    const current = await readCounter(env, STATS_JOBS_DONE_KEY);
    await env.storage.put(STATS_JOBS_DONE_KEY, current + 1);
  } catch {
    /* counter only */
  }
}

async function handleStats(req, env) {
  const now = env.now();
  let cursor;
  let nodesAlive = 0;
  let watts = 0;
  let wattsMeasured = 0;
  // the get budget is spent before the staleness filter, because a record has to be read
  // to know whether it is stale. partial says the totals are a floor, not the whole grid.
  let gets = 0;
  let partial = false;
  const hoods = new Map();

  for (let page = 0; page < STATS_MAX_PAGES && !partial; page++) {
    const listed = await env.storage.list({ prefix: 'node:', limit: STATS_PAGE, cursor });
    for (const k of listed.keys) {
      if (gets >= STATS_MAX_GETS) {
        partial = true;
        break;
      }
      gets += 1;
      const rec = await env.storage.get(k.name);
      if (!rec) continue;
      if (now - rec.last_seen > STALE_MS) continue;

      const w = Number(rec.wattage);
      const watt = Number.isFinite(w) && w > 0 ? w : 0;
      nodesAlive += 1;
      watts += watt;
      if (readWattsSource(rec) === 'measured') wattsMeasured += watt;

      const name = readNeighborhood(rec);
      const hood = hoods.get(name) || { name, nodes: 0, watts: 0 };
      hood.nodes += 1;
      hood.watts += watt;
      hoods.set(name, hood);
    }
    if (listed.list_complete || !listed.cursor) break;
    cursor = listed.cursor;
    // the page cap ends the scan just as short as the get budget does
    if (page === STATS_MAX_PAGES - 1) partial = true;
  }

  const neighborhoods = [...hoods.values()]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map((h) => ({ name: h.name, nodes: h.nodes, watts: round1(h.watts) }));

  const out = {
    ok: true,
    nodes_alive: nodesAlive,
    watts: round1(watts),
    watts_measured: round1(wattsMeasured),
    jobs_done: await readCounter(env, STATS_JOBS_DONE_KEY),
    neighborhoods,
  };
  // absent on a complete scan, so a healthy grid answers exactly the shape it always did
  if (partial) out.partial = true;
  return json(200, out, PUBLIC_CACHE_HEADERS);
}

async function handleSubmit(req, env) {
  // the gate runs before the body is parsed, so an outsider gets the same 403 whatever
  // they put in the body. the size cap comes first so nobody gets a 2 MiB signature
  // check out of an unauthenticated request.
  if (req.bodyBytes && req.bodyBytes.length > MAX_BODY_BYTES) {
    return json(413, { error: 'body too large' });
  }
  const gateErr = await checkMemberCard(req, env);
  if (gateErr) return gateErr;

  const { err, value: body } = readJsonBody(req);
  if (err) return err;

  const toNode = body.to_node;
  if (!isNodeId(toNode)) return json(400, { error: 'invalid to_node' });

  const blobErr = checkBlob(body.blob_b64);
  if (blobErr) return blobErr;
  if (!isKey32(body.reply_pubkey)) return json(400, { error: 'reply_pubkey must be 32 base64 bytes' });

  let idemKey = null;
  if (body.idempotency_key !== undefined && body.idempotency_key !== null) {
    if (typeof body.idempotency_key !== 'string' || !IDEM_RE.test(body.idempotency_key)) {
      return json(400, { error: 'invalid idempotency_key' });
    }
    // scoped per target node, not global: a shared namespace would hand one client
    // another client's job_id, and job_id possession is the only read control.
    idemKey = `idem:${toNode}:${body.idempotency_key}`;
  }

  const node = await env.storage.get(nodeKey(toNode));
  if (!node) return json(404, { error: 'unknown node' });

  if (idemKey) {
    const prior = await env.storage.get(idemKey);
    if (prior && prior.job_id) return json(200, { job_id: prior.job_id, duplicate: true });
  }

  const backlog = await env.storage.list({ prefix: queuePrefix(toNode), limit: MAX_QUEUED_PER_NODE });
  if (backlog.keys.length >= MAX_QUEUED_PER_NODE) return json(429, { error: 'node queue full' });

  const jobId = env.randomUUID();
  const now = env.now();
  const record = {
    job_id: jobId,
    to_node: toNode,
    blob_b64: body.blob_b64,
    reply_pubkey: body.reply_pubkey,
    status: 'queued',
    attempts: 0,
    lease_until: 0,
    created_ms: now,
    updated_ms: now,
    result_b64: null,
  };
  await env.storage.put(jobKey(jobId), record, { expirationTtl: QUEUED_TTL_S });
  // one kv key per queue entry: kv has no CAS, so a shared queue value loses jobs.
  await env.storage.put(queueKey(toNode, now, jobId), { job_id: jobId }, { expirationTtl: QUEUED_TTL_S });
  if (idemKey) await env.storage.put(idemKey, { job_id: jobId }, { expirationTtl: QUEUED_TTL_S });

  return json(200, { job_id: jobId });
}

async function handlePull(req, env) {
  const nodeId = req.query.node_id;
  if (!isNodeId(nodeId)) return json(400, { error: 'invalid node_id' });
  // the signer owns the queue it drains. path-with-query is signed, so this cannot
  // be re-targeted after the fact either.
  if (req.headers['x-nycc-node-id'] !== nodeId) {
    return json(403, { error: 'node_id does not match signer' });
  }

  const node = await env.storage.get(nodeKey(nodeId));
  if (!node) return json(404, { error: 'unknown node' });

  const sigErr = await checkSignature(req, env, node.verify_key);
  if (sigErr) return sigErr;

  const now = env.now();
  const listed = await env.storage.list({ prefix: queuePrefix(nodeId), limit: PULL_MAX * 4 });
  const jobs = [];

  for (const k of listed.keys) {
    if (jobs.length >= PULL_MAX) break;

    const entry = await env.storage.get(k.name);
    const jobId = entry && entry.job_id;
    if (!jobId) {
      await env.storage.delete(k.name);
      continue;
    }
    const job = await env.storage.get(jobKey(jobId));
    if (!job) {
      await env.storage.delete(k.name);
      continue;
    }
    // terminal states never leave. a stale or replayed index entry pointing at a
    // done job is dropped, never re-marked running.
    if (job.status === 'done' || job.status === 'failed') {
      await env.storage.delete(k.name);
      continue;
    }
    if (job.to_node !== nodeId) continue;
    if (job.status === 'running' && job.lease_until > now) continue;

    if (job.status === 'running' && job.attempts >= MAX_ATTEMPTS) {
      job.status = 'failed';
      job.updated_ms = now;
      job.failed_reason = 'lease expired after max attempts';
      await env.storage.put(jobKey(jobId), job, { expirationTtl: DONE_TTL_S });
      await env.storage.delete(k.name);
      continue;
    }

    job.status = 'running';
    job.attempts = (job.attempts || 0) + 1;
    job.lease_until = now + LEASE_MS;
    job.updated_ms = now;
    await env.storage.put(jobKey(jobId), job, { expirationTtl: QUEUED_TTL_S });

    jobs.push({
      job_id: job.job_id,
      to_node: job.to_node,
      blob_b64: job.blob_b64, // JOB ciphertext, sealed to the node
      reply_pubkey: job.reply_pubkey,
      status: 'running',
    });
  }
  return json(200, { jobs });
}

async function handleResult(req, env) {
  const { err, value: body } = readJsonBody(req);
  if (err) return err;

  if (!isJobId(body.job_id)) return json(400, { error: 'invalid job_id' });
  const blobErr = checkBlob(body.blob_b64);
  if (blobErr) return blobErr;

  // the receipt is stored and handed back untouched. the coordinator does not verify
  // it and cannot: it is signed by the node, for the client, about work the
  // coordinator never saw. see the README, this is not coordinator-attested.
  let receipt = null;
  if (body.receipt !== undefined && body.receipt !== null) {
    if (typeof body.receipt !== 'object' || Array.isArray(body.receipt)) {
      return json(400, { error: 'receipt must be a json object' });
    }
    if (JSON.stringify(body.receipt).length > MAX_RECEIPT_BYTES) {
      return json(413, { error: 'receipt too large' });
    }
    receipt = body.receipt;
  }

  const nodeId = req.headers['x-nycc-node-id'];
  if (!isNodeId(nodeId)) return json(401, { error: 'invalid node id header' });

  const node = await env.storage.get(nodeKey(nodeId));
  if (!node) return json(404, { error: 'unknown node' });

  const sigErr = await checkSignature(req, env, node.verify_key);
  if (sigErr) return sigErr;

  const job = await env.storage.get(jobKey(body.job_id));
  if (!job) return json(404, { error: 'unknown job' });
  // without this any registered node could post a result for any job_id it guessed.
  if (job.to_node !== nodeId) return json(403, { error: 'not your job' });

  // first result wins. a node retrying after a lost response is safe.
  if (job.status === 'done') return json(200, { ok: true, status: 'done', duplicate: true });
  if (job.status === 'failed') return json(409, { error: 'job failed', status: 'failed' });
  if (job.status !== 'running') return json(409, { error: 'job not running', status: job.status });

  job.status = 'done';
  job.result_b64 = body.blob_b64;
  if (receipt !== null) job.receipt = receipt;
  job.lease_until = 0;
  job.updated_ms = env.now();
  await env.storage.put(jobKey(job.job_id), job, { expirationTtl: DONE_TTL_S });
  await env.storage.delete(queueKey(job.to_node, job.created_ms, job.job_id));
  await bumpJobsDone(env);
  return json(200, { ok: true, status: 'done' });
}

async function handleJobStatus(req, env, jobId) {
  if (!isJobId(jobId)) return json(404, { error: 'unknown job' });
  const job = await env.storage.get(jobKey(jobId));
  if (!job) return json(404, { error: 'unknown job' });
  // the RESULT ciphertext only, and only when done. the job ciphertext never
  // comes back out of this endpoint.
  if (job.status === 'done') {
    const out = { status: 'done', blob_b64: job.result_b64 };
    // absent for a v1 node that posted no receipt, rather than a null to unpack
    if (job.receipt) out.receipt = job.receipt;
    return json(200, out);
  }
  return json(200, { status: job.status });
}

// --------------------------------------------------------------------- router

const ROUTES = {
  '/v1/nodes/register': ['POST'],
  '/v1/nodes/heartbeat': ['POST'],
  '/v1/nodes': ['GET'],
  '/v1/stats': ['GET'],
  '/v1/jobs': ['POST'],
  '/v1/jobs/pull': ['GET'],
  '/v1/jobs/result': ['POST'],
  '/healthz': ['GET'],
};

export function isApiPath(pathname) {
  return pathname === '/v1' || pathname.startsWith('/v1/');
}

async function route(req, env) {
  const m = req.method;
  const p = req.pathname;

  // preflight is answered for anything under /v1/, including paths that do not exist,
  // because a browser asks before it can be told a route is missing.
  if (m === 'OPTIONS' && isApiPath(p)) return { status: 204, body: null };

  if (m === 'GET' && p === '/healthz') return json(200, { ok: true });
  if (m === 'POST' && p === '/v1/nodes/register') return handleRegister(req, env);
  if (m === 'POST' && p === '/v1/nodes/heartbeat') return handleHeartbeat(req, env);
  if (m === 'GET' && p === '/v1/nodes') return handleListNodes(req, env);
  if (m === 'GET' && p === '/v1/stats') return handleStats(req, env);
  if (m === 'POST' && p === '/v1/jobs') return handleSubmit(req, env);
  if (m === 'GET' && p === '/v1/jobs/pull') return handlePull(req, env);
  if (m === 'POST' && p === '/v1/jobs/result') return handleResult(req, env);
  if (m === 'GET' && p.startsWith('/v1/jobs/')) return handleJobStatus(req, env, p.slice('/v1/jobs/'.length));

  const allowed = ROUTES[p];
  if (allowed && !allowed.includes(m)) return json(405, { error: 'method not allowed' });
  return json(404, { error: 'not found' });
}

// req: {method, pathname, path (pathname+search), host, headers (lowercase keys),
//       query (object), bodyBytes (Uint8Array)}
//
// responses are {status, body, headers?}. headers is set here for /v1/* so cors lives
// in the tested layer and worker.js only copies it onto the Response. a wildcard
// origin grants a browser nothing: every write is authenticated by signature, not by
// a cookie or an origin, so there is no ambient authority for a page to borrow.
export async function handleRequest(req, env) {
  const res = await route(req, env);
  if (isApiPath(req.pathname)) res.headers = { ...CORS_HEADERS, ...(res.headers || {}) };
  return res;
}
