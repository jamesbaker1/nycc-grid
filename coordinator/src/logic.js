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
// env also carries now() -> ms epoch and randomUUID() -> string.

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

function json(status, body) {
  return { status, body };
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

  const existing = await env.storage.get(nodeKey(nodeId));
  // proof of possession for a new id; for an existing id the CURRENT key must sign,
  // so rotation works but nobody can overwrite another member's pubkey.
  const verifyKeyB64 = existing ? existing.verify_key : body.verify_key;
  const sigErr = await checkSignature(req, env, verifyKeyB64);
  if (sigErr) return sigErr;

  const now = env.now();
  await env.storage.put(nodeKey(nodeId), {
    node_id: nodeId,
    pubkey: body.pubkey,
    verify_key: body.verify_key,
    wattage,
    last_seen: now,
    registered_ms: existing ? existing.registered_ms : now,
  });
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
  node.last_seen = env.now();
  await env.storage.put(nodeKey(nodeId), node);
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
      last_seen: rec.last_seen,
      alive: now - rec.last_seen <= STALE_MS,
    });
  }
  const out = { nodes };
  if (!listed.list_complete && listed.cursor) out.cursor = listed.cursor;
  return json(200, out);
}

async function handleSubmit(req, env) {
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
  job.lease_until = 0;
  job.updated_ms = env.now();
  await env.storage.put(jobKey(job.job_id), job, { expirationTtl: DONE_TTL_S });
  await env.storage.delete(queueKey(job.to_node, job.created_ms, job.job_id));
  return json(200, { ok: true, status: 'done' });
}

async function handleJobStatus(req, env, jobId) {
  if (!isJobId(jobId)) return json(404, { error: 'unknown job' });
  const job = await env.storage.get(jobKey(jobId));
  if (!job) return json(404, { error: 'unknown job' });
  // the RESULT ciphertext only, and only when done. the job ciphertext never
  // comes back out of this endpoint.
  if (job.status === 'done') return json(200, { status: 'done', blob_b64: job.result_b64 });
  return json(200, { status: job.status });
}

// --------------------------------------------------------------------- router

const ROUTES = {
  '/v1/nodes/register': ['POST'],
  '/v1/nodes/heartbeat': ['POST'],
  '/v1/nodes': ['GET'],
  '/v1/jobs': ['POST'],
  '/v1/jobs/pull': ['GET'],
  '/v1/jobs/result': ['POST'],
  '/healthz': ['GET'],
};

// req: {method, pathname, path (pathname+search), host, headers (lowercase keys),
//       query (object), bodyBytes (Uint8Array)}
export async function handleRequest(req, env) {
  const m = req.method;
  const p = req.pathname;

  if (m === 'GET' && p === '/healthz') return json(200, { ok: true });
  if (m === 'POST' && p === '/v1/nodes/register') return handleRegister(req, env);
  if (m === 'POST' && p === '/v1/nodes/heartbeat') return handleHeartbeat(req, env);
  if (m === 'GET' && p === '/v1/nodes') return handleListNodes(req, env);
  if (m === 'POST' && p === '/v1/jobs') return handleSubmit(req, env);
  if (m === 'GET' && p === '/v1/jobs/pull') return handlePull(req, env);
  if (m === 'POST' && p === '/v1/jobs/result') return handleResult(req, env);
  if (m === 'GET' && p.startsWith('/v1/jobs/')) return handleJobStatus(req, env, p.slice('/v1/jobs/'.length));

  const allowed = ROUTES[p];
  if (allowed && !allowed.includes(m)) return json(405, { error: 'method not allowed' });
  return json(404, { error: 'not found' });
}
