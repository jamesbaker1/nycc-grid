// thin adapter: route parsing, webcrypto verify, kv i/o. every branch decision
// lives in logic.js. this file ships untested, see README status.

import { handleRequest, b64ToBytes, isApiPath, CORS_HEADERS, MAX_BODY_BYTES } from './logic.js';

function kvStorage(kv) {
  return {
    async get(key) {
      return await kv.get(key, 'json');
    },
    async put(key, value, opts) {
      await kv.put(key, JSON.stringify(value), opts || {});
    },
    async delete(key) {
      await kv.delete(key);
    },
    async list({ prefix, limit, cursor }) {
      const r = await kv.list({ prefix, limit, cursor });
      return {
        keys: r.keys.map((k) => ({ name: k.name })),
        list_complete: r.list_complete,
        cursor: r.cursor,
      };
    },
  };
}

// ed25519 naming differs across workers runtime versions. both spellings are tried
// and any throw becomes false, matching pygrid.crypto.verify semantics.
const ED25519_ALGOS = [{ name: 'Ed25519' }, { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' }];

const webcryptoVerifier = {
  async verify(verifyKeyB64, msg, sig) {
    const raw = b64ToBytes(verifyKeyB64);
    if (raw === null || raw.length !== 32) return false;
    for (const algo of ED25519_ALGOS) {
      let key;
      try {
        key = await crypto.subtle.importKey('raw', raw, algo, false, ['verify']);
      } catch {
        continue;
      }
      try {
        return await crypto.subtle.verify(algo, key, sig, msg);
      } catch {
        return false;
      }
    }
    return false;
  },
};

function jsonResponse(status, body, extra) {
  const headers = { 'cache-control': 'no-store', ...(extra || {}) };
  // 204 carries no body at all: a preflight answer with one is malformed.
  if (status === 204 || body === null || body === undefined) {
    return new Response(null, { status, headers });
  }
  headers['content-type'] = 'application/json; charset=utf-8';
  return new Response(JSON.stringify(body), { status, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // cors on the early exits too, or a browser reads a network error instead of a 413
    const cors = isApiPath(url.pathname) ? CORS_HEADERS : undefined;

    const declared = Number(request.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      return jsonResponse(413, { error: 'body too large' }, cors);
    }

    let bodyBytes = new Uint8Array(0);
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      // raw received bytes: the signature covers these, never a re-serialization.
      bodyBytes = new Uint8Array(await request.arrayBuffer());
    }

    const headers = {};
    for (const [k, v] of request.headers) headers[k.toLowerCase()] = v;

    const query = {};
    for (const [k, v] of url.searchParams) if (!(k in query)) query[k] = v;

    const req = {
      method: request.method,
      pathname: url.pathname,
      path: url.pathname + url.search, // signed exactly as sent, query included
      host: url.host,
      headers,
      query,
      bodyBytes,
    };

    const logicEnv = {
      storage: kvStorage(env.GRID),
      verifier: webcryptoVerifier,
      now: () => Date.now(),
      randomUUID: () => crypto.randomUUID(),
      // plain [vars] value. empty or unset means no club gate and open submission,
      // which is what v1 deployed with, so shipping this file changes nothing until
      // the key is actually set.
      clubVerifyKey: typeof env.CLUB_VERIFY_KEY === 'string' ? env.CLUB_VERIFY_KEY : '',
    };

    let res;
    try {
      res = await handleRequest(req, logicEnv);
    } catch (e) {
      // never leak internals to an unauthenticated caller.
      console.error('coordinator error', e && e.stack ? e.stack : String(e));
      res = { status: 500, body: { error: 'internal error' }, headers: cors };
    }
    return jsonResponse(res.status, res.body, res.headers);
  },
};
