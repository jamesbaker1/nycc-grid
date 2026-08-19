# nycc grid coordinator

a cloudflare worker that routes sealed ciphertext between club members and the gpus
they point at each other. it is a mailbox, not a scheduler and not an inference
service. it never holds plaintext and never holds a private key.

zero npm deps. one kv namespace, bound as `GRID`.

## layout

```
coordinator/
  src/logic.js          pure request logic. storage, verifier, clock and uuid source injected.
  src/worker.js         thin adapter: route parsing, webcrypto ed25519 verify, kv i/o.
  test/logic.test.mjs   node --test suite against logic.js.
  wrangler.toml         deploy config. the kv id in it is the live production namespace.
```

every branch decision lives in `logic.js`. `worker.js` decides nothing, so the whole
state machine is testable with `node --test` and no wrangler, no network, no kv.

## running the tests

```
cd coordinator
node --test
```

or from the repo root:

```
node --test coordinator/test/logic.test.mjs
```

node 22+ (module syntax detection loads `src/logic.js` as esm without a package.json).
54 tests, no dependencies, under a second.

## api

| method | path | signed | notes |
| --- | --- | --- | --- |
| POST | /v1/nodes/register | yes | proof of possession. new id accepted, existing id must verify against the currently registered key. |
| POST | /v1/nodes/heartbeat | yes | 404 for an unknown node id, which is the agent's signal to re-register. |
| GET | /v1/nodes | no | `?limit=` (default 50, max 200) plus `cursor`. returns node_id, pubkey, verify_key, wattage, last_seen, alive. |
| POST | /v1/jobs | no | `{to_node, blob_b64, reply_pubkey, idempotency_key?}` returns `{job_id}`. |
| GET | /v1/jobs/pull?node_id= | yes | at most 10 envelopes, oldest first. blob_b64 here is the JOB ciphertext. |
| POST | /v1/jobs/result | yes | `{job_id, blob_b64}`. signer must be the job's to_node and the job must be running. |
| GET | /v1/jobs/&lt;job_id&gt; | no | `{status}` while queued, running or failed. when done it also returns blob_b64, which is the RESULT ciphertext. never the job ciphertext. |
| GET | /healthz | no | `{ok:true}`. |

job ids come from `crypto.randomUUID` (128 bits of csprng). possession of the job id
is the only access control on `GET /v1/jobs/<job_id>`, which is why it is never
sequential or timestamp derived.

## signed requests

headers on every signed request:

```
X-NYCC-Node-Id      the node id
X-NYCC-Timestamp    unix seconds, decimal string
X-NYCC-Nonce        16 csprng bytes, base64
X-NYCC-Signature    base64 detached ed25519 signature
```

the signed message is exactly:

```
"nycc-grid-v1|" + <coordinator host> + "\n"
  + METHOD + "\n"
  + <full path including query string> + "\n"
  + <timestamp> + "\n"
  + <nonce> + "\n"
  + <raw body bytes, empty for GET>
```

verification runs over the raw received body bytes. no re-serialization, no json
canonicalization, anywhere, ever. every signer in the grid cites this same string;
if you change a byte of it, change `pygrid` in the same commit.

pinning the path with its query string means a signature for
`/v1/jobs/pull?node_id=alpha` cannot be re-pointed at another member's queue. the
delimiters stop byte shifting collisions between fields. the domain prefix plus host
means a signature captured from one deployment does not verify against another
deployment that shares node keys.

replay protection: timestamps skewed more than 300 seconds from coordinator time are
rejected, and a nonce already seen inside that window is rejected. the nonce set is kv
under `nonce:<node_id>:<nonce>` with a 600 second ttl. the signature is checked before
the nonce is written, so an unauthenticated caller cannot burn a node's nonce space.

## leases, and why pull is not just a read

`GET /v1/jobs/pull` marks each delivered job `running`. that write is what makes
delivery observable, and it is also the hazard: a replayed or duplicated pull, or a
node that dies between pulling and posting, would otherwise strand a job in `running`
forever with nobody left to finish it.

so delivery is a lease, not a handoff:

- a delivered job gets `lease_until = now + 10 minutes` and `attempts + 1`.
- a later pull by the job's own `to_node` re-delivers any running job whose lease has
  expired. status stays `running`, the lease is renewed, attempts goes up again.
- after 5 attempts the next pull moves the job to terminal `failed` instead of
  delivering it again, so a poison job cannot redeliver forever. clients see `failed`
  on `GET /v1/jobs/<job_id>`.

the failed transition is lazy: it happens on the next pull for that queue, not on a
timer. a job whose node never comes back sits at `running` with an expired lease until
someone pulls or the record's ttl collects it.

## at-least-once, on purpose

kv is eventually consistent, roughly 60 seconds cross edge. that is not a bug to route
around, it is the delivery guarantee:

- a node may see the same job delivered twice. jobs must be safe to run twice, and
  today nothing in the sealed payload ties it to a job id or a freshness value.
- a client may briefly read stale status, including `queued` for a job another edge has
  already marked `running`.
- two edges can both observe a job as deliverable.

this is exactly why the monotonic state machine and the idempotent result post are
load bearing rather than tidy. status moves `queued -> running -> (done | failed)` and
never backwards. any write that would regress status is dropped silently, so a stale
pull cannot re-mark a done job as running. `done` and `failed` are terminal. the first
result posted for a job wins and is never overwritten, so a node retrying after a lost
response is safe.

## storage

kv has no compare-and-swap, so nothing is ever read-modify-written by two paths at
once. there is no shared queue value to lose jobs into.

```
node:<node_id>                              node record, no ttl
job:<job_id>                                envelope, status, attempts, lease_until, timestamps, result
queue:<node_id>:<created_ms padded>:<job_id> index entry, job_id only
idem:<to_node>:<idempotency_key>            job_id, so a client retry does not pay twice
nonce:<node_id>:<nonce>                     replay set, 600s ttl
```

the queue is an index of job ids, one kv key per entry, listed by prefix so
lexicographic order is oldest first. submit, pull and result each touch different keys.
index entries are deleted when a job leaves the deliverable states.

idempotency keys are scoped per target node. a global namespace would hand one client
another client's job id, and the job id is the only read control on results.

job records carry a ttl: 24 hours after reaching `done` or `failed`, 7 days for a job
that is never pulled. clients must fetch results inside that window. this is what keeps
the namespace and the queue indexes from growing forever.

## limits

| limit | value | response |
| --- | --- | --- |
| request body | 2 MiB | 413 |
| blob_b64 on POST /v1/jobs and /v1/jobs/result | 1 MiB of encoded text | 413 |
| queued jobs per to_node | 100 | 429 |
| jobs per pull | 10 | truncated |
| nodes per list page | 50 default, 200 max | paged with cursor |

the body cap sits above the blob cap so a maximum blob plus its json framing still
fits, and every kv value stays far under the 25 MiB kv value cap.

## deploying

deployed. `wrangler.toml` carries the real production namespace id and the
`grid.newyorkcomputeclub.com` custom domain route, so `wrangler deploy` from this
directory ships to the live coordinator. treat it that way.

there is no preview namespace. `wrangler dev` on its own is fine, it simulates kv
locally, but `wrangler dev --remote` needs one and must not borrow the production id:

```
wrangler kv namespace create GRID --preview
```

then add the id it prints as `preview_id` under `[[kv_namespaces]]`. a dev run against
the production namespace can overwrite a live job record or a node's registered key.

## status, honestly

- **`src/worker.js` ships untested.** it is deployed and it has served real requests, but
  the test suite covers `src/logic.js` only. the adapter's webcrypto ed25519 import, the kv
  adapter, and the request parsing have no automated coverage in any environment; what is
  known about them is whatever the live deployment has happened to exercise.
- ed25519 in webcrypto is named differently across workers runtime versions, so
  `worker.js` tries two spellings. which one this compatibility date gets is unverified.
- `POST /v1/jobs` is unauthenticated. anyone who can reach the worker can queue work
  onto a member's gpu, up to the per-node cap. there is no client identity and no quota.
- first-time `POST /v1/nodes/register` is unauthenticated. it proves possession of the
  key in the body, not membership. first-come node id squatting works. re-registration
  is protected, initial claim is not.
- nonce dedup rides on eventually consistent kv, so cross edge replay suppression is
  best effort. the 300 second timestamp window is the hard bound.
- the coordinator distributes node pubkeys, so "the coordinator never holds plaintext"
  holds only for an honest-but-curious coordinator. anyone with the cloudflare account
  can substitute a pubkey at registration or in `GET /v1/nodes` and read every job.
  see `docs/THREAT_MODEL.md`.
- the coordinator sees metadata: blob sizes, timing, node ids, reply pubkeys, the
  client-to-node routing graph, job frequency, and the wattage and last_seen series,
  which `GET /v1/nodes` publishes to anyone who asks.
- no rate limiting beyond the per-node queue cap. no cors headers. no admin endpoint.
  no way to delete a job or evict a node short of editing kv by hand.
