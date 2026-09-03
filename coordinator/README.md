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
  wrangler.toml         deploy config. the kv id in it is the live production namespace,
                        and CLUB_VERIFY_KEY in [vars] is the club gate switch.
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
102 tests, no dependencies, under a second.

## api

| method | path | signed | notes |
| --- | --- | --- | --- |
| POST | /v1/nodes/register | yes | proof of possession. new id accepted, existing id must verify against the currently registered key. body may carry `neighborhood` and `watts_source`. |
| POST | /v1/nodes/heartbeat | yes | 404 for an unknown node id, which is the agent's signal to re-register. body may carry `wattage` and `watts_source`. |
| GET | /v1/nodes | no | `?limit=` (default 50, max 200) plus `cursor`. returns node_id, pubkey, verify_key, wattage, watts_source, neighborhood, last_seen, alive. |
| GET | /v1/stats | no | public counters for the site. see below. |
| POST | /v1/jobs | card, when the club key is set | `{to_node, blob_b64, reply_pubkey, idempotency_key?}` returns `{job_id}`. |
| GET | /v1/jobs/pull?node_id= | yes | at most 10 envelopes, oldest first. blob_b64 here is the JOB ciphertext. |
| POST | /v1/jobs/result | yes | `{job_id, blob_b64, receipt?}`. signer must be the job's to_node and the job must be running. |
| GET | /v1/jobs/&lt;job_id&gt; | no | `{status}` while queued, running or failed. when done it also returns blob_b64, which is the RESULT ciphertext, and `receipt` if the node posted one. never the job ciphertext. |
| OPTIONS | /v1/&lt;anything&gt; | no | 204 preflight with the cors headers. |
| GET | /healthz | no | `{ok:true}`. |

v2 added the card gate, receipts, stats and cors. it changed no byte of the canonical
signing string and no v1 field, so a v1 node and a v1 client keep working against it.

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

## member cards

`POST /v1/jobs` shipped open in v1: anyone who could reach the worker could queue work
onto a member's gpu. v2 can gate it on a club membership card, and does that only when
`CLUB_VERIFY_KEY` is set in `[vars]`. empty or unset means open submission, byte for
byte the v1 behavior.

it is set. commit 767312e committed the real key into `wrangler.toml`, and the deployed
coordinator has run gated since: submission is members only. verified 2026-09-03, an
uncarded `POST /v1/jobs` came back 403 `{"error": "member card required", "code":
"card_required"}`, checked in `handleSubmit` before the body is parsed.

a card is issued by `python -m pygrid.club` and looks like:

```json
{"card": {"member": "...", "member_verify_key": "<b64>", "issued": "<iso8601>", "serial": 1755600000},
 "sig": "<b64 ed25519 by the club key>"}
```

the club signature covers exactly these bytes:

```
json.dumps(card, sort_keys=True, separators=(",", ":")).encode("utf-8")
```

`canonicalJson` in `logic.js` reproduces that python encoder, `ensure_ascii` included:
sorted keys, no spaces, every code point outside 0x20..0x7e escaped `\uXXXX` in
lowercase hex, non-bmp as surrogate pairs. `JSON.stringify` does not do this, which is
why it is hand rolled and pinned by a test against real python output. every key on the
card is canonicalized, not only the four that are checked, so a field the club signs
later still verifies here and a field an attacker adds does not.

a gated submit carries four headers:

```
X-NYCC-Card           b64 of the utf-8 json card document above
X-NYCC-Member-Ts      unix seconds
X-NYCC-Member-Nonce   16 csprng bytes, base64
X-NYCC-Member-Sig     b64 ed25519 over the SAME canonical string as node signing
```

the member signature is the same byte string as every other signed request in the grid,
under different header names, and gets the same 300 second window and the same nonce
dedup, scoped to the member verify key under `mnonce:<member_verify_key>:<nonce>`.

every failure is a 403 with a stable code:

| code | meaning |
| --- | --- |
| `card_required` | the club key is set and no card header was sent |
| `card_malformed` | the header is not base64, not utf-8 json, or has no usable sig |
| `card_invalid` | the card's fields are the wrong type, length or shape |
| `card_not_signed_by_club` | the club signature does not verify over the canonical bytes |
| `member_sig_missing` | a member signature header is absent |
| `member_sig_malformed` | timestamp, nonce or signature is not a well formed value |
| `member_sig_expired` | timestamp outside the 300 second window |
| `member_sig_invalid` | the signature does not verify against the card's member key |
| `member_sig_replay` | that nonce was already used by that member key |

the gate runs before the body is parsed, so an outsider gets the same 403 whatever they
put in the body. what a card proves is narrow, and worth being clear about:

- it proves the holder of the member private key asked for this exact request, and that
  the club signed that key into a card at some point. nothing else.
- there is no revocation and no expiry. a card is good until the club rotates
  `CLUB_VERIFY_KEY`, which invalidates every card at once.
- the card is not bound to the job. the coordinator does not record which member
  submitted which job, so cards gate access, they do not attribute work.
- the card itself is not a secret and is not a bearer token. it rides in the clear on
  every submit and copying it buys nothing, because a copy cannot produce the member
  signature. the member private key is the secret, and whoever holds it is the member.
- the gate is on submission only. registering a node, pulling and posting results are
  authenticated by node key as in v1, and reading `GET /v1/jobs/<job_id>` still needs
  only the job id.

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

## neighborhood and measured watts

a node record carries two display fields on top of its keys.

`neighborhood` is optional on register and must match `^[a-z0-9][a-z0-9 \-']{0,31}$`,
lowercase only so "bed-stuy" and "Bed-Stuy" cannot become two pins on the same map.
anything else is a 400. a node that sends none is filed as `undisclosed`, and so is
every node record written by v1. register is a full upsert, so re-registering without a
neighborhood puts a node back under `undisclosed`.

`watts_source` is `measured` or `claimed`, on register and on heartbeat, and anything
else is a 400. `measured` means the node read `nvidia-smi power.draw` before it sent the
number. records from v1 have no such field and read back as `claimed`.

neither is verified. wattage was self reported in v1 and it still is: a node can send
`watts_source: measured` with an invented number, and can name any neighborhood it
likes. these fields describe what a node says about itself, which is what the site
publishes, and they carry no weight in routing.

## receipts

a node may post a signed receipt alongside a result:

```json
{"job_id": "...", "blob_b64": "...", "receipt": {"receipt": {...}, "sig": "<b64>"}}
```

the coordinator stores that object opaquely and hands it back on
`GET /v1/jobs/<job_id>` when the job is done. it does not parse it, does not verify it,
and does not know what is in it. it cannot: the receipt is signed by the node, for the
client, about a computation the coordinator never saw and about plaintext it never
holds. the client verifies it against the node's `verify_key` from `GET /v1/nodes`.

a receipt is therefore not coordinator-attested. it is a node's claim, checkable by the
client. a result posted with no receipt is accepted exactly as in v1, and the finished
job then carries no `receipt` key at all. the first result wins, so the first receipt
wins with it: a retry never replaces one.

the only things checked here are that the receipt is a json object and under 8 KiB, so
it cannot be used to stuff a job record.

## stats and cors

`GET /v1/stats` is the endpoint the site and browser nodes read:

```json
{"ok": true, "nodes_alive": 3, "watts": 105.3, "watts_measured": 75.1, "jobs_done": 12,
 "neighborhoods": [{"name": "bed-stuy", "nodes": 2, "watts": 95.3}]}
```

every number covers alive nodes only, by the same three-missed-heartbeats rule as the
`alive` flag. `watts_measured` is the part of `watts` that came from nodes reporting
`measured`. sums are rounded to one decimal, which is the precision nodes report anyway.

the node scan is the expensive part of this route: one kv list per page plus one kv get
per node record, and the staleness filter can only run after the get. a worker invocation
is capped at 1000 kv operations, so the scan stops at 800 gets or 20 pages, whichever
comes first, and adds `"partial": true` to the response when it stopped early. the totals
are then a floor rather than the whole grid, which is the answer a namespace that has
outgrown one invocation can actually give. node records also carry a 7 day ttl, so one-off
registrations stop accumulating against that budget forever.

`jobs_done` is a single kv integer at `__stats__:jobs_done`, incremented when a result
is accepted. it is read-modify-write with no compare-and-swap under it, so two results
landing at the same instant can collapse into one increment. it undercounts under
concurrency and never decreases. it is a counter for a wall display, not an invoice. a
failure to bump it is swallowed rather than failing the result post, which is already
durable by then.

every `/v1/*` response, errors included, carries:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: content-type plus every x-nycc-* header in use
Access-Control-Max-Age: 86400
```

and `OPTIONS` anywhere under `/v1/` is a 204 with those headers, including paths that do
not exist, because a browser asks before it can be told a route is missing. the wildcard
origin grants a page nothing: every authenticated route is authenticated by signature,
never by a cookie or an origin, so there is no ambient authority for a page to borrow.
what it does grant any page is what any curl already had, which is the unauthenticated
reads: `/v1/nodes`, `/v1/stats`, and `/v1/jobs/<job_id>` for a job id it knows.

cors lives in `logic.js` so it is under test; `worker.js` only copies the headers onto
the Response.

`worker.js` sends `Cache-Control: no-store` by default. the two public reads override it:
`GET /v1/nodes` and `GET /v1/stats` answer `Cache-Control: public, max-age=15`, because
they take no credentials, say the same thing to everyone, and are what the site polls, and
15 seconds is half a heartbeat interval so a node still shows up promptly. every other
route keeps `no-store`, which matters for `GET /v1/jobs/<job_id>`, where the job id is the
only access control, and for every signed route. the header is set in `logic.js` beside
cors, so it is under test too.

## storage

kv has no compare-and-swap, so nothing is ever read-modify-written by two paths at
once, with one exception noted below. there is no shared queue value to lose jobs into.

```
node:<node_id>                              node record, 7 day ttl, renewed by every heartbeat
job:<job_id>                                envelope, status, attempts, lease_until, timestamps, result, receipt
queue:<node_id>:<created_ms padded>:<job_id> index entry, job_id only
idem:<to_node>:<idempotency_key>            job_id, so a client retry does not pay twice
nonce:<node_id>:<nonce>                     node replay set, 600s ttl
mnonce:<member_verify_key>:<nonce>          member replay set, 600s ttl
__stats__:jobs_done                         integer, the one read-modify-written key
```

the queue is an index of job ids, one kv key per entry, listed by prefix so
lexicographic order is oldest first. submit, pull and result each touch different keys.
index entries are deleted when a job leaves the deliverable states.

idempotency keys are scoped per target node. a global namespace would hand one client
another client's job id, and the job id is the only read control on results.

job records carry a ttl: 24 hours after reaching `done` or `failed`, 7 days for a job
that is never pulled. clients must fetch results inside that window. this is what keeps
the namespace and the queue indexes from growing forever.

node records carry one too: 7 days, pushed out again by every register and every
heartbeat, so it only ever collects a node that has been silent for a week. that is many
multiples of the staleness window, and a node that is still running re-registers on the
first heartbeat 404 and gets its record straight back, so a live node never notices.
without it every one-off registration sat in the namespace forever and `/v1/stats` paid
a kv get for each one.

## limits

| limit | value | response |
| --- | --- | --- |
| request body | 2 MiB | 413 |
| blob_b64 on POST /v1/jobs and /v1/jobs/result | 1 MiB of encoded text | 413 |
| receipt on POST /v1/jobs/result | 8 KiB of json | 413 |
| x-nycc-card header | 8 KiB of base64 | 403 `card_malformed` |
| member name on a card | 64 code points | 403 `card_invalid` |
| queued jobs per to_node | 100 | 429 |
| jobs per pull | 10 | truncated |
| nodes per list page | 50 default, 200 max | paged with cursor |
| node records scanned by /v1/stats | 800 kv gets, 20 pages | `"partial": true` |

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

`CLUB_VERIFY_KEY` ships empty by default, which would keep submission open. it is a
public key, so it lives in `[vars]` rather than in a secret. setting it is a one way door
for anyone without a card: the moment it deploys, every uncarded submit is a 403. issue
the cards first, then set it. commit 767312e set it — the real key has been committed and
deployed since, so submission is members only today, verified 2026-09-03 by an uncarded
`POST /v1/jobs` coming back 403 `card_required`.

## status, honestly

- **`src/worker.js` ships untested.** it is deployed and it has served real requests, but
  the test suite covers `src/logic.js` only. the adapter's webcrypto ed25519 import, the kv
  adapter, the request parsing, the cors header copy and the 204 preflight path have no
  automated coverage in any environment; what is known about them is whatever the live
  deployment has happened to exercise.
- ed25519 in webcrypto is named differently across workers runtime versions, so
  `worker.js` tries two spellings. which one this compatibility date gets is unverified.
  the club and member signatures go through that same unverified import.
- `POST /v1/jobs` would be unauthenticated while `CLUB_VERIFY_KEY` is empty, but that is
  not how it is deployed: the key has been committed and live since commit 767312e, so
  submission is gated on a card, verified in production 2026-09-03 (uncarded submit, 403
  `card_required`). gating is all it does: there is still no quota, and cards have no
  revocation and no expiry. the card is not bound to the job either, so the coordinator
  now sees a member name on every submission without recording which job it went with.
- first-time `POST /v1/nodes/register` is unauthenticated. it proves possession of the
  key in the body, not membership. first-come node id squatting works. re-registration
  is protected, initial claim is not. cards gate submission only, not registration.
- nonce dedup rides on eventually consistent kv, so cross edge replay suppression is
  best effort, for member nonces as much as node nonces. the 300 second timestamp window
  is the hard bound.
- receipts are stored and echoed, never verified here. a lying node can post any receipt
  it likes; the client is what catches that, and only if the client checks.
- `wattage`, `watts_source` and `neighborhood` are self reported and unauthenticated. a
  node claiming `measured` may have measured nothing. `/v1/stats` publishes those claims
  as if they were facts, because that is all anyone in this system has.
- `jobs_done` is read-modify-write on kv with no compare-and-swap. concurrent results
  can collapse into one increment, so it is a floor, not a count.
- the coordinator distributes node pubkeys, so "the coordinator never holds plaintext"
  holds only for an honest-but-curious coordinator. anyone with the cloudflare account
  can substitute a pubkey at registration or in `GET /v1/nodes` and read every job.
  see `docs/THREAT_MODEL.md`.
- the coordinator sees metadata: blob sizes, timing, node ids, reply pubkeys, the
  client-to-node routing graph, job frequency, and the wattage, watts_source,
  neighborhood and last_seen series, which `GET /v1/nodes` and `GET /v1/stats` publish to
  anyone who asks, from any origin now that cors is on.
- no rate limiting beyond the per-node queue cap. no admin endpoint. no way to delete a
  job, evict a node or burn a card short of editing kv or rotating the club key by hand.
