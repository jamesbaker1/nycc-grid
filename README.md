# nycc-grid

the encrypted mesh behind [newyorkcomputeclub.com](https://newyorkcomputeclub.com). members
run gpus in apartments and offices around the city, a cloudflare worker routes sealed
envelopes between them, and the thing in the middle never sees a prompt.

three pieces:

- **client** (`pygrid/client.py`), seals a job to a node's public key and hands the
  ciphertext to the coordinator
- **coordinator** (`coordinator/`), a cloudflare worker plus KV. routes ciphertext, holds no
  keys, sees metadata
- **node agent** (`pygrid/node.py`), pulls sealed jobs, runs them on a local
  [nycc-engine](../nycc-engine), seals the answer back to the client

the honest summary of what that buys you is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
read it. the short version is that a node you send work to can read your prompt, and the
coordinator hands out the keys you seal to.

v2 adds four things on top of that, all of them additive: neighborhoods, measured wattage,
membership cards, and signed job receipts. every v1 client, node and deployment keeps
working unchanged. what each one does and does not prove is spelled out below.

## layout

```
pygrid/
  crypto.py      sealed boxes, ed25519 signing, the canonical signed request string
  club.py        membership cards: issue, verify, print. club cli
  watts.py       nvidia-smi power reading, or None
  protocol.py    NodeInfo and JobEnvelope, json serde. no liveness rule, see below
  node.py        NodeAgent, node cli
  client.py      GridClient, client cli
  testkit.py     MockCoordinator and MockEngine for local runs
coordinator/
  src/logic.js   pure routing and state machine logic, tested with node --test
  src/worker.js  thin adapter: routes, webcrypto verify, KV io. ships untested
  wrangler.toml  deploy config. real production kv id, live custom domain
tests/           pytest, loopback only
docs/            threat model
```

## install

python 3.12. one runtime dependency, pynacl. all http goes through stdlib
`urllib.request`, so `requests` is not needed and is not installed.

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install pynacl pytest
```

## running a node

```
.venv\Scripts\python.exe -m pygrid.node ^
  --coordinator https://grid.newyorkcomputeclub.com ^
  --engine http://127.0.0.1:8000 ^
  --keyfile C:\Users\you\.nycc\node.keys.json ^
  --neighborhood "bed-stuy" ^
  --wattage 310
```

the keyfile is generated on first run if it does not exist. it holds four keys: a
curve25519 box keypair (jobs are sealed to the public half) and an ed25519 signing keypair
(coordinator requests are signed with it).

private keys are read from the keyfile or from the environment
(`NYCC_NODE_PRIVKEY`, `NYCC_NODE_SIGNKEY`, plus the ids). they are never accepted as command
line arguments, because argv lands in shell history and in every process listing on the box.
they do sit unencrypted in that file. see the status section.

`--engine` must be loopback. the engine has no authentication and prompts travel to it as
plaintext http.

`--neighborhood` is a lowercase string, up to 32 characters of `a-z0-9`, space, `-` and `'`,
so `bed-stuy`, `hell's kitchen` and `long island city` all pass. it defaults to
`undisclosed`. nothing checks it: it is a label a node types about itself, it shows up in
`GET /v1/nodes` and in the neighborhood breakdown on `GET /v1/stats`, and a node in jersey
can call itself whatever it likes.

### measured watts

the node reads its own power draw before every heartbeat. `pygrid/watts.py` shells out to
`nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits` with a 3 second timeout and
sums the values. any failure at all, including no nvidia-smi, a non-zero exit, a driver that
answers `[N/A]`, or no gpus, gives no reading rather than a zero.

with a reading, the node reports that number and `watts_source: "measured"`. without one it
reports `--wattage` and `watts_source: "claimed"`. `GET /v1/nodes` and `GET /v1/stats` both
carry the source, and stats totals both `watts` and `watts_measured` so you can see how much
of the grid total is a meter and how much is a number somebody typed.

this is not attested. the node still self reports both the value and the label, so a node
that wants to advertise 5 measured watts can. it removes an honest node's guesswork, not a
dishonest node's options.

## submitting a job

```
.venv\Scripts\python.exe -m pygrid.client --coordinator https://grid.newyorkcomputeclub.com ^
  run --prompt "write a haiku about the l train" --max-tokens 64
```

or from python:

```python
from pygrid.client import GridClient

client = GridClient("https://grid.newyorkcomputeclub.com")
job_id = client.submit("write a haiku about the l train", max_tokens=64)
print(client.result(job_id, timeout=60))
```

`submit()` with no `to_node` auto-picks the alive node advertising the lowest wattage.
wattage is self reported, measured or not, so a hostile node can claim 0 watts and win every
auto-picked job on the grid. pass `to_node` explicitly when that matters.

"alive" is the coordinator's flag on each `GET /v1/nodes` record, and the client reads it
rather than recomputing one. there is exactly one liveness rule, in `logic.js`: three missed
30 second heartbeats. a second copy in python would have to know the unit of `last_seen`,
which is milliseconds from the worker and seconds from the test mock.

the reply keypair is ephemeral and per job, generated in the client process and never sent
anywhere except its public half. that means `result()` only works from the same process that
called `submit()`. to split the two, use the cli:

```
... submit --prompt "..." --job-file job.json
... result --job-file job.json
```

which writes the reply private key to `job.json` in cleartext. that file is as sensitive as
the completion it will open.

## membership cards

a card is an ed25519 certificate the club signs for a member:

```json
{"card": {"issued": "2026-08-19T14:02:11Z",
          "member": "james baker",
          "member_verify_key": "<32 base64 bytes>",
          "serial": 1755612131},
 "sig": "<club signature, base64>"}
```

the signed bytes are the card with no `sig` in it, serialized as
`json.dumps(card, sort_keys=True, separators=(",", ":"))` and utf-8 encoded. that is
`crypto.canonical_json()`, and `logic.js` rebuilds the same bytes in javascript, escapes and
all. it is a different rule from request signing on purpose: a request signs the raw bytes on
the wire, a card is re-serialized by whoever checks it.

```
python -m pygrid.club init
python -m pygrid.club issue --member "james baker" --member-keygen --out card.json
python -m pygrid.club show card.json
python -m pygrid.club svg card.json --out card.svg
```

`init` writes `~/.nycc/club.keys.json` and refuses to overwrite it, because a new club key
invalidates every card ever issued and there is no revocation list to undo that with.
`issue --member-keygen` also writes `member.keys.json` next to the card: that file is the
member's ed25519 signing key, unencrypted, and it is the half that actually authenticates.
the card without it is a name in a json file. `svg` renders the printable card, 856 by 540,
with the member name, the serial, the issue date and the sha256 fingerprint of the member
verify key.

a client carries the pair on submission:

```
... run --prompt "..." --card card.json --member-keys member.keys.json
```

or `GridClient(url, card_path=..., member_keys_path=...)`, or the env vars `NYCC_CARD` (a
path) and `NYCC_MEMBER_SIGNKEY` (the seed itself, never argv). the card rides in the
`X-NYCC-Card` header and the request is signed with the member key using the same canonical
string node requests use, under `X-NYCC-Member-Ts`, `X-NYCC-Member-Nonce` and
`X-NYCC-Member-Sig`.

**the gate only exists when the coordinator has the club key.** the worker reads
`CLUB_VERIFY_KEY` from `[vars]` in `wrangler.toml`. it ships empty, and empty means
`POST /v1/jobs` is exactly as open as it was in v1: no card required, cards ignored if sent.
set it and submission becomes members only. that default is deliberate, so deploying v2 does
not lock the grid out of itself.

what a card proves when the gate is on: the club's key signed this member name together with
this member verify key, and whoever sent the request holds that key. the nonce and the 300
second timestamp window mean a captured request cannot be replayed, so it is not a bearer
token you can copy off the wire.

what it does not prove: that the name belongs to any particular human, that the member
keyfile has not been copied off a laptop, or that the member deserves the gpu time. there is
no revocation, no expiry check (`issued` is a printed date, nothing enforces it), and no
quota. a leaked club signing key mints unlimited cards, and the only fix is rotating
`CLUB_VERIFY_KEY`, which invalidates everyone.

it also costs you something: with the gate on, the coordinator sees the member name on every
submission, so the routing graph it already had gains a name column.

## job receipts

after the engine call, a node signs a receipt with its node key:

```json
{"receipt": {"job_id": "...", "node_id": "node-gowanus",
             "started": "2026-08-19T14:02:11Z", "finished": "2026-08-19T14:02:12Z",
             "duration_ms": 812, "watts": 65.0, "watts_source": "claimed",
             "request_sha256": "<sha256 of the raw job blob>",
             "result_sha256": "<sha256 of the raw result blob>"},
 "sig": "<node signature, base64>"}
```

signed over `crypto.canonical_json(receipt)`, the same rule cards use. it rides along in the
result post, the coordinator stores and returns it opaquely, and a v1 node that posts no
receipt is still a perfectly good node.

```python
text, receipt, verified = client.result_with_receipt(job_id)
```

`verified` is true only when the receipt's `result_sha256` matches the ciphertext this client
actually received, the `job_id` matches, and the signature checks out against that node's
`verify_key` from `GET /v1/nodes`. the cli prints one line after a run:
`receipt: node-gowanus, 812ms, 65.0w claimed, verified`, or `receipt: missing`, or
`receipt: FAILED VERIFICATION`.

what a verified receipt proves: a node key stands behind this exact result ciphertext for
this job. that is the piece v1 was missing, where anyone holding the reply pubkey could seal
a completion and have it accepted silently.

what it does not prove:

- **that the completion is any good.** the node signs what it produced, not that a model
  produced it.
- **that the watts or the timestamps are real.** every number in the receipt except the two
  hashes is the node describing itself, on its own clock.
- **anything against a malicious coordinator.** the verify key is fetched from the same
  coordinator that served the result. substitute both and the receipt verifies.
- **that anyone checked.** `result()` returns the text whether or not a receipt was there.
  nothing in this repo refuses an unverified result, the cli included: it prints the verdict
  and moves on. call `result_with_receipt()` and act on the boolean if you want the property.

## coordinator api

json over https. `POST /v1/jobs`, `GET /v1/jobs/<job_id>`, `GET /v1/nodes` and `GET /v1/stats`
are for clients and the site, the rest is for nodes.

| endpoint | signed | purpose |
| --- | --- | --- |
| `POST /v1/nodes/register` | node | claim a node_id, publish box and verify keys, neighborhood |
| `POST /v1/nodes/heartbeat` | node | refresh last_seen, wattage and watts_source. 404 means re-register |
| `GET /v1/nodes` | no | list nodes with an `alive` flag. paginated with `limit` and `cursor` |
| `GET /v1/stats` | no | public counters: alive nodes, watts, watts measured, jobs done, neighborhoods |
| `POST /v1/jobs` | member, when configured | queue a sealed job, returns `job_id` |
| `GET /v1/jobs/pull?node_id=` | node | up to 10 jobs, oldest first, leased for 10 minutes |
| `POST /v1/jobs/result` | node | store a sealed result plus optional receipt. only the assigned node, only once |
| `GET /v1/jobs/<job_id>` | no | `{status}`, plus `blob_b64` and `receipt` when done |

`blob_b64` means the job ciphertext in a pull envelope and the result ciphertext in a status
response. those are different blobs and the api never returns the job ciphertext to a client.

caps: 2 MiB request body, 1 MiB of base64 blob, 100 queued jobs per node, 8 KiB of card
header, 8 KiB of receipt. over any of those you get a 413 or a 429.

job status is strictly monotonic, `queued -> running -> done | failed`. a pull marks a job
running with a lease. a lease that expires makes the job deliverable again with an
incremented attempt counter, so a node that dies mid job does not wedge it forever. after 5
attempts the job goes to `failed` terminally, so a poison job stops cycling.

`jobs_done` in `/v1/stats` is a KV counter bumped read-modify-write when a result is
accepted. KV has no compare-and-swap, so two results landing at the same instant can collapse
into one increment. it is a number for a wall display, not an invoice.

every `/v1/*` response carries `Access-Control-Allow-Origin: *`, the methods `GET, POST,
OPTIONS`, `content-type` plus every `x-nycc-*` header in use, and a 24 hour preflight cache.
`OPTIONS` anywhere under `/v1/` answers 204. the wildcard grants nothing: authentication is a
signature over the request, not a cookie or an origin, so a browser reaching the api from any
page can do exactly what an unauthenticated curl can do.

when submission is gated, a rejected `POST /v1/jobs` is a 403 with a machine readable `code`:

| code | meaning |
| --- | --- |
| `card_required` | no `X-NYCC-Card` header and the coordinator wanted one |
| `card_malformed` | the header is not base64 of a card shaped json document |
| `card_invalid` | card shaped, but a field the club would never have signed |
| `card_not_signed_by_club` | the club signature does not verify |
| `member_sig_missing` | the card is fine, the member signature headers are absent |
| `member_sig_malformed` | member timestamp, nonce or signature is not the right shape |
| `member_sig_expired` | member timestamp outside the 300 second window |
| `member_sig_invalid` | the member signature does not verify against the key in the card |
| `member_sig_replay` | that member nonce was already spent |

`pygrid/club.py` exports the same strings as `ERR_*` constants, and `MockCoordinator`
answers with them, so a test written against the mock asserts what the deployed worker
really returns.

## signed requests

every node endpoint carries four headers:

```
X-NYCC-Node-Id      the node id
X-NYCC-Timestamp    unix seconds, decimal string
X-NYCC-Nonce        16 csprng bytes, base64
X-NYCC-Signature    detached ed25519 signature, base64
```

over exactly these bytes:

```
"nycc-grid-v1|" + coordinator_host + "\n" + METHOD + "\n" + path_with_query + "\n"
  + timestamp + "\n" + nonce + "\n" + raw_body_bytes
```

verification runs over the raw received body. there is no json canonicalization anywhere in
request signing, in either the python or the javascript, and adding some would break both.

a carded client signs the same byte string with its member key and puts the result in
`X-NYCC-Member-Ts`, `X-NYCC-Member-Nonce` and `X-NYCC-Member-Sig`. same string, same window,
same nonce rule, different header names, so a node signature and a member signature can ride
on one request without shadowing each other. the domain tag stayed `nycc-grid-v1` because the
string did not change.

the pieces earn their place: the path carries the query string so a signature for
`/v1/jobs/pull?node_id=alice` cannot be re-pointed at bob, the newline delimiters stop two
different requests from producing the same byte string, and the domain tag plus host mean a
signature captured from one deployment does not verify against another deployment that shares
node keys.

replay is bounded by a 300 second timestamp window and a nonce set with a 600 second TTL,
namespaced by node id for node signatures and by member verify key for member signatures.
`crypto.verify()` returns `False` for malformed, truncated, forged, and wrong key input, and
never raises. the worker agrees.

cards and receipts are the one place json is canonicalized, because they are documents that
get re-serialized by whoever verifies them rather than bytes on a wire.
`crypto.canonical_json()` is that rule, in one function, used by both.

## tests

```
.venv\Scripts\python.exe -m pytest tests/
node --test coordinator/test/logic.test.mjs
```

python tests are loopback only and start every server they talk to on `('127.0.0.1', 0)`.
the end to end test wires a `MockCoordinator`, a `MockEngine`, a real `NodeAgent`, and a real
`GridClient` together and drives `run_once()` synchronously from the test thread, so there is
no background poller and no sleeps. it asserts the client gets its text back and that the
plaintext prompt appears in nothing the coordinator recorded, on the carded path as well as
the open one.

`MockCoordinator` does not verify node signatures, on purpose. that correctness is covered by
the logic.js tests with an injectable stub verifier and by the crypto roundtrip tests.
re-implementing the canonical string in a third place would add a way to get it wrong, not a
way to catch it. the one thing it does verify is the member card gate, since
`MockCoordinator(club_verify_key=...)` exists precisely to exercise that path, and it does it
by calling `crypto.signing_message()` rather than by writing the string out again.

## status, and what does not exist

- **a node reads every job you send it.** TEE attestation is not started. sealed boxes protect
  the job from the coordinator and the network, not from the machine running it.
- **the coordinator hands out the keys you seal to.** confidentiality against the coordinator
  holds only if it is honest but curious. that now also covers receipts: the verify key a
  receipt is checked against comes from the same place. out of band fingerprint checking is
  the only mitigation and the client does not do it for you.
- **receipts are reported, not enforced.** `result()` returns text regardless, and the cli
  prints `FAILED VERIFICATION` and exits 0. the property only exists for code that reads the
  boolean.
- **submission is open unless you configure it.** `CLUB_VERIFY_KEY` ships empty, so today
  `POST /v1/jobs` still has no client identity, no quota, and no accounting. the per node
  queue cap is the only backpressure.
- **cards have no expiry and no revocation.** `issued` is printed, not enforced. losing a
  member keyfile means minting a new card and rotating the club key, which invalidates every
  other member's card too.
- **measured watts are still self reported.** nvidia-smi is read on the node, by the node,
  and the number and the `watts_source` label are both whatever the node sends. auto-pick
  still trusts it, so 0 watts still attracts every auto-picked job.
- **neighborhoods are decoration.** a free string a node types about itself. nothing
  geolocates anything.
- **`/v1/stats` counts approximately.** the jobs counter is read-modify-write on KV with no
  CAS, so concurrent finishes undercount.
- **node and club private keys sit unencrypted on disk.** no passphrase, no keychain, no
  rotation workflow beyond re-registering or re-issuing.
- **fetch your results inside the window.** finished jobs expire from KV 24 hours after
  reaching done or failed, and never pulled jobs expire after 7 days. after that the result
  is gone, and there is no archive.
- **the protocol is at least once.** KV is eventually consistent, so a node can see a job
  twice and a client can read stale status for a moment. that is why monotonic transitions
  and idempotent result posts are load bearing rather than tidy.
- **`worker.js` ships untested.** its logic lives in `logic.js`, which is tested. the adapter
  around it, route parsing plus webcrypto verify plus KV io plus the CORS wrapper, has no
  automated coverage; it is deployed at `grid.newyorkcomputeclub.com` and the live edge is the
  only thing exercising it. `wrangler.toml` names the production KV namespace and has no
  preview namespace, so `wrangler dev --remote` is not wired up on purpose. see
  `coordinator/README.md`.
- **no scheduling, no fairness, no billing.** jobs go to one node, in order, and nothing
  tracks who used how much of whose gpu. a card says who asked, not what they are owed.

`docs/THREAT_MODEL.md` was written against v1 and still reads that way in places: it lists
signed results, membership authentication and measured wattage as unstarted v2 candidates.
they are the three features above. everything it says about what remains broken is still
true.

## a note on the club voice

if you add docs here, keep them lowercase, dry, and specific, and do not claim a security
property that is not in the code. the threat model is the contract. overselling it is worse
than shipping nothing.
