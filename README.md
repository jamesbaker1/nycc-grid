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

## layout

```
pygrid/
  crypto.py      sealed boxes, ed25519 signing, the canonical signed request string
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
wattage is self reported and nothing measures it, so a hostile node can claim 0 watts and win
every auto-picked job on the grid. pass `to_node` explicitly when that matters.

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

## coordinator api

json over https. `POST /v1/jobs` and `GET /v1/jobs/<job_id>` are for clients, the rest is for
nodes.

| endpoint | signed | purpose |
| --- | --- | --- |
| `POST /v1/nodes/register` | yes | claim a node_id, publish box and verify keys |
| `POST /v1/nodes/heartbeat` | yes | refresh last_seen and wattage. 404 means re-register |
| `GET /v1/nodes` | no | list nodes with an `alive` flag. paginated with `limit` and `cursor` |
| `POST /v1/jobs` | no | queue a sealed job, returns `job_id` |
| `GET /v1/jobs/pull?node_id=` | yes | up to 10 jobs, oldest first, leased for 10 minutes |
| `POST /v1/jobs/result` | yes | store a sealed result. only the assigned node, only once |
| `GET /v1/jobs/<job_id>` | no | `{status}`, plus `blob_b64` (the result ciphertext) when done |

`blob_b64` means the job ciphertext in a pull envelope and the result ciphertext in a status
response. those are different blobs and the api never returns the job ciphertext to a client.

caps: 2 MiB request body, 1 MiB of base64 blob, 100 queued jobs per node. over any of those
you get a 413 or a 429.

job status is strictly monotonic, `queued -> running -> done | failed`. a pull marks a job
running with a lease. a lease that expires makes the job deliverable again with an
incremented attempt counter, so a node that dies mid job does not wedge it forever. after 5
attempts the job goes to `failed` terminally, so a poison job stops cycling.

## signed requests

every signed endpoint carries four headers:

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

verification runs over the raw received body. there is no json canonicalization anywhere,
in either the python or the javascript, and adding some would break both.

the pieces earn their place: the path carries the query string so a signature for
`/v1/jobs/pull?node_id=alice` cannot be re-pointed at bob, the newline delimiters stop two
different requests from producing the same byte string, and the domain tag plus host mean a
signature captured from one deployment does not verify against another deployment that shares
node keys.

replay is bounded by a 300 second timestamp window and a nonce set with a 600 second TTL.
`crypto.verify()` returns `False` for malformed, truncated, forged, and wrong key input, and
never raises. the worker agrees.

## tests

```
.venv\Scripts\python.exe -m pytest tests/
node --test coordinator/test/logic.test.mjs
```

python tests are loopback only and start every server they talk to on `('127.0.0.1', 0)`.
the end to end test wires a `MockCoordinator`, a `MockEngine`, a real `NodeAgent`, and a real
`GridClient` together and drives `run_once()` synchronously from the test thread, so there is
no background poller and no sleeps. it asserts the client gets its text back and that the
plaintext prompt appears in nothing the coordinator recorded.

`MockCoordinator` does not verify signatures on purpose. signature correctness is covered by
the logic.js tests with an injectable stub verifier and by the crypto roundtrip tests.
re-implementing the canonical string in a third place would add a way to get it wrong, not a
way to catch it.

## status, and what does not exist

- **a node reads every job you send it.** TEE attestation is v2 and is not started. sealed
  boxes protect the job from the coordinator and the network, not from the machine running it.
- **the coordinator hands out the keys you seal to.** confidentiality against the coordinator
  holds only if it is honest but curious. out of band fingerprint checking is the only
  mitigation and the client does not do it for you.
- **results are not authenticated.** sealed boxes are anonymous. anyone holding the reply
  pubkey, the coordinator included, can forge a result you will unseal without complaint.
- **`POST /v1/jobs` is open to the internet.** no client identity, no api key, no quota. the
  per node queue cap is the only backpressure.
- **node private keys sit unencrypted on disk.** no passphrase, no keychain, no rotation
  workflow beyond re-registering.
- **auto-pick trusts self reported wattage.** 0 watts attracts every auto-picked job.
- **fetch your results inside the window.** finished jobs expire from KV 24 hours after
  reaching done or failed, and never pulled jobs expire after 7 days. after that the result
  is gone, and there is no archive.
- **the protocol is at least once.** KV is eventually consistent, so a node can see a job
  twice and a client can read stale status for a moment. that is why monotonic transitions
  and idempotent result posts are load bearing rather than tidy.
- **`worker.js` ships untested.** its logic lives in `logic.js`, which is tested. the adapter
  around it, route parsing plus webcrypto verify plus KV io, has no automated coverage; it is
  deployed at `grid.newyorkcomputeclub.com` and the live edge is the only thing exercising it.
  `wrangler.toml` names the production KV namespace and has no preview namespace, so
  `wrangler dev --remote` is not wired up on purpose. see `coordinator/README.md`.
- **no scheduling, no fairness, no billing.** jobs go to one node, in order, and nothing
  tracks who used how much of whose gpu.

## a note on the club voice

if you add docs here, keep them lowercase, dry, and specific, and do not claim a security
property that is not in the code. the threat model is the contract. overselling it is worse
than shipping nothing.
