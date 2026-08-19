# threat model

what nycc-grid actually protects, and what it does not. read the second half before
you send anything you would mind a stranger reading.

this document describes the code in this repo today, protocol v2 included. where
something is designed but not built it says so, and says where the design lives.

## what is actually implemented

- jobs and results are libsodium sealed boxes (`crypto_box_seal`, X25519 + XSalsa20-Poly1305).
  a job is sealed to the target node's curve25519 public key. a result is sealed to a
  per-job ephemeral reply key that lives in the submitting client process.
- the coordinator stores and forwards ciphertext. it holds no private keys and never sees
  a prompt or a completion.
- every node to coordinator request is signed with ed25519 over a pinned byte string that
  covers the domain tag, coordinator host, method, path with query, timestamp, nonce, and
  the raw body bytes. see the signed requests section in the root README.
- replay of a signed request is bounded by a 300 second timestamp window plus a nonce set.
- registration proves possession of the submitted key. re-registering an existing node_id
  requires a signature from the currently registered verify key, so nobody can overwrite a
  member's pubkey and start receiving that member's job plaintext.
- job ids are 128 bit CSPRNG values, because possession of the job_id is the only access
  control on `GET /v1/jobs/<job_id>`.
- results are accepted only from the node the job was routed to, only while that job is in
  `running`, and only once. status transitions are monotonic: `queued -> running -> done|failed`.
- a finished job can carry a receipt the node signed with its ed25519 key: job id, node id,
  start and finish times, watts, and the sha256 of both the job and the result ciphertext.
  the client checks that signature and re-hashes the blob it decrypted. see section 2 for
  what that is worth and what it is not.
- `POST /v1/jobs` can be gated on a club-signed membership card plus a member signature over
  the same canonical string node requests use. it is gated only when the coordinator has a
  club verify key configured, and it ships without one. see section 3.

that is the whole list. everything below is a gap.

## 1. the coordinator distributes the keys it is not supposed to be able to read

node public keys reach clients through `GET /v1/nodes`, which is served by the coordinator.
so "the coordinator never holds plaintext" holds only for an honest but curious coordinator.

a malicious or compromised coordinator, or anyone with access to the cloudflare account, can
substitute its own public key at registration or in the `GET /v1/nodes` response and read
every job submitted from that point on. the client seals to whatever key it was handed, and
nothing in the protocol lets it tell the difference.

the only mitigation available today is out of band verification: get the node's pubkey
fingerprint from the operator over a channel the coordinator does not control, then pass
`--to-node` and check the key yourself. pinning is not implemented and the client does not
warn you when a node's advertised key changes.

## 2. results are signed, but the key they are checked against comes from the coordinator

the sealing layer authenticates nobody. `crypto_box_seal` is anonymous by construction: the
sealed box carries an ephemeral sender key generated at seal time, so it proves nobody
tampered with the ciphertext and nothing about who produced it. the reply pubkey travels in
every job envelope, so the coordinator sees it and so does the node, and either could seal
an arbitrary payload to that key and post it as the result.

receipts sit on top of that. a node posts one alongside the result, signed with its ed25519
key over `crypto.canonical_json` of the receipt, and `GridClient.result_with_receipt()`
hands back `(text, receipt, verified)`. `verified` is true only when the signature checks
out, the receipt names this job id, and `result_sha256` matches the blob this client
actually decrypted. a coordinator that swapped the result cannot make that check pass.

three caveats, all load bearing:

- the verify key comes from `GET /v1/nodes`, which the coordinator serves. this catches a
  coordinator that swapped a result. it does not catch a coordinator that lies about the
  result and the key together, which is section 1 again. pin the node's verify key out of
  band if that matters; the client does not pin it and does not warn when it changes.
- plain `result()` ignores the receipt and returns the text either way. only
  `result_with_receipt()` and `verify_receipt()` produce the boolean, and the cli prints
  `receipt: FAILED VERIFICATION` and still exits 0. the property exists for code that reads
  the boolean, and for nobody else.
- a node that posts no receipt at all is not an error: `verified` is false, and the text
  comes back regardless.

what a verified receipt says is that this node's key stands behind this exact result
ciphertext. it does not make the watts or the timings in it true, and it is not an
attestation that the engine ran what it claims. section 5 still applies to the numbers.

## 3. job submission is open unless the club key is set, and first registration is open either way

`POST /v1/jobs` is card-gated only when the coordinator has `CLUB_VERIFY_KEY` configured.
it ships empty and the deployed coordinator runs that way, so submission is open today:
anyone who can reach it can queue work onto members' gpus, up to the per node cap of 100
queued jobs and the 1 MiB blob cap.

set the key and every submit needs a card the club signed plus a member signature, and an
uncarded submit is a 403. what that buys is narrow. cards have no expiry and no revocation,
so one is good until the club rotates its key, which invalidates every member's card at
once. there is still no quota and no accounting: the queue cap and its 429 remain the only
backpressure. and it gates submission only.

`POST /v1/nodes/register` for a new node_id is open with or without a club key. the
signature proves possession of the key in the body, not membership of the club. anyone can
register any number of sybil nodes, advertise attractive wattage, and collect auto-picked
jobs from every client on the grid.

## 4. sealed job blobs carry no replay binding

nothing inside the sealed payload ties it to a job_id, a timestamp, or a nonce. the payload
is `{prompt, max_tokens, temperature}` and that is all.

anyone who observes a job ciphertext, including the coordinator, which stores all of them,
can resubmit those exact bytes as a brand new job. the node will unseal it and re-execute it,
because from the node's side it is a perfectly valid job. billing this to the original
submitter is not possible today because there is no submitter identity to bill.

the signed request replay protection covers node to coordinator traffic. it does nothing for
the sealed payload, which is a different layer.

## 5. wattage is self reported, and auto-pick trusts it

`GridClient.submit()` with no `to_node` picks the alive node advertising the lowest wattage.
wattage is a number the node sends in its own heartbeat. v2 added a `watts_source` label
beside it: a node that read `nvidia-smi power.draw` says `measured`, one that did not says
`claimed`. the number and the label are both whatever the node sends, and nothing on the
receiving end can check either one.

a malicious node advertises 0 watts and attracts every auto-picked job on the grid. "clients
choose nodes they trust" is only true when you pass `to_node` explicitly. the auto-pick is a
convenience for a club that already knows each other, not a security boundary.

## 6. metadata is not protected, and some of it is public

the coordinator sees, and therefore cloudflare sees, because every envelope sits in a KV
namespace on their infrastructure:

- job and result blob sizes, which bound prompt and completion length
- submission, pull, and completion timing for every job
- node ids and the reply pubkey on every envelope
- the mapping from client IP to the node it routes to, which is the full club routing graph
- job frequency per client IP and per node
- per member wattage and last_seen time series

`GET /v1/nodes` is unauthenticated, so the wattage and last_seen series is published to
anyone who asks. that is a usable side channel: it tells an observer when a given member's
gpu is busy and roughly how hard.

sealed boxes hide content. they hide none of the above.

## 7. node_id squatting

re-registration is protected. the initial claim is not. the first party to register a given
node_id owns it, and there is no allowlist of member node ids. squatting a name another
member intended to use is possible and cheap. the practical fix today is to notice and pick
another name.

## 8. key storage

node private keys, both the curve25519 box key and the ed25519 signing key, sit unencrypted
in a json keyfile on disk. the CLI refuses to accept private keys as arguments, so they stay
out of shell history and process listings, and the file is chmod 600 where the filesystem
honors that, which windows ACLs largely do not.

anyone who can read that file is that node, permanently. there is no key rotation workflow
beyond re-registering, no passphrase, and no hardware key support.

client reply keys are ephemeral and in memory only, except when you use
`pygrid.client submit --job-file`, which writes the reply private key to disk in cleartext so
a later `result` invocation can open the box. that file is as sensitive as the completion.

## 9. replay suppression is best effort at the edges

the nonce set lives in cloudflare KV, keyed by node_id, with a 600 second TTL. KV is
eventually consistent, roughly 60 seconds across edge locations. a signed request replayed
quickly against a different edge can land before the nonce write propagates.

the timestamp window is the hard bound: 300 seconds, checked against the edge's own clock.
treat nonce dedup as defense in depth, not as the guarantee.

## 10. no attestation. a malicious node reads your prompts

this is the big one, so it gets said plainly: **today, a node can read every job sent to it.**

that is not a bug in the implementation, it is the design. the node has to decrypt the
prompt to run inference on it. sealed boxes protect the job from the coordinator and from
the network. they protect nothing from the machine doing the work.

TEE attestation, where a node proves it is running an unmodified engine inside an enclave and
the client seals to an attested key rather than a self declared one, is not started. there is
no enclave, no measurement, no attestation implementation, and no verification path anywhere
in this repo. what does exist is the design: [ATTESTATION.md](ATTESTATION.md) works through
the candidate mechanisms, what each one does and does not cover, and the phased plan for
where it would plug in. it is a document, not a defense, and it says so itself.

until that exists, the trust model is social: send jobs to members you know, and assume
anything you send is readable by whoever runs that box.

## who sees what, today

| party | sees prompt text | sees result text | sees metadata |
| --- | --- | --- | --- |
| the client | yes | yes | yes |
| the coordinator and cloudflare | no | no | yes, all of it |
| the target node | yes | yes | yes |
| a network observer | no | no | sizes and timing |
| any other registered node | no | no | the public /v1/nodes view |
| whoever holds the reply pubkey | can forge a result | can forge a result | yes |

a forged result now leaves a mark: whoever forged it cannot sign a receipt with the node's
key, so `result_with_receipt()` reports `verified=False`. the two exceptions are the node
itself, which really does hold that key, and a coordinator that swaps the verify key along
with the result, per section 2. plain `result()` returns the forgery as text either way, and
the cli still exits 0, so this only helps a caller that reads the boolean.

## still missing

- TEE attestation and sealing to an attested key. designed in
  [ATTESTATION.md](ATTESTATION.md), not started, and the most expensive item here.
- key fingerprint pinning in the client, with a loud warning on change
- replay binding inside the sealed payload (job_id plus freshness value)
- encrypted key storage with a passphrase or an OS keychain
- quota, accounting, card expiry and card revocation on top of the membership gate
- anything that makes a node's wattage or timing claims checkable by the party reading them

protocol v2 took three items off this list: signed results (section 2), membership
authentication on `POST /v1/jobs` (section 3), and measured wattage (section 5). none of
the three is verified by anyone but the party making the claim, which is why they moved
sections rather than disappearing.
