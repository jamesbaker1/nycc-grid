# threat model

what nycc-grid v1 actually protects, and what it does not. read the second half before
you send anything you would mind a stranger reading.

this document describes the code in this repo today. where something is aspirational it
says v2, and v2 means not built.

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

## 2. results have no sender authentication

`crypto_box_seal` is anonymous by construction. the sealed box carries an ephemeral sender
key generated at seal time, and the recipient learns nothing about who sealed it. it proves
nobody tampered with the ciphertext. it does not prove who produced it.

the reply pubkey travels in every job envelope, so the coordinator sees it, and so does the
node. either can seal an arbitrary payload to that key and post it as the result. the client
will unseal it happily and print it. a substituted or forged completion is indistinguishable
from a real one.

signing results with the node's ed25519 key would fix this. it is not implemented.

## 3. job submission and first registration are unauthenticated

`POST /v1/jobs` has no authentication at all. anyone who can reach the coordinator can queue
work onto members' gpus, up to the per node cap of 100 queued jobs and the 1 MiB blob cap.
there is no client identity, no api key, no quota, and no accounting: the only backpressure
is the queue cap and the 429 it returns.

`POST /v1/nodes/register` for a new node_id is equally open. the signature proves possession
of the key in the body, not membership of the club. anyone can register any number of sybil
nodes, advertise attractive wattage, and collect auto-picked jobs from every client on the
grid.

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
wattage is a number the node types into its own heartbeat. nothing measures it.

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
the client seals to an attested key rather than a self declared one, is v2. it is not
started. there is no enclave, no measurement, no attestation document, and no verification
path anywhere in this repo.

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

## v2 candidates, none started

- TEE attestation and sealing to an attested key
- signed results, so a completion proves which node produced it
- membership authentication on `POST /v1/jobs`, with per client quota and accounting
- key fingerprint pinning in the client, with a loud warning on change
- replay binding inside the sealed payload (job_id plus freshness value)
- encrypted key storage with a passphrase or an OS keychain
- measured wattage instead of self reported wattage
