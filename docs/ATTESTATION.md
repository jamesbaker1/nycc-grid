# attestation

the v2 roadmap for the gap that [THREAT_MODEL.md](THREAT_MODEL.md) section 10 states
plainly: today, a node can read every job sent to it.

nothing in this document is implemented. there is no enclave, no measurement, no
attestation report, and no verification path anywhere in this repo. this is a design
for a seam, written down so that when the code arrives it lands in the right place.

## the property v1 does not have

sealed boxes give the grid confidentiality against the coordinator and the network.
they give nothing against the machine doing the work, because that machine has to
decrypt the prompt to run inference on it. the missing property is confidentiality
from the executing node: the ability to send a job to a member's box and have the
box compute on it without the member, or anyone who has rooted the member's box,
being able to read it.

that property has a name and a price. the name is a trusted execution environment.
the price is real hardware, a verification pipeline, and a pile of caveats that this
document is mostly about.

one honesty check before the acronyms start: the engine this grid runs today is a
float64 numpy gpt-2 doing a few tokens a second on 1 MiB job blobs. nobody needs an
enclave for that. the reason to design attestation now is that it touches exactly two
places, the node record and the client's sealing call, and both exist today. get the
seam right while the stakes are a toy and the 405B version inherits it.

## candidate mechanisms

### host TEE: amd SEV-SNP or intel TDX

a confidential VM whose memory is encrypted and integrity protected against the
hypervisor and the host OS. the hardware measures what was loaded at launch and will
sign a report saying so, chained to a vendor root key (amd's VCEK chain, intel's
DCAP quoting infrastructure).

what it buys: the node operator, or malware with root on the node, cannot read guest
memory or tamper with it undetected. the launch measurement pins the exact kernel and
software stack the guest booted.

what it does not buy: the hypervisor still controls scheduling and can starve, pause,
or kill the guest. page-level access patterns leak. the vendor's key hierarchy and
firmware are inside your trust base whether you like it or not, and both have a CVE
history (cipherleaks against pre-SNP SEV, voltage glitching, TCB rollback issues).
a determined attacker with physical access and lab equipment is not in the threat
model these things actually hold against.

one accident of the current toy: the reference engine is numpy on CPU, so a host TEE
alone covers everything the engine touches today. that stops being true the moment a
real backend exists, because the GPU is outside the CPU enclave.

### GPU TEE: nvidia H100/H200 confidential computing mode

hopper-class cards can run in CC mode: the GPU pairs with a CPU TEE, traffic across
PCIe goes through encrypted bounce buffers, and the GPU produces its own attestation
evidence over SPDM, verifiable against nvidia's certificate chain and reference
integrity manifests (their nvtrust tooling, or their hosted attestation service if
you are willing to put a web service in the trust base).

what it buys: the prompt, the kv cache, and the activations stay protected while they
are on the card, not just in host RAM. this is the only way the confidentiality claim
survives contact with a real inference backend.

what it does not buy, and one that hurts here: no consumer card has it. a 4090 cannot
attest. the club thesis is that a 405B model fits a borough of consumer cards, and
the attestation story currently only exists on datacenter silicon. so v2 attestation
is honestly for two populations: members who happen to own H100-class hardware, and
club-rented cloud boxes, which is exactly the "not your compute" territory the launch
essay was suspicious of. this tension does not resolve, it just gets written down.
if consumer cards ever grow CC mode, the seam designed here is where it plugs in.

the CC mode toll is mostly on PCIe transfer, small for compute-bound decode, worse
for transfer-heavy work. pipeline parallelism is transfer-heavy by design, which
leads to the next point.

### the pipeline makes it worse, not better

the whole point of the grid is pipeline parallelism, and in a pipeline the prompt
does not visit one node, its activations visit every stage. activations are not
plaintext, but they invert well enough that treating them as public is negligent.
so "seal to an attested node" is not sufficient for a pipelined job: every stage
must attest, the client must verify all of them before the first token moves, and
the stage-to-stage links need their own encryption to attested endpoints. one
unattested stage in the middle and the property is gone. this multiplies every cost
in this document by the pipeline depth.

## the remote attestation flow

the shape is the same regardless of vendor:

1. the node boots its measured stack and asks the hardware for an attestation report
   over a challenge. the report contains the launch measurement, the TCB version, and
   64 bytes of caller-chosen report_data.
2. the node generates a fresh curve25519 sealing keypair inside the enclave and binds
   the public half into report_data (hash of the key, plus a freshness nonce). the
   private half never leaves the enclave.
3. the node publishes the report, the vendor certificate chain, and the enclave
   pubkey in its node record.
4. the client verifies: the signature chains to the vendor root, the TCB is not
   revoked, the measurement matches a golden value the club published for a known
   engine release, and report_data binds the offered pubkey.
5. only then does the client seal the job to the enclave key. not to the bare
   `pubkey` field in the node record, which is a key the operator holds and always
   will be.

step 4 is where the real cost lives. verifying a certificate chain is easy. deciding
what measurement is acceptable means the club builds reproducible node images, pins
golden measurements per release, and maintains a revocation story for when a release
turns out to have a hole. that is a distro's job, taken on by a club.

## what attestation still does not cover

- **side channels.** timing, job blob sizes, memory access patterns, power draw.
  everything in THREAT_MODEL.md section 6 survives attestation untouched. an enclave
  hides the prompt text, not the fact that your gpu got busy at 2am for 40 seconds.
- **a malicious host with physical access.** interposers, glitching, cold boot
  adjacent tricks. vendor marketing says covered, the CVE record says mostly. for a
  cloud box you also trust the cloud's firmware supply chain, which you cannot see.
- **the supply chain.** the vendor root keys, the CPU microcode, the GPU firmware,
  and the measured image itself. attestation proves the node runs the bits the club
  blessed. it does not prove the blessed bits are free of an exfiltration bug. a
  measurement of a leaky engine is a cryptographically strong proof that you are
  talking to the leak.
- **who, as opposed to what.** a report binds a key to a measurement, not to a
  member. a malicious coordinator can still route your job to somebody else's
  correctly attested enclave. attestation answers "what is running", membership and
  key pinning (THREAT_MODEL.md sections 1 and 3) still have to answer "whose box",
  and both answers are required.

## why a members-own-the-hardware club is a strange place for this

attestation was built for the cloud case: you do not trust the operator, the
hardware proves things the operator cannot fake. a club is the inverted case. you
picked the node because you trust the member. you have their number.

the guarantee is still worth having, for reasons that have nothing to do with
suspecting your friends:

- **compromise is not consent.** trusting a member is not the same as trusting every
  process on a box that also runs a browser and a torrent client. attestation
  protects jobs from the member's malware, not just from the member.
- **it converts a promise into a property.** "we can't read your prompts" is a
  different sentence from "we promise not to look", legally and socially. a member
  who cannot read job traffic cannot be subpoenaed, pressured, or socially
  engineered into producing it.
- **it protects the member too.** an operator who can prove they never see plaintext
  is holding a much smaller liability than one who pinky-swears.
- **boxes outlive intentions.** hardware gets sold, borrowed, left at an ex's
  apartment. an enclave key that dies with the boot session does not care.

so the club setting does not remove the need, it changes the failure posture: here,
attestation failing open (falling back to the v1 bare key) is often acceptable,
because v1 social trust is the floor, not a breach. that is why the client policy
flag in v2a is a flag and not a hard requirement.

## the phased plan

### v2a: the seam. attested key in the node record, policy flag in the client

extend the node record with an optional `attestation` object: evidence blob, vendor
chain, the enclave-bound sealing pubkey, a freshness timestamp. extend the client
with a `require_attested` policy flag: when set, `submit()` refuses to seal to any
node offering only a bare `pubkey`, and seals to the attested key after verification.

honesty about v2a: with no measured image yet, there is no golden value to check a
measurement against, so early verification is structural (signatures, chains,
freshness, key binding) and the measurement check is a stub that trusts a
club-published list. v2a is scaffolding. its value is that the protocol shape,
record fields and refusal behavior stop being hypothetical, and everything after it
is an upgrade to a verifier rather than a protocol change.

### v2b: something worth measuring. reproducible image, measured boot, GPU evidence

a reproducible node image (engine, pygrid node agent, pinned kernel) whose launch
measurement is deterministic. measured boot into a SEV-SNP or TDX guest. on CC-mode
hardware, GPU evidence chained into the same report. the club publishes golden
measurements per engine release, and revokes them when a release is bad. the client
verifier from v2a starts checking measurements against the published set instead of
accepting the stub list.

### v2c: sealed to the enclave, and only to the enclave

the sealing key becomes enclave-generated, boot-fresh, and bound in report_data as
described above. the node record's bare `pubkey` is demoted to a routing identity.
for pipelined jobs, per-stage attestation and encrypted stage links land here too.
at v2c, and not before, the sentence in THREAT_MODEL.md section 10 gets rewritten
from "a node can read every job sent to it" to "a node in attested mode computes on
jobs it cannot read, modulo the side channel and supply chain caveats above", which
is as good as this sentence gets on anyone's hardware, anywhere.

## sequencing note

none of this is started, and none of it should start before the cheaper v2 items in
THREAT_MODEL.md that fix active weaknesses. two of those now exist from the protocol
v2 work: signed results (node-signed receipts binding the result hash) and membership
auth on job submission (member cards gating `POST /v1/jobs` when the club key is set).
what remains cheaper than attestation is key pinning and tighter replay binding.
attestation is the most expensive item on that list and it defends against the most
honest failure mode. do it last, design it first.
