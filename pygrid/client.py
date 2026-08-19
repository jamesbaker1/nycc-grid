"""grid client: seal a job to a node, hand the ciphertext to the coordinator, unseal the reply.

the coordinator only ever sees ciphertext plus routing metadata. the reply keypair is
ephemeral and lives in this process only, so a job submitted by one process cannot be
read by another unless the reply private key is deliberately written out (see the cli
--job-file flow, which puts a private key on disk in cleartext).

results come back with a signed receipt when the node sent one. result() ignores it and
returns text as it always has; result_with_receipt() hands back the receipt and whether
it checked out. a verified receipt says a node key stands behind this exact ciphertext,
not that the watts or the timings in it are true.

a member card (pygrid.club) is optional here and optional at the coordinator: when the
coordinator has no club key configured, submission is open and a card changes nothing.
when it does, submit() must carry one. the card is an admission control, not a
confidentiality control: it does not encrypt anything and it does not hide the member
name from the coordinator.

stdlib urllib only: requests is not installed in the grid venv.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from . import crypto

DEFAULT_HTTP_TIMEOUT_S = 10.0
DEFAULT_RESULT_TIMEOUT_S = 30.0
POLL_INTERVAL_S = 0.25
NODES_PAGE_LIMIT = 50
# bounded so a coordinator that always hands back a cursor cannot spin the client forever
MAX_NODE_PAGES = 100

# card path, and the member ed25519 seed itself. the key material env var mirrors
# NYCC_NODE_SIGNKEY in node.py: private keys come from a file or the environment,
# never from argv, where every ps on the box can read them.
ENV_CARD = "NYCC_CARD"
ENV_MEMBER_SIGN = "NYCC_MEMBER_SIGNKEY"

# pygrid.club writes member.keys.json with "signkey", the same field name node.py uses
# in its keyfile. the aliases cost nothing and save a member who hand-rolled the file.
MEMBER_SIGN_FIELDS = ("signkey", "sign_key", "member_signkey")


class CoordinatorError(RuntimeError):
    """non-2xx from the coordinator, or a body that is not the json we expect."""

    def __init__(self, status: int, url: str, detail: str = "") -> None:
        self.status = status
        self.url = url
        self.detail = detail
        super().__init__(f"coordinator {status} for {url}: {detail}".rstrip(": "))


class JobFailed(RuntimeError):
    """terminal 'failed' status: the coordinator gave up redelivering the job."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=False)


class GridClient:
    """talks to one coordinator. optionally carries a club card on job submission.

    card_path and member_keys_path win over the NYCC_CARD and NYCC_MEMBER_SIGNKEY env
    vars, so a flag always beats whatever the shell already had exported. a card
    without its key (or the other way round) is a configuration error and raises here
    rather than turning into a 403 later.
    """

    def __init__(
        self,
        coordinator_url: str,
        timeout: float = DEFAULT_HTTP_TIMEOUT_S,
        card_path: str | None = None,
        member_keys_path: str | None = None,
    ) -> None:
        self.coordinator_url = coordinator_url.rstrip("/")
        self.timeout = float(timeout)
        # job_id -> (reply_pub_b64, reply_prv_b64); ephemeral, one keypair per job
        self._reply_keys: dict[str, tuple[str, str]] = {}

        card_path = card_path or os.environ.get(ENV_CARD) or None
        self.card_doc = _load_card(card_path) if card_path else None
        self.member_sign_b64 = _load_member_sign_key(member_keys_path)
        if self.card_doc is not None and not self.member_sign_b64:
            raise ValueError(
                "a card was given with no member sign key: pass member_keys_path or set "
                + ENV_MEMBER_SIGN
            )
        if self.member_sign_b64 and self.card_doc is None:
            raise ValueError(
                "a member sign key was given with no card: pass card_path or set " + ENV_CARD
            )
        # the whole {"card":...,"sig":...} document, b64 of its canonical json. the
        # coordinator re-serializes the inner card to check the club signature, so the
        # bytes here only have to decode to the same object, not to the same file.
        self.card_header = (
            crypto.b64e(crypto.canonical_json(self.card_doc)) if self.card_doc else None
        )

    @property
    def member(self) -> str | None:
        """the name on the card, or None. unverified locally: what the card asserts."""
        if not self.card_doc:
            return None
        name = self.card_doc.get("card", {}).get("member")
        return str(name) if name else None

    # ---- http -------------------------------------------------------------

    def _call(
        self, method: str, path: str, payload: dict | None = None, as_member: bool = False
    ) -> dict:
        url = self.coordinator_url + path
        data = None
        # a real product UA: urllib's default is on every bot-signature blocklist,
        # including the one in front of our own coordinator.
        headers = {"Accept": "application/json", "User-Agent": "nycc-client/0.1"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if as_member and self.card_header and self.member_sign_b64:
            # signs the exact bytes about to be sent, same canonical string as node
            # signing. the card rides along so the coordinator knows which member key
            # to check the signature against.
            headers[crypto.CARD_HEADER] = self.card_header
            headers.update(
                crypto.member_signed_headers(
                    self.member_sign_b64, url, method, data or b""
                )
            )
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise CoordinatorError(exc.code, url, body.strip()[:400]) from None
        except urllib.error.URLError as exc:
            raise CoordinatorError(0, url, str(exc.reason)) from None
        if not raw:
            return {}
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CoordinatorError(status, url, f"non-json body: {exc}") from None
        if not isinstance(doc, dict):
            raise CoordinatorError(status, url, "expected a json object")
        return doc

    # ---- nodes ------------------------------------------------------------

    def nodes(self, limit: int = NODES_PAGE_LIMIT) -> list[dict]:
        """every node the coordinator will admit to, alive or not."""
        out: list[dict] = []
        cursor: str | None = None
        for _ in range(MAX_NODE_PAGES):
            path = f"/v1/nodes?limit={int(limit)}"
            if cursor:
                path += "&cursor=" + urllib.parse.quote(cursor, safe="")
            doc = self._call("GET", path)
            page = doc.get("nodes") or []
            if not isinstance(page, list):
                raise CoordinatorError(200, path, "nodes was not a list")
            out.extend(n for n in page if isinstance(n, dict))
            cursor = doc.get("cursor") or None
            if not cursor:
                break
        return out

    def pick_node(self) -> dict:
        """lowest advertised wattage among alive nodes.

        wattage is self reported and unauthenticated: a hostile node can claim 0 watts
        and win every auto-picked job. pass to_node explicitly when that matters.
        """
        alive = [n for n in self.nodes() if n.get("alive")]
        if not alive:
            raise RuntimeError("no alive nodes registered with the coordinator")
        return min(alive, key=lambda n: (_as_float(n.get("wattage")), str(n.get("node_id", ""))))

    def _node_record(self, node_id: str | None) -> dict:
        if node_id is None:
            return self.pick_node()
        for node in self.nodes():
            if node.get("node_id") == node_id:
                return node
        raise RuntimeError(f"node {node_id!r} is not registered with the coordinator")

    # ---- jobs -------------------------------------------------------------

    def submit(
        self,
        prompt: str,
        to_node: str | None = None,
        max_tokens: int = 64,
        temperature: float = 0.0,
        idempotency_key: str | None = None,
    ) -> str:
        """seal {prompt,max_tokens,temperature} to the node pubkey and queue it.

        the node pubkey comes from the coordinator, so this is only confidential against
        an honest-but-curious coordinator. see docs/THREAT_MODEL.md.

        a configured card is sent with this request and only this one. whether it is
        required is the coordinator's call: with no club key configured it ignores the
        card entirely and takes jobs from anyone.
        """
        node = self._node_record(to_node)
        pubkey = node.get("pubkey")
        node_id = node.get("node_id")
        if not pubkey or not node_id:
            raise RuntimeError(f"node record is missing node_id/pubkey: {node!r}")

        reply_pub, reply_prv = crypto.keygen()
        payload = {
            "prompt": prompt,
            "max_tokens": int(max_tokens),
            "temperature": float(temperature),
        }
        blob = crypto.seal(pubkey, json.dumps(payload).encode("utf-8"))
        body = {
            "to_node": node_id,
            "blob_b64": _b64e(blob),
            "reply_pubkey": reply_pub,
        }
        if idempotency_key:
            body["idempotency_key"] = idempotency_key

        doc = self._call("POST", "/v1/jobs", body, as_member=True)
        job_id = doc.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            raise CoordinatorError(200, "/v1/jobs", f"no job_id in response: {doc!r}")
        # keep the reply key even on an idempotency replay: the first submit's key is
        # overwritten only if this call really did create a new job_id
        self._reply_keys.setdefault(job_id, (reply_pub, reply_prv))
        return job_id

    def status(self, job_id: str) -> dict:
        return self._call("GET", "/v1/jobs/" + urllib.parse.quote(job_id, safe=""))

    def _await_done(self, job_id: str, timeout: float) -> dict:
        """poll until the job is done, then hand back the whole status document.

        polls once before sleeping, so an already-finished job returns with no delay.
        """
        deadline = time.monotonic() + float(timeout)
        while True:
            doc = self.status(job_id)
            state = doc.get("status")
            if state == "done":
                return doc
            if state == "failed":
                raise JobFailed(f"job {job_id} is terminally failed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"job {job_id} still {state!r} after {timeout}s")
            time.sleep(min(POLL_INTERVAL_S, remaining))

    def result(self, job_id: str, timeout: float = DEFAULT_RESULT_TIMEOUT_S) -> str:
        """poll until done, then unseal the result to text."""
        text, _receipt, _verified = self.result_with_receipt(job_id, timeout=timeout)
        return text

    def result_with_receipt(
        self, job_id: str, timeout: float = DEFAULT_RESULT_TIMEOUT_S
    ) -> tuple[str, dict | None, bool]:
        """(text, receipt, verified).

        receipt is the inner receipt dict, or None when the node did not send one (a
        v1 node, or a coordinator that dropped it). verified is True only when the
        node's signature over that dict checks out AND result_sha256 matches the blob
        this client actually decrypted, which is what makes the receipt worth anything:
        it binds a node identity to this exact ciphertext.

        verified False is never an exception. the text is still returned, because the
        sealed box already proved the result was encrypted to this client's reply key.
        """
        keys = self._reply_keys.get(job_id)
        if keys is None:
            raise KeyError(
                f"no reply key for job {job_id!r} in this client; "
                "reply keypairs are ephemeral and per-process"
            )
        reply_pub, reply_prv = keys
        doc = self._await_done(job_id, timeout)
        blob_b64 = doc.get("blob_b64")
        if not blob_b64:
            raise CoordinatorError(200, job_id, "status done but no blob_b64")
        raw = _b64d(blob_b64)
        text = _text_of(crypto.unseal(reply_prv, reply_pub, raw))

        signed = doc.get("receipt")
        if not isinstance(signed, dict) or not isinstance(signed.get("receipt"), dict):
            return text, None, False
        return text, signed["receipt"], self.verify_receipt(job_id, signed, raw)

    def verify_receipt(self, job_id: str, signed: dict, result_raw: bytes) -> bool:
        """true only for a receipt that this job's node really signed over this blob.

        the verify key comes from the coordinator's own node list, so this detects a
        coordinator that swapped a result, not a coordinator that lies about both the
        result and the key. pin the node's verify_key out of band if that matters.
        never raises: any malformed input is just False.
        """
        try:
            receipt = signed["receipt"]
            sig = crypto.b64d(signed["sig"])
            if receipt.get("job_id") != job_id:
                return False
            if receipt.get("result_sha256") != hashlib.sha256(result_raw).hexdigest():
                return False
            node_id = receipt.get("node_id")
            node = next((n for n in self.nodes() if n.get("node_id") == node_id), None)
            if node is None:
                return False
            return crypto.verify(
                str(node.get("verify_key") or ""), crypto.canonical_json(receipt), sig
            )
        except Exception:
            return False

    def run(self, prompt: str, to_node: str | None = None, max_tokens: int = 64,
            temperature: float = 0.0, timeout: float = DEFAULT_RESULT_TIMEOUT_S) -> str:
        """submit then wait, keeping the ephemeral reply key in memory the whole time."""
        job_id = self.submit(prompt, to_node=to_node, max_tokens=max_tokens,
                             temperature=temperature)
        return self.result(job_id, timeout=timeout)

    # ---- reply key plumbing for the cli -----------------------------------

    def reply_key(self, job_id: str) -> tuple[str, str]:
        return self._reply_keys[job_id]

    def adopt_reply_key(self, job_id: str, reply_pub: str, reply_prv: str) -> None:
        """load a reply keypair saved by an earlier process (see cli --job-file)."""
        self._reply_keys[job_id] = (reply_pub, reply_prv)


def _load_card(path: str) -> dict:
    """read a {"card": {...}, "sig": "..."} document written by pygrid.club."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("card"), dict) or not doc.get("sig"):
        raise ValueError(f"{path} is not a card document: expected keys card and sig")
    return doc


def _load_member_sign_key(path: str | None) -> str | None:
    """the member ed25519 seed, base64, from a keyfile or the environment.

    the keyfile holds an unencrypted private key, exactly like the node keyfile. the
    shape is checked here so a truncated key fails at construction with a name attached
    instead of as an unexplained 403 on the first submit.
    """
    if not path:
        env = (os.environ.get(ENV_MEMBER_SIGN) or "").strip()
        if not env:
            return None
        return _checked_sign_key(env, ENV_MEMBER_SIGN)
    with open(path, "r", encoding="utf-8") as fh:
        keys = json.load(fh)
    if not isinstance(keys, dict):
        raise ValueError(f"{path} is not a json object")
    for field in MEMBER_SIGN_FIELDS:
        value = keys.get(field)
        if isinstance(value, str) and value.strip():
            return _checked_sign_key(value.strip(), path)
    raise ValueError(
        f"{path} has no member sign key: looked for {', '.join(MEMBER_SIGN_FIELDS)}"
    )


def _checked_sign_key(value: str, where: str) -> str:
    try:
        raw = crypto.b64d(value)
    except Exception:
        raise ValueError(f"member sign key from {where} is not base64") from None
    if len(raw) != crypto.KEY_BYTES:
        raise ValueError(
            f"member sign key from {where} is {len(raw)} bytes, expected {crypto.KEY_BYTES}"
        )
    return value


def format_receipt(receipt: dict | None, verified: bool) -> str:
    """the one line the cli prints after a run.

    an unverified receipt prints no numbers on purpose: quoting watts and milliseconds
    from a signature that did not check out would dress up a claim nobody stands behind.
    """
    if not receipt:
        return "receipt: missing"
    if not verified:
        return "receipt: FAILED VERIFICATION"
    return "receipt: %s, %dms, %.1fw %s, verified" % (
        receipt.get("node_id") or "?",
        int(_finite(receipt.get("duration_ms"))),
        _finite(receipt.get("watts")),
        receipt.get("watts_source") or "?",
    )


def _finite(value: object, default: float = 0.0) -> float:
    """a number safe to format, whatever the node put in the field."""
    try:
        out = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if out != out or out in (float("inf"), float("-inf")):
        return default
    return out


def _as_float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return float("inf")


def _text_of(plain: bytes) -> str:
    """result payload is {"text": ...}; tolerate a bare string for hand-rolled nodes."""
    body = plain.decode("utf-8", "replace")
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        return body
    if isinstance(doc, dict) and "text" in doc:
        return str(doc["text"])
    if isinstance(doc, str):
        return doc
    return body


# ---- cli ------------------------------------------------------------------


def _read_prompt(args: argparse.Namespace) -> str:
    if args.prompt_file:
        if args.prompt_file == "-":
            return sys.stdin.read()
        with open(args.prompt_file, "r", encoding="utf-8") as fh:
            return fh.read()
    if args.prompt is None:
        raise SystemExit("give --prompt or --prompt-file")
    return args.prompt


def _write_job_file(path: str, job_id: str, reply_pub: str, reply_prv: str) -> None:
    # cleartext private key on disk, same as the node keyfile. documented in README.
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"job_id": job_id, "reply_pubkey": reply_pub, "reply_prvkey": reply_prv},
                  fh, indent=2)
        fh.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pygrid.client",
        description="submit sealed jobs to the nycc grid",
    )
    parser.add_argument("--coordinator", required=True, help="coordinator base url")
    parser.add_argument("--http-timeout", type=float, default=DEFAULT_HTTP_TIMEOUT_S)
    sub = parser.add_subparsers(dest="command", required=True)

    p_nodes = sub.add_parser("nodes", help="list registered nodes")
    p_nodes.add_argument("--json", action="store_true", help="dump raw json")

    def add_submit_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--prompt")
        p.add_argument("--prompt-file", help="path, or - for stdin")
        p.add_argument("--to-node", default=None, help="skip auto-pick and name the node")
        p.add_argument("--max-tokens", type=int, default=64)
        p.add_argument("--temperature", type=float, default=0.0)
        p.add_argument("--card", default=None,
                       help=f"membership card json (env {ENV_CARD})")
        p.add_argument("--member-keys", default=None,
                       help=f"member keyfile holding the ed25519 seed (env {ENV_MEMBER_SIGN}); "
                            "the seed itself never comes from argv")

    p_run = sub.add_parser("run", help="submit and wait in one process")
    add_submit_args(p_run)
    p_run.add_argument("--timeout", type=float, default=DEFAULT_RESULT_TIMEOUT_S)

    p_submit = sub.add_parser("submit", help="queue a job and exit")
    add_submit_args(p_submit)
    p_submit.add_argument("--job-file", required=True,
                          help="where to save job_id plus the ephemeral reply keypair")

    p_result = sub.add_parser("result", help="wait for a job saved with submit --job-file")
    p_result.add_argument("--job-file", required=True)
    p_result.add_argument("--timeout", type=float, default=DEFAULT_RESULT_TIMEOUT_S)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = GridClient(
        args.coordinator,
        timeout=args.http_timeout,
        card_path=getattr(args, "card", None),
        member_keys_path=getattr(args, "member_keys", None),
    )

    if args.command == "nodes":
        nodes = client.nodes()
        if args.json:
            print(json.dumps(nodes, indent=2))
            return 0
        if not nodes:
            print("no nodes registered")
            return 0
        for node in sorted(nodes, key=lambda n: str(n.get("node_id"))):
            flag = "alive" if node.get("alive") else "stale"
            source = str(node.get("watts_source") or "claimed")
            hood = str(node.get("neighborhood") or "undisclosed")
            print(f"{node.get('node_id'):24} {flag:5} {_as_float(node.get('wattage')):8.1f}w "
                  f"{source:8} {hood:20} {node.get('pubkey', '')}")
        return 0

    if args.command == "run":
        job_id = client.submit(
            _read_prompt(args),
            to_node=args.to_node,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
        )
        text, receipt, verified = client.result_with_receipt(job_id, timeout=args.timeout)
        print(text)
        print(format_receipt(receipt, verified))
        return 0

    if args.command == "submit":
        job_id = client.submit(
            _read_prompt(args),
            to_node=args.to_node,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
        )
        reply_pub, reply_prv = client.reply_key(job_id)
        _write_job_file(args.job_file, job_id, reply_pub, reply_prv)
        print(job_id)
        return 0

    if args.command == "result":
        with open(args.job_file, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        job_id = saved["job_id"]
        client.adopt_reply_key(job_id, saved["reply_pubkey"], saved["reply_prvkey"])
        text, receipt, verified = client.result_with_receipt(job_id, timeout=args.timeout)
        print(text)
        print(format_receipt(receipt, verified))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
