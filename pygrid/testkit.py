"""in-process mocks for local end-to-end runs: a coordinator and an engine.

MockCoordinator implements the shape of the real worker api in plain dicts and records
every request body it saw, so a test can assert the coordinator never held plaintext.

it deliberately does NOT verify NODE signatures. that correctness is covered by the
coordinator's logic.js tests (injectable stub verifier) and by the crypto sign/verify
roundtrip; re-implementing the canonical signing string here would couple this file to
the worker byte for byte and add a second place to get it wrong. what it does enforce is
the parts the python side has to get right: node id headers, job ownership, monotonic
status transitions, leases, and the size and queue caps.

the one exception is the member certificate gate, and only when a club verify key is
configured. that path is the whole point of MockCoordinator(club_verify_key=...), so it
really does check the club signature on the card and the member signature on the request,
by calling crypto.signing_message rather than by writing the canonical string out again.

no external deps beyond pynacl, stdlib http.server only. always binds 127.0.0.1 on an
ephemeral port. no CORS here: browsers do not talk to this mock, only python tests do.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from . import club, crypto

# the neighborhood grammar and the watts_source labels come from protocol.py rather than
# a second copy: a value this mock accepts and the worker rejects would be a bug a test
# had been taught to trust.
from .protocol import DEFAULT_NEIGHBORHOOD, WATTS_SOURCES, valid_neighborhood

# mirrors of the coordinator constants; kept small enough to exercise in tests
PULL_MAX = 10
LEASE_MS = 10 * 60 * 1000
MAX_ATTEMPTS = 5
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_BLOB_B64_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 8 * 1024
MAX_QUEUED_PER_NODE = 100
HEARTBEAT_S = 30.0
STALE_AFTER_S = 3 * HEARTBEAT_S
DEFAULT_NODES_LIMIT = 50

NODE_ID_HEADER = "X-NYCC-Node-Id"

# the only fields a pull envelope may carry: extra keys break a strict from_json
_ENVELOPE_FIELDS = ("job_id", "to_node", "blob_b64", "reply_pubkey", "status")

# "the field was invalid and the 400 already went out", distinct from "absent"
_BAD = object()


def js_round_trip(doc: object) -> object:
    """what a document looks like after the deployed coordinator has re-emitted it.

    the real worker is javascript: it JSON.parses a request body and JSON.stringifies
    the response, and javascript has one number type, so 65.0 arrives back as 65. this
    mock keeps python objects and therefore keeps the float, which is the one production
    behaviour it does not reproduce, so a test that cares has to apply this itself.

    written out here rather than reusing crypto._js_numbers on purpose: a regression test
    that agreed with the implementation by construction would catch nothing.
    """
    if isinstance(doc, float) and doc.is_integer():
        return int(doc)
    if isinstance(doc, dict):
        return {k: js_round_trip(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [js_round_trip(v) for v in doc]
    return doc


class _MockServer:
    """shared lifecycle: ephemeral loopback port, daemon threads, clean close."""

    handler_class: type[BaseHTTPRequestHandler]

    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler_class)
        self.server.daemon_threads = True
        self.server.mock = self  # type: ignore[attr-defined]
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.requests: list[dict] = []
        self.bodies: list[bytes] = []
        self.lock = threading.RLock()
        self._thread: threading.Thread | None = None

    def start(self) -> "_MockServer":
        if self._thread is None:
            self._thread = threading.Thread(
                target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        if self._thread is not None:
            self.server.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self.server.server_close()

    def __enter__(self) -> "_MockServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---- recording --------------------------------------------------------

    def record(self, method: str, path: str, headers: dict, raw: bytes, direction: str) -> None:
        with self.lock:
            self.requests.append(
                {
                    "direction": direction,
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "body": raw,
                }
            )
            self.bodies.append(raw)

    def saw(self, needle: str | bytes) -> bool:
        """true if the literal bytes appear in anything that crossed this server."""
        probe = needle.encode("utf-8") if isinstance(needle, str) else needle
        with self.lock:
            return any(probe in body for body in self.bodies) or any(
                probe in entry["path"].encode("utf-8") for entry in self.requests
            )


class _JsonHandler(BaseHTTPRequestHandler):
    server_version = "nycc-mock/0.1"

    def log_message(self, fmt: str, *args: object) -> None:  # silence stderr noise
        pass

    @property
    def mock(self):
        return self.server.mock  # type: ignore[attr-defined]

    def _headers(self) -> dict:
        return {k.lower(): v for k, v in self.headers.items()}

    def _read_body(self) -> bytes | None:
        """None means the caller already got a 413."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            self._send(413, {"error": "request body too large"})
            return None
        return self.rfile.read(length) if length else b""

    def _json_body(self) -> tuple[dict | None, bytes]:
        raw = self._read_body()
        if raw is None:
            return None, b""
        self.mock.record(self.command, self.path, self._headers(), raw, "request")
        if not raw:
            return {}, raw
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"error": "body is not json"})
            return None, raw
        if not isinstance(doc, dict):
            self._send(400, {"error": "body is not a json object"})
            return None, raw
        return doc, raw

    def _send(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.mock.record(self.command, self.path, {}, raw, "response")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)


def _now_ms() -> int:
    return int(time.time() * 1000)


class MockCoordinator(_MockServer):
    """the routing api, in dicts. holds ciphertext and metadata, never plaintext.

    club_verify_key mirrors the worker's CLUB_VERIFY_KEY var. empty or None means job
    submission is open, exactly as in v1. set it and POST /v1/jobs demands a card.
    """

    def __init__(self, club_verify_key: str | None = None) -> None:
        self.nodes: dict[str, dict] = {}
        self.jobs: dict[str, dict] = {}
        self.idempotency: dict[str, str] = {}
        self.club_verify_key = club_verify_key or ""
        # (member verify key, nonce) -> unix seconds. the worker keeps this in KV with a
        # TTL; here it grows for the life of the process, which is a few seconds.
        self.member_nonces: dict[tuple[str, str], float] = {}
        # member names off accepted cards, in order. the coordinator sees these.
        self.members_seen: list[str] = []
        self.jobs_done = 0
        self._seq = 0
        self.handler_class = _CoordinatorHandler
        super().__init__()

    # ---- state helpers (called under self.lock by the handler) ------------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def alive(self, node: dict, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (now - float(node.get("last_seen", 0.0))) <= STALE_AFTER_S

    def node_view(self, node: dict) -> dict:
        # last_seen here is unix SECONDS; the deployed worker stores Date.now(), which is
        # milliseconds. consume the server-computed alive flag rather than recomputing
        # liveness from last_seen, which is the only reading that works against both.
        view = {
            k: node[k]
            for k in (
                "node_id",
                "pubkey",
                "verify_key",
                "wattage",
                "watts_source",
                "neighborhood",
                "last_seen",
            )
        }
        view["alive"] = self.alive(node)
        return view

    def stats(self) -> dict:
        """the public counters. alive nodes only, so a stale node stops contributing
        watts the moment it stops heartbeating."""
        alive = [n for n in self.nodes.values() if self.alive(n)]
        hoods: dict[str, dict] = {}
        for node in alive:
            hood = hoods.setdefault(
                node.get("neighborhood") or DEFAULT_NEIGHBORHOOD, {"nodes": 0, "watts": 0.0}
            )
            hood["nodes"] += 1
            hood["watts"] += _f(node.get("wattage"))
        return {
            "ok": True,
            "nodes_alive": len(alive),
            "watts": round(sum(_f(n.get("wattage")) for n in alive), 1),
            "watts_measured": round(
                sum(_f(n.get("wattage")) for n in alive if n.get("watts_source") == "measured"), 1
            ),
            "jobs_done": self.jobs_done,
            "neighborhoods": [
                {"name": name, "nodes": v["nodes"], "watts": round(v["watts"], 1)}
                for name, v in sorted(hoods.items())
            ],
        }

    def envelope(self, job: dict) -> dict:
        return {k: job[k] for k in _ENVELOPE_FIELDS}

    def queued_count(self, node_id: str) -> int:
        return sum(
            1
            for job in self.jobs.values()
            if job["to_node"] == node_id and job["status"] in ("queued", "running")
        )

    def touch(
        self,
        node_id: str,
        wattage: float | None = None,
        watts_source: str | None = None,
    ) -> None:
        node = self.nodes.get(node_id)
        if node is None:
            return
        node["last_seen"] = time.time()
        if wattage is not None:
            node["wattage"] = float(wattage)
        if watts_source is not None:
            node["watts_source"] = watts_source

    def set_last_seen(self, node_id: str, last_seen: float) -> None:
        """test hook: age a node out so alive flips to false."""
        with self.lock:
            self.nodes[node_id]["last_seen"] = last_seen

    def expire_lease(self, job_id: str) -> None:
        """test hook: pretend the lease on a running job already ran out."""
        with self.lock:
            self.jobs[job_id]["lease_until_ms"] = _now_ms() - 1


class _CoordinatorHandler(_JsonHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        self.mock.record("GET", self.path, self._headers(), b"", "request")

        if path == "/healthz":
            self._send(200, {"ok": True})
            return
        if path == "/v1/stats":
            with self.mock.lock:
                payload = self.mock.stats()
            self._send(200, payload)
            return
        if path == "/v1/nodes":
            self._list_nodes(query)
            return
        if path == "/v1/jobs/pull":
            self._pull(query)
            return
        if path.startswith("/v1/jobs/"):
            self._job_status(unquote(path[len("/v1/jobs/"):]))
            return
        self._send(404, {"error": "no such route"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        routes = {
            "/v1/nodes/register": self._register,
            "/v1/nodes/heartbeat": self._heartbeat,
            "/v1/jobs": self._create_job,
            "/v1/jobs/result": self._result,
        }
        handler = routes.get(path)
        if handler is None:
            self._read_body()
            self._send(404, {"error": "no such route"})
            return
        body, raw = self._json_body()
        if body is None:
            return
        # the gate runs before any submit validation: an outsider must not learn which
        # node ids exist by reading 404s off a route it is not allowed to call.
        if path == "/v1/jobs" and not self._member_gate(raw):
            return
        handler(body)

    # ---- member certificates ----------------------------------------------

    def _deny(self, code: str, detail: str) -> None:
        """403 with a machine readable code. `error` stays human, `code` is the contract."""
        self._send(403, {"error": detail, "code": code})

    def _member_gate(self, raw: bytes) -> bool:
        """true when POST /v1/jobs may proceed. sends the 403 itself when it may not.

        open grid when no club key is configured, which is the deploy-safe default and
        exactly the v1 behaviour.
        """
        mock = self.mock
        club_key = mock.club_verify_key
        if not club_key:
            return True

        hdrs = self._headers()
        header_value = hdrs.get(club.CARD_HEADER)
        if not header_value:
            self._deny(club.ERR_CARD_REQUIRED, "membership card required")
            return False
        doc = club.decode_card_header(header_value)
        if doc is None:
            self._deny(club.ERR_CARD_MALFORMED, "card header is not base64 json")
            return False
        code = club.check_card(club_key, doc)
        if code is not None:
            self._deny(code, "card rejected")
            return False

        ts = hdrs.get(club.MEMBER_TS_HEADER)
        nonce = hdrs.get(club.MEMBER_NONCE_HEADER)
        sig_b64 = hdrs.get(club.MEMBER_SIG_HEADER)
        if not ts or not nonce or not sig_b64:
            self._deny(club.ERR_MEMBER_SIG_MISSING, "member signature headers required")
            return False
        try:
            ts_int = int(ts)
        except ValueError:
            self._deny(club.ERR_MEMBER_SIG_MALFORMED, "member timestamp is not an integer")
            return False
        if abs(time.time() - ts_int) > crypto.MAX_SKEW_S:
            self._deny(club.ERR_MEMBER_SIG_EXPIRED, "member timestamp outside the window")
            return False
        try:
            sig = crypto.b64d(sig_b64)
        except Exception:
            self._deny(club.ERR_MEMBER_SIG_MALFORMED, "member signature is not base64")
            return False

        # same canonical string as node signing, produced by the same helper. the host
        # is the Host header the client signed over, port included.
        host = (self.headers.get("Host") or "").lower()
        msg = crypto.signing_message(host, "POST", self.path, ts, nonce, raw)
        member_key = doc["card"]["member_verify_key"]
        if not crypto.verify(member_key, msg, sig):
            self._deny(club.ERR_MEMBER_SIG_INVALID, "member signature does not verify")
            return False

        # scoped to the member key, never to the name: names are not unique and the name
        # is not what the signature is checked against.
        key = (member_key, nonce)
        with mock.lock:
            if key in mock.member_nonces:
                self._deny(club.ERR_MEMBER_SIG_REPLAY, "member nonce already used")
                return False
            mock.member_nonces[key] = time.time()
            # a gated coordinator learns who submits what. that is the trade the card
            # makes, and a test can assert it rather than discover it later.
            mock.members_seen.append(doc["card"]["member"])
        return True

    # ---- nodes ------------------------------------------------------------

    def _register(self, body: dict) -> None:
        node_id = body.get("node_id")
        pubkey = body.get("pubkey")
        verify_key = body.get("verify_key")
        if not isinstance(node_id, str) or not node_id or not pubkey or not verify_key:
            self._send(400, {"error": "node_id, pubkey and verify_key are required"})
            return
        neighborhood = body.get("neighborhood")
        if neighborhood is None:
            neighborhood = DEFAULT_NEIGHBORHOOD
        elif not valid_neighborhood(neighborhood):
            self._send(400, {"error": "invalid neighborhood"})
            return
        watts_source = self._watts_source(body)
        if watts_source is _BAD:
            return
        mock = self.mock
        with mock.lock:
            # the real worker rejects a re-register that does not verify against the
            # stored verify_key. this mock has no verifier, so it accepts and records.
            existed = node_id in mock.nodes
            mock.nodes[node_id] = {
                "node_id": node_id,
                "pubkey": pubkey,
                "verify_key": verify_key,
                "wattage": _f(body.get("wattage")),
                "watts_source": "claimed" if watts_source is None else watts_source,
                "neighborhood": neighborhood,
                "last_seen": time.time(),
            }
        self._send(200, {"ok": True, "node_id": node_id, "rotated": existed})

    def _watts_source(self, body: dict):
        """the declared source: a str, None when the body omits it, or _BAD when a 400
        already went out. absent must not silently downgrade a stored "measured".

        it is a label the node types, not a measurement anything here can check.
        """
        value = body.get("watts_source")
        if value is None:
            return None
        if value not in WATTS_SOURCES:
            self._send(400, {"error": "watts_source must be one of %s" % (WATTS_SOURCES,)})
            return _BAD
        return value

    def _heartbeat(self, body: dict) -> None:
        node_id = body.get("node_id")
        header_id = self.headers.get(NODE_ID_HEADER)
        mock = self.mock
        with mock.lock:
            if node_id not in mock.nodes:
                # 404 lands before any identity check, as in the worker: the verify key
                # lives in the record, and NodeAgent needs this as the re-register signal.
                self._send(404, {"error": "unknown node_id, re-register"})
                return
            if header_id is not None and header_id != node_id:
                self._send(400, {"error": "node_id header does not match body"})
                return
            watts_source = self._watts_source(body)
            if watts_source is _BAD:
                return
            mock.touch(node_id, _f(body.get("wattage")), watts_source)
        self._send(200, {"ok": True, "node_id": node_id})

    def _list_nodes(self, query: dict) -> None:
        limit = _int(query.get("limit", [DEFAULT_NODES_LIMIT])[0], DEFAULT_NODES_LIMIT)
        limit = max(1, min(limit, 500))
        cursor = query.get("cursor", [None])[0]
        mock = self.mock
        with mock.lock:
            ordered = [mock.nodes[k] for k in sorted(mock.nodes)]
            if cursor:
                ordered = [n for n in ordered if n["node_id"] > cursor]
            page = ordered[:limit]
            payload: dict = {"nodes": [mock.node_view(n) for n in page]}
            if len(ordered) > limit and page:
                payload["cursor"] = page[-1]["node_id"]
        self._send(200, payload)

    # ---- jobs -------------------------------------------------------------

    def _create_job(self, body: dict) -> None:
        to_node = body.get("to_node")
        blob_b64 = body.get("blob_b64")
        reply_pubkey = body.get("reply_pubkey")
        if not isinstance(to_node, str) or not isinstance(blob_b64, str) \
                or not isinstance(reply_pubkey, str) or not to_node or not blob_b64:
            self._send(400, {"error": "to_node, blob_b64 and reply_pubkey are required"})
            return
        if len(blob_b64) > MAX_BLOB_B64_BYTES:
            self._send(413, {"error": "blob_b64 over 1 MiB"})
            return
        idem = body.get("idempotency_key")
        mock = self.mock
        with mock.lock:
            if to_node not in mock.nodes:
                self._send(404, {"error": "unknown to_node"})
                return
            if isinstance(idem, str) and idem in mock.idempotency:
                self._send(200, {"job_id": mock.idempotency[idem], "duplicate": True})
                return
            if mock.queued_count(to_node) >= MAX_QUEUED_PER_NODE:
                self._send(429, {"error": "per-node queue is full"})
                return
            job_id = str(uuid.uuid4())
            mock.jobs[job_id] = {
                "job_id": job_id,
                "to_node": to_node,
                "blob_b64": blob_b64,
                "reply_pubkey": reply_pubkey,
                "status": "queued",
                "result_b64": None,
                "receipt": None,
                "lease_until_ms": 0,
                "attempts": 0,
                "created_ms": _now_ms(),
                "seq": mock._next_seq(),
            }
            if isinstance(idem, str) and idem:
                mock.idempotency[idem] = job_id
        self._send(200, {"job_id": job_id})

    def _pull(self, query: dict) -> None:
        node_id = query.get("node_id", [None])[0]
        header_id = self.headers.get(NODE_ID_HEADER)
        mock = self.mock
        with mock.lock:
            if not node_id or node_id not in mock.nodes:
                self._send(404, {"error": "unknown node_id, re-register"})
                return
            if header_id is not None and header_id != node_id:
                self._send(403, {"error": "signing node does not match node_id"})
                return
            mock.touch(node_id)
            now_ms = _now_ms()
            out: list[dict] = []
            for job in sorted(mock.jobs.values(), key=lambda j: j["seq"]):
                if len(out) >= PULL_MAX:
                    break
                if job["to_node"] != node_id:
                    continue
                if job["status"] == "queued":
                    pass
                elif job["status"] == "running" and job["lease_until_ms"] <= now_ms:
                    if job["attempts"] >= MAX_ATTEMPTS:
                        # terminal: a poison job must stop redelivering forever
                        job["status"] = "failed"
                        continue
                else:
                    continue
                job["status"] = "running"
                job["lease_until_ms"] = now_ms + LEASE_MS
                job["attempts"] += 1
                out.append(mock.envelope(job))
        self._send(200, {"jobs": out})

    def _result(self, body: dict) -> None:
        job_id = body.get("job_id")
        blob_b64 = body.get("blob_b64")
        node_id = self.headers.get(NODE_ID_HEADER)
        if not node_id:
            self._send(400, {"error": f"missing {NODE_ID_HEADER}"})
            return
        if not isinstance(job_id, str) or not isinstance(blob_b64, str) or not blob_b64:
            self._send(400, {"error": "job_id and blob_b64 are required"})
            return
        if len(blob_b64) > MAX_BLOB_B64_BYTES:
            self._send(413, {"error": "blob_b64 over 1 MiB"})
            return
        # a v1 node posts no receipt at all, and that stays a good request. the receipt
        # is stored and handed back opaquely: nothing here verifies it, the client does.
        # the size cap is the only thing stopping it being free storage on a job record.
        receipt = body.get("receipt")
        if receipt is not None:
            if not isinstance(receipt, dict):
                self._send(400, {"error": "receipt must be a json object"})
                return
            if len(json.dumps(receipt)) > MAX_RECEIPT_BYTES:
                self._send(413, {"error": "receipt too large"})
                return
        mock = self.mock
        with mock.lock:
            job = mock.jobs.get(job_id)
            if job is None:
                self._send(404, {"error": "unknown job_id"})
                return
            if job["to_node"] != node_id:
                self._send(403, {"error": "job does not belong to this node"})
                return
            mock.touch(node_id)
            if job["status"] == "done":
                # first result wins; a retry after a lost response is a no-op
                self._send(200, {"ok": True, "status": "done", "duplicate": True})
                return
            if job["status"] != "running":
                # monotonic: nothing leaves queued without a pull, nothing leaves failed
                self._send(409, {"error": f"job is {job['status']}, not running",
                                 "status": job["status"]})
                return
            job["status"] = "done"
            job["result_b64"] = blob_b64
            job["receipt"] = receipt
            job["lease_until_ms"] = 0
            # counted once, on the transition. a duplicate post returned above.
            mock.jobs_done += 1
        self._send(200, {"ok": True, "status": "done"})

    def _job_status(self, job_id: str) -> None:
        mock = self.mock
        with mock.lock:
            job = mock.jobs.get(job_id)
            if job is None:
                self._send(404, {"error": "unknown job_id"})
                return
            if job["status"] == "done":
                # blob_b64 here is the RESULT ciphertext, never the job ciphertext
                payload = {"status": "done", "blob_b64": job["result_b64"]}
                # absent when the node posted no receipt, so a v1 node still produces a
                # v1 shaped status response
                if job.get("receipt") is not None:
                    payload["receipt"] = job["receipt"]
            else:
                payload = {"status": job["status"]}
        self._send(200, payload)


class MockEngine(_MockServer):
    """stands in for nycc-engine: echoes the prompt back through the completions shape."""

    def __init__(self, echo_prefix: str = "echo: ") -> None:
        self.echo_prefix = echo_prefix
        self.prompts: list[str] = []
        self.handler_class = _EngineHandler
        super().__init__()


class _EngineHandler(_JsonHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        self.mock.record("GET", self.path, self._headers(), b"", "request")
        if path == "/healthz":
            self._send(200, {"ok": True, "watts": 0.0})
        elif path == "/v1/models":
            self._send(200, {"data": [{"id": "nycc-mock"}]})
        else:
            self._send(404, {"error": "no such route"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/v1/completions":
            self._read_body()
            self._send(404, {"error": "no such route"})
            return
        body, _raw = self._json_body()
        if body is None:
            return
        prompt = str(body.get("prompt", ""))
        max_tokens = _int(body.get("max_tokens"), 0)
        with self.mock.lock:
            self.mock.prompts.append(prompt)
        text = self.mock.echo_prefix + prompt
        self._send(
            200,
            {
                "id": "cmpl-" + uuid.uuid4().hex[:12],
                "object": "text_completion",
                "model": "nycc-mock",
                "choices": [{"index": 0, "text": text, "finish_reason": "length"}],
                "usage": {
                    "prompt_tokens": len(prompt.encode("utf-8")),
                    "completion_tokens": max_tokens,
                    "total_tokens": len(prompt.encode("utf-8")) + max_tokens,
                },
            },
        )


def _f(value: object, default: float = 0.0) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
