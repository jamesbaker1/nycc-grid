"""grid client: seal a job to a node, hand the ciphertext to the coordinator, unseal the reply.

the coordinator only ever sees ciphertext plus routing metadata. the reply keypair is
ephemeral and lives in this process only, so a job submitted by one process cannot be
read by another unless the reply private key is deliberately written out (see the cli
--job-file flow, which puts a private key on disk in cleartext).

stdlib urllib only: requests is not installed in the grid venv.
"""

from __future__ import annotations

import argparse
import base64
import json
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
    def __init__(self, coordinator_url: str, timeout: float = DEFAULT_HTTP_TIMEOUT_S) -> None:
        self.coordinator_url = coordinator_url.rstrip("/")
        self.timeout = float(timeout)
        # job_id -> (reply_pub_b64, reply_prv_b64); ephemeral, one keypair per job
        self._reply_keys: dict[str, tuple[str, str]] = {}

    # ---- http -------------------------------------------------------------

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        url = self.coordinator_url + path
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
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

        doc = self._call("POST", "/v1/jobs", body)
        job_id = doc.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            raise CoordinatorError(200, "/v1/jobs", f"no job_id in response: {doc!r}")
        # keep the reply key even on an idempotency replay: the first submit's key is
        # overwritten only if this call really did create a new job_id
        self._reply_keys.setdefault(job_id, (reply_pub, reply_prv))
        return job_id

    def status(self, job_id: str) -> dict:
        return self._call("GET", "/v1/jobs/" + urllib.parse.quote(job_id, safe=""))

    def result(self, job_id: str, timeout: float = DEFAULT_RESULT_TIMEOUT_S) -> str:
        """poll until done, then unseal the result to text.

        polls once before sleeping, so an already-finished job returns with no delay.
        """
        keys = self._reply_keys.get(job_id)
        if keys is None:
            raise KeyError(
                f"no reply key for job {job_id!r} in this client; "
                "reply keypairs are ephemeral and per-process"
            )
        reply_pub, reply_prv = keys
        deadline = time.monotonic() + float(timeout)
        while True:
            doc = self.status(job_id)
            state = doc.get("status")
            if state == "done":
                blob_b64 = doc.get("blob_b64")
                if not blob_b64:
                    raise CoordinatorError(200, job_id, "status done but no blob_b64")
                plain = crypto.unseal(reply_prv, reply_pub, _b64d(blob_b64))
                return _text_of(plain)
            if state == "failed":
                raise JobFailed(f"job {job_id} is terminally failed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"job {job_id} still {state!r} after {timeout}s")
            time.sleep(min(POLL_INTERVAL_S, remaining))

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
    client = GridClient(args.coordinator, timeout=args.http_timeout)

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
            print(f"{node.get('node_id'):24} {flag:5} {_as_float(node.get('wattage')):8.1f}w "
                  f"{node.get('pubkey', '')}")
        return 0

    if args.command == "run":
        text = client.run(
            _read_prompt(args),
            to_node=args.to_node,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
            timeout=args.timeout,
        )
        print(text)
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
        print(client.result(job_id, timeout=args.timeout))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
