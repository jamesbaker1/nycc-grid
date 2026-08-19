"""node agent: pull sealed jobs from the coordinator, run them on the local engine,
seal the result back to the client's reply key.

the engine has no authentication, so engine_url must be loopback: prompts travel to
it as plaintext http.

every finished job also ships a signed receipt (build_receipt), which hashes the two
ciphertext blobs and states the watts and the wall time. the signature attributes the
claim to this node's key; it does not make the numbers true.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

from . import crypto, watts
from .protocol import (
    DEFAULT_NEIGHBORHOOD,
    HEARTBEAT_S,
    JobEnvelope,
    valid_neighborhood,
)

POLL_S = 5.0
HTTP_TIMEOUT_S = 60.0
DEFAULT_MAX_TOKENS = 16

# private keys are read from a keyfile or these env vars, never from argv.
ENV_NODE_ID = "NYCC_NODE_ID"
ENV_PUB = "NYCC_NODE_PUBKEY"
ENV_PRV = "NYCC_NODE_PRIVKEY"
ENV_VERIFY = "NYCC_NODE_VERIFY_KEY"
ENV_SIGN = "NYCC_NODE_SIGNKEY"

__all__ = ["NodeAgent", "main", "load_keys", "make_keys"]


class NodeAgent:
    def __init__(
        self,
        coordinator_url: str,
        engine_url: str,
        node_id: str,
        box_pub_b64: str,
        box_prv_b64: str,
        verify_b64: str,
        sign_b64: str,
        wattage: float = 0.0,
        neighborhood: str = DEFAULT_NEIGHBORHOOD,
    ) -> None:
        self.coordinator_url = coordinator_url.rstrip("/")
        self.engine_url = engine_url.rstrip("/")
        self.node_id = node_id
        self.box_pub_b64 = box_pub_b64
        self.box_prv_b64 = box_prv_b64
        self.verify_b64 = verify_b64
        self.sign_b64 = sign_b64
        # what the operator typed in. kept separately from self.wattage so a meter that
        # stops answering falls back to it instead of freezing on the last reading.
        self.claimed_wattage = float(wattage)
        self.neighborhood = str(neighborhood or DEFAULT_NEIGHBORHOOD)
        self.wattage = self.claimed_wattage
        self.watts_source = "claimed"
        self.registered = False
        self._last_heartbeat = 0.0
        _warn_if_not_loopback(self.engine_url)
        self.measure_watts()  # at startup, so the first register carries a real number

    # ------------------------------------------------------------------ watts

    def measure_watts(self) -> float:
        """re-read the meter. measured wins over claimed, and watts_source says which.

        called at startup and before every heartbeat, so a gpu that spins up after the
        node started still shows up, and a driver that goes away falls back cleanly.
        """
        reading = watts.measure()
        if reading is None:
            self.wattage = self.claimed_wattage
            self.watts_source = "claimed"
        else:
            self.wattage = round(float(reading), 1)
            self.watts_source = "measured"
        return self.wattage

    # ------------------------------------------------------------------ http

    def _http(
        self,
        url: str,
        method: str,
        body: bytes = b"",
        signed: bool = False,
        timeout: float = HTTP_TIMEOUT_S,
    ) -> tuple[int, dict]:
        # a real product UA: urllib's default is on every bot-signature blocklist,
        # including the one in front of our own coordinator.
        headers = {"Accept": "application/json", "User-Agent": "nycc-node/0.1"}
        if body:
            headers["Content-Type"] = "application/json"
        if signed:
            # signature covers the exact bytes sent, including the empty body on GET.
            headers.update(
                crypto.signed_headers(self.node_id, self.sign_b64, url, method, body)
            )
        req = urllib.request.Request(
            url, data=body if body else None, headers=headers, method=method.upper()
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, _parse_json(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, _parse_json(exc.read())

    def _coord(
        self, method: str, path: str, payload: dict | None = None, signed: bool = True
    ) -> tuple[int, dict]:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        return self._http(self.coordinator_url + path, method, body, signed=signed)

    # ------------------------------------------------------------- lifecycle

    def register(self) -> None:
        """proof of possession: signed by the sign key whose verify_key is in the body.
        re-registering an existing node_id only works from the registered key."""
        status, data = self._coord(
            "POST",
            "/v1/nodes/register",
            {
                "node_id": self.node_id,
                "pubkey": self.box_pub_b64,
                "verify_key": self.verify_b64,
                "wattage": self.wattage,
                "watts_source": self.watts_source,
                "neighborhood": self.neighborhood,
            },
        )
        if status not in (200, 201):
            raise RuntimeError("register failed: http %s %s" % (status, data))
        self.registered = True
        self._last_heartbeat = time.monotonic()

    def heartbeat(self) -> bool:
        """404 means the coordinator lost our registration; re-register instead of
        heartbeating into the void."""
        self.measure_watts()
        status, data = self._coord(
            "POST",
            "/v1/nodes/heartbeat",
            {
                "node_id": self.node_id,
                "wattage": self.wattage,
                "watts_source": self.watts_source,
            },
        )
        self._last_heartbeat = time.monotonic()
        if status == 404:
            self.registered = False
            self.register()
            return False
        if status != 200:
            raise RuntimeError("heartbeat failed: http %s %s" % (status, data))
        return True

    def _heartbeat_if_due(self) -> None:
        if time.monotonic() - self._last_heartbeat >= HEARTBEAT_S:
            self.heartbeat()

    def pull(self) -> list[JobEnvelope]:
        path = "/v1/jobs/pull?node_id=" + urllib.parse.quote(self.node_id, safe="")
        status, data = self._coord("GET", path)
        if status == 404:
            self.registered = False
            self.register()
            status, data = self._coord("GET", path)
        if status != 200:
            raise RuntimeError("pull failed: http %s %s" % (status, data))
        return [JobEnvelope.from_dict(j) for j in data.get("jobs") or []]

    # ----------------------------------------------------------------- work

    def _infer(self, payload: dict) -> str:
        body = json.dumps(
            {
                "prompt": payload.get("prompt", ""),
                "max_tokens": int(payload.get("max_tokens") or DEFAULT_MAX_TOKENS),
                "temperature": float(payload.get("temperature") or 0.0),
            }
        ).encode("utf-8")
        status, data = self._http(self.engine_url + "/v1/completions", "POST", body)
        if status != 200:
            raise RuntimeError("engine failed: http %s %s" % (status, data))
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("engine returned no choices")
        return choices[0].get("text", "")

    def build_receipt(
        self,
        job_id: str,
        started: str,
        finished: str,
        duration_ms: int,
        request_raw: bytes,
        result_raw: bytes,
    ) -> dict:
        """a signed statement that this node produced this exact result ciphertext.

        what the signature proves: whoever holds this node's sign key saw a job blob
        with request_sha256 and emitted a result blob with result_sha256, and stated
        these times. the client re-hashes the blob it received, so a coordinator that
        swapped the result cannot make the receipt check out.

        what it does not prove: that the watts are real (self reported, watts_source
        only says where the number came from), that the timings are real, or that the
        engine ran the model it claims. it is an attributable claim, not an attestation.

        both hashes are over ciphertext, so the receipt can be checked by anyone
        without ever seeing the prompt or the answer.
        """
        receipt = {
            "job_id": job_id,
            "node_id": self.node_id,
            "started": started,
            "finished": finished,
            "duration_ms": int(duration_ms),
            "watts": float(self.wattage),
            "watts_source": self.watts_source,
            "request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "result_sha256": hashlib.sha256(result_raw).hexdigest(),
        }
        sig = crypto.sign(self.sign_b64, crypto.canonical_json(receipt))
        return {"receipt": receipt, "sig": crypto.b64e(sig)}

    def process(self, env: JobEnvelope) -> None:
        started_at = time.monotonic()
        started = _iso_now()
        request_raw = crypto.b64d(env.blob_b64)
        plain = crypto.unseal(self.box_prv_b64, self.box_pub_b64, request_raw)
        payload = json.loads(plain.decode("utf-8"))
        text = self._infer(payload)
        sealed = crypto.seal(env.reply_pubkey, json.dumps({"text": text}).encode("utf-8"))
        finished = _iso_now()
        duration_ms = int(round((time.monotonic() - started_at) * 1000))
        receipt = self.build_receipt(
            env.job_id, started, finished, duration_ms, request_raw, sealed
        )
        status, data = self._coord(
            "POST",
            "/v1/jobs/result",
            {
                "job_id": env.job_id,
                "blob_b64": crypto.b64e(sealed),
                "receipt": receipt,
            },
        )
        if status != 200:
            raise RuntimeError("result failed: http %s %s" % (status, data))

    def run_once(self) -> int:
        """register (first call) or heartbeat, pull, run, post results. returns the
        number of jobs completed. a job that raises is skipped: its lease expires and
        the coordinator redelivers it, or fails it after MAX_ATTEMPTS."""
        if not self.registered:
            self.register()
        else:
            self._heartbeat_if_due()
        done = 0
        for env in self.pull():
            try:
                self.process(env)
                done += 1
            except Exception as exc:  # one poison job must not stop the agent
                print("job %s failed: %r" % (env.job_id, exc), file=sys.stderr)
        return done

    def run_forever(self, interval: float = POLL_S) -> None:
        while True:
            try:
                self.run_once()
            except Exception as exc:
                print("run_once failed: %r" % (exc,), file=sys.stderr)
            time.sleep(interval)


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")


def _warn_if_not_loopback(engine_url: str) -> None:
    """the engine has zero authentication and prompts reach it as plaintext http, so a
    non-loopback engine_url exposes both. warn, do not block: the operator may have a
    tunnel we cannot see."""
    host = urllib.parse.urlsplit(engine_url).hostname or ""
    if host.lower() not in _LOOPBACK_HOSTS:
        print(
            "warning: engine url %s is not loopback. the engine has no auth and prompts "
            "travel to it in plaintext." % engine_url,
            file=sys.stderr,
        )


def _iso_now() -> str:
    """utc iso8601 with a Z, which is what every receipt reader expects to parse."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_json(raw: bytes) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


# ------------------------------------------------------------------- keyfile


def make_keys(node_id: str | None = None) -> dict:
    pub, prv = crypto.keygen()
    verify, sign = crypto.sign_keygen()
    return {
        "node_id": node_id or ("node-" + uuid.uuid4().hex[:12]),
        "pubkey": pub,
        "privkey": prv,
        "verify_key": verify,
        "signkey": sign,
    }


def load_keys(path: str | None, node_id: str | None = None) -> dict:
    """env vars win over the keyfile. the keyfile is generated when absent and holds
    unencrypted private keys."""
    env = {
        "node_id": os.environ.get(ENV_NODE_ID),
        "pubkey": os.environ.get(ENV_PUB),
        "privkey": os.environ.get(ENV_PRV),
        "verify_key": os.environ.get(ENV_VERIFY),
        "signkey": os.environ.get(ENV_SIGN),
    }
    if all(env.values()):
        return env
    if not path:
        raise SystemExit("need --keyfile, or all of %s" % ", ".join(
            [ENV_NODE_ID, ENV_PUB, ENV_PRV, ENV_VERIFY, ENV_SIGN]
        ))
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            keys = json.load(fh)
    else:
        keys = make_keys(node_id)
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(keys, fh, indent=2)
        try:
            os.chmod(path, 0o600)  # no-op on windows acls
        except OSError:
            pass
        print("wrote new keys to %s (private keys are unencrypted on disk)" % path)
    missing = [k for k in ("node_id", "pubkey", "privkey", "verify_key", "signkey") if not keys.get(k)]
    if missing:
        raise SystemExit("keyfile %s is missing: %s" % (path, ", ".join(missing)))
    return keys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m pygrid.node",
        description="run a nycc grid node. private keys come from --keyfile or env, never argv.",
    )
    ap.add_argument("--coordinator", required=True, help="coordinator base url")
    ap.add_argument("--engine", required=True, help="local engine base url (loopback only)")
    ap.add_argument("--keyfile", help="json keyfile; generated if absent")
    ap.add_argument("--node-id", help="node id for a freshly generated keyfile")
    ap.add_argument("--wattage", type=float, default=0.0,
                    help="watts to claim when nothing local can be measured")
    ap.add_argument("--neighborhood", default=DEFAULT_NEIGHBORHOOD,
                    help="lowercase, 32 chars: letters, digits, space, - and '. "
                         "published to anyone who lists nodes, so say as little as you like")
    ap.add_argument("--interval", type=float, default=POLL_S)
    ap.add_argument("--once", action="store_true", help="one pass, then exit")
    args = ap.parse_args(argv)

    if not valid_neighborhood(args.neighborhood):
        raise SystemExit(
            "bad --neighborhood %r: lowercase a-z0-9, space, - and ', 1 to 32 chars"
            % (args.neighborhood,)
        )

    keys = load_keys(args.keyfile, args.node_id)
    agent = NodeAgent(
        coordinator_url=args.coordinator,
        engine_url=args.engine,
        node_id=keys["node_id"],
        box_pub_b64=keys["pubkey"],
        box_prv_b64=keys["privkey"],
        verify_b64=keys["verify_key"],
        sign_b64=keys["signkey"],
        wattage=args.wattage,
        neighborhood=args.neighborhood,
    )
    print("node %s -> %s (engine %s)" % (agent.node_id, agent.coordinator_url, agent.engine_url))
    print("%.1fw %s, %s" % (agent.wattage, agent.watts_source, agent.neighborhood))
    if args.once:
        print("ran %d jobs" % agent.run_once())
        return 0
    try:
        agent.run_forever(args.interval)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
