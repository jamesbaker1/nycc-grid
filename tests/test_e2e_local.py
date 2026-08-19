"""end to end on loopback: mock coordinator + mock engine + real NodeAgent + real GridClient.

choreography is deliberately synchronous. NodeAgent.run_once() is driven from the test
thread, so there is no polling node loop and no sleeps; by the time result() is called the
result is already stored. a background node thread would be flaky by construction.

v2 adds three things to this file: the member certificate gate, which only bites when the
mock coordinator is given a club verify key, signed job receipts, and the public stats
counters. the plaintext canary assertions from v1 still run on the carded path, because a
membership check is not an excuse to start trusting the middle.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.request

import pytest

from pygrid import club, crypto
from pygrid.client import CoordinatorError, GridClient, JobFailed
from pygrid.node import NodeAgent
from pygrid.testkit import MAX_ATTEMPTS, MAX_QUEUED_PER_NODE, MockCoordinator, MockEngine

# distinctive enough that finding it anywhere in a recorded body means a real leak
PROMPT = "nycc-plaintext-canary hudson yards diesel generator poem"


def _http(method: str, url: str, payload: dict | None = None,
          headers: dict | None = None) -> tuple[int, dict]:
    """raw call that returns the status instead of raising, for coordinator edge cases."""
    data = None
    hdrs = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}


def _register(
    coord: MockCoordinator,
    node_id: str,
    wattage: float = 100.0,
    neighborhood: str | None = None,
    watts_source: str | None = None,
) -> tuple[str, str]:
    pub, prv = crypto.keygen()
    verify_b64, _sign_b64 = crypto.sign_keygen()
    body = {"node_id": node_id, "pubkey": pub, "verify_key": verify_b64, "wattage": wattage}
    if neighborhood is not None:
        body["neighborhood"] = neighborhood
    if watts_source is not None:
        body["watts_source"] = watts_source
    status, _doc = _http(
        "POST", coord.url + "/v1/nodes/register", body, {"X-NYCC-Node-Id": node_id}
    )
    assert status == 200
    return pub, prv


@pytest.fixture
def coord():
    server = MockCoordinator()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def engine():
    server = MockEngine()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _agent(coord: MockCoordinator, engine: MockEngine, node_id: str = "node-gowanus",
           wattage: float = 210.0) -> NodeAgent:
    box_pub, box_prv = crypto.keygen()
    verify_b64, sign_b64 = crypto.sign_keygen()
    return NodeAgent(
        coord.url, engine.url, node_id, box_pub, box_prv, verify_b64, sign_b64, wattage=wattage
    )


def test_end_to_end_local_loop(coord, engine):
    agent = _agent(coord, engine)

    # first run registers and finds nothing to do
    assert agent.run_once() == 0
    assert "node-gowanus" in coord.nodes

    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=8)

    queued = client.status(job_id)
    assert queued["status"] == "queued"
    assert "blob_b64" not in queued, "queued status must never expose the job ciphertext"

    assert agent.run_once() == 1

    text = client.result(job_id, timeout=5)
    assert text == "echo: " + PROMPT

    # the engine is the one place plaintext legitimately exists
    assert engine.prompts == [PROMPT]

    # the coordinator saw ciphertext and routing metadata only
    assert coord.saw(job_id), "sanity: the recorder can find a string that really was sent"
    assert not coord.saw(PROMPT), "plaintext prompt reached the coordinator"
    assert not coord.saw("echo: " + PROMPT), "plaintext result reached the coordinator"


def test_result_blob_is_sealed_to_the_reply_key_only(coord, engine):
    agent = _agent(coord, engine)
    agent.run_once()
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=4)
    agent.run_once()

    stored = base64.b64decode(client.status(job_id)["blob_b64"])
    assert PROMPT.encode("utf-8") not in stored

    wrong_pub, wrong_prv = crypto.keygen()
    with pytest.raises(Exception):
        crypto.unseal(wrong_prv, wrong_pub, stored)


def test_auto_pick_takes_the_lowest_wattage_alive_node(coord, engine):
    _register(coord, "node-hot", wattage=900.0)
    quiet_pub, _quiet_prv = _register(coord, "node-quiet", wattage=45.0)
    _register(coord, "node-dead", wattage=1.0)
    coord.set_last_seen("node-dead", 0.0)  # stale, must not be picked despite 1 watt

    client = GridClient(coord.url)
    picked = client.pick_node()
    assert picked["node_id"] == "node-quiet"
    assert picked["pubkey"] == quiet_pub

    job_id = client.submit(PROMPT)
    assert coord.jobs[job_id]["to_node"] == "node-quiet"


def test_explicit_to_node_overrides_auto_pick(coord):
    _register(coord, "node-quiet", wattage=45.0)
    _register(coord, "node-hot", wattage=900.0)
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, to_node="node-hot")
    assert coord.jobs[job_id]["to_node"] == "node-hot"

    with pytest.raises(RuntimeError, match="not registered"):
        client.submit(PROMPT, to_node="node-that-never-was")


def test_submit_without_alive_nodes_is_an_error(coord):
    client = GridClient(coord.url)
    with pytest.raises(RuntimeError, match="no alive nodes"):
        client.submit(PROMPT)


def test_result_needs_the_ephemeral_reply_key_from_this_process(coord, engine):
    agent = _agent(coord, engine)
    agent.run_once()
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=4)
    agent.run_once()

    stranger = GridClient(coord.url)
    with pytest.raises(KeyError):
        stranger.result(job_id, timeout=1)


def test_result_times_out_while_still_queued(coord):
    _register(coord, "node-quiet", wattage=10.0)
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT)
    with pytest.raises(TimeoutError):
        client.result(job_id, timeout=0.2)


def test_failed_jobs_surface_as_JobFailed(coord):
    _register(coord, "node-quiet", wattage=10.0)
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT)
    coord.jobs[job_id]["status"] = "failed"
    with pytest.raises(JobFailed):
        client.result(job_id, timeout=1)


def test_idempotency_key_returns_the_same_job(coord):
    _register(coord, "node-quiet")
    client = GridClient(coord.url)
    first = client.submit(PROMPT, idempotency_key="retry-me")
    second = client.submit(PROMPT, idempotency_key="retry-me")
    assert first == second
    assert len(coord.jobs) == 1


def test_pull_and_heartbeat_404_for_unknown_nodes(coord):
    status, _doc = _http("GET", coord.url + "/v1/jobs/pull?node_id=ghost")
    assert status == 404
    status, _doc = _http("POST", coord.url + "/v1/nodes/heartbeat",
                         {"node_id": "ghost", "wattage": 1.0})
    assert status == 404


def test_lease_expiry_redelivers_then_fails_terminally(coord):
    _register(coord, "node-quiet")
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT)
    url = coord.url + "/v1/jobs/pull?node_id=node-quiet"

    for attempt in range(1, MAX_ATTEMPTS + 1):
        status, doc = _http("GET", url)
        assert status == 200
        assert [j["job_id"] for j in doc["jobs"]] == [job_id], f"attempt {attempt}"
        assert coord.jobs[job_id]["attempts"] == attempt
        coord.expire_lease(job_id)

    status, doc = _http("GET", url)
    assert doc["jobs"] == []
    assert client.status(job_id)["status"] == "failed"


def test_result_ownership_and_monotonic_transitions(coord):
    _register(coord, "node-quiet")
    _register(coord, "node-thief")
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT)
    result_url = coord.url + "/v1/jobs/result"

    # queued, never pulled: nothing to post a result against
    status, _doc = _http("POST", result_url, {"job_id": job_id, "blob_b64": "AAAA"},
                         {"X-NYCC-Node-Id": "node-quiet"})
    assert status == 409

    _http("GET", coord.url + "/v1/jobs/pull?node_id=node-quiet")

    status, _doc = _http("POST", result_url, {"job_id": job_id, "blob_b64": "dGhpZWY="},
                         {"X-NYCC-Node-Id": "node-thief"})
    assert status == 403

    status, _doc = _http("POST", result_url, {"job_id": job_id, "blob_b64": "Zmlyc3Q="},
                         {"X-NYCC-Node-Id": "node-quiet"})
    assert status == 200

    # first result wins; a retry after a lost response must not overwrite
    status, doc = _http("POST", result_url, {"job_id": job_id, "blob_b64": "c2Vjb25k"},
                        {"X-NYCC-Node-Id": "node-quiet"})
    assert status == 200
    assert doc["duplicate"] is True
    assert coord.jobs[job_id]["blob_b64"] != "Zmlyc3Q="
    assert client.status(job_id) == {"status": "done", "blob_b64": "Zmlyc3Q="}

    # done is terminal: a replayed pull must not drag it back to running
    status, doc = _http("GET", coord.url + "/v1/jobs/pull?node_id=node-quiet")
    assert doc["jobs"] == []
    assert coord.jobs[job_id]["status"] == "done"


def test_size_and_queue_caps(coord):
    _register(coord, "node-quiet")
    status, _doc = _http("POST", coord.url + "/v1/jobs",
                         {"to_node": "node-quiet", "blob_b64": "A" * (1024 * 1024 + 1),
                          "reply_pubkey": "x"})
    assert status == 413

    with coord.lock:
        for i in range(MAX_QUEUED_PER_NODE):
            coord.jobs[f"filler-{i}"] = {
                "job_id": f"filler-{i}", "to_node": "node-quiet", "blob_b64": "AAAA",
                "reply_pubkey": "x", "status": "queued", "result_b64": None,
                "lease_until_ms": 0, "attempts": 0, "created_ms": 0, "seq": coord._next_seq(),
            }
    status, _doc = _http("POST", coord.url + "/v1/jobs",
                         {"to_node": "node-quiet", "blob_b64": "AAAA", "reply_pubkey": "x"})
    assert status == 429


def test_pull_is_capped_and_oldest_first(coord, engine):
    agent = _agent(coord, engine, node_id="node-busy")
    agent.run_once()
    client = GridClient(coord.url)
    job_ids = [client.submit(f"{PROMPT} {i}", max_tokens=2) for i in range(12)]

    status, doc = _http("GET", coord.url + "/v1/jobs/pull?node_id=node-busy")
    assert status == 200
    assert [j["job_id"] for j in doc["jobs"]] == job_ids[:10]
    assert set(doc["jobs"][0]) == {"job_id", "to_node", "blob_b64", "reply_pubkey", "status"}


# ------------------------------------------------------- v2: member certificates


@pytest.fixture
def carded(tmp_path):
    """a club key, a member key the club signed, and the two files a client reads.

    the member keyfile is exactly what `python -m pygrid.club issue --member-keygen`
    writes: an unencrypted ed25519 signing key next to the card it belongs to.
    """
    club_keys = club.init_club_keys(str(tmp_path / "club.keys.json"))
    member_keys = club.make_member_keys("james baker")
    card = club.issue(club_keys["signkey"], "james baker", member_keys["verify_key"])
    card_path = str(tmp_path / "card.json")
    keys_path = str(tmp_path / "member.keys.json")
    club.save_card(card_path, card)
    with open(keys_path, "w", encoding="utf-8") as fh:
        json.dump(member_keys, fh)
    return {
        "club_verify_key": club_keys["verify_key"],
        "club_signkey": club_keys["signkey"],
        "card": card,
        "card_path": card_path,
        "member_keys": member_keys,
        "member_keys_path": keys_path,
    }


@pytest.fixture
def gated(carded):
    """a coordinator that was given the club verify key, so submission is members only."""
    server = MockCoordinator(club_verify_key=carded["club_verify_key"])
    server.start()
    try:
        yield server
    finally:
        server.stop()


def _error_code(exc: CoordinatorError) -> str:
    return json.loads(exc.detail).get("code")


def test_gated_submit_without_a_card_is_refused(gated, engine):
    agent = _agent(gated, engine)
    agent.run_once()
    client = GridClient(gated.url)
    with pytest.raises(CoordinatorError) as caught:
        client.submit(PROMPT)
    assert caught.value.status == 403
    assert _error_code(caught.value) == club.ERR_CARD_REQUIRED
    assert gated.jobs == {}


def test_gated_submit_with_a_card_runs_end_to_end(gated, engine, carded):
    agent = _agent(gated, engine)
    agent.run_once()
    client = GridClient(
        gated.url,
        card_path=carded["card_path"],
        member_keys_path=carded["member_keys_path"],
    )
    job_id = client.submit(PROMPT, max_tokens=8)
    assert agent.run_once() == 1
    assert client.result(job_id, timeout=5) == "echo: " + PROMPT

    # the card really rode along, and it rode in a header rather than in the body
    submits = [r for r in gated.requests
               if r["direction"] == "request" and r["path"] == "/v1/jobs"]
    assert submits and club.CARD_HEADER in submits[0]["headers"]

    # a membership check is not a reason to stop checking the canary
    assert not gated.saw(PROMPT), "plaintext prompt reached the coordinator"
    assert not gated.saw("echo: " + PROMPT), "plaintext result reached the coordinator"

    # what the gate does cost: the coordinator now knows which member sent that job
    assert gated.members_seen == ["james baker"]


def test_a_card_from_another_club_is_refused(gated, tmp_path, carded):
    _register(gated, "node-quiet")
    other = club.init_club_keys(str(tmp_path / "other-club.keys.json"))
    forged = club.issue(other["signkey"], "james baker", carded["member_keys"]["verify_key"])
    forged_path = str(tmp_path / "forged.json")
    club.save_card(forged_path, forged)

    client = GridClient(
        gated.url, card_path=forged_path, member_keys_path=carded["member_keys_path"]
    )
    with pytest.raises(CoordinatorError) as caught:
        client.submit(PROMPT)
    assert caught.value.status == 403
    assert _error_code(caught.value) == club.ERR_CARD_NOT_SIGNED


def test_a_card_you_do_not_hold_the_member_key_for_is_refused(gated, tmp_path, carded):
    """a stolen card alone buys nothing: the request signature has to match the key in it."""
    _register(gated, "node-quiet")
    stranger = club.make_member_keys("somebody else")
    stranger_path = str(tmp_path / "stranger.keys.json")
    with open(stranger_path, "w", encoding="utf-8") as fh:
        json.dump(stranger, fh)

    client = GridClient(
        gated.url, card_path=carded["card_path"], member_keys_path=stranger_path
    )
    with pytest.raises(CoordinatorError) as caught:
        client.submit(PROMPT)
    assert caught.value.status == 403
    assert _error_code(caught.value) == club.ERR_MEMBER_SIG_INVALID


def test_an_open_coordinator_ignores_cards(coord, engine, carded):
    """deploy safety: with no club key configured the grid is exactly as open as v1."""
    agent = _agent(coord, engine)
    agent.run_once()
    carded_client = GridClient(
        coord.url,
        card_path=carded["card_path"],
        member_keys_path=carded["member_keys_path"],
    )
    job_id = carded_client.submit(PROMPT, max_tokens=4)
    assert agent.run_once() == 1
    assert carded_client.result(job_id, timeout=5) == "echo: " + PROMPT
    # and so is a client that has never heard of a card
    assert GridClient(coord.url).submit(PROMPT, max_tokens=4)


def _replay(url: str, sent: dict) -> tuple[int, dict]:
    """re-send a recorded request byte for byte, headers and all."""
    headers = {k: v for k, v in sent["headers"].items()
               if k.startswith("x-nycc-") or k == "content-type"}
    req = urllib.request.Request(url, data=sent["body"], method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_replaying_a_carded_submit_is_refused(gated, engine, carded):
    """the card is not a bearer token you can copy off the wire and reuse: the member
    signature carries a nonce, and the nonce is spent."""
    agent = _agent(gated, engine)
    agent.run_once()
    client = GridClient(
        gated.url,
        card_path=carded["card_path"],
        member_keys_path=carded["member_keys_path"],
    )
    client.submit(PROMPT, max_tokens=4)
    sent = [r for r in gated.requests
            if r["direction"] == "request" and r["path"] == "/v1/jobs"][0]

    status, doc = _replay(gated.url + "/v1/jobs", sent)
    assert status == 403
    assert doc["code"] == club.ERR_MEMBER_SIG_REPLAY
    assert len(gated.jobs) == 1, "the replay must not have queued a second job"


def test_the_gate_only_covers_submission(gated, engine, carded):
    """nodes authenticate with node keys, not cards. registering, pulling, heartbeating
    and reading a job status all stay card free."""
    agent = _agent(gated, engine)
    assert agent.run_once() == 0
    client = GridClient(
        gated.url,
        card_path=carded["card_path"],
        member_keys_path=carded["member_keys_path"],
    )
    job_id = client.submit(PROMPT, max_tokens=4)
    # no card anywhere on this call, and it still answers
    status, doc = _http("GET", gated.url + "/v1/jobs/" + job_id)
    assert status == 200 and doc["status"] == "queued"
    assert _http("GET", gated.url + "/v1/nodes")[0] == 200


# ------------------------------------------------------------- v2: job receipts


def _receipt_body(receipt: object) -> dict:
    """the receipt fields, whether the client hands back the inner dict or the whole
    {"receipt": ..., "sig": ...} document."""
    assert isinstance(receipt, dict), f"expected a receipt dict, got {receipt!r}"
    inner = receipt.get("receipt")
    return inner if isinstance(inner, dict) else receipt


def test_receipt_round_trip_verifies(coord, engine):
    agent = _agent(coord, engine, node_id="node-gowanus", wattage=65.0)
    agent.run_once()
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=8)
    job_blob = base64.b64decode(coord.jobs[job_id]["blob_b64"])
    assert agent.run_once() == 1

    text, receipt, verified = client.result_with_receipt(job_id, timeout=5)
    assert text == "echo: " + PROMPT
    assert verified is True

    body = _receipt_body(receipt)
    assert body["job_id"] == job_id
    assert body["node_id"] == "node-gowanus"
    assert isinstance(body["duration_ms"], int) and body["duration_ms"] >= 0
    assert body["started"] <= body["finished"]
    assert body["watts_source"] in ("claimed", "measured")
    if body["watts_source"] == "claimed":
        assert float(body["watts"]) == 65.0
    else:
        assert float(body["watts"]) >= 0.0

    # the hashes bind the receipt to these exact blobs, not to a retelling of them
    assert body["request_sha256"] == hashlib.sha256(job_blob).hexdigest()
    result_blob = base64.b64decode(client.status(job_id)["blob_b64"])
    assert body["result_sha256"] == hashlib.sha256(result_blob).hexdigest()


def test_a_tampered_receipt_does_not_verify(coord, engine):
    agent = _agent(coord, engine, node_id="node-gowanus", wattage=65.0)
    agent.run_once()
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=4)
    agent.run_once()

    with coord.lock:
        coord.jobs[job_id]["receipt"]["receipt"]["watts"] = 0.1

    text, _receipt, verified = client.result_with_receipt(job_id, timeout=5)
    assert verified is False
    # the completion still opens: the receipt is a claim about the run, not the seal
    assert text == "echo: " + PROMPT


def test_a_result_posted_without_a_receipt_still_works(coord):
    """v1 nodes are still nodes. no receipt is reported as missing, not as a failure."""
    _register(coord, "node-quiet")
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=4)

    _status, doc = _http("GET", coord.url + "/v1/jobs/pull?node_id=node-quiet")
    reply_pubkey = doc["jobs"][0]["reply_pubkey"]
    sealed = crypto.seal(reply_pubkey, json.dumps({"text": "no paperwork"}).encode("utf-8"))
    status, _doc = _http(
        "POST",
        coord.url + "/v1/jobs/result",
        {"job_id": job_id, "blob_b64": crypto.b64e(sealed)},
        {"X-NYCC-Node-Id": "node-quiet"},
    )
    assert status == 200
    assert "receipt" not in client.status(job_id)

    text, receipt, verified = client.result_with_receipt(job_id, timeout=5)
    assert text == "no paperwork"
    assert receipt is None
    assert verified is False


def test_an_oversized_receipt_is_refused(coord):
    """the receipt is stored opaquely, so the size cap is the only thing keeping it from
    being free storage hanging off a job record."""
    _register(coord, "node-quiet")
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=4)
    _http("GET", coord.url + "/v1/jobs/pull?node_id=node-quiet")

    status, _doc = _http(
        "POST",
        coord.url + "/v1/jobs/result",
        {"job_id": job_id, "blob_b64": "AAAA", "receipt": {"pad": "x" * 9000}},
        {"X-NYCC-Node-Id": "node-quiet"},
    )
    assert status == 413
    assert coord.jobs[job_id]["status"] == "running", "a refused receipt must not finish the job"


# ----------------------------------------------- v2: neighborhoods and public stats


def test_neighborhood_and_watts_source_are_echoed(coord):
    _register(coord, "node-bedstuy", neighborhood="bed-stuy", watts_source="measured")
    _register(coord, "node-quiet")
    nodes = {n["node_id"]: n for n in GridClient(coord.url).nodes()}
    assert nodes["node-bedstuy"]["neighborhood"] == "bed-stuy"
    assert nodes["node-bedstuy"]["watts_source"] == "measured"
    # a node that says nothing is undisclosed and claimed, never blank
    assert nodes["node-quiet"]["neighborhood"] == "undisclosed"
    assert nodes["node-quiet"]["watts_source"] == "claimed"


@pytest.mark.parametrize("hood", ["hell's kitchen", "long island city", "bed-stuy", "sunset park"])
def test_neighborhoods_the_grammar_allows(coord, hood):
    _register(coord, "node-" + hood.replace(" ", "-").replace("'", ""), neighborhood=hood)


@pytest.mark.parametrize(
    "hood",
    # the trailing newline is the one that matters: python's $ would let it through and
    # the worker's javascript would not, so the mock has to agree with the worker.
    ["Bushwick", " bushwick", "bushwick!", "x" * 33, "", "-bushwick", "bushwick\n"],
)
def test_neighborhoods_the_grammar_refuses(coord, hood):
    pub, _prv = crypto.keygen()
    verify_b64, _sign = crypto.sign_keygen()
    status, _doc = _http(
        "POST",
        coord.url + "/v1/nodes/register",
        {"node_id": "node-bad", "pubkey": pub, "verify_key": verify_b64, "neighborhood": hood},
        {"X-NYCC-Node-Id": "node-bad"},
    )
    assert status == 400
    assert "node-bad" not in coord.nodes


def test_stats_counts_alive_nodes_watts_and_neighborhoods(coord):
    _register(coord, "node-bushwick", wattage=200.0, neighborhood="bushwick",
              watts_source="measured")
    _register(coord, "node-gowanus", wattage=110.0, neighborhood="gowanus")
    _register(coord, "node-ghost", wattage=1000.0, neighborhood="bushwick")
    coord.set_last_seen("node-ghost", 0.0)

    status, doc = _http("GET", coord.url + "/v1/stats")
    assert status == 200
    assert doc["ok"] is True
    assert doc["nodes_alive"] == 2
    assert doc["watts"] == pytest.approx(310.0)
    # the measured number is a strict subset of the claimed total, never the other way
    assert doc["watts_measured"] == pytest.approx(200.0)
    assert doc["jobs_done"] == 0
    assert doc["neighborhoods"] == [
        {"name": "bushwick", "nodes": 1, "watts": 200.0},
        {"name": "gowanus", "nodes": 1, "watts": 110.0},
    ]


def test_stats_jobs_done_counts_accepted_results_once(coord, engine):
    agent = _agent(coord, engine)
    agent.run_once()
    client = GridClient(coord.url)
    job_id = client.submit(PROMPT, max_tokens=4)
    agent.run_once()

    _status, doc = _http("GET", coord.url + "/v1/stats")
    assert doc["jobs_done"] == 1

    # a duplicate post after a lost response must not count twice
    _http("POST", coord.url + "/v1/jobs/result", {"job_id": job_id, "blob_b64": "AAAA"},
          {"X-NYCC-Node-Id": "node-gowanus"})
    _status, doc = _http("GET", coord.url + "/v1/stats")
    assert doc["jobs_done"] == 1
