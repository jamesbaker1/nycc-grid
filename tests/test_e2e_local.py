"""end to end on loopback: mock coordinator + mock engine + real NodeAgent + real GridClient.

choreography is deliberately synchronous. NodeAgent.run_once() is driven from the test
thread, so there is no polling node loop and no sleeps; by the time result() is called the
result is already stored. a background node thread would be flaky by construction.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

import pytest

from pygrid import crypto
from pygrid.client import GridClient, JobFailed
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


def _register(coord: MockCoordinator, node_id: str, wattage: float = 100.0) -> tuple[str, str]:
    pub, prv = crypto.keygen()
    verify_b64, _sign_b64 = crypto.sign_keygen()
    status, _doc = _http(
        "POST",
        coord.url + "/v1/nodes/register",
        {"node_id": node_id, "pubkey": pub, "verify_key": verify_b64, "wattage": wattage},
        {"X-NYCC-Node-Id": node_id},
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
