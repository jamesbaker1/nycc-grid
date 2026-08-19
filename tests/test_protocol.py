import json

import pytest

from pygrid import protocol
from pygrid.protocol import JobEnvelope, NodeInfo


def _node():
    return NodeInfo(
        node_id="node-1",
        pubkey="cHVi",
        verify_key="dmVy",
        wattage=310.5,
        last_seen=1700000000.0,
        watts_source="measured",
        neighborhood="gowanus",
    )


def _job():
    return JobEnvelope(
        job_id="8f14e45fea3f4b6d9b2c1a0e7d3c5b21",
        to_node="node-1",
        blob_b64="Y2lwaGVydGV4dA==",
        reply_pubkey="cmVwbHk=",
        status="queued",
    )


def test_nodeinfo_roundtrip():
    node = _node()
    text = node.to_json()
    assert isinstance(text, str)
    assert NodeInfo.from_json(text) == node


def test_jobenvelope_roundtrip():
    job = _job()
    assert JobEnvelope.from_json(job.to_json()) == job


def test_roundtrip_through_bytes_and_dict():
    job = _job()
    assert JobEnvelope.from_json(job.to_json().encode("utf-8")) == job
    assert JobEnvelope.from_json(job.to_dict()) == job


def test_module_level_helpers():
    node = _node()
    assert protocol.from_json(NodeInfo, protocol.to_json(node)) == node
    assert json.loads(protocol.to_json({"b": 1, "a": 2})) == {"a": 2, "b": 1}


def test_to_dict_keys_are_the_wire_field_names():
    assert set(_node().to_dict()) == {
        "node_id",
        "pubkey",
        "verify_key",
        "wattage",
        "last_seen",
        "watts_source",
        "neighborhood",
    }
    assert set(_job().to_dict()) == {
        "job_id",
        "to_node",
        "blob_b64",
        "reply_pubkey",
        "status",
    }


def test_from_dict_ignores_unknown_fields():
    # GET /v1/nodes appends alive, and the coordinator adds lease/attempts to jobs.
    node = NodeInfo.from_json(dict(_node().to_dict(), alive=True))
    assert node == _node()
    job = JobEnvelope.from_json(
        dict(_job().to_dict(), lease_until=123, attempts=2, created_ms=5)
    )
    assert job == _job()


def test_from_dict_coerces_numbers_and_defaults():
    node = NodeInfo.from_json(
        {"node_id": "n", "pubkey": "p", "verify_key": "v", "wattage": "250"}
    )
    assert node.wattage == 250.0
    assert node.last_seen == 0.0
    # a v1 record: it said neither, so it reads as claimed watts, place unstated
    assert node.watts_source == "claimed"
    assert node.neighborhood == "undisclosed"
    job = JobEnvelope.from_json(
        {"job_id": "j", "to_node": "n", "blob_b64": "", "reply_pubkey": "r"}
    )
    assert job.status == "queued"


def test_missing_required_field_is_a_value_error():
    with pytest.raises(ValueError):
        NodeInfo.from_json({"node_id": "n", "pubkey": "p"})
    with pytest.raises(ValueError):
        JobEnvelope.from_json({"job_id": "j", "to_node": "n", "blob_b64": "b"})


def test_from_json_rejects_non_objects():
    with pytest.raises(ValueError):
        NodeInfo.from_json("[1, 2]")


@pytest.mark.parametrize("status", protocol.JOB_STATUSES)
def test_every_status_in_the_enum_is_accepted(status):
    assert JobEnvelope.from_json(dict(_job().to_dict(), status=status)).status == status


def test_failed_is_a_terminal_status():
    assert "failed" in protocol.JOB_STATUSES
    assert set(protocol.TERMINAL_STATUSES) == {"done", "failed"}


@pytest.mark.parametrize("status", ["", "QUEUED", "pending", "cancelled"])
def test_unknown_status_is_rejected(status):
    with pytest.raises(ValueError):
        JobEnvelope(
            job_id="j", to_node="n", blob_b64="b", reply_pubkey="r", status=status
        )


def test_heartbeat_interval_matches_the_coordinator():
    # logic.js: HEARTBEAT_S = 30, STALE_MS = 3 * HEARTBEAT_S * 1000. node.py heartbeats
    # on this constant, so drifting it apart from the worker makes nodes read stale.
    assert protocol.HEARTBEAT_S == 30.0


def test_watts_source_is_read_off_the_record():
    node = NodeInfo.from_json(
        {"node_id": "n", "pubkey": "p", "verify_key": "v", "wattage": 65.0,
         "watts_source": "measured", "neighborhood": "bed-stuy"}
    )
    assert node.watts_source == "measured"
    assert node.neighborhood == "bed-stuy"
    assert set(protocol.WATTS_SOURCES) == {"claimed", "measured"}
    assert protocol.DEFAULT_WATTS_SOURCE == "claimed"
    assert protocol.DEFAULT_NEIGHBORHOOD == "undisclosed"


def test_watts_source_is_provenance_not_proof():
    # nothing attests either string. a node can send "measured" over a made up number,
    # so NodeInfo takes whatever the record says instead of pretending to validate it.
    node = NodeInfo.from_json(
        {"node_id": "n", "pubkey": "p", "verify_key": "v", "watts_source": "vibes"}
    )
    assert node.watts_source == "vibes"


@pytest.mark.parametrize(
    "value",
    ["gowanus", "bed-stuy", "hell's kitchen", "long island city", "undisclosed",
     "11201", "a", "a" * 32],
)
def test_neighborhoods_the_coordinator_accepts(value):
    assert protocol.valid_neighborhood(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",                     # empty
        "Gowanus",              # uppercase
        " gowanus",             # leading space
        "-gowanus",             # leading punctuation
        "'gowanus",
        "a" * 33,               # one over the cap
        "red_hook",             # underscore is not in the class
        "greenpoint\n",         # python's $ would let this through, \Z does not
        "gowanus\nbrooklyn",
        "c\u00f4te",            # non-ascii
        "node:1",
        None,
        42,
    ],
)
def test_neighborhoods_the_coordinator_rejects(value):
    assert protocol.valid_neighborhood(value) is False


def test_neighborhood_rule_is_the_coordinators_rule_verbatim():
    # ported from logic.js. drifting them apart means a node that starts clean locally
    # and 400s at register time.
    assert protocol.NEIGHBORHOOD_RE.pattern == r"^[a-z0-9][a-z0-9 \-']{0,31}\Z"


def test_no_local_liveness_rule():
    # liveness is the coordinator's to compute and it ships as the `alive` field. a
    # helper here would have to guess the unit of last_seen (worker: ms, testkit: s).
    assert not hasattr(protocol, "is_alive")
    assert not hasattr(NodeInfo, "is_alive")
    assert "alive" not in NodeInfo.__dataclass_fields__
