"""wire dataclasses shared by node, client, and the coordinator's json.

nothing here is secret: NodeInfo is what GET /v1/nodes publishes to anyone, and
JobEnvelope carries ciphertext plus routing metadata.

there is no liveness helper here on purpose. the coordinator owns that rule and
publishes the answer as the `alive` field on each GET /v1/nodes record, which is what
client.pick_node() reads. recomputing it here would need the unit of last_seen, and
that is not one unit: the deployed worker stores Date.now() milliseconds while
testkit's MockCoordinator stores unix seconds. consume `alive`.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Type, TypeVar

# job status is strictly monotonic: queued -> running -> (done | failed).
JOB_STATUSES = ("queued", "running", "done", "failed")
TERMINAL_STATUSES = ("done", "failed")

# how often node.py heartbeats. the coordinator calls a node stale after three missed
# ones (logic.js STALE_MS); it applies that rule itself, see the module docstring.
HEARTBEAT_S = 30.0

# where a watts number came from. "measured" means a meter answered on the node
# (pygrid.watts), "claimed" means an operator typed it in. neither is attested: a
# hostile node can send either string. it is provenance, not proof.
WATTS_SOURCES = ("claimed", "measured")
DEFAULT_WATTS_SOURCE = "claimed"

# a node that does not say where it is.
DEFAULT_NEIGHBORHOOD = "undisclosed"

# the coordinator's rule, ported: ^[a-z0-9][a-z0-9 \-']{0,31}$ . \Z rather than $
# because python's $ also matches before a trailing newline and javascript's does not,
# and a value that passes here must pass there. self reported and never verified: this
# bounds the character set, it does not mean the node is in that neighborhood.
NEIGHBORHOOD_RE = re.compile(r"^[a-z0-9][a-z0-9 \-']{0,31}\Z")

T = TypeVar("T", bound="_Serde")

__all__ = [
    "JOB_STATUSES",
    "TERMINAL_STATUSES",
    "HEARTBEAT_S",
    "WATTS_SOURCES",
    "DEFAULT_WATTS_SOURCE",
    "DEFAULT_NEIGHBORHOOD",
    "NEIGHBORHOOD_RE",
    "valid_neighborhood",
    "NodeInfo",
    "JobEnvelope",
    "to_json",
    "from_json",
]


def valid_neighborhood(value: object) -> bool:
    """true for a string the coordinator will accept in a register body.

    checked client side only so a typo fails at the cli instead of as a 400 halfway
    through a node start. the coordinator re-checks; this is convenience, not control.
    """
    return isinstance(value, str) and NEIGHBORHOOD_RE.match(value) is not None


def _req(data: Mapping[str, Any], key: str) -> Any:
    if key not in data:
        raise ValueError("missing field: %s" % key)
    return data[key]


class _Serde:
    """json helpers. from_dict ignores unknown keys, because the coordinator adds
    fields (GET /v1/nodes appends alive) that the dataclass does not model."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[call-overload]

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls: Type[T], data: str | bytes | Mapping[str, Any]) -> T:
        if isinstance(data, (str, bytes, bytearray)):
            data = json.loads(data)
        if not isinstance(data, Mapping):
            raise ValueError("expected a json object")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls: Type[T], data: Mapping[str, Any]) -> T:
        raise NotImplementedError


@dataclass
class NodeInfo(_Serde):
    """one GET /v1/nodes record, minus the coordinator-computed `alive` flag.

    last_seen carries whatever unit the coordinator wrote (milliseconds from the
    deployed worker), so it is a display and ordering value here, not something to
    compare against local time. read `alive` off the raw record for liveness.

    wattage, watts_source and neighborhood are all reported by the node itself and are
    not attested by anything. the defaults are what a v1 record looks like read by v2
    code: a node that registered before v2 said neither, so it reads back as claimed
    watts from an undisclosed neighborhood.
    """

    node_id: str
    pubkey: str
    verify_key: str
    wattage: float = 0.0
    last_seen: float = 0.0
    watts_source: str = DEFAULT_WATTS_SOURCE
    neighborhood: str = DEFAULT_NEIGHBORHOOD

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NodeInfo":
        return cls(
            node_id=str(_req(data, "node_id")),
            pubkey=str(_req(data, "pubkey")),
            verify_key=str(_req(data, "verify_key")),
            wattage=float(data.get("wattage") or 0.0),
            last_seen=float(data.get("last_seen") or 0.0),
            watts_source=str(data.get("watts_source") or DEFAULT_WATTS_SOURCE),
            neighborhood=str(data.get("neighborhood") or DEFAULT_NEIGHBORHOOD),
        )


@dataclass
class JobEnvelope(_Serde):
    job_id: str
    to_node: str
    blob_b64: str
    reply_pubkey: str
    status: str = "queued"

    def __post_init__(self) -> None:
        if self.status not in JOB_STATUSES:
            raise ValueError("bad status: %r" % (self.status,))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "JobEnvelope":
        return cls(
            job_id=str(_req(data, "job_id")),
            to_node=str(_req(data, "to_node")),
            blob_b64=str(_req(data, "blob_b64")),
            reply_pubkey=str(_req(data, "reply_pubkey")),
            status=str(data.get("status") or "queued"),
        )


def to_json(obj: Any) -> str:
    """serialize a dataclass from this module, or any json-able value."""
    if isinstance(obj, _Serde):
        return obj.to_json()
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def from_json(cls: Type[T], data: str | bytes | Mapping[str, Any]) -> T:
    """from_json(NodeInfo, text) for callers that prefer a free function."""
    return cls.from_json(data)
