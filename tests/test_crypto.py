import base64
import json

import pytest
from nacl.exceptions import CryptoError

from pygrid import crypto


def test_keygen_shapes():
    pub, prv = crypto.keygen()
    assert pub != prv
    assert len(base64.b64decode(pub)) == crypto.KEY_BYTES
    assert len(base64.b64decode(prv)) == crypto.KEY_BYTES
    assert crypto.keygen()[0] != pub


def test_seal_unseal_roundtrip():
    pub, prv = crypto.keygen()
    msg = b"pooled gpus, unpooled trust"
    blob = crypto.seal(pub, msg)
    assert msg not in blob
    assert len(blob) > len(msg)
    assert crypto.unseal(prv, pub, blob) == msg


def test_seal_is_nondeterministic():
    pub, prv = crypto.keygen()
    a = crypto.seal(pub, b"same plaintext")
    b = crypto.seal(pub, b"same plaintext")
    assert a != b
    assert crypto.unseal(prv, pub, a) == crypto.unseal(prv, pub, b)


def test_unseal_wrong_key_fails():
    pub, _ = crypto.keygen()
    other_pub, other_prv = crypto.keygen()
    blob = crypto.seal(pub, b"not for you")
    with pytest.raises(CryptoError):
        crypto.unseal(other_prv, other_pub, blob)


def test_unseal_tampered_ciphertext_fails():
    pub, prv = crypto.keygen()
    blob = bytearray(crypto.seal(pub, b"integrity please"))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        crypto.unseal(prv, pub, bytes(blob))


def test_unseal_truncated_ciphertext_fails():
    pub, prv = crypto.keygen()
    blob = crypto.seal(pub, b"integrity please")
    with pytest.raises(CryptoError):
        crypto.unseal(prv, pub, blob[:-4])


def test_unseal_rejects_mismatched_pub():
    pub, prv = crypto.keygen()
    other_pub, _ = crypto.keygen()
    blob = crypto.seal(pub, b"hello")
    with pytest.raises(ValueError):
        crypto.unseal(prv, other_pub, blob)


def test_sign_verify_roundtrip():
    verify_b64, sign_b64 = crypto.sign_keygen()
    data = b"POST\n/v1/jobs/result\n"
    sig = crypto.sign(sign_b64, data)
    assert len(sig) == crypto.SIG_BYTES
    assert crypto.verify(verify_b64, data, sig) is True


def test_verify_rejects_tampered_data():
    verify_b64, sign_b64 = crypto.sign_keygen()
    sig = crypto.sign(sign_b64, b"wattage=100")
    assert crypto.verify(verify_b64, b"wattage=101", sig) is False


def test_verify_rejects_wrong_key():
    verify_b64, sign_b64 = crypto.sign_keygen()
    other_verify, _ = crypto.sign_keygen()
    sig = crypto.sign(sign_b64, b"payload")
    assert crypto.verify(other_verify, b"payload", sig) is False


def test_verify_rejects_forged_signature():
    verify_b64, _ = crypto.sign_keygen()
    assert crypto.verify(verify_b64, b"payload", b"\x00" * crypto.SIG_BYTES) is False


@pytest.mark.parametrize(
    "sig",
    [b"", b"\x00" * 63, b"\x00" * 65, "not bytes", None, 42],
)
def test_verify_never_raises_on_bad_signature(sig):
    verify_b64, sign_b64 = crypto.sign_keygen()
    assert crypto.verify(verify_b64, b"payload", sig) is False


@pytest.mark.parametrize(
    "key",
    ["", "!!!not base64!!!", base64.b64encode(b"short").decode(), None, 7],
)
def test_verify_never_raises_on_bad_verify_key(key):
    _, sign_b64 = crypto.sign_keygen()
    sig = crypto.sign(sign_b64, b"payload")
    assert crypto.verify(key, b"payload", sig) is False


def test_signing_message_is_the_pinned_byte_string():
    msg = crypto.signing_message(
        "grid.example.com", "post", "/v1/jobs/pull?node_id=a", 1700000000, "bm9uY2U=", b'{"a":1}'
    )
    assert msg == (
        b"nycc-grid-v1|grid.example.com\n"
        b"POST\n"
        b"/v1/jobs/pull?node_id=a\n"
        b"1700000000\n"
        b"bm9uY2U=\n"
        b'{"a":1}'
    )


def test_signing_message_empty_body_for_get():
    msg = crypto.signing_message("h", "GET", "/v1/nodes", "1", "n")
    assert msg.endswith(b"\n1\nn\n")


def test_signing_message_binds_host_method_path_and_body():
    base = dict(host="h", method="GET", path="/p", timestamp="1", nonce="n", body=b"b")
    ref = crypto.signing_message(**base)
    for field, value in [
        ("host", "h2"),
        ("method", "POST"),
        ("path", "/p?x=1"),
        ("timestamp", "2"),
        ("nonce", "n2"),
        ("body", b"b2"),
    ]:
        assert crypto.signing_message(**{**base, field: value}) != ref


def test_split_target():
    assert crypto.split_target("http://127.0.0.1:8787/v1/jobs/pull?node_id=x") == (
        "127.0.0.1:8787",
        "/v1/jobs/pull?node_id=x",
    )
    assert crypto.split_target("https://Grid.Example.COM/v1/nodes") == (
        "grid.example.com",
        "/v1/nodes",
    )
    assert crypto.split_target("https://grid.example.com")[1] == "/"


def test_new_nonce_is_random_and_16_bytes():
    a, b = crypto.new_nonce(), crypto.new_nonce()
    assert a != b
    assert len(base64.b64decode(a)) == crypto.NONCE_BYTES


def test_signed_headers_verify_against_the_canonical_message():
    verify_b64, sign_b64 = crypto.sign_keygen()
    url = "http://127.0.0.1:9/v1/jobs/result"
    body = b'{"job_id":"j1","blob_b64":"AA=="}'
    headers = crypto.signed_headers("node-1", sign_b64, url, "POST", body)
    assert headers["X-NYCC-Node-Id"] == "node-1"
    host, path = crypto.split_target(url)
    msg = crypto.signing_message(
        host, "POST", path, headers["X-NYCC-Timestamp"], headers["X-NYCC-Nonce"], body
    )
    sig = base64.b64decode(headers["X-NYCC-Signature"])
    assert crypto.verify(verify_b64, msg, sig) is True
    # a verifier that drops the query string or the body must fail
    assert crypto.verify(verify_b64, msg[:-1], sig) is False


def test_signed_headers_nonce_is_fresh_per_request():
    _, sign_b64 = crypto.sign_keygen()
    url = "http://127.0.0.1:9/v1/nodes/heartbeat"
    one = crypto.signed_headers("n", sign_b64, url, "POST", b"{}")
    two = crypto.signed_headers("n", sign_b64, url, "POST", b"{}")
    assert one["X-NYCC-Nonce"] != two["X-NYCC-Nonce"]
    assert one["X-NYCC-Signature"] != two["X-NYCC-Signature"]


# ---------------------------------------------------- canonical json documents


def test_canonical_json_is_sorted_compact_utf8():
    raw = crypto.canonical_json({"b": 1, "a": "x", "c": [1, 2]})
    assert raw == b'{"a":"x","b":1,"c":[1,2]}'
    assert isinstance(raw, bytes)


def test_canonical_json_ignores_key_insertion_order():
    # the whole point: a verifier rebuilds the dict from json and gets the same bytes
    doc = {"serial": 7, "member": "j. baker", "issued": "2026-08-19T00:00:00Z"}
    shuffled = {k: doc[k] for k in reversed(list(doc))}
    assert crypto.canonical_json(doc) == crypto.canonical_json(shuffled)
    assert crypto.canonical_json(json.loads(json.dumps(doc, indent=4))) == crypto.canonical_json(doc)


def test_canonical_json_signature_survives_a_json_roundtrip():
    # a receipt is signed by the node, serialized, stored by the coordinator, and
    # re-parsed by the client. the signature has to survive all of that.
    verify_b64, sign_b64 = crypto.sign_keygen()
    receipt = {
        "job_id": "j1",
        "node_id": "node-gowanus",
        "duration_ms": 812,
        "watts": 65.0,
        "watts_source": "claimed",
        "request_sha256": "aa" * 32,
        "result_sha256": "bb" * 32,
    }
    sig = crypto.sign(sign_b64, crypto.canonical_json(receipt))
    reparsed = json.loads(json.dumps({"receipt": receipt, "sig": crypto.b64e(sig)}))
    assert crypto.verify(
        verify_b64, crypto.canonical_json(reparsed["receipt"]), crypto.b64d(reparsed["sig"])
    ) is True


def test_canonical_json_writes_an_integral_float_as_an_int():
    """javascript has one number type, so JSON.stringify(65.0) is "65". the coordinator
    re-serializes every document it forwards, so the two languages have to agree on these
    bytes or a receipt with integral watts stops verifying in production."""
    assert crypto.canonical_json({"watts": 65.0}) == crypto.canonical_json({"watts": 65})
    assert crypto.canonical_json({"watts": 65.0}) == b'{"watts":65}'
    # nested, because a card or a receipt is not always flat
    assert crypto.canonical_json({"a": [1.0, {"b": -2.0}]}) == b'{"a":[1,{"b":-2}]}'
    # a fraction is left alone: round(x, 1) prints the same shortest repr on both sides
    assert crypto.canonical_json({"watts": 65.4}) == b'{"watts":65.4}'
    # bool is an int subclass, not a float, and must stay true rather than become 1
    assert crypto.canonical_json({"ok": True}) == b'{"ok":true}'


def test_canonical_json_signature_breaks_on_any_edit():
    verify_b64, sign_b64 = crypto.sign_keygen()
    receipt = {"job_id": "j1", "watts": 65.0, "duration_ms": 812}
    sig = crypto.sign(sign_b64, crypto.canonical_json(receipt))
    for field, value in [("watts", 5.0), ("duration_ms", 811), ("job_id", "j2")]:
        tampered = dict(receipt, **{field: value})
        assert crypto.verify(verify_b64, crypto.canonical_json(tampered), sig) is False


# ------------------------------------------------------ member (card) signatures


def test_member_headers_are_the_same_bytes_as_node_headers():
    # one canonicalization in the grid. same key, same request, same timestamp and
    # nonce: the signature must be identical and only the header names differ.
    _, sign_b64 = crypto.sign_keygen()
    url = "http://127.0.0.1:9/v1/jobs"
    body = b'{"to_node":"node-1"}'
    node = crypto.signed_headers("node-1", sign_b64, url, "POST", body, timestamp=1700000000, nonce="bm9uY2U=")
    member = crypto.member_signed_headers(sign_b64, url, "POST", body, timestamp=1700000000, nonce="bm9uY2U=")
    assert member["X-NYCC-Member-Sig"] == node["X-NYCC-Signature"]
    assert member["X-NYCC-Member-Ts"] == node["X-NYCC-Timestamp"] == "1700000000"
    assert member["X-NYCC-Member-Nonce"] == node["X-NYCC-Nonce"] == "bm9uY2U="


def test_member_headers_carry_no_node_id():
    # the member identity is in the card, not in the signed string and not in a header
    # the coordinator would otherwise have to trust.
    _, sign_b64 = crypto.sign_keygen()
    headers = crypto.member_signed_headers(sign_b64, "http://h/v1/jobs", "POST", b"{}")
    assert set(headers) == {"X-NYCC-Member-Ts", "X-NYCC-Member-Nonce", "X-NYCC-Member-Sig"}


def test_member_signature_verifies_against_the_canonical_message():
    verify_b64, sign_b64 = crypto.sign_keygen()
    url = "http://127.0.0.1:9/v1/jobs"
    body = b'{"to_node":"node-1","blob_b64":"AA=="}'
    headers = crypto.member_signed_headers(sign_b64, url, "POST", body)
    host, path = crypto.split_target(url)
    msg = crypto.signing_message(
        host, "POST", path, headers["X-NYCC-Member-Ts"], headers["X-NYCC-Member-Nonce"], body
    )
    sig = base64.b64decode(headers["X-NYCC-Member-Sig"])
    assert crypto.verify(verify_b64, msg, sig) is True
    # a coordinator that verified the wrong body, or the wrong member key, must fail
    assert crypto.verify(verify_b64, msg[:-1], sig) is False
    other_verify, _ = crypto.sign_keygen()
    assert crypto.verify(other_verify, msg, sig) is False


def test_member_nonce_is_fresh_per_request():
    _, sign_b64 = crypto.sign_keygen()
    one = crypto.member_signed_headers(sign_b64, "http://h/v1/jobs", "POST", b"{}")
    two = crypto.member_signed_headers(sign_b64, "http://h/v1/jobs", "POST", b"{}")
    assert one["X-NYCC-Member-Nonce"] != two["X-NYCC-Member-Nonce"]
    assert one["X-NYCC-Member-Sig"] != two["X-NYCC-Member-Sig"]


def test_header_names_are_pinned_constants():
    # the worker reads these lowercase; changing either side alone breaks submission
    assert crypto.NODE_ID_HEADER == "X-NYCC-Node-Id"
    assert crypto.TIMESTAMP_HEADER == "X-NYCC-Timestamp"
    assert crypto.NONCE_HEADER == "X-NYCC-Nonce"
    assert crypto.SIGNATURE_HEADER == "X-NYCC-Signature"
    assert crypto.CARD_HEADER == "X-NYCC-Card"
    assert crypto.MEMBER_TIMESTAMP_HEADER == "X-NYCC-Member-Ts"
    assert crypto.MEMBER_NONCE_HEADER == "X-NYCC-Member-Nonce"
    assert crypto.MEMBER_SIGNATURE_HEADER == "X-NYCC-Member-Sig"


def test_v2_did_not_fork_the_signing_domain():
    # v2 extends the deployed v1. a new domain string would 401 every deployed node.
    assert crypto.SIGN_DOMAIN == "nycc-grid-v1"
    assert crypto.signing_message("h", "GET", "/v1/nodes", "1", "n").startswith(b"nycc-grid-v1|")
