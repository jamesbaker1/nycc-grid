"""sealed boxes for payloads, ed25519 for signed coordinator requests.

sealed box = crypto_box_seal (X25519 + XSalsa20-Poly1305). anonymous: the recipient
learns nothing about the sender, and there is no sender authentication.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any
from urllib.parse import urlsplit

from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

# every signed request is bound to this domain string plus the coordinator host, so a
# signature captured from one deployment cannot be replayed against another deployment
# that shares node keys.
#
# v2 keeps the v1 domain on purpose. the canonical string did not change: member
# signatures reuse it byte for byte and differ only in which headers carry the result.
SIGN_DOMAIN = "nycc-grid-v1"

NONCE_BYTES = 16
# the worker rejects timestamps skewed more than this from its own clock.
MAX_SKEW_S = 300

KEY_BYTES = 32
SIG_BYTES = 64

# node request signature, v1.
NODE_ID_HEADER = "X-NYCC-Node-Id"
TIMESTAMP_HEADER = "X-NYCC-Timestamp"
NONCE_HEADER = "X-NYCC-Nonce"
SIGNATURE_HEADER = "X-NYCC-Signature"

# member (club card) request signature, v2. a different set of header names over the
# SAME canonical string, so a node signature and a member signature can ride on one
# request without either one shadowing the other.
CARD_HEADER = "X-NYCC-Card"
MEMBER_TIMESTAMP_HEADER = "X-NYCC-Member-Ts"
MEMBER_NONCE_HEADER = "X-NYCC-Member-Nonce"
MEMBER_SIGNATURE_HEADER = "X-NYCC-Member-Sig"

__all__ = [
    "SIGN_DOMAIN",
    "NONCE_BYTES",
    "MAX_SKEW_S",
    "NODE_ID_HEADER",
    "TIMESTAMP_HEADER",
    "NONCE_HEADER",
    "SIGNATURE_HEADER",
    "CARD_HEADER",
    "MEMBER_TIMESTAMP_HEADER",
    "MEMBER_NONCE_HEADER",
    "MEMBER_SIGNATURE_HEADER",
    "keygen",
    "seal",
    "unseal",
    "sign_keygen",
    "sign",
    "verify",
    "new_nonce",
    "canonical_json",
    "signing_message",
    "signed_headers",
    "member_signed_headers",
    "split_target",
    "b64e",
    "b64d",
]


def b64e(raw: bytes) -> str:
    """standard base64 with padding; the worker decodes with atob."""
    return base64.b64encode(bytes(raw)).decode("ascii")


def b64d(text: str | bytes) -> bytes:
    if isinstance(text, bytes):
        return base64.b64decode(text, validate=True)
    return base64.b64decode(text.encode("ascii"), validate=True)


_b64e = b64e
_b64d = b64d


# ---------------------------------------------------------------- sealed boxes


def keygen() -> tuple[str, str]:
    """new curve25519 keypair. returns (pub_b64, prv_b64)."""
    prv = PrivateKey.generate()
    return _b64e(bytes(prv.public_key)), _b64e(bytes(prv))


def seal(pub_b64: str, data: bytes) -> bytes:
    """seal data to a curve25519 public key. output is longer than the input and
    differs on every call (fresh ephemeral sender key)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("seal() takes bytes")
    return SealedBox(PublicKey(_b64d(pub_b64))).encrypt(bytes(data))


def unseal(prv_b64: str, pub_b64: str, blob: bytes) -> bytes:
    """open a sealed box.

    pub_b64 is the public half of prv_b64; it is not needed to decrypt (sealed boxes
    carry the ephemeral sender key) and is checked only to catch caller mixups.
    raises nacl.exceptions.CryptoError on a wrong key or tampered ciphertext.
    """
    prv = PrivateKey(_b64d(prv_b64))
    if pub_b64:
        if _b64d(pub_b64) != bytes(prv.public_key):
            raise ValueError("unseal(): pub_b64 is not the public half of prv_b64")
    return SealedBox(prv).decrypt(bytes(blob))


# ---------------------------------------------------------------- signatures


def sign_keygen() -> tuple[str, str]:
    """new ed25519 keypair. returns (verify_b64, sign_b64); sign_b64 is the 32 byte seed."""
    sk = SigningKey.generate()
    return _b64e(bytes(sk.verify_key)), _b64e(bytes(sk))


def sign(sign_b64: str, data: bytes) -> bytes:
    """detached 64 byte ed25519 signature over data."""
    return SigningKey(_b64d(sign_b64)).sign(bytes(data)).signature


def verify(verify_b64: str, data: bytes, sig: bytes) -> bool:
    """true only for a good signature. malformed, truncated, forged, or wrong-key
    inputs return False; this never raises. the worker must agree on this."""
    try:
        VerifyKey(_b64d(verify_b64)).verify(bytes(data), bytes(sig))
        return True
    except Exception:
        return False


# ------------------------------------------------- signed request canonical form


def new_nonce() -> str:
    """16 csprng bytes, base64."""
    return _b64e(os.urandom(NONCE_BYTES))


def canonical_json(doc: Any) -> bytes:
    """the one byte string a signed json document is signed over.

    sorted keys, no whitespace, utf-8, and every integral float written as an int. used
    by member cards (pygrid.club) and job receipts (pygrid.node), so a verifier that can
    rebuild the dict can rebuild the signed bytes without keeping the original
    serialization around.

    the integral float rule is the one that is not obvious. these documents cross into
    javascript: the coordinator JSON.parses a body and JSON.stringifies it back out, and
    javascript has a single number type, so 65.0 and 65 are the same value and
    JSON.stringify prints "65" for both. python would print "65.0", the two canonical
    byte strings would differ, and the node's signature over a receipt with integral
    watts would fail to verify on the client after the round trip. collapsing here makes
    both sides agree, and it covers any float a future card carries too, since the
    coordinator re-canonicalizes cards in javascript.

    non-integral floats are left alone. the only ones in this protocol come from
    round(x, 1) watts, whose shortest repr is the same string in python and javascript.

    this is for documents that are re-serialized by whoever verifies them. request
    bodies are never canonicalized: those sign the raw bytes on the wire, see
    signing_message().
    """
    return json.dumps(_js_numbers(doc), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _js_numbers(doc: Any) -> Any:
    """the document with every integral float replaced by the int javascript prints.

    bools are not touched: bool is an int subclass, not a float. see canonical_json.
    """
    if isinstance(doc, float) and doc.is_integer():
        return int(doc)
    if isinstance(doc, dict):
        return {k: _js_numbers(v) for k, v in doc.items()}
    if isinstance(doc, (list, tuple)):
        return [_js_numbers(v) for v in doc]
    return doc


def signing_message(
    host: str,
    method: str,
    path: str,
    timestamp: int | str,
    nonce: str,
    body: bytes = b"",
) -> bytes:
    """the exact byte string every signed request signs.

    "nycc-grid-v1|" + host + "\\n" + METHOD + "\\n" + path?query + "\\n" +
    timestamp + "\\n" + nonce + "\\n" + raw body bytes.

    path carries the query string, so /v1/jobs/pull?node_id=X cannot be re-targeted.
    body is the raw bytes on the wire: never re-serialize or canonicalize json.
    """
    head = "{domain}|{host}\n{method}\n{path}\n{ts}\n{nonce}\n".format(
        domain=SIGN_DOMAIN,
        host=host,
        method=method.upper(),
        path=path,
        ts=timestamp,
        nonce=nonce,
    )
    return head.encode("utf-8") + bytes(body or b"")


def split_target(url: str) -> tuple[str, str]:
    """(host, path-with-query) for a full url, matching what the worker sees in the
    Host header and request url. host keeps the port when there is one."""
    parts = urlsplit(url)
    host = parts.netloc.lower()
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    return host, path


def _request_signature(
    sign_b64: str,
    url: str,
    method: str,
    body: bytes = b"",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> tuple[str, str, str]:
    """(timestamp, nonce, signature_b64) over the canonical string for url.

    the single place a request signature is produced. node signing and member signing
    both come through here, so there is one canonicalization in the grid and adding a
    third signer cannot quietly invent a second one.
    """
    host, path = split_target(url)
    ts = str(int(time.time()) if timestamp is None else int(timestamp))
    nce = new_nonce() if nonce is None else nonce
    msg = signing_message(host, method, path, ts, nce, body)
    return ts, nce, _b64e(sign(sign_b64, msg))


def signed_headers(
    node_id: str,
    sign_b64: str,
    url: str,
    method: str,
    body: bytes = b"",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """the four X-NYCC-* headers for a node-signed request to url."""
    ts, nce, sig = _request_signature(sign_b64, url, method, body, timestamp, nonce)
    return {
        NODE_ID_HEADER: node_id,
        TIMESTAMP_HEADER: ts,
        NONCE_HEADER: nce,
        SIGNATURE_HEADER: sig,
    }


def member_signed_headers(
    sign_b64: str,
    url: str,
    method: str,
    body: bytes = b"",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """the three X-NYCC-Member-* headers for a card-holding client.

    identical bytes to signed_headers() for the same key, url, body, timestamp and
    nonce: only the header names differ. the member identity is not in the signed
    string, it comes from the card in X-NYCC-Card, whose member_verify_key is the key
    the coordinator checks this signature against.
    """
    ts, nce, sig = _request_signature(sign_b64, url, method, body, timestamp, nonce)
    return {
        MEMBER_TIMESTAMP_HEADER: ts,
        MEMBER_NONCE_HEADER: nce,
        MEMBER_SIGNATURE_HEADER: sig,
    }
