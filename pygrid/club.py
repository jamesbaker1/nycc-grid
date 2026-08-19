"""member certificates: the club signs a card, the member signs requests with the key in it.

a card on the wire is a two field document:

    {"card": {"issued": ..., "member": ..., "member_verify_key": ..., "serial": ...},
     "sig": base64 ed25519 signature by the CLUB signing key}

the signed bytes are exactly

    json.dumps(card, sort_keys=True, separators=(",", ":")).encode("utf-8")

over the card with no "sig" in it. that is the only canonicalization in this file, and
the coordinator repeats it in javascript. it is deliberately not the request signing
string: requests are signed over the raw body bytes, cards are signed over canonical
json, and the two never meet.

what a card proves: the club's ed25519 key signed this member name together with this
member verify key, and the request carrying it was signed by that member key.

what it does not prove: that the name belongs to a real person, that the card and member
key were not copied off a member's laptop, or anything at all when the coordinator has no
club verify key configured. in that case submission is open to anyone and a card is
decoration.

stdlib plus pynacl. no external deps.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

from . import crypto

# where `python -m pygrid.club init` puts the club keypair. same directory as the node
# keyfile, and just as unencrypted: see the README.
DEFAULT_CLUB_KEYS = os.path.join(os.path.expanduser("~"), ".nycc", "club.keys.json")

MEMBER_MAX = 64
# what issue() writes and check_card() requires. a card the club signs later with more
# fields on it still verifies: they are inside the signature, so only the club can add
# one, and refusing unknown fields would make every future field a flag day.
CARD_FIELDS = ("issued", "member", "member_verify_key", "serial")

# headers a carded request carries, lowercased for dict lookups against a received
# request. the spelling lives in crypto.py with every other header name, so a verifier
# here and a signer there cannot drift apart.
CARD_HEADER = crypto.CARD_HEADER.lower()
MEMBER_TS_HEADER = crypto.MEMBER_TIMESTAMP_HEADER.lower()
MEMBER_NONCE_HEADER = crypto.MEMBER_NONCE_HEADER.lower()
MEMBER_SIG_HEADER = crypto.MEMBER_SIGNATURE_HEADER.lower()

# machine readable failure codes, the same strings coordinator/src/logic.js answers 403
# with. the code is the contract; the prose beside it is not.
ERR_CARD_REQUIRED = "card_required"
ERR_CARD_MALFORMED = "card_malformed"  # not a card shaped document at all
ERR_CARD_INVALID = "card_invalid"  # right shape, a field the club would never sign
ERR_CARD_NOT_SIGNED = "card_not_signed_by_club"
ERR_MEMBER_SIG_MISSING = "member_sig_missing"
ERR_MEMBER_SIG_MALFORMED = "member_sig_malformed"
ERR_MEMBER_SIG_EXPIRED = "member_sig_expired"
ERR_MEMBER_SIG_INVALID = "member_sig_invalid"
ERR_MEMBER_SIG_REPLAY = "member_sig_replay"

# the header value cap the worker applies before it decodes anything.
MAX_CARD_HEADER = 8 * 1024
# javascript cannot represent an integer past this exactly, so neither can a serial.
MAX_SAFE_INT = 2 ** 53 - 1
# character for character the coordinator's ISSUED_RE, prefix matched the same way: an
# iso8601 date, optionally followed by a time. loose on purpose, because a date alone is
# iso8601 and so is a full timestamp with an offset. this only has to reject junk, the
# club signature decides everything that matters. keep it identical to logic.js: a card
# accepted by one side and refused by the other is the bug this pair exists to prevent.
ISSUED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?")

# card art. one background, one dot, text. see render_svg().
CARD_W = 856
CARD_H = 540
INK = "#EDE6DA"
GROUND = "#0E0C0A"
ORANGE = "#FF4E00"
FADE = "#8E8472"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

__all__ = [
    "DEFAULT_CLUB_KEYS",
    "CARD_HEADER",
    "MEMBER_TS_HEADER",
    "MEMBER_NONCE_HEADER",
    "MEMBER_SIG_HEADER",
    "MEMBER_MAX",
    "CARD_FIELDS",
    "MAX_CARD_HEADER",
    "ERR_CARD_REQUIRED",
    "ERR_CARD_MALFORMED",
    "ERR_CARD_INVALID",
    "ERR_CARD_NOT_SIGNED",
    "ERR_MEMBER_SIG_MISSING",
    "ERR_MEMBER_SIG_MALFORMED",
    "ERR_MEMBER_SIG_EXPIRED",
    "ERR_MEMBER_SIG_INVALID",
    "ERR_MEMBER_SIG_REPLAY",
    "card_bytes",
    "issue",
    "verify_card",
    "check_card",
    "fingerprint",
    "fingerprint_lines",
    "encode_card_header",
    "decode_card_header",
    "club_keygen",
    "init_club_keys",
    "load_club_keys",
    "make_member_keys",
    "load_member_keys",
    "load_card",
    "save_card",
    "render_svg",
    "main",
]


# ---------------------------------------------------------------- canonical bytes


def card_bytes(card: dict) -> bytes:
    """the exact bytes the club key signs: the card without its signature, canonical json.

    crypto.canonical_json is the one implementation of that rule; receipts sign the same
    way. ascii escaped, because python's json.dumps escapes non ascii and javascript's
    JSON.stringify does not. issue() refuses non ascii member names for that reason, so
    both sides produce the same bytes for every card this tool writes.
    """
    return crypto.canonical_json({k: v for k, v in card.items() if k != "sig"})


def _is_verify_key(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(base64.b64decode(value.encode("ascii"), validate=True)) == crypto.KEY_BYTES
    except Exception:
        return False


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def issue(
    club_sign_b64: str,
    member: str,
    member_verify_b64: str,
    issued: str | None = None,
    serial: int | None = None,
) -> dict:
    """sign a card. serial defaults to unix seconds, issued to now in iso8601 utc.

    an accent in a name is fine: both canonicalizers escape non ascii to \\uXXXX, so the
    bytes agree. control characters are refused, because a name is printed on a card and
    echoed into terminals, and a newline in it is nobody's real name.
    """
    if not isinstance(member, str) or not 1 <= len(member) <= MEMBER_MAX:
        raise ValueError("member must be 1..%d characters" % MEMBER_MAX)
    if not member.isprintable():
        raise ValueError("member must be printable: no control characters, no newlines")
    if not _is_verify_key(member_verify_b64):
        raise ValueError("member_verify_key must be 32 base64 bytes")
    card = {
        "issued": issued or _iso_now(),
        "member": member,
        "member_verify_key": member_verify_b64,
        "serial": int(time.time()) if serial is None else int(serial),
    }
    return {"card": card, "sig": crypto.b64e(crypto.sign(club_sign_b64, card_bytes(card)))}


def check_card(club_verify_b64: str, doc: object) -> str | None:
    """None when the document is a well formed card the club really signed, else the
    error code the coordinator would answer with. never raises.

    the checks and the codes are the same ones logic.js applies, in the same order, so a
    card that passes here passes there. unknown fields are allowed through: they are
    inside the signature, so only the club can have put them on, and refusing them would
    make every future card field a flag day.
    """
    if not isinstance(doc, dict):
        return ERR_CARD_MALFORMED
    card = doc.get("card")
    sig_b64 = doc.get("sig")
    if not isinstance(card, dict) or not isinstance(sig_b64, str) or not sig_b64:
        return ERR_CARD_MALFORMED
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
    except Exception:
        return ERR_CARD_MALFORMED

    member = card.get("member")
    if not isinstance(member, str) or not 1 <= len(member) <= MEMBER_MAX:
        return ERR_CARD_INVALID
    if not _is_verify_key(card.get("member_verify_key")):
        return ERR_CARD_INVALID
    issued = card.get("issued")
    if not isinstance(issued, str) or len(issued) > 64 or not ISSUED_RE.match(issued):
        return ERR_CARD_INVALID
    serial = card.get("serial")
    if not isinstance(serial, int) or isinstance(serial, bool) or abs(serial) > MAX_SAFE_INT:
        return ERR_CARD_INVALID

    if not crypto.verify(club_verify_b64, card_bytes(card), sig):
        return ERR_CARD_NOT_SIGNED
    return None


def verify_card(club_verify_b64: str, doc: object) -> bool:
    """true only for a card this club key signed. wraps check_card for callers that do
    not care which way it failed."""
    return check_card(club_verify_b64, doc) is None


def fingerprint(verify_b64: str) -> str:
    """sha256 of the RAW verify key bytes, uppercase hex, in groups of four.

    64 hex characters is exactly sixteen groups, which the printed card lays out as four
    rows of four. this is a display aid for reading a key aloud, not an identity: the
    whole digest is here, so comparing two of them is comparing two sha256 values.
    """
    return " ".join(_fingerprint_groups(verify_b64))


def fingerprint_lines(verify_b64: str, per_line: int = 4) -> list[str]:
    """fingerprint() as rows of `per_line` groups. four rows of four by default."""
    groups = _fingerprint_groups(verify_b64)
    return [" ".join(groups[i:i + per_line]) for i in range(0, len(groups), per_line)]


def _fingerprint_groups(verify_b64: str) -> list[str]:
    raw = base64.b64decode((verify_b64 or "").encode("ascii"), validate=False)
    digest = hashlib.sha256(raw).hexdigest().upper()
    return [digest[i:i + 4] for i in range(0, len(digest), 4)]


# ------------------------------------------------------------------ header codec


def encode_card_header(doc: dict) -> str:
    """the value of x-nycc-card: base64 of the utf-8 json card document.

    base64 because a header value cannot carry raw json newlines or non ascii, and the
    document travels beside a signature over the request body, not inside it.
    """
    return crypto.b64e(crypto.canonical_json(doc))


def decode_card_header(value: str) -> dict | None:
    """None for anything that is not base64 of a json object. never raises.

    the length cap comes before the decode, same as the worker: an unauthenticated
    header should not buy a megabyte of json parsing.
    """
    if not isinstance(value, str) or not value or len(value) > MAX_CARD_HEADER:
        return None
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        doc = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return doc if isinstance(doc, dict) else None


# --------------------------------------------------------------------- keyfiles


def club_keygen() -> tuple[str, str]:
    """(verify_b64, sign_b64) for the club root key. one per club, kept by whoever
    issues cards."""
    return crypto.sign_keygen()


def _write_json(path: str, payload: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
    try:
        os.chmod(path, 0o600)  # no-op on windows acls
    except OSError:
        pass


def init_club_keys(path: str = DEFAULT_CLUB_KEYS) -> dict:
    """generate the club keypair. refuses to overwrite: overwriting invalidates every
    card ever issued, and there is no revocation list to undo it with."""
    if os.path.exists(path):
        raise FileExistsError(
            "%s already exists. issuing keys are not regenerated: a new club key "
            "invalidates every card already issued" % path
        )
    verify_b64, sign_b64 = club_keygen()
    keys = {"created": _iso_now(), "signkey": sign_b64, "verify_key": verify_b64}
    _write_json(path, keys)
    return keys


def load_club_keys(path: str = DEFAULT_CLUB_KEYS) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        keys = json.load(fh)
    if not isinstance(keys, dict) or not keys.get("signkey") or not keys.get("verify_key"):
        raise ValueError("%s is not a club keyfile (needs signkey and verify_key)" % path)
    return keys


def make_member_keys(member: str) -> dict:
    verify_b64, sign_b64 = crypto.sign_keygen()
    return {
        "created": _iso_now(),
        "member": member,
        "signkey": sign_b64,
        "verify_key": verify_b64,
    }


def load_member_keys(path: str) -> dict:
    """the member half of a card: the ed25519 key the card names, unencrypted on disk."""
    with open(path, "r", encoding="utf-8") as fh:
        keys = json.load(fh)
    if not isinstance(keys, dict) or not keys.get("signkey"):
        raise ValueError("%s is not a member keyfile (needs signkey)" % path)
    return keys


def load_card(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or "card" not in doc or "sig" not in doc:
        raise ValueError("%s is not a card document (needs card and sig)" % path)
    return doc


def save_card(path: str, doc: dict) -> None:
    _write_json(path, doc)


# ------------------------------------------------------------------------- card art


def _esc(text: object) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_svg(doc: dict) -> str:
    """a printable membership card. no decoration beyond one dot: the card is a name, a
    number, a date, and a key fingerprint, and everything else would be a costume.

    this renders whatever is in the document. it does not verify the signature, so a
    forged card draws exactly as well as a real one. verification is the coordinator's
    job, and `show` prints the local answer.
    """
    card = doc.get("card") if isinstance(doc, dict) else None
    if not isinstance(card, dict):
        raise ValueError("not a card document")
    member = _esc(card.get("member", ""))
    serial = _esc(card.get("serial", ""))
    issued = _esc(str(card.get("issued", ""))[:10])
    rows = fingerprint_lines(str(card.get("member_verify_key", "")))

    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" '
        'width="%d" height="%d" role="img" aria-label="new york compute club membership card">'
        % (CARD_W, CARD_H, CARD_W, CARD_H),
        '<rect width="%d" height="%d" fill="%s"/>' % (CARD_W, CARD_H, GROUND),
        '<circle cx="792" cy="86" r="14" fill="%s"/>' % ORANGE,
        '<g font-family="%s" fill="%s">' % (_esc(MONO), INK),
        '<text x="56" y="94" font-size="24" letter-spacing="6">NEW YORK COMPUTE CLUB</text>',
        '<text x="56" y="300" font-size="42">%s</text>' % member,
        '<text x="56" y="348" font-size="18">no. %s</text>' % serial,
        '<text x="56" y="378" font-size="18">issued %s</text>' % issued,
        "</g>",
        '<g font-family="%s" fill="%s" font-size="15" letter-spacing="1">' % (_esc(MONO), FADE),
    ]
    y = 442
    for row in rows:
        lines.append('<text x="56" y="%d">%s</text>' % (y, _esc(row)))
        y += 22
    lines.append("</g>")
    lines.append("</svg>")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------ cli


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pygrid.club",
        description="issue and inspect nycc membership cards",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="generate the club keypair, once")
    p_init.add_argument("--keys", default=DEFAULT_CLUB_KEYS, help="club keyfile path")

    p_issue = sub.add_parser("issue", help="sign a card for a member")
    p_issue.add_argument("--member", required=True, help="member name, printable ascii")
    p_issue.add_argument("--member-key", help="the member's ed25519 verify key, base64")
    p_issue.add_argument(
        "--member-keygen",
        action="store_true",
        help="generate the member keypair too and write member.keys.json next to the card",
    )
    p_issue.add_argument("--out", required=True, help="where to write card.json")
    p_issue.add_argument("--keys", default=DEFAULT_CLUB_KEYS, help="club keyfile path")

    p_show = sub.add_parser("show", help="print what a card says")
    p_show.add_argument("card", help="path to card.json")
    p_show.add_argument("--keys", default=DEFAULT_CLUB_KEYS, help="club keyfile to check against")

    p_svg = sub.add_parser("svg", help="render the printable card")
    p_svg.add_argument("card", help="path to card.json")
    p_svg.add_argument("--out", required=True, help="where to write card.svg")
    return parser


def _cmd_init(args: argparse.Namespace) -> int:
    try:
        keys = init_club_keys(args.keys)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("wrote %s (the signing key is unencrypted on disk)" % args.keys)
    print("club verify key: %s" % keys["verify_key"])
    print("set CLUB_VERIFY_KEY to that value in the coordinator to gate job submission")
    return 0


def _cmd_issue(args: argparse.Namespace) -> int:
    if not args.member_key and not args.member_keygen:
        print("give --member-key, or --member-keygen to make one", file=sys.stderr)
        return 2
    club = load_club_keys(args.keys)

    member_keys = None
    member_verify = args.member_key
    if args.member_keygen:
        member_keys = make_member_keys(args.member)
        member_verify = member_keys["verify_key"]

    doc = issue(club["signkey"], args.member, member_verify)
    save_card(args.out, doc)
    print("wrote %s" % args.out)

    if member_keys is not None:
        side = os.path.join(os.path.dirname(os.path.abspath(args.out)), "member.keys.json")
        _write_json(side, member_keys)
        print("wrote %s (unencrypted member signing key: it is the card)" % side)

    print("serial no. %d" % doc["card"]["serial"])
    print("fingerprint %s" % fingerprint(member_verify))
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    doc = load_card(args.card)
    card = doc["card"]
    print("member      %s" % card.get("member"))
    print("serial      no. %s" % card.get("serial"))
    print("issued      %s" % card.get("issued"))
    print("fingerprint %s" % fingerprint(str(card.get("member_verify_key", ""))))
    if os.path.exists(args.keys):
        verdict = "ok" if verify_card(load_club_keys(args.keys)["verify_key"], doc) else "DOES NOT VERIFY"
        print("club sig    %s (against %s)" % (verdict, args.keys))
    else:
        print("club sig    unchecked, no club keyfile at %s" % args.keys)
    return 0


def _cmd_svg(args: argparse.Namespace) -> int:
    doc = load_card(args.card)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render_svg(doc))
    print("wrote %s" % args.out)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "issue":
        return _cmd_issue(args)
    if args.command == "show":
        return _cmd_show(args)
    if args.command == "svg":
        return _cmd_svg(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
