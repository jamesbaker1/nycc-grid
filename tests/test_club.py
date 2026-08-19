"""member certificates: the canonical bytes, the signature, the keyfiles, the card art.

the byte string in test_card_bytes_is_the_pinned_canonical_form is the contract with the
coordinator's javascript. change it and every card ever issued stops verifying.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import xml.etree.ElementTree as ET

import pytest

from pygrid import club, crypto


@pytest.fixture
def club_keys(tmp_path):
    return club.init_club_keys(str(tmp_path / "club.keys.json"))


@pytest.fixture
def member():
    verify_b64, sign_b64 = crypto.sign_keygen()
    return {"verify_key": verify_b64, "signkey": sign_b64}


# ---------------------------------------------------------------- canonical bytes


def test_card_bytes_is_the_pinned_canonical_form():
    card = {
        "issued": "2026-08-19T00:00:00Z",
        "member": "james baker",
        "member_verify_key": "AAAA",
        "serial": 7,
    }
    assert club.card_bytes(card) == (
        b'{"issued":"2026-08-19T00:00:00Z","member":"james baker",'
        b'"member_verify_key":"AAAA","serial":7}'
    )


def test_card_bytes_sorts_keys_and_drops_the_signature():
    card = {"serial": 1, "member": "a", "issued": "i", "member_verify_key": "k"}
    signed = club.card_bytes(card)
    assert signed == club.card_bytes(dict(card, sig="not part of the message"))
    assert list(json.loads(signed)) == ["issued", "member", "member_verify_key", "serial"]
    assert b", " not in signed and b": " not in signed


# ------------------------------------------------------------------- issue/verify


def test_issue_and_verify_roundtrip(club_keys, member):
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"])
    assert set(doc) == {"card", "sig"}
    assert set(doc["card"]) == set(club.CARD_FIELDS)
    assert doc["card"]["member"] == "james baker"
    assert doc["card"]["member_verify_key"] == member["verify_key"]
    assert club.verify_card(club_keys["verify_key"], doc) is True
    assert club.check_card(club_keys["verify_key"], doc) is None


def test_serial_defaults_to_unix_seconds_and_issued_to_now(club_keys, member):
    before = int(time.time())
    doc = club.issue(club_keys["signkey"], "quiet member", member["verify_key"])
    assert before <= doc["card"]["serial"] <= int(time.time())
    assert doc["card"]["issued"].endswith("Z")
    assert len(doc["card"]["issued"]) == 20


def test_explicit_serial_and_issued_are_kept(club_keys, member):
    doc = club.issue(
        club_keys["signkey"], "m", member["verify_key"], issued="2026-01-02T03:04:05Z", serial=42
    )
    assert doc["card"]["serial"] == 42
    assert doc["card"]["issued"] == "2026-01-02T03:04:05Z"
    assert club.verify_card(club_keys["verify_key"], doc)


def test_another_club_key_does_not_verify(club_keys, member, tmp_path):
    other = club.init_club_keys(str(tmp_path / "other.keys.json"))
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"])
    assert club.check_card(other["verify_key"], doc) == club.ERR_CARD_NOT_SIGNED


@pytest.mark.parametrize("field,value", [("member", "somebody else"), ("serial", 999)])
def test_editing_a_signed_card_breaks_it(club_keys, member, field, value):
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"])
    doc["card"][field] = value
    assert club.check_card(club_keys["verify_key"], doc) == club.ERR_CARD_NOT_SIGNED


def test_swapping_in_your_own_member_key_breaks_it(club_keys, member):
    """the point of the card: a member key the club did not sign is not a member key."""
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"])
    attacker_verify, _attacker_sign = crypto.sign_keygen()
    doc["card"]["member_verify_key"] = attacker_verify
    assert club.check_card(club_keys["verify_key"], doc) == club.ERR_CARD_NOT_SIGNED


@pytest.mark.parametrize(
    "doc",
    [
        None,
        "a card, honest",
        {},
        {"card": {}},
        {"card": "not an object", "sig": "AAAA"},
        {"sig": "AAAA"},
        {"card": {"member": "m"}, "sig": "!!! not base64 !!!"},
    ],
)
def test_malformed_documents_are_rejected_without_raising(club_keys, doc):
    assert club.check_card(club_keys["verify_key"], doc) == club.ERR_CARD_MALFORMED


@pytest.mark.parametrize(
    "field,value",
    [
        ("member", ""),
        ("member", "x" * 65),
        ("member", 7),
        ("member_verify_key", "AAAA"),
        ("issued", "sometime last spring"),
        ("issued", "19/08/2026"),
        ("issued", 20260819),
        ("serial", "42"),
        ("serial", 1.5),
        ("serial", True),
        ("serial", 2 ** 60),
    ],
)
def test_card_shaped_documents_with_impossible_fields(club_keys, member, field, value):
    """right shape, a field the club would never have signed. a distinct code from
    malformed, and the same one logic.js returns."""
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"])
    doc["card"][field] = value
    assert club.check_card(club_keys["verify_key"], doc) == club.ERR_CARD_INVALID


@pytest.mark.parametrize(
    "issued",
    [
        "2026-08-19",
        "2026-08-19T12:00:00+00:00",
        "2026-08-19 12:00",
        "2026-08-19T12:00:00.123456Z",
    ],
)
def test_issued_is_accepted_as_a_date_or_as_a_full_timestamp(club_keys, member, issued):
    """the same four strings logic.js accepts, in the test of the same name. issue() only
    ever writes the full form, but the club can sign any of these by hand, and a card the
    deployed worker admits must not be refused here."""
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"], issued=issued)
    assert club.check_card(club_keys["verify_key"], doc) is None, issued


def test_a_field_the_club_signed_later_still_verifies(club_keys, member):
    """forward compatibility: unknown fields are inside the signature, so only the club
    can add one. bolting one on afterwards breaks the signature, which is the check."""
    card = {
        "issued": "2026-08-19T00:00:00Z",
        "member": "james baker",
        "member_verify_key": member["verify_key"],
        "serial": 5,
        "quota": 1000,
    }
    signed = {"card": card, "sig": crypto.b64e(crypto.sign(club_keys["signkey"],
                                                           club.card_bytes(card)))}
    assert club.check_card(club_keys["verify_key"], signed) is None

    tampered = json.loads(json.dumps(signed))
    tampered["card"]["quota"] = 10 ** 9
    assert club.check_card(club_keys["verify_key"], tampered) == club.ERR_CARD_NOT_SIGNED


@pytest.mark.parametrize("name", ["", "x" * 65, "line\nbreak", "tab\there"])
def test_issue_rejects_names_that_would_not_survive_the_wire(club_keys, member, name):
    with pytest.raises(ValueError):
        club.issue(club_keys["signkey"], name, member["verify_key"])


def test_an_accented_name_is_fine(club_keys, member):
    """both canonicalizers escape non ascii the same way, so this verifies in javascript
    too. the escaping is the reason it is allowed, not an accident."""
    doc = club.issue(club_keys["signkey"], "josé ramírez", member["verify_key"])
    assert club.verify_card(club_keys["verify_key"], doc)
    assert b"jos\\u00e9" in club.card_bytes(doc["card"])


@pytest.mark.parametrize("key", ["", "AAAA", "not base64", None])
def test_issue_rejects_a_bad_member_key(club_keys, key):
    with pytest.raises(ValueError):
        club.issue(club_keys["signkey"], "james baker", key)


# ------------------------------------------------------------------- fingerprint


def test_fingerprint_is_sha256_of_the_raw_key_bytes(member):
    expected = hashlib.sha256(base64.b64decode(member["verify_key"])).hexdigest().upper()
    printed = club.fingerprint(member["verify_key"])
    assert printed.replace(" ", "") == expected
    groups = printed.split(" ")
    assert len(groups) == 16
    assert all(len(g) == 4 for g in groups)


def test_fingerprint_lines_are_four_rows_of_four(member):
    rows = club.fingerprint_lines(member["verify_key"])
    assert len(rows) == 4
    assert all(len(row.split(" ")) == 4 for row in rows)
    assert " ".join(rows) == club.fingerprint(member["verify_key"])


def test_different_keys_have_different_fingerprints():
    a, _ = crypto.sign_keygen()
    b, _ = crypto.sign_keygen()
    assert club.fingerprint(a) != club.fingerprint(b)


# ----------------------------------------------------------------- header codec


def test_card_header_roundtrip(club_keys, member):
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"])
    header = club.encode_card_header(doc)
    assert base64.b64decode(header.encode("ascii"), validate=True)
    assert club.decode_card_header(header) == doc
    assert club.verify_card(club_keys["verify_key"], club.decode_card_header(header))


@pytest.mark.parametrize("value", ["", "!!!", "bm90IGpzb24=", None, base64.b64encode(b"[1,2]").decode()])
def test_decode_card_header_returns_none_for_junk(value):
    assert club.decode_card_header(value) is None


def test_decode_card_header_caps_the_length_before_it_parses():
    fat = base64.b64encode(json.dumps({"card": {"pad": "x" * 20000}}).encode()).decode()
    assert len(fat) > club.MAX_CARD_HEADER
    assert club.decode_card_header(fat) is None


# -------------------------------------------------------------------- keyfiles


def test_init_writes_a_keypair_and_refuses_to_overwrite(tmp_path):
    path = str(tmp_path / "nested" / "club.keys.json")
    keys = club.init_club_keys(path)
    assert len(base64.b64decode(keys["verify_key"])) == crypto.KEY_BYTES
    assert len(base64.b64decode(keys["signkey"])) == crypto.KEY_BYTES
    with pytest.raises(FileExistsError):
        club.init_club_keys(path)
    # the refusal did not touch the file
    assert club.load_club_keys(path) == keys


def test_load_club_keys_rejects_a_file_that_is_not_a_keyfile(tmp_path):
    path = tmp_path / "junk.json"
    path.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(ValueError):
        club.load_club_keys(str(path))


def test_member_keys_shape(tmp_path):
    keys = club.make_member_keys("james baker")
    path = tmp_path / "member.keys.json"
    path.write_text(json.dumps(keys), encoding="utf-8")
    assert club.load_member_keys(str(path))["signkey"] == keys["signkey"]
    assert len(base64.b64decode(keys["verify_key"])) == crypto.KEY_BYTES


def test_card_file_roundtrip(tmp_path, club_keys, member):
    doc = club.issue(club_keys["signkey"], "james baker", member["verify_key"])
    path = str(tmp_path / "card.json")
    club.save_card(path, doc)
    assert club.load_card(path) == doc


def test_load_card_rejects_a_file_that_is_not_a_card(tmp_path):
    path = tmp_path / "nope.json"
    path.write_text('{"card": {}}', encoding="utf-8")
    with pytest.raises(ValueError):
        club.load_card(str(path))


# ------------------------------------------------------------------------- cli


def _run(argv, capsys):
    code = club.main(argv)
    return code, capsys.readouterr().out


def test_cli_init_issue_show_svg(tmp_path, capsys):
    keys_path = str(tmp_path / "club.keys.json")
    card_path = str(tmp_path / "card.json")
    svg_path = str(tmp_path / "card.svg")

    code, out = _run(["init", "--keys", keys_path], capsys)
    assert code == 0
    verify_key = club.load_club_keys(keys_path)["verify_key"]
    assert verify_key in out

    code, out = _run(["init", "--keys", keys_path], capsys)
    assert code == 1, "init must not clobber a club key that already issued cards"

    code, out = _run(
        ["issue", "--member", "james baker", "--member-keygen", "--out", card_path,
         "--keys", keys_path],
        capsys,
    )
    assert code == 0
    doc = club.load_card(card_path)
    assert club.verify_card(verify_key, doc)

    member_keys = club.load_member_keys(str(tmp_path / "member.keys.json"))
    assert member_keys["verify_key"] == doc["card"]["member_verify_key"]
    # the generated member key really is the one the card names
    sig = crypto.sign(member_keys["signkey"], b"probe")
    assert crypto.verify(doc["card"]["member_verify_key"], b"probe", sig)

    code, out = _run(["show", card_path, "--keys", keys_path], capsys)
    assert code == 0
    assert "james baker" in out
    assert "no. %d" % doc["card"]["serial"] in out
    assert doc["card"]["issued"] in out
    assert club.fingerprint(doc["card"]["member_verify_key"]) in out
    assert "ok" in out

    code, out = _run(["svg", card_path, "--out", svg_path], capsys)
    assert code == 0
    assert "NEW YORK COMPUTE CLUB" in open(svg_path, encoding="utf-8").read()


def test_cli_issue_with_an_existing_member_key(tmp_path, capsys, member):
    keys_path = str(tmp_path / "club.keys.json")
    card_path = str(tmp_path / "card.json")
    _run(["init", "--keys", keys_path], capsys)
    code, _out = _run(
        ["issue", "--member", "quiet member", "--member-key", member["verify_key"],
         "--out", card_path, "--keys", keys_path],
        capsys,
    )
    assert code == 0
    assert not (tmp_path / "member.keys.json").exists(), "no keygen, no keyfile"
    doc = club.load_card(card_path)
    assert doc["card"]["member_verify_key"] == member["verify_key"]


def test_cli_issue_refuses_to_clobber_an_existing_member_keyfile(tmp_path, capsys):
    """the keyfile name is fixed, so issuing twice into one directory would destroy the
    first member's signing key, which is the only thing their card can sign with."""
    keys_path = str(tmp_path / "club.keys.json")
    _run(["init", "--keys", keys_path], capsys)
    code, _out = _run(
        ["issue", "--member", "james baker", "--member-keygen",
         "--out", str(tmp_path / "card.json"), "--keys", keys_path],
        capsys,
    )
    assert code == 0
    first = (tmp_path / "member.keys.json").read_text(encoding="utf-8")

    code = club.main(
        ["issue", "--member", "somebody else", "--member-keygen",
         "--out", str(tmp_path / "second.json"), "--keys", keys_path]
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "member.keys.json" in err and "--out" in err
    assert (tmp_path / "member.keys.json").read_text(encoding="utf-8") == first
    # refused before anything was written, so there is no half-made card either
    assert not (tmp_path / "second.json").exists()


def test_cli_issue_needs_a_member_key(tmp_path, capsys):
    keys_path = str(tmp_path / "club.keys.json")
    _run(["init", "--keys", keys_path], capsys)
    assert club.main(["issue", "--member", "m", "--out", str(tmp_path / "c.json"),
                      "--keys", keys_path]) == 2


def test_cli_show_says_when_it_cannot_check(tmp_path, capsys, club_keys, member):
    card_path = str(tmp_path / "card.json")
    club.save_card(card_path, club.issue(club_keys["signkey"], "m", member["verify_key"]))
    code, out = _run(["show", card_path, "--keys", str(tmp_path / "absent.json")], capsys)
    assert code == 0
    assert "unchecked" in out


def test_cli_show_reports_a_card_the_club_did_not_sign(tmp_path, capsys, club_keys, member):
    # club_keys wrote tmp_path/club.keys.json; the card is edited after signing
    card_path = str(tmp_path / "card.json")
    doc = club.issue(club_keys["signkey"], "m", member["verify_key"])
    doc["card"]["member"] = "somebody else"
    club.save_card(card_path, doc)
    code, out = _run(["show", card_path, "--keys", str(tmp_path / "club.keys.json")], capsys)
    assert code == 0
    assert "DOES NOT VERIFY" in out


# ---------------------------------------------------------------------- card art


@pytest.fixture
def rendered(club_keys, member):
    doc = club.issue(
        club_keys["signkey"], "james baker", member["verify_key"], issued="2026-08-19T14:00:00Z",
        serial=1755612000,
    )
    return doc, club.render_svg(doc)


def test_svg_is_well_formed_xml_with_the_pinned_geometry(rendered):
    _doc, svg = rendered
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert root.get("viewBox") == "0 0 856 540"


def test_svg_carries_the_club_palette_and_face(rendered):
    _doc, svg = rendered
    assert club.GROUND in svg and club.INK in svg and club.FADE in svg
    assert "ui-monospace" in svg
    assert ">NEW YORK COMPUTE CLUB<" in svg


def test_svg_has_exactly_one_orange_dot_and_no_other_decoration(rendered):
    _doc, svg = rendered
    root = ET.fromstring(svg)
    circles = [e for e in root.iter() if e.tag.endswith("circle")]
    assert len(circles) == 1
    assert circles[0].get("fill") == club.ORANGE
    rects = [e for e in root.iter() if e.tag.endswith("rect")]
    assert len(rects) == 1 and rects[0].get("fill") == club.GROUND
    for junk in ("<path", "<image", "Gradient", "<filter", "<use", "opacity"):
        assert junk not in svg


def test_svg_says_member_serial_issued_and_fingerprint(rendered):
    doc, svg = rendered
    texts = [(e.text or "") for e in ET.fromstring(svg).iter() if e.tag.endswith("text")]
    assert "james baker" in texts
    assert "no. 1755612000" in texts
    assert "issued 2026-08-19" in texts
    for row in club.fingerprint_lines(doc["card"]["member_verify_key"]):
        assert row in texts


def test_svg_escapes_the_member_name(club_keys, member):
    doc = club.issue(club_keys["signkey"], 'ampersand & <tag>', member["verify_key"])
    svg = club.render_svg(doc)
    assert "<tag>" not in svg
    assert "&amp; &lt;tag&gt;" in svg
    assert ET.fromstring(svg) is not None


def test_render_svg_rejects_something_that_is_not_a_card():
    with pytest.raises(ValueError):
        club.render_svg({"nope": 1})
