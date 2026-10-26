"""Record what the Python panel's secrets code produces, for the Rust `panel-secrets` tests.

Run as root on the lab host, from the repository root, with the panel's Python environment:

    PYTHONPATH=. /root/dev/proxy-control/.venv/bin/python \
        panel/crates/secrets/tests/fixtures/generators/gen_secrets.py panel/crates/secrets/tests/fixtures \
        [--rust-made PATH]

Writes (every key below is test material made up here — no real secret):
- `keyring/*.json`: keyring files written by `Keyring.save` (byte-exact output of `to_json`);
- `keyring-cases.json`: files `Keyring.load` accepts or refuses, with the result or message;
- `golden.sqlite3` + `golden-keyring.json` + `secret-versions.json`: a migrated database whose
  `secret_versions` rows were written by `SecretStore.store` and a partial `rewrap` after a
  rotation (rows under two keys), the keyring that decrypts them, and every row with its AAD and
  plaintext;
- `argon2.json`: PHC strings made by argon2-cffi (random and fixed salts, other parameters,
  invalid strings) with `verify`/`check_needs_rehash` verdicts; with `--rust-made`, the PHC
  strings the Rust crate made (`cargo test -- --ignored print_rust_made_hashes`) and Python's
  verdicts on them;
- `audit.json`: `scrub` + `detail_json` + `digest` of detail dicts, `_forbidden` verdicts and the
  `str.casefold` table for every non-ASCII code point whose fold contains ASCII.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import hash_secret

from panel import audit
from panel.database import Database
from panel.keyring import Key, Keyring, KeyringError
from panel.migrations import apply_migrations
from panel.secrets_store import SecretRef, SecretStore, _aad

MATERIAL_A = bytes(range(32))
MATERIAL_B = bytes(range(32, 64))
MATERIAL_C = bytes(range(64, 96))


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=1, ensure_ascii=False, sort_keys=True) + "\n")


# --- keyring ---------------------------------------------------------------------------------

def keyring_files(out: Path) -> None:
    folder = out / "keyring"
    folder.mkdir(exist_ok=True)
    one = Keyring((Key("k-0a1b2c3d", "active", 1761350400, MATERIAL_A),), "k-0a1b2c3d")
    rotated = Keyring(
        (
            Key("k-11223344", "active", 1761436800, MATERIAL_B),
            Key("k-0a1b2c3d", "retiring", 1761350400, MATERIAL_A),
            Key("k-99aabbcc", "retiring", 1700000000, MATERIAL_C),
        ),
        "k-11223344",
    )
    unicode = Keyring((Key("k-ключ-🙂", "active", 0, MATERIAL_A),), "k-ключ-🙂")
    for name, keyring in (("one-key", one), ("rotated", rotated), ("non-ascii-id", unicode)):
        path = folder / f"{name}.json"
        if path.exists():
            path.unlink()
        keyring.save(path)
        # The file Python wrote reads back to the same keyring.
        loaded = Keyring.load(path)
        assert loaded.active_key_id == keyring.active_key_id and loaded.keys == keyring.keys
        path.chmod(0o644)  # git does not keep 0600; the tests copy the file and set the mode


DEFAULT = object()


def key_item(key_id="k-0a1b2c3d", state="active", created_at=1761350400, material=DEFAULT):
    return {
        "key_id": key_id,
        "state": state,
        "created_at": created_at,
        "key_material": base64.b64encode(MATERIAL_A).decode() if material is DEFAULT else material,
    }


def keyring_text(keys=None, active="k-0a1b2c3d", schema=1, **extra) -> str:
    document = {"schema": schema, "active_key_id": active, "keys": [key_item()] if keys is None else keys}
    document.update(extra)
    return json.dumps(document)


def keyring_cases(out: Path) -> None:
    good = base64.b64encode(MATERIAL_A).decode()
    assert good.endswith("=") and len(good) == 44
    trailing_bits = good[:42] + chr(ord(good[42]) + 1) + "="  # non-zero bits Python ignores
    cases: list[dict] = []

    def add(name, text=None, *, raw=None, mode=0o600, kind="file"):
        cases.append(
            {
                "name": name,
                "kind": kind,
                "mode": mode,
                "content_b64": base64.b64encode(raw if raw is not None else (text or "").encode()).decode(),
            }
        )

    add("valid 0600", keyring_text())
    add("valid 0400", keyring_text(), mode=0o400)
    add("valid 0700 (group/other bits are what counts)", keyring_text(), mode=0o700)
    add("valid 0200", keyring_text(), mode=0o200)
    add("mode 0644", keyring_text(), mode=0o644)
    add("mode 0640", keyring_text(), mode=0o640)
    add("mode 0601", keyring_text(), mode=0o601)
    add("missing", kind="missing")
    add("symlink to a valid file", keyring_text(), kind="symlink")
    add("directory", kind="dir", mode=0o700)
    add("not json", "{not json")
    add("empty file", "")
    add("invalid utf-8", raw=b'{"schema": 1, "x": "\xff"}')
    add("top-level list", "[]")
    add("top-level string", '"keys"')
    add("schema missing", json.dumps({"active_key_id": "k-0a1b2c3d", "keys": [key_item()]}))
    add("schema 2", keyring_text(schema=2))
    add("schema string 1", keyring_text(schema="1"))
    add("schema 1.0", keyring_text(schema=1.0))
    add("schema true", keyring_text(schema=True))
    add("schema null", keyring_text(schema=None))
    add("keys empty list", keyring_text(keys=[]))
    add("keys empty object", keyring_text(keys={}))
    add("keys empty string", keyring_text(keys=""))
    add("keys non-empty string", keyring_text(keys="ab"))
    add("keys non-empty object", keyring_text(keys={"a": 1}))
    add("keys null", json.dumps({"schema": 1, "active_key_id": "k-0a1b2c3d", "keys": None}))
    add("keys number", keyring_text(keys=5))
    add("key item is a list", keyring_text(keys=[[1, 2]]))
    add("key item is a string", keyring_text(keys=["abc"]))
    add("key_id missing", keyring_text(keys=[{k: v for k, v in key_item().items() if k != "key_id"}]))
    add("key_id integer", keyring_text(keys=[key_item(key_id=123)], active="123"))
    add("key_id null", keyring_text(keys=[key_item(key_id=None)], active="None"))
    add("key_id true", keyring_text(keys=[key_item(key_id=True)], active="True"))
    add("key_id float", keyring_text(keys=[key_item(key_id=1.5)], active="1.5"))
    add("active_key_id integer", keyring_text(keys=[key_item(key_id="7")], active=7))
    add("active_key_id missing", json.dumps({"schema": 1, "keys": [key_item()]}))
    add("state missing", keyring_text(keys=[{k: v for k, v in key_item().items() if k != "state"}]))
    add("state revoked", keyring_text(keys=[key_item(state="revoked")]))
    add("state integer", keyring_text(keys=[key_item(state=1)]))
    add("created_at string", keyring_text(keys=[key_item(created_at="123")]))
    add("created_at padded string", keyring_text(keys=[key_item(created_at=" 12 ")]))
    add("created_at underscore string", keyring_text(keys=[key_item(created_at="1_000")]))
    add("created_at float", keyring_text(keys=[key_item(created_at=1.9)]))
    add("created_at negative float", keyring_text(keys=[key_item(created_at=-1.9)]))
    add("created_at true", keyring_text(keys=[key_item(created_at=True)]))
    add("created_at null", keyring_text(keys=[key_item(created_at=None)]))
    add("created_at decimal string", keyring_text(keys=[key_item(created_at="1.5")]))
    add("created_at NaN", keyring_text(keys=[key_item(created_at=float("nan"))]))
    add("material missing", keyring_text(keys=[{k: v for k, v in key_item().items() if k != "key_material"}]))
    add("material not base64", keyring_text(keys=[key_item(material="!!!!")]))
    add("material 31 bytes", keyring_text(keys=[key_item(material=base64.b64encode(MATERIAL_A[:31]).decode())]))
    add("material 33 bytes", keyring_text(keys=[key_item(material=base64.b64encode(bytes(33)).decode())]))
    add("material without padding", keyring_text(keys=[key_item(material=good[:-1])]))
    add("material with extra padding", keyring_text(keys=[key_item(material=good + "=")]))
    add("material with three padding chars", keyring_text(keys=[key_item(material=good + "==")]))
    add("material non-canonical trailing bits", keyring_text(keys=[key_item(material=trailing_bits)]))
    add("material with newline", keyring_text(keys=[key_item(material=good + "\n")]))
    add("material with inner space", keyring_text(keys=[key_item(material=good[:10] + " " + good[10:])]))
    add("material url-safe alphabet", keyring_text(keys=[key_item(material=base64.urlsafe_b64encode(bytes([251] * 32)).decode())]))
    add("material with data after padding", keyring_text(keys=[key_item(material=good[:43] + "=" + "QUJD")]))
    add("material empty string", keyring_text(keys=[key_item(material="")]))
    add("material leading padding", keyring_text(keys=[key_item(material="=" + good[:-1])]))
    add("material 43 data chars and two pads", keyring_text(keys=[key_item(material=good[:43] + "==")]))
    add("material integer", keyring_text(keys=[key_item(material=5)]))
    add("material null", keyring_text(keys=[key_item(material=None)]))
    add("material non-ascii", keyring_text(keys=[key_item(material=good[:-2] + "é=")]))
    add("duplicate key id", keyring_text(keys=[key_item(), key_item(state="retiring")]))
    add("unknown active key id", keyring_text(active="k-ffffffff"))
    add("active key retiring", keyring_text(keys=[key_item(state="retiring")]))
    add(
        "invalid key checked before duplicate and unknown",
        keyring_text(keys=[key_item(), key_item(), key_item(state="nope")], active="k-zzz"),
    )
    add("duplicate checked before unknown", keyring_text(keys=[key_item(), key_item()], active="k-zzz"))
    add(
        "duplicate json member: last wins",
        keyring_text()[:-1] + ', "active_key_id": "k-0a1b2c3d", "active_key_id": "k-other"}',
    )
    add("extra members ignored", keyring_text(extra_member={"x": [1]}))
    add(
        "two keys",
        keyring_text(
            keys=[key_item("k-new", "active", 5, base64.b64encode(MATERIAL_B).decode()), key_item(state="retiring")],
            active="k-new",
        ),
    )
    add("utf-8 bom", raw=b"\xef\xbb\xbf" + keyring_text().encode())
    add("trailing garbage", keyring_text() + " x")
    add("surrounding whitespace", "\n  " + keyring_text() + "\n\n")

    with tempfile.TemporaryDirectory() as tmp:
        for index, case in enumerate(cases):
            folder = Path(tmp) / str(index)
            folder.mkdir()
            path = folder / "master-key"
            if case["kind"] == "file":
                path.write_bytes(base64.b64decode(case["content_b64"]))
                path.chmod(case["mode"])
            elif case["kind"] == "symlink":
                target = folder / "target"
                target.write_bytes(base64.b64decode(case["content_b64"]))
                target.chmod(case["mode"])
                path.symlink_to(target)
            elif case["kind"] == "dir":
                path.mkdir(mode=case["mode"])
            try:
                keyring = Keyring.load(path)
            except KeyringError as exc:
                case["expected"] = {"error": str(exc)}
            except Exception as exc:  # noqa: BLE001 — recorded, not hidden
                case["expected"] = {"exception": type(exc).__name__}
            else:
                case["expected"] = {
                    "active_key_id": keyring.active_key_id,
                    "keys": [[k.key_id, k.state, k.created_at, k.material.hex()] for k in keyring.keys],
                }
    write_json(out / "keyring-cases.json", cases)


# --- secret store ----------------------------------------------------------------------------

def secret_identities():
    grant = "6f1c2a8e-3b4d-4e5f-9a0b-1c2d3e4f5a6b"
    sub = "0d9e8f7a-6b5c-4d3e-8f1a-2b3c4d5e6f70"
    exit_id = "9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d"
    relay = "11111111-2222-4333-8444-555555555555"
    return [
        # secret_id, version, purpose, grant_id, permitted_node_id, plaintext, state
        (f"grant:{grant}", 1, "grant.credential", grant, "local", b"00112233445566778899aabbccddeeff", "retiring"),
        (f"grant:{grant}", 2, "grant.credential", grant, "local", b"test-credential-v2-not-real-xxxx", "active"),
        (f"grant:{grant}", 3, "grant.credential", grant, "edge-01", b"test-credential-v3-pending-xxxxx", "pending"),
        (f"subscription:{sub}", 1, "subscription", None, None, b"TestSubscriptionTokenNotReal_0123456789abcd", "active"),
        ("node-key:edge-01:abcd1234", 1, "node-api-key", None, "edge-01", b"pc_deadbeef_TestOnlyKeyNotRealxxxxxxxxxxxxxxxxxxxxxxxxx", "active"),
        (f"grant:central-{grant}", 4, "fleet-managed", None, "local", b"fleet-pushed-test-value", "active"),
        (relay, 1, "relay-account", None, "edge-02", b"22222222-3333-4444-8555-666666666666", "active"),
        (
            f"exit:{exit_id}",
            3,
            "exit.credential",
            None,
            "edge-01",
            json.dumps({"username": "test-user", "password": "test-pass"}).encode(),
            "active",
        ),
        (
            "grant:awg-0000",
            1,
            "grant.credential",
            "awg-0000",
            "local",
            json.dumps(
                {"private_key": base64.b64encode(bytes(32)).decode(), "preshared_key": base64.b64encode(bytes([7] * 32)).decode()},
                separators=(",", ":"),
            ).encode(),
            "active",
        ),
        ("revoked-row", 1, "grant.credential", "g-revoked", "local", b"revoked-value", "revoked"),
        ("секрет-☃", 1, "purpose-é", "g-🙂", "узел", "значение 🙂".encode(), "active"),
        ('quote"back\\slash\n\x7f\x01', 7, "p\t", "g ", "n/ÿ", b"control chars in identity", "active"),
        ("empty-plaintext", 1, "p", None, None, b"", "active"),
        ("binary-plaintext", 1, "p", "g", "local", bytes(range(256)), "active"),
        ("large-plaintext", 1, "p", "g", "local", bytes((i * 7) % 256 for i in range(4096)), "active"),
        ("big-version", 2**40, "p", None, "local", b"v", "active"),
        ("negative-version", -3, "p", None, "local", b"v", "active"),
    ]


def golden_database(out: Path) -> None:
    first = Keyring((Key("k-0a1b2c3d", "active", 1761350400, MATERIAL_A),), "k-0a1b2c3d")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "panel.sqlite3"
        database = Database(path)
        apply_migrations(database)
        store = SecretStore(first)
        with database.transaction() as db:
            for secret_id, version, purpose, grant_id, node, plaintext, state in secret_identities():
                store.store(
                    db,
                    secret_id=secret_id,
                    version=version,
                    purpose=purpose,
                    grant_id=grant_id,
                    permitted_node_id=node,
                    plaintext=plaintext,
                    state=state,
                )
        # Rotate to a fixed second key and rewrap one batch only, as an interrupted rotation leaves it.
        rotated = Keyring(
            (Key("k-11223344", "active", 1761436800, MATERIAL_B), Key("k-0a1b2c3d", "retiring", 1761350400, MATERIAL_A)),
            "k-11223344",
        )
        assert [k.state for k in first.rotate().keys] == ["active", "retiring"]
        rotated_store = SecretStore(rotated)
        with database.transaction() as db:
            assert rotated_store.rewrap(db, batch_size=6) == 6
        rows = []
        plaintexts = {(s, v): p for s, v, _, _, _, p, _ in secret_identities()}
        with database.connect() as db:
            counts = rotated_store.verify_all(db)
            for row in db.execute("SELECT * FROM secret_versions ORDER BY rowid"):
                aad = _aad(row["secret_id"], row["version"], row["purpose"], row["grant_id"], row["permitted_node_id"])
                ref = SecretRef(row["secret_id"], row["version"])
                if row["state"] == "revoked":
                    revealed = None
                else:
                    revealed = rotated_store.reveal(
                        db, ref, purpose=row["purpose"], grant_id=row["grant_id"], permitted_node_id=row["permitted_node_id"]
                    )
                    assert revealed == plaintexts[(row["secret_id"], row["version"])]
                rows.append(
                    {
                        "secret_id": row["secret_id"],
                        "version": row["version"],
                        "purpose": row["purpose"],
                        "grant_id": row["grant_id"],
                        "permitted_node_id": row["permitted_node_id"],
                        "key_id": row["key_id"],
                        "state": row["state"],
                        "nonce_hex": row["nonce"].hex(),
                        "ciphertext_hex": row["ciphertext"].hex(),
                        "aad_hex": aad.hex(),
                        "plaintext_hex": plaintexts[(row["secret_id"], row["version"])].hex(),
                    }
                )
        # One file, no WAL beside it, so the fixture is self-contained.
        with sqlite3.connect(path) as raw:
            raw.execute("PRAGMA journal_mode=DELETE")
        with sqlite3.connect(path) as raw:
            raw.execute("VACUUM")
        shutil.copyfile(path, out / "golden.sqlite3")
    keyring_path = out / "golden-keyring.json"
    if keyring_path.exists():
        keyring_path.unlink()
    rotated.save(keyring_path)
    keyring_path.chmod(0o644)
    write_json(out / "secret-versions.json", {"rows": rows, "verify_all": counts})


# --- argon2 ----------------------------------------------------------------------------------

PASSWORDS = [
    "correct horse battery staple",
    "exactly12chr",
    "пароль-с-кириллицей-🙂",
    "tab\tand space and \\ backslash",
    "x" * 1024,
]


def verdict(phc: str, password: str) -> str:
    try:
        PasswordHasher().verify(phc, password)
    except VerifyMismatchError:
        return "mismatch"
    except InvalidHashError:
        return "invalid"
    except VerificationError:
        return "error"
    return "ok"


def argon2_vectors(out: Path, rust_made: Path | None) -> None:
    policy = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
    random_salt = []
    for password in PASSWORDS:
        phc = policy.hash(password)
        random_salt.append(
            {
                "password": password,
                "phc": phc,
                "verify": verdict(phc, password),
                "verify_wrong": verdict(phc, password + "!"),
                "needs_rehash": policy.check_needs_rehash(phc),
            }
        )
    fixed_salt = []
    for index, password in enumerate(PASSWORDS[:3]):
        salt = bytes((index * 16 + i) % 256 for i in range(16))
        phc = hash_secret(
            password.encode(), salt, time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID
        ).decode()
        fixed_salt.append({"password": password, "salt_hex": salt.hex(), "phc": phc})
    other = []
    for label, kwargs in (
        ("t=2", dict(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)),
        ("m=32768", dict(time_cost=3, memory_cost=32768, parallelism=2, hash_len=32, type=Type.ID)),
        ("p=1", dict(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID)),
        ("hash_len=16", dict(time_cost=3, memory_cost=65536, parallelism=2, hash_len=16, type=Type.ID)),
        ("argon2i", dict(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.I)),
        ("argon2d", dict(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.D)),
        ("version 16", dict(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID, version=16)),
    ):
        phc = hash_secret(b"other-params-pass", bytes(range(16)), **kwargs).decode()
        other.append(
            {
                "label": label,
                "password": "other-params-pass",
                "phc": phc,
                "verify": verdict(phc, "other-params-pass"),
                "needs_rehash": policy.check_needs_rehash(phc),
            }
        )
    salt8 = hash_secret(b"other-params-pass", bytes(range(8)), time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID).decode()
    other.append(
        {"label": "salt_len=8", "password": "other-params-pass", "phc": salt8,
         "verify": verdict(salt8, "other-params-pass"), "needs_rehash": policy.check_needs_rehash(salt8)}
    )
    invalid = []
    for phc in (
        "",
        "nonsense",
        "$argon2id$v=19$m=65536,t=3,p=2$abc",
        "$argon2id$v=19$m=65536,t=3,p=2$WgRGk2j919KU4cq8Aoq1eQ$",
        "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E",
    ):
        invalid.append({"phc": phc, "verify": verdict(phc, "whatever-password")})
    document = {
        "dummy_hash": "$argon2id$v=19$m=65536,t=3,p=2$WgRGk2j919KU4cq8Aoq1eQ$Yu6TDt/n0xMCzUMjf0cpxeC/CkNXj2ilMtTlv2L+2wU",
        "random_salt": random_salt,
        "fixed_salt": fixed_salt,
        "other_parameters": other,
        "invalid": invalid,
    }
    from panel.store import DUMMY_PASSWORD_HASH

    assert document["dummy_hash"] == DUMMY_PASSWORD_HASH
    document["dummy_verify_any"] = verdict(DUMMY_PASSWORD_HASH, "not-the-real-password")
    if rust_made is not None:
        made = json.loads(rust_made.read_text())
        document["rust_made"] = [
            {
                "password": item["password"],
                "phc": item["phc"],
                "python_verify": verdict(item["phc"], item["password"]),
                "python_verify_wrong": verdict(item["phc"], item["password"] + "!"),
                "python_needs_rehash": policy.check_needs_rehash(item["phc"]),
            }
            for item in made
        ]
    elif (out / "argon2.json").exists():
        previous = json.loads((out / "argon2.json").read_text())
        if "rust_made" in previous:
            document["rust_made"] = previous["rust_made"]
    write_json(out / "argon2.json", document)


# --- audit -----------------------------------------------------------------------------------

AUDIT_DETAILS = [
    {},
    {"quota_bytes": 5, "password": "CANARY-PASSWORD", "clients": [{"share_url": "naive+https://x"}]},
    {"password": "CANARY-1", "quota_bytes": 5},
    {"nested": {"share_url": "mierus://user:CANARY-2@host", "keep": 1}, "quota_bytes": 5},
    {"list": [{"token": "CANARY-3"}], "quota_bytes": 5},
    {"proxy-url": "CANARY-4", "quota_bytes": 5},
    {"name": "central", "scope": "node-sync", "expires_at": None},
    {"display_name": "Анна · телефон 🙂", "enabled": True, "ratio": 0.1, "big": 1e16, "tiny": 1e-7, "neg": -0.0},
    {"long": "я" * 600, "emoji": "🙂" * 513, "ascii": "a" * 512},
    {"items": list(range(150)), "nested": [[1, 2, {"Secret": 1, "ok": [3]}]]},
    {"Authorization": "Bearer x", "AUTH": 1, "authorisation": 2, "LINK_ID": 3, "Token-Hash": 4, "creds": 5, "uri": 6},
    {"ſecret": 1, "ẞ": 2, "paſſword": 3, "ﬅoken": 4, "tokeń": 5, "Ｓｅｃｒｅｔ": 6, "secreẗ": 7, "KEY": 8},
    {"order": 1, "zeta": 2, "alpha": 3, "Δ": 4, "\u0000ctl": "\u007f\b\f\n\r\t "},
    {"int_max": 2**63 - 1, "int_min": -(2**63), "float": 123456789.123456789, "exp": 1.5e300, "small": 5e-324},
]

FORBIDDEN_PROBES = [
    "secret", "SECRET", "client_secret", "password", "Password", "pass_word", "token", "TOKEN_HASH",
    "credential", "credentials", "link", "links", "LinkLabel", "url", "share-url", "share_url", "URL",
    "authorization", "Authorization", "auth", "authorisation", "uri", "key", "name", "ſecret", "paſſword",
    "ﬅoken", "secreẗ", "ẞecret", "Ｓｅｃｒｅｔ", "lınk", "lİnk", "uRl", "cred-ential", "cred_ential",
    "", "-", "—", "tokeń", "ŧoken", "u̲rl",
]


def audit_vectors(out: Path) -> None:
    details = []
    for detail in AUDIT_DETAILS:
        scrubbed = audit.scrub(detail)
        details.append(
            {
                "detail_json_input": json.dumps(detail, ensure_ascii=False),
                "detail_json": json.dumps(scrubbed, ensure_ascii=True),
                "digest": audit.digest(detail),
                "digest_scrubbed": audit.digest(scrubbed),
            }
        )
    folds = []
    for cp in range(0x80, 0x110000):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        folded = chr(cp).casefold()
        if any(ord(ch) < 0x80 for ch in folded):
            folds.append([cp, folded])
    document = {
        "details": details,
        "forbidden": [[key, audit._forbidden(key)] for key in FORBIDDEN_PROBES],
        "casefold_with_ascii": folds,
        "record_none_detail": json.dumps(audit.scrub(None or {}), ensure_ascii=True),
    }
    write_json(out / "audit.json", document)


def main() -> None:
    args = sys.argv[1:]
    rust_made = None
    if "--rust-made" in args:
        index = args.index("--rust-made")
        rust_made = Path(args[index + 1])
        del args[index : index + 2]
    out = Path(args[0])
    out.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    keyring_files(out)
    keyring_cases(out)
    golden_database(out)
    argon2_vectors(out, rust_made)
    audit_vectors(out)


if __name__ == "__main__":
    main()
