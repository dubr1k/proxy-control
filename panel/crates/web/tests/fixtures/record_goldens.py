"""Record the goldens of the panel's HTTP shell (WP4) from the Python panel.

Run on ams-test from the root of a checkout, with the panel's virtualenv:

    /root/dev/proxy-control/.venv/bin/python panel/crates/web/tests/fixtures/record_goldens.py

It writes, next to this file:

- `json_corpus.json` — what `json.loads(bytes)` makes of valid and malformed request bodies: the
  value (as JSON) or the `JSONDecodeError` (`msg`, `pos`), or the non-JSON error FastAPI turns into
  400 "There was an error parsing the body";
- `framework_probes.json` — raw HTTP/1.1 requests sent to `uvicorn panel.app:create_app` on a Unix
  socket (the production flags: `--proxy-headers --forwarded-allow-ips 172.16.0.0/12
  --no-access-log`) and the normalised answers (status, headers, body) — the framework behaviour
  of inventory §2.3 (404/405/307/HEAD/400 host/413/422 precedence/security headers/static files);
- `python_constants.json` — the subscription page CSP, the image's `mimetypes` tables, and
  `formatdate`/etag vectors of `FileResponse`;
- `../../openapi/panel-openapi.json` — the exact bytes `GET /api/openapi.json` serves.

The probe list itself is `probes.json` (shared with the Rust replay in `tests/framework_probes.rs`).
No real secret is involved: the database, keyring, admin and API keys are made up for the run and
normalised away.
"""
from __future__ import annotations

import base64
import email.utils
import hashlib
import json
import mimetypes
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(ROOT))

OWNER_PASSWORD = "correct horse battery staple"


# -- json.loads corpus -------------------------------------------------------------------------

JSON_CASES = [
    b'{}', b'[]', b'{"a": 1}', b' {"a" : [1, 2.5, -0, 1e3, 1E-2, true, false, null]} ', b'"x"', b'1', b'-1',
    b'{"a": "\\u00e9\\ud83d\\ude00\\n\\t\\/\\\\\\""}', b'{"a": 1, "a": 2, "b": 3}', b'{"b": 1, "a": 2}',
    '{"name": "Узел ·"}'.encode(), b'\xef\xbb\xbf{"a": 1}', '{"a": 1}'.encode("utf-16"),
    '{"a": 1}'.encode("utf-16-le"), '{"a": 1}'.encode("utf-16-be"), '{"a": 1}'.encode("utf-32"),
    b'12345678901234567890', b'1.0', b'0.1', b'1e400', b'-1e400', b'123.456e-7', b'5e-324',
    # malformed
    b'{', b'{bad', b'{"a"', b'{"a" 1}', b'{"a": }', b'{"a": 1,}', b'{"a": 1 "b": 2}', b'[1,]', b'[1 2]', b'[',
    b'[1', b']', b'}', b'', b' ', b'nul', b'tru', b'-', b'-a', b'01', b'1.', b'1e', b'1.e5', b'.5', b'+1',
    b'{"a": 1}x', b'{"a": 1} {"b": 2}', b'"abc', b'"a\\x"', b'"a\\u12"', b'"a\\u12g4"', b'"a\\u1234',
    b'"\\ud800"', b'"\\ud800\\u0041"', b'"\\ud800\\udc00"', b'"\\udc00"', b'"a\x01b"', b'"\\', b'"a\\',
    b'{"a": "\\u"}', b"{'a': 1}", b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}', b'NaN', b'[1, 2',
    b'{"a": [1, {"b": }]}', b'\xff', b'{"a": "\xff"}', b'\x00', b'{"a":\n\n  x}', b'{,}', b'{"a":1,,}',
    b'[,]', b'{"a":1,"b"}', b'\t\n\r {"a":1} \t', b'\x0c{}', b'{"a": 1}\x00', b'{"a": tru}', b'{"a": nulx}',
    b'[-]', b'[--1]', b'[1.5e+]', b'[0x10]', b'{"a":"\\u0000"}', b'"\\uDBFF\\uDFFF"', b'"\\uD834"x',
    '{"é": 1, x}'.encode(), '["ü", ]'.encode(), b'{"a": 1}' + b' ' * 3 + b'2',
]


def json_corpus() -> list[dict]:
    out = []
    for raw in JSON_CASES:
        item = {"input": base64.b64encode(raw).decode()}
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            item["error"] = {"msg": exc.msg, "pos": exc.pos}
        except Exception as exc:  # noqa: BLE001 - FastAPI: 400 "There was an error parsing the body"
            item["other_error"] = type(exc).__name__
        else:
            try:
                item["value"] = json.dumps(value, ensure_ascii=True, allow_nan=False)
            except ValueError:
                item["value_not_json"] = repr(value)
            else:
                # A lone surrogate survives json.loads but cannot be stored or encoded as UTF-8.
                try:
                    json.dumps(value, ensure_ascii=False).encode("utf-8")
                except UnicodeEncodeError:
                    item["lone_surrogate"] = True
        out.append(item)
    return out


# -- constants -------------------------------------------------------------------------------

def constants() -> dict:
    from panel.subscriptions.page_assets import CSP

    db = mimetypes.MimeTypes(filenames=())
    vectors = []
    for mtime, size in [(1761400000.0, 10), (1761400000.123456, 4096), (1700000000.5, 0), (1761471234.987654321, 77)]:
        vectors.append({
            "mtime": mtime, "size": size,
            "last_modified": email.utils.formatdate(mtime, usegmt=True),
            "etag": '"' + hashlib.md5((str(mtime) + "-" + str(size)).encode(), usedforsecurity=False).hexdigest() + '"',
            "mtime_str": str(mtime),
        })
    guesses = {}
    for name in ["a.js", "a.css", "a.html", "a.json", "a.png", "a.svg", "a.ico", "a.txt", "a.woff2", "a.map", "a",
                 "a.JS", "a.webp", "a.mjs", "a.js.gz", "a.tgz", "a.tar.gz", "a.svgz", "a.Z", "a.bz2", ".js", "a.",
                 "a.HTML", "dir.d/a", "a.js.br", "a.xz", "a.css.Z"]:
        # The panel image has no /etc/mime.types: only Python's built-in table counts.
        guesses[name] = db.guess_type("/app/panel/static/" + name)[0]
    return {
        "subscription_csp": CSP,
        "types_map": dict(sorted(db.types_map[True].items())),
        "encodings_map": dict(sorted(db.encodings_map.items())),
        "suffix_map": dict(sorted(db.suffix_map.items())),
        "guesses": guesses,
        "file_vectors": vectors,
    }


# -- the live panel --------------------------------------------------------------------------

def http(sock_path: str, raw: bytes, timeout: float = 30.0) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(sock_path)
        sock.sendall(raw)
        chunks = []
        while True:
            try:
                chunk = sock.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def parse_response(raw: bytes, head: bool) -> tuple[int, list[tuple[str, str]], bytes]:
    head_part, _, body = raw.partition(b"\r\n\r\n")
    lines = head_part.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.append((name.strip().lower(), value.strip()))
    if any(name == "transfer-encoding" and "chunked" in value for name, value in headers):
        decoded, rest = b"", body
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                break
            decoded, rest = decoded + rest[:size], rest[size + 2:]
        body = decoded
    if head:
        body = b""
    return status, headers, body


def main() -> None:
    probes = json.loads((HERE / "probes.json").read_text())
    (HERE / "json_corpus.json").write_text(json.dumps(json_corpus(), indent=1) + "\n")
    (HERE / "python_constants.json").write_text(json.dumps(constants(), indent=1, ensure_ascii=False) + "\n")

    from panel.keyring import Keyring

    work = Path(tempfile.mkdtemp(prefix="wp4-goldens-"))
    sock = str(work / "panel.sock")
    key = work / "master-key"
    Keyring.generate().save(key)
    env = {
        "PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/root"),
        "PANEL_DATABASE": str(work / "panel.sqlite3"), "PANEL_MASTER_KEY_FILE": str(key),
        "PANEL_ALLOWED_HOSTS": probes["allowed_hosts"], "PANEL_COOKIE_SECURE": "false",
        "PANEL_METRICS_ENABLED": "false", "PANEL_VERSION_FILE": str(work / "VERSION"),
        "NAIVE_MANAGER_SOCKET": str(work / "none.sock"), "MIERU_MANAGER_SOCKET": str(work / "none.sock"),
        "AWG_MANAGER_SOCKET": str(work / "none.sock"), "TRUSTTUNNEL_MANAGER_SOCKET": str(work / "none.sock"),
        "VERSION_AGENT_SOCKET": str(work / "none.sock"), "TELEMT_API_URL": "http://127.0.0.1:9",
        "PYTHONPATH": str(ROOT), "PANEL_FLEET_HEARTBEAT_SECONDS": "3600",
    }
    (work / "VERSION").write_text("9.9.9\n")
    python = sys.executable

    def cli(*argv: str, stdin: str = "") -> str:
        done = subprocess.run([python, "-m", "panel.cli", *argv], input=stdin, env=env, capture_output=True,
                              text=True, check=True, cwd=ROOT)
        return done.stdout

    cli("create-admin", "--username", "owner", "--role", "owner", "--password-stdin", stdin=OWNER_PASSWORD + "\n")
    keys = {scope: json.loads(cli("api-key-create", "--name", f"probe-{scope}", "--scope", scope))["plaintext"]
            for scope in ("admin", "monitor", "node-sync")}
    uvicorn = Path(python).with_name("uvicorn")
    server = subprocess.Popen(
        [str(uvicorn), "panel.app:create_app", "--factory", "--uds", sock, "--proxy-headers",
         "--forwarded-allow-ips", "172.16.0.0/12", "--no-access-log"],
        env=env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=open(work / "uvicorn.log", "wb"))
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                if http(sock, b"GET /healthz HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n\r\n").startswith(
                        b"HTTP/1.1 200"):
                    break
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise SystemExit("uvicorn did not start:\n" + (work / "uvicorn.log").read_text())
            time.sleep(0.2)
        session = login(sock)
        context = {"csrf": session["csrf"], "session": session["session"], **{f"key_{scope.replace('-', '_')}": value
                                                                               for scope, value in keys.items()}}
        _, static_headers, _ = parse_response(
            http(sock, b"GET /static/app.js HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n\r\n"), head=False)
        context["etag_app_js"] = dict(static_headers)["etag"]
        context["last_modified_app_js"] = dict(static_headers)["last-modified"]
        results = []
        for probe in probes["probes"]:
            results.append(run_probe(sock, probe, context))
        openapi = http(sock, render("GET /api/openapi.json HTTP/1.1\r\nHost: testserver\r\nCookie: "
                                    "panel_session={session}; panel_csrf={csrf}\r\nConnection: close\r\n\r\n",
                                    context).encode())
        _, _, body = parse_response(openapi, head=False)
        (HERE.parents[1] / "openapi" / "panel-openapi.json").write_bytes(body)
    finally:
        server.terminate()
        server.wait(10)
    (HERE / "framework_probes.json").write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n")
    print(f"recorded {len(results)} probes, {len(JSON_CASES)} json cases")


def login(sock: str) -> dict:
    page = http(sock, b"GET /login HTTP/1.1\r\nHost: testserver\r\nConnection: close\r\n\r\n")
    csrf = re.search(rb"panel_csrf=([A-Za-z0-9_-]+)", page).group(1).decode()
    body = json.dumps({"username": "owner", "password": OWNER_PASSWORD}).encode()
    answer = http(sock, b"POST /api/auth/login HTTP/1.1\r\nHost: testserver\r\nContent-Type: application/json\r\n"
                  + f"X-CSRF-Token: {csrf}\r\nCookie: panel_csrf={csrf}\r\nContent-Length: {len(body)}\r\n".encode()
                  + b"Connection: close\r\n\r\n" + body)
    session = re.search(rb"panel_session=([A-Za-z0-9_-]+)", answer).group(1).decode()
    csrf = re.search(rb"panel_csrf=([A-Za-z0-9_-]+)", answer).group(1).decode()
    return {"session": session, "csrf": csrf}


def render(text: str, context: dict) -> str:
    for name, value in context.items():
        text = text.replace("{" + name + "}", value)
    return text


VOLATILE_JSON_KEYS = ("created_at", "plaintext", "prefix", "last_used_at")


def mask_json(body: bytes) -> bytes:
    """Values that differ on every run (`"created_at":1761…`, a key's `plaintext`/`prefix`) become
    `"<masked>"`, in place in the serialised text, so the bytes around them still compare."""
    text = body.decode("utf-8", errors="replace")
    for key in VOLATILE_JSON_KEYS:
        text = re.sub(r'"%s":(-?\d+|"[^"]*"|null)' % key, '"%s":"<masked>"' % key, text)
    return text.encode("utf-8")


def normalise(status: int, headers: list[tuple[str, str]], body: bytes) -> dict:
    """The shape both implementations are compared on (`tests/framework_probes.rs` does the same)."""
    boundary = None
    out = []
    for name, value in headers:
        if name in {"date", "server", "connection"}:
            continue
        if name == "x-request-id":
            value = "<request-id>" if re.fullmatch(r"[0-9a-f]{16}", value) else "<bad:" + value + ">"
        elif name == "set-cookie":
            value = re.sub(r"^(panel_session|panel_csrf)=[A-Za-z0-9_-]{43}", r"\1=<token>", value)
        elif name in {"etag", "last-modified"}:
            value = f"<{name}>"
        elif name == "content-type" and "boundary=" in value:
            boundary = value.split("boundary=", 1)[1]
            value = value.replace(boundary, "<boundary>")
        out.append([name, value])
    out.sort()
    if boundary:
        body = body.replace(boundary.encode(), b"<boundary>")
    if any(name == "content-type" and value == "application/json" for name, value in out):
        body = mask_json(body)
    shown: dict = {"status": status, "headers": out}
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and len(body) <= 4096:
        shown["body"] = text
    else:
        shown["body_sha256"] = hashlib.sha256(body).hexdigest()
        shown["body_length"] = len(body)
    return shown


def run_probe(sock: str, probe: dict, context: dict) -> dict:
    raw = render(probe["request"], context).encode("latin-1")
    if "body_b64" in probe:
        raw += base64.b64decode(probe["body_b64"])
    elif "body" in probe:
        raw += probe["body"].encode("utf-8")
    answer = http(sock, raw)
    status, headers, body = parse_response(answer, head=probe["request"].startswith("HEAD "))
    return {"name": probe["name"], **normalise(status, headers, body)}


if __name__ == "__main__":
    main()
