#!/usr/bin/env python3
"""Does the pinned Telemt build accept a caller-supplied secret? Runs against the
live Telemt of the ams-test install, creates one throw-away user, deletes it."""
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9091"
TOKEN = open(os.environ.get("TELEMT_API_TOKEN_FILE", "/run/secrets/telemt-api-token")).read().strip()
USER = f"probe-{secrets.token_hex(3)}"
SECRET = secrets.token_hex(16)


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method,
                                     headers={"Authorization": TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


status, body = call("POST", "/v1/users", {"username": USER, "secret": SECRET})
print("create:", status, json.dumps(body)[:300])
verdict = "rejected"
if status < 400:
    try:
        rows = call("GET", "/v1/users")[1].get("data") or []
        row = next((r for r in rows if r.get("username") == USER), {})
        link = ((row.get("links") or [{}])[0] or {}).get("link", "") if isinstance(row.get("links"), list) else json.dumps(row)
        verdict = "supported" if SECRET in link or SECRET in json.dumps(row) else "generated-instead"
        redacted = json.dumps(row).replace(SECRET, SECRET[:4] + "...<redacted>")
        print("GET /v1/users row:", redacted)
    finally:
        call("DELETE", f"/v1/users/{USER}")
print("TELEMT_CALLER_SECRET =", verdict)
