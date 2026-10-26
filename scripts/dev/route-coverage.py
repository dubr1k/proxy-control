#!/usr/bin/env python3
"""Audit actual Rust panel routes and their HTTP authorization refusals.

The native test `panel/crates/web/tests/route_gate_inventory.rs` enumerates the very
`routes::all()` used by the server, probes each operation through an isolated Unix
socket and compares the schema operations with OpenAPI. This script consumes that
test's bounded JSON report. OpenAPI supplies neither gate labels nor auth evidence.

    python3 scripts/dev/route-coverage.py          # verdict, exit 1 on a problem
    python3 scripts/dev/route-coverage.py --json   # observed inventory
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUST_TEST = "route_gate_inventory"
BEGIN = "ROUTE_GATE_INVENTORY_BEGIN"
END = "ROUTE_GATE_INVENTORY_END"

# Explicit authorization contract; all other routes must require a session or key.
PUBLIC = [
    ("GET", "/"),
    ("GET", "/favicon.ico"),
    ("GET", "/healthz"),
    ("GET", "/login"),
    ("POST", "/api/auth/login"),
    ("GET", "/s/{token}"),
    ("HEAD", "/s/{token}"),
]
PUBLIC_STATUS = {
    ("GET", "/"): 303,
    ("GET", "/favicon.ico"): 204,
    ("GET", "/healthz"): 200,
    ("GET", "/login"): 200,
    ("POST", "/api/auth/login"): 403,  # unauthenticated login still requires its CSRF token
    ("GET", "/s/{token}"): 404,  # absent subscription token must not disclose identity
    ("HEAD", "/s/{token}"): 404,
}
ROLELESS_MUTATIONS = {("POST", "/api/auth/logout")}
# Preview and explain accept structured input but do not persist changes.
VIEWER_PROBES = {
    ("POST", "/api/routing/policies/{node_id}/{protocol}/preview"),
    ("POST", "/api/routing/policies/{node_id}/{protocol}/explain"),
}
RESTRICTED_READS = {
    ("GET", "/api/readiness"),
    ("GET", "/api/openapi.json"),
    ("GET", "/api/admins"),
    ("GET", "/api/keys"),
    ("GET", "/api/clients/import/inventory"),
    ("GET", "/api/operations/{operation_id}"),
    ("GET", "/api/nodes/{node_id}/inventory"),
    ("GET", "/api/nodes/{node_id}/generations"),
}
OWNER_ONLY_READS = {
    ("GET", "/api/admins"),
    ("GET", "/api/keys"),
}
OWNER_ONLY_MUTATIONS = {
    ("POST", "/api/admins"),
    ("PATCH", "/api/admins/{admin_id}"),
    ("DELETE", "/api/admins/{admin_id}"),
    ("POST", "/api/keys"),
    ("POST", "/api/keys/{key_id}/enabled"),
    ("DELETE", "/api/keys/{key_id}"),
    ("POST", "/api/nodes/{node_id}/rename"),
    ("POST", "/api/nodes/{node_id}/disable"),
    ("POST", "/api/nodes/{node_id}/enable"),
    ("POST", "/api/nodes/local/unlink"),
    ("POST", "/api/versions/check"),
    ("POST", "/api/versions/{component}/update"),
    ("POST", "/api/versions/panel/rebuild-managers"),
    ("POST", "/api/nodes/fingerprint"),
    ("POST", "/api/nodes/test"),
    ("POST", "/api/nodes/link"),
    ("POST", "/api/nodes/{node_id}/link"),
    ("POST", "/api/nodes/{node_id}/pause"),
    ("POST", "/api/nodes/{node_id}/resume"),
    ("POST", "/api/nodes/{node_id}/probe"),
    ("DELETE", "/api/nodes/{node_id}"),
    ("POST", "/api/nodes/{node_id}/import"),
    ("POST", "/api/nodes/{node_id}/versions/check"),
    ("POST", "/api/nodes/{node_id}/versions/{component}"),
    ("PUT", "/api/routing/policies/{node_id}/{protocol}"),
    ("DELETE", "/api/routing/policies/{node_id}/{protocol}"),
    ("POST", "/api/routing/policies/{node_id}/{protocol}/apply"),
    ("POST", "/api/routing/policies/{node_id}/{protocol}/rollback"),
    ("POST", "/api/routing/relay/{node_id}/enable"),
    ("POST", "/api/routing/relay/{node_id}/rotate"),
    ("POST", "/api/routing/lanes/{grant_id}"),
    ("POST", "/api/routing/exits"),
    ("POST", "/api/routing/exits/import"),
    ("PUT", "/api/routing/exits/{exit_id}"),
    ("POST", "/api/routing/exits/{exit_id}/test"),
    ("POST", "/api/routing/exits/{exit_id}/{action}"),
    ("PUT", "/api/routing/geodata/settings"),
    ("POST", "/api/routing/geodata/{action}"),
    ("POST", "/api/routing/targets/{node_id}/{protocol}/attach"),
    ("POST", "/api/routing/targets/{node_id}/{protocol}/detach"),
}
GATE_DETAILS = {
    "authentication required", "CSRF validation failed", "insufficient role",
    "a node-sync or admin API key is required",
}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
SEARCH_DIRS = ("panel/crates/web/tests", "panel/tests", "tests", "scripts/lab")
EXCLUDE_TESTS = {"test_route_coverage.py", "test_verification_matrix.py", "route_gate_inventory.rs"}


@lru_cache(maxsize=1)
def collect_routes() -> list[dict]:
    completed = subprocess.run(
        ["cargo", "test", "-p", "panel-web", "--test", RUST_TEST, "--", "--nocapture"],
        cwd=ROOT / "panel", capture_output=True, text=True, check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"native router gate audit failed:\n{completed.stdout}\n{completed.stderr}")
    match = re.search(re.escape(BEGIN) + r"(\[.*?\])" + re.escape(END), completed.stdout, re.S)
    if match is None:
        raise RuntimeError("native router audit passed without an inventory report")
    routes = json.loads(match.group(1))
    if not isinstance(routes, list) or not routes:
        raise RuntimeError("native router audit returned an empty inventory")
    return routes


def gate_problems(routes: list[dict]) -> list[str]:
    problems = []
    listed_public = set(PUBLIC)
    present = set()
    for row in routes:
        method, path = row["method"], row["path"]
        key = (method, path)
        label = f"{method} {path}"
        if key in present:
            problems.append(f"{label}: duplicate route")
        present.add(key)
        if row.get("inventory") != "panel_web::routes::all":
            problems.append(f"{label}: not inventoried from the native server router")
        status = row.get("anonymous_status")
        detail = row.get("anonymous_detail")
        if key in listed_public:
            if status != PUBLIC_STATUS[key] or detail == "authentication required":
                problems.append(f"{label}: declared public but unexpected runtime answer ({status}: {detail})")
            continue
        if status != 401 or detail != "authentication required":
            problems.append(f"{label}: anonymous runtime did not refuse with authentication required ({status}: {detail})")
        if path.startswith("/api/fleet/v2/"):
            if row.get("viewer_status") != 403 or row.get("viewer_detail") != "a node-sync or admin API key is required":
                problems.append(f"{label}: node-only route accepted a viewer session")
            if not isinstance(row.get("node_key_status"), int) or row.get("node_key_detail") in {
                "authentication required", "a node-sync or admin API key is required",
            }:
                problems.append(f"{label}: node-sync bearer did not reach the fleet handler")
        if method not in MUTATING:
            if key in RESTRICTED_READS and (
                row.get("viewer_status") != 403 or row.get("viewer_detail") != "insufficient role"
            ):
                problems.append(f"{label}: restricted read lacked viewer role refusal")
            if key in OWNER_ONLY_READS and (
                row.get("admin_status") != 403 or row.get("admin_detail") != "insufficient role"
            ):
                problems.append(f"{label}: owner-only read accepted an admin")
            if path.startswith("/api/fleet/v2/"):
                continue
            if not isinstance(row.get("owner_status"), int) or row.get("owner_detail") in GATE_DETAILS:
                problems.append(f"{label}: owner read did not reach the handler")
            if key not in RESTRICTED_READS and (
                not isinstance(row.get("viewer_status"), int) or row.get("viewer_detail") in GATE_DETAILS
            ):
                problems.append(f"{label}: viewer read did not reach the handler")
            continue
        csrf_status = row.get("session_no_csrf_status")
        csrf_detail = row.get("session_no_csrf_detail")
        if csrf_status != 403 or csrf_detail not in {
            "CSRF validation failed", "a node-sync or admin API key is required",
        }:
            problems.append(f"{label}: session mutation lacked a CSRF or API-key refusal ({csrf_status}: {csrf_detail})")
        if key in OWNER_ONLY_MUTATIONS and (
            row.get("admin_status") != 403 or row.get("admin_detail") != "insufficient role"
        ):
            problems.append(f"{label}: owner-only mutation accepted an admin")
        if key not in ROLELESS_MUTATIONS and csrf_detail != "a node-sync or admin API key is required" and (
            not isinstance(row.get("session_csrf_status"), int) or row.get("session_csrf_detail") in GATE_DETAILS
        ):
            problems.append(f"{label}: owner's valid-CSRF mutation did not reach the handler")
        if csrf_detail == "a node-sync or admin API key is required":
            if row.get("session_csrf_detail") != csrf_detail or row.get("viewer_detail") != csrf_detail:
                problems.append(f"{label}: node-only mutation accepted a session")
        elif key in VIEWER_PROBES:
            if not isinstance(row.get("viewer_status"), int) or row.get("viewer_detail") in GATE_DETAILS:
                problems.append(f"{label}: read-only probe wrongly refuses viewer")
        elif key not in ROLELESS_MUTATIONS and (
            row.get("viewer_status") != 403 or row.get("viewer_detail") != "insufficient role"
        ):
            problems.append(f"{label}: viewer's valid-CSRF mutation lacked role refusal")
    if present & listed_public != listed_public:
        problems.append(f"missing public routes: {sorted(listed_public - present)}")
    if present & OWNER_ONLY_READS != OWNER_ONLY_READS:
        problems.append(f"missing owner-only reads: {sorted(OWNER_ONLY_READS - present)}")
    if present & OWNER_ONLY_MUTATIONS != OWNER_ONLY_MUTATIONS:
        problems.append(f"missing owner-only mutations: {sorted(OWNER_ONLY_MUTATIONS - present)}")
    return problems


def _pattern(path: str) -> re.Pattern:
    # A template parameter can be an f-string expression or a concrete path segment.
    parts = re.split(r"\{[^}]+\}", path)
    hole = r"(?:\{[^{}]*\}|[^/\s\"'`{}]+)"
    return re.compile("".join(re.escape(part) + (hole if i < len(parts) - 1 else "") for i, part in enumerate(parts)))


def unmentioned(routes: list[dict], root: Path) -> list[tuple[str, str]]:
    corpus = []
    for directory in SEARCH_DIRS:
        for file in sorted((root / directory).rglob("*")):
            if file.suffix in {".py", ".sh", ".rs"} and file.is_file() and file.name not in EXCLUDE_TESTS:
                corpus.append(file.read_text(encoding="utf-8", errors="replace"))
    text = "\n".join(corpus)
    return [(row["method"], row["path"]) for row in routes
            if (row["method"], row["path"]) not in PUBLIC and _pattern(row["path"]).search(text) is None]


def main(argv: list[str]) -> int:
    routes = collect_routes()
    problems = gate_problems(routes)
    missing = unmentioned(routes, ROOT)
    if "--json" in argv:
        print(json.dumps(routes, indent=2, ensure_ascii=False))
    else:
        width = max(len(row["path"]) for row in routes)
        for row in routes:
            print(f"{row['method']:<6} {row['path']:<{width}}  "
                  f"anonymous={row['anonymous_status']} "
                  f"session-no-CSRF={row.get('session_no_csrf_status', '—')} "
                  f"viewer={row.get('viewer_status', '—')}")
        for problem in problems:
            print("GATE:", problem, file=sys.stderr)
        for method, path in missing:
            print(f"UNMENTIONED: {method} {path}", file=sys.stderr)
        print(f"{len(routes)} native routes, {len(problems)} gate problems, {len(missing)} unmentioned")
    return 1 if problems or missing else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
