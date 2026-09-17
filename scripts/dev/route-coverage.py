#!/usr/bin/env python3
"""Audit the panel's routes (v0.6): every route with the gate it enforces, every mutation
behind CSRF or an API key and a role, every route mentioned by a test or a lab scenario.

    python3 scripts/dev/route-coverage.py           # table + verdict, exit 1 on a problem
    python3 scripts/dev/route-coverage.py --json    # the routes as JSON (the matrix reads it)

The gates come from `RequestContext` (`gate` on each dependency); the mentions are looked
up in `panel/tests`, `tests` and `scripts/lab` by the path template with its parameters
as wildcards. Run from the repository root.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Routes that answer without a session on purpose: the login form, the health probe, the
# static shell, the login itself, the subscriber endpoint (its token is the credential).
PUBLIC = [
    ("GET", "/"),
    ("GET", "/favicon.ico"),
    ("GET", "/healthz"),
    ("GET", "/login"),
    ("POST", "/api/auth/login"),
    ("GET", "/s/{token}"),
    ("HEAD", "/s/{token}"),
]
# Mutations whose gate is the session itself, not a role: every signed-in user may do them.
ROLELESS_MUTATIONS = {
    ("POST", "/api/auth/logout"),
}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
SEARCH_DIRS = ("panel/tests", "tests", "scripts/lab", "scripts/dev")


def build_app():
    from panel.app import Settings, create_app
    from panel.keyring import Keyring
    from panel.mieru import MemoryMieru
    from panel.naive import MemoryNaive
    from panel.telemt import MemoryTelemt
    from panel.versions import VersionClient

    tmp = Path(tempfile.mkdtemp(prefix="route-coverage-"))
    key = tmp / "master-key"
    Keyring.generate().save(key)
    settings = Settings(database_path=tmp / "panel.sqlite3", master_key_file=key, session_cookie_secure=False,
                        allowed_hosts=("testserver",), naive_public_host="naive.example", naive_enabled=True,
                        mieru_enabled=True, version_agent_socket=str(tmp / "none.sock"))
    return create_app(settings, telemt=MemoryTelemt(public_host="proxy.example"), naive=MemoryNaive(),
                      mieru=MemoryMieru(), version_client=VersionClient(str(tmp / "none.sock")))


def _gates(dependant, seen=None) -> list[str]:
    seen = seen if seen is not None else set()
    found: list[str] = []
    for dependency in getattr(dependant, "dependencies", ()):
        call = dependency.call
        gate = getattr(call, "gate", None)
        if gate:
            name = gate[0] if len(gate) == 1 else f"{gate[0]}:{','.join(gate[1:])}"
            if name not in seen:
                seen.add(name)
                found.append(name)
        found += _gates(dependency, seen)
    return found


def collect_routes() -> list[dict]:
    app = build_app()
    rows = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        dependant = getattr(route, "dependant", None)
        if not path or not methods or dependant is None:
            continue  # mounts (static files) and the like
        for method in sorted(methods):
            if method == "OPTIONS":
                continue
            rows.append({"method": method, "path": path, "gates": _gates(dependant)})
    rows.sort(key=lambda r: (r["path"], r["method"]))
    return rows


def gate_problems(routes: list[dict]) -> list[str]:
    problems = []
    public = set(PUBLIC)
    for row in routes:
        key = (row["method"], row["path"])
        gates = row["gates"]
        if key in public:
            if gates:
                problems.append(f"{row['method']} {row['path']}: listed public but gated by {gates}")
            continue
        if not gates:
            problems.append(f"{row['method']} {row['path']}: no gate and not in PUBLIC")
            continue
        if row["method"] in MUTATING:
            if not any(g == "mutation" or g == "fleet_key" for g in gates):
                problems.append(f"{row['method']} {row['path']}: mutation without CSRF/API-key gate ({gates})")
            has_role = any(g.startswith("roles:") for g in gates) or "fleet_key" in gates
            if not has_role and key not in ROLELESS_MUTATIONS:
                problems.append(f"{row['method']} {row['path']}: mutation without a role gate ({gates})")
    return problems


def _pattern(path: str) -> re.Pattern:
    # `{param}` matches an f-string expression (`{grants['naive']['id']}`), a literal
    # value or a `%s`-style hole — anything but a path separator.
    parts = re.split(r"\{[^}]+\}", path)
    hole = r"(?:\{[^{}]*\}|[^/\s\"'`{}]+)"
    return re.compile("".join(re.escape(part) + (hole if i < len(parts) - 1 else "") for i, part in enumerate(parts)))


def unmentioned(routes: list[dict], root: Path) -> list[tuple[str, str]]:
    corpus = []
    for directory in SEARCH_DIRS:
        for file in sorted((root / directory).rglob("*")):
            if file.suffix in {".py", ".sh"} and file.is_file():
                corpus.append(file.read_text(encoding="utf-8", errors="replace"))
    text = "\n".join(corpus)
    missing = []
    for row in routes:
        if (row["method"], row["path"]) in set(PUBLIC):
            continue
        if _pattern(row["path"]).search(text) is None:
            missing.append((row["method"], row["path"]))
    return missing


def main(argv: list[str]) -> int:
    routes = collect_routes()
    if "--json" in argv:
        print(json.dumps(routes, indent=2, ensure_ascii=False))
        return 0
    width = max(len(r["path"]) for r in routes)
    for row in routes:
        print(f"{row['method']:<6} {row['path']:<{width}}  {', '.join(row['gates']) or '(public)'}")
    problems = gate_problems(routes)
    missing = unmentioned(routes, ROOT)
    for problem in problems:
        print("GATE:", problem, file=sys.stderr)
    for method, path in missing:
        print(f"UNMENTIONED: {method} {path}", file=sys.stderr)
    print(f"{len(routes)} routes, {len(problems)} gate problems, {len(missing)} unmentioned")
    return 1 if problems or missing else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
