#!/usr/bin/env python3
"""Verification matrix: the fixture records claims and proofs; the native Rust router
and live HTTP gate probe in `route-coverage.py` supply its route inventory.

    python3 scripts/dev/verification-matrix.py --render   # rewrite the document
    python3 scripts/dev/verification-matrix.py --check    # proofs exist, document current, gaps listed

Proof forms:
    pytest::<file>::<test>          a test function in that file
    cargo::<file>::<test>           a `#[test] fn` in that Rust source file
    lab-host::<scenario>            a `case_run <scenario>` of scripts/lab/guest-runner.sh
    lab-container::<scenario>       the same runner in its container mode
    fleet::<prefix>                 a `check("<prefix>_…` of scripts/lab/fleet-acceptance.py
    ui::<view>.<scenario>           a `check("<view>.<scenario>` of scripts/lab/ui-acceptance.py
    script::<path>                  a lab script that exists (its own report is the proof)
    doc::<path>                     a document that exists (a policy, a matrix)
"""
from __future__ import annotations
import ast

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/verification-matrix.json"
DOCUMENT = ROOT / "docs/VERIFICATION_MATRIX.md"

STATUS_MARK = {"proven": "✅ proven", "fixed-in-0.6": "🔧 fixed in 0.6", "gap": "⛔ gap"}


def check_names(path: Path) -> list[str]:
    """Read executable check calls, not comments or arbitrary string mentions."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = []
    wrappers = {}
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in functions:
        bindings = {}
        for loop in (node for node in ast.walk(scope) if isinstance(node, ast.For)):
            try:
                values = ast.literal_eval(loop.iter)
            except (ValueError, TypeError):
                continue
            targets = loop.target.elts if isinstance(loop.target, (ast.Tuple, ast.List)) else [loop.target]
            for value in values:
                parts = value if isinstance(loop.target, (ast.Tuple, ast.List)) else [value]
                for target, part in zip(targets, parts):
                    if isinstance(target, ast.Name) and isinstance(part, str):
                        bindings.setdefault(target.id, set()).add(part)
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            if not ((isinstance(function, ast.Attribute) and function.attr == "check")
                    or (isinstance(function, ast.Name) and function.id == "check")):
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                names.append(first.value)
            elif isinstance(first, ast.JoinedStr) and first.values and isinstance(first.values[0], ast.Constant):
                names.append(first.values[0].value)
            elif isinstance(first, ast.Name):
                names.extend(bindings.get(first.id, ()))
                parameters = [argument.arg for argument in scope.args.args if argument.arg != "self"]
                if first.id in parameters:
                    wrappers[scope.name] = parameters.index(first.id)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in wrappers:
            index = wrappers[node.func.attr]
            if index < len(node.args) and isinstance(node.args[index], ast.Constant):
                value = node.args[index].value
                if isinstance(value, str):
                    names.append(value)
    return names


def proof_problem(proof: str, root: Path) -> str | None:
    kind, _, rest = proof.partition("::")
    if kind == "pytest":
        file, _, name = rest.partition("::")
        path = root / file
        if not path.is_file():
            return "no such file"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        tests = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        return None if name.startswith("test_") and any(node.name == name for node in tests) else "no such test"
    if kind == "cargo":
        file, _, full_name = rest.partition("::")
        path = root / file
        if not path.is_file():
            return "no such file"
        name = full_name.rsplit("::", 1)[-1]
        pattern = (rf"#\[(?:tokio::)?test(?:\([^\]\n]*\))?\]\s*"
                   rf"(?:#\[[^\]]*\]\s*)*(?:pub\s+)?(?:async\s+)?fn {re.escape(name)}\(")
        return None if name and re.search(pattern, path.read_text(encoding="utf-8")) else "no such test"
    if kind in {"lab-host", "lab-container"}:
        text = (root / "scripts/lab/guest-runner.sh").read_text(encoding="utf-8")
        return None if re.search(rf"case_run {re.escape(rest)} |emit {re.escape(rest)} passed", text) else "no such scenario"
    if kind == "fleet":
        path = root / "scripts/lab/fleet-acceptance.py"
        return None if path.is_file() and any(name.startswith(rest + "_") for name in check_names(path)) else "no such check prefix"
    if kind == "ui":
        path = root / "scripts/lab/ui-acceptance.py"
        return None if path.is_file() and rest in check_names(path) else "no such ui scenario"
    if kind == "script":
        return None if (root / rest).is_file() else "no such script"
    if kind == "doc":
        return None if (root / rest).is_file() else "no such document"
    return f"unknown proof kind {kind!r}"


def load() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["rows"]


def render(rows: list[dict]) -> str:
    lines = [
        "# Verification matrix — maintained functions and their proofs",
        "",
        "Generated from `tests/fixtures/verification-matrix.json` by `scripts/dev/verification-matrix.py --render`;",
        "`tests/test_verification_matrix.py` checks proofs and matches routes against the native Rust HTTP",
        "router/gate probe (`scripts/dev/route-coverage.py`), not the retired Python panel or static OpenAPI",
        "authorization labels. The probe checks anonymous, owner/admin/viewer sessions, CSRF and scoped",
        "keys against the registered router; `VERIFICATION_STRICT=1` refuses gaps. One row per maintained",
        "function: its claim, proof, routes and status. A proof binding is an executable acceptance",
        "contract, not a record that the current combined tree passed it. Run the named tests/scenarios",
        "on the native Ubuntu stand; neither a source-string assertion nor a document proves behavior.",
        "Installer adapter tests use isolated filesystems and recorded host commands unless explicitly",
        "named as a real process/HTTP probe; staged artifact tests do not prove upstream availability.",
        "",
    ]
    total = len(rows)
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in STATUS_MARK}
    lines.append(f"**{total} rows** — " + ", ".join(f"{STATUS_MARK[s]}: {n}" for s, n in counts.items()) + ".")
    lines.append("")
    gaps = [row for row in rows if row["status"] == "gap"]
    if gaps:
        lines += ["## Remaining behavior gaps", "", "| id | proof still required |", "| --- | --- |"]
        lines += [f"| `{row['id']}` | {row['missing_proof']} |" for row in gaps]
        lines.append("")
    for area in ("backend", "clients", "fleet", "routing", "router", "installer", "release", "ui"):
        subset = [row for row in rows if row["area"] == area]
        if not subset:
            continue
        lines += [f"## {area}", "", "| id | since | claim | proof | routes | status |", "| --- | --- | --- | --- | --- | --- |"]
        for row in subset:
            proofs = "<br>".join(f"`{p}`" for p in row["proof"]) or "—"
            routes = "<br>".join(f"`{r}`" for r in row["routes"]) or "—"
            lines.append(f"| `{row['id']}` | {row['since']} | {row['claim']} | {proofs} | {routes} | {STATUS_MARK[row['status']]} |")
        lines.append("")
    return "\n".join(lines)


def row_problems(rows: list[dict]) -> list[str]:
    return ([f"{row['id']}: non-gap row has no proof" for row in rows if row["status"] != "gap" and not row["proof"]]
            + [f"{row['id']}: gap has no explicit missing behavior" for row in rows
               if row["status"] == "gap" and not row.get("missing_proof")]
            + [f"{row['id']}: resolved row still declares a missing proof" for row in rows
               if row["status"] != "gap" and row.get("missing_proof")])


def route_problems(rows: list[dict], routes: list[dict]) -> list[str]:
    actual = {f"{row['method']} {row['path']}" for row in routes}
    claimed = {route for row in rows for route in row["routes"]}
    return ([f"native route not covered: {route}" for route in sorted(actual - claimed)]
            + [f"retired route still claimed: {route}" for route in sorted(claimed - actual)])


def main(argv: list[str]) -> int:
    rows = load()
    if "--render" in argv:
        DOCUMENT.write_text(render(rows), encoding="utf-8")
        print(f"rendered {len(rows)} rows to {DOCUMENT.relative_to(ROOT)}")
        return 0
    proofs = row_problems(rows) + [f"{row['id']}: {proof} — {why}" for row in rows for proof in row["proof"]
              for why in [proof_problem(proof, ROOT)] if why]
    for problem in proofs:
        print("PROOF:", problem, file=sys.stderr)
    route_coverage = __import__("route-coverage")
    inventory = route_coverage.collect_routes()
    routes = route_problems(rows, inventory) + route_coverage.gate_problems(inventory)
    for problem in routes:
        print("ROUTE:", problem, file=sys.stderr)
    stale = DOCUMENT.read_text(encoding="utf-8") != render(rows) if DOCUMENT.is_file() else True
    if stale:
        print("DOCUMENT: docs/VERIFICATION_MATRIX.md is stale", file=sys.stderr)
    gaps = [row["id"] for row in rows if row["status"] == "gap"]
    strict = os.environ.get("VERIFICATION_STRICT") == "1"
    print(f"{len(rows)} rows, {len(proofs)} bad proofs, {len(routes)} bad routes, {len(gaps)} gaps"
          + (f": {', '.join(gaps)}" if gaps else ""))
    if strict and gaps:
        print("STRICT: verification gaps are forbidden", file=sys.stderr)
    return 1 if proofs or routes or stale or (strict and gaps) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
