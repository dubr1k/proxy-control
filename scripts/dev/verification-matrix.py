#!/usr/bin/env python3
"""The verification matrix (v0.6): `tests/fixtures/verification-matrix.json` is the truth,
`docs/VERIFICATION_MATRIX.md` its rendering, and every proof a name that exists in the tree.

    python3 scripts/dev/verification-matrix.py --render   # rewrite the document
    python3 scripts/dev/verification-matrix.py --check    # proofs exist, document current, gaps listed

Proof forms:
    pytest::<file>::<test>          a test function in that file
    lab-host::<scenario>            a `case_run <scenario>` of scripts/lab/guest-runner.sh
    lab-container::<scenario>       the same runner in its container mode
    fleet::<prefix>                 a `check("<prefix>_…` of scripts/lab/fleet-acceptance.py
    ui::<view>.<scenario>           a `check("<view>.<scenario>` of scripts/lab/ui-acceptance.py
    script::<path>                  a lab script that exists (its own report is the proof)
    live::<version>                 the «Живая проверка» section of docs/releases/v<version>.md
    doc::<path>                     a document that exists (a policy, a matrix)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/verification-matrix.json"
DOCUMENT = ROOT / "docs/VERIFICATION_MATRIX.md"

STATUS_MARK = {"proven": "✅ proven", "fixed-in-0.6": "🔧 fixed in 0.6", "gap": "⛔ gap"}


def proof_problem(proof: str, root: Path) -> str | None:
    kind, _, rest = proof.partition("::")
    if kind == "pytest":
        file, _, name = rest.partition("::")
        path = root / file
        if not path.is_file():
            return "no such file"
        if not re.search(rf"^\s*(?:async )?def {re.escape(name)}\(", path.read_text(encoding="utf-8"), re.M):
            return "no such test"
        return None
    if kind in {"lab-host", "lab-container"}:
        text = (root / "scripts/lab/guest-runner.sh").read_text(encoding="utf-8")
        return None if re.search(rf"case_run {re.escape(rest)} |emit {re.escape(rest)} passed", text) else "no such scenario"
    if kind == "fleet":
        text = (root / "scripts/lab/fleet-acceptance.py").read_text(encoding="utf-8")
        return None if re.search(rf'check\(f?"{re.escape(rest)}_', text) else "no such check prefix"
    if kind == "ui":
        path = root / "scripts/lab/ui-acceptance.py"
        if not path.is_file():
            return "ui-acceptance.py is not in the tree"
        return None if f'"{rest}' in path.read_text(encoding="utf-8") else "no such ui scenario"
    if kind == "script":
        return None if (root / rest).is_file() else "no such script"
    if kind == "live":
        path = root / f"docs/releases/v{rest}.md"
        if not path.is_file():
            return "no such release note"
        return None if "### Живая проверка" in path.read_text(encoding="utf-8") else "no live-check section"
    if kind == "doc":
        return None if (root / rest).is_file() else "no such document"
    return f"unknown proof kind {kind!r}"


def load() -> list[dict]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["rows"]


def render(rows: list[dict]) -> str:
    lines = [
        "# Verification matrix — v0.2–v0.7 functions and their proofs",
        "",
        "Generated from `tests/fixtures/verification-matrix.json` by `scripts/dev/verification-matrix.py --render`;",
        "`tests/test_verification_matrix.py` keeps every proof pointing at something that exists and refuses a",
        "`gap` on the release tree (`VERIFICATION_STRICT=1`). One row per promised function: what it claims, which",
        "test, lab scenario, browser scenario or live check proves it, and the routes it covers.",
        "",
    ]
    total = len(rows)
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in STATUS_MARK}
    lines.append(f"**{total} rows** — " + ", ".join(f"{STATUS_MARK[s]}: {n}" for s, n in counts.items()) + ".")
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


def main(argv: list[str]) -> int:
    rows = load()
    if "--render" in argv:
        DOCUMENT.write_text(render(rows), encoding="utf-8")
        print(f"rendered {len(rows)} rows to {DOCUMENT.relative_to(ROOT)}")
        return 0
    problems = [f"{row['id']}: {proof} — {why}" for row in rows for proof in row["proof"] for why in [proof_problem(proof, ROOT)] if why]
    for problem in problems:
        print("PROOF:", problem, file=sys.stderr)
    stale = DOCUMENT.read_text(encoding="utf-8") != render(rows) if DOCUMENT.is_file() else True
    if stale:
        print("DOCUMENT: docs/VERIFICATION_MATRIX.md is stale", file=sys.stderr)
    gaps = [row["id"] for row in rows if row["status"] == "gap"]
    print(f"{len(rows)} rows, {len(problems)} bad proofs, {len(gaps)} gaps" + (f": {', '.join(gaps)}" if gaps else ""))
    return 1 if problems or stale else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
