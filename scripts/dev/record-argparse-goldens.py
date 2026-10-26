#!/usr/bin/env python3
"""Record what the Python installer's argparse surface prints for a corpus of command lines.

The Rust port (`installer_core::argparse`, `installer_core::cli`) must reproduce these bytes. Run
from a checkout on ams-test (Python 3.12, the hosts' interpreter) and commit the output:

    python3 scripts/dev/record-argparse-goldens.py > installer_core/tests/data/argparse-python.json
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "release"))

INSTALLER = [
    [], ["-h"], ["--help"], ["--he"], ["foo"], ["--root"], ["--root", "/x"], ["--root=/x", "status"],
    ["--r", "/x", "status"], ["-x"], ["--", "plan"], ["--=x"], ["-hfoo"], ["--root", "", "status"],
    ["--root", "//a/./b/", "status"], ["status", "--root", "/"], ["status", "x"],
    ["plan"], ["plan", "--config"], ["plan", "--config", "x", "--json=1"], ["plan", "--config=x", "extra"],
    ["plan", "--c", "x"], ["plan", "--conf", "x", "--js"], ["plan", "--config", "-x"], ["plan", "--config", "-1"],
    ["plan", "--config", "a b"], ["plan", "--config", "--json"], ["plan", "-hx"], ["plan", "-h=x"],
    ["plan", "--help=x"], ["plan", "--config", "x", "--config", "y"], ["plan", "--zzz"],
    ["plan", "--config", "x", "--", "y"], ["plan", "--config", "./a//b.toml"], ["plan", "--config", ""],
    ["plan", "--config", "пример.toml"], ["plan", "--json=", "--config", "x"], ["plan", "-"],
    ["install", "--config", "x"], ["install", "--accept-plan", "d"], ["install", "--a", "d", "--c", "x"],
    ["install", "--config", "x", "--accept-plan=", "--json"],
    ["wizard"], ["wizard", "--lang", "de"], ["wizard", "--lang", "en"], ["wizard", "--l", "ru", "--c", "out"],
    ["wizard", "--config-output"], ["wizard", "--json", "--json"], ["wizard", "--lang=ru", "--config-output=a/"],
    ["report"], ["report", "--config", "c"], ["report", "--o", "o", "--c", "c", "--j"],
    ["uninstall", "--purge-data", "--json"], ["uninstall", "--p"], ["uninstall", "--purge-data=yes"],
    ["reconcile-panel-update"], ["reconcile-panel-update", "--archive", "a"],
    ["reconcile-panel-update", "--s", "x", "--a", "y"], ["reconcile-panel-update", "--a", "y", "--s", "z", "--json"],
    ["resume", "--json"], ["repair", "-x"], ["repair", "--json", "extra", "--root", "/"],
    ["wizard", "-h"], ["plan", "-h"], ["install", "-h"], ["status", "-h"], ["resume", "-h"], ["repair", "-h"],
    ["report", "-h"], ["uninstall", "-h"], ["reconcile-panel-update", "-h"],
]

VERIFY = [
    [], ["-h"], ["x"], ["manifest"], ["manifest", "-h"], ["manifest", "m.json"], ["manifest", "m.json", "extra"],
    ["artifact", "m", "xray", "i386", "f"], ["artifact", "m", "xray", "amd64"], ["artifact", "-h"],
    ["artifact", "m", "n", "arm64", "f"], ["artifact", "--", "m", "n", "amd64", "f"],
]

HELP_WIDTHS = ("80", "40", "120", "20")


def run(make_parser, argv: list[str], columns: str) -> dict[str, object]:
    os.environ["COLUMNS"] = columns
    parser = make_parser()
    stdout, stderr = io.StringIO(), io.StringIO()
    record: dict[str, object] = {"argv": argv, "columns": int(columns)}
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            namespace = parser.parse_args(argv)
        except SystemExit as exc:
            record["exit"] = exc.code if isinstance(exc.code, int) else 1
        else:
            record["exit"] = None
            record["namespace"] = {
                key: (str(value) if isinstance(value, Path) else value) for key, value in sorted(vars(namespace).items())
            }
    record["stdout"] = stdout.getvalue()
    record["stderr"] = stderr.getvalue()
    return record


def main() -> int:
    from installer import cli

    sys.argv[0] = "proxy-control-installer verify-release"
    import verify  # release/verify.py

    records = {"installer": [], "verify": []}
    for argv in INSTALLER:
        widths = HELP_WIDTHS if any(a in ("-h", "--help", "--he") for a in argv) else ("80",)
        for columns in widths:
            records["installer"].append(run(cli._parser, argv, columns))
    for argv in VERIFY:
        widths = HELP_WIDTHS if "-h" in argv else ("80",)
        for columns in widths:
            records["verify"].append(run(verify._parser, argv, columns))
    json.dump(records, sys.stdout, ensure_ascii=False, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
