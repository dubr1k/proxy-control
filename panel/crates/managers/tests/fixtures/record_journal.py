"""Records the Telemt egress journal as the Python panel writes and reads it (WP5 golden).

    cd /root/dev/rust-panel-wp5 && PYTHONPATH=. /root/dev/proxy-control/.venv/bin/python \
        panel/crates/managers/tests/fixtures/record_journal.py > panel/crates/managers/tests/fixtures/telemt-journal.json
"""
from __future__ import annotations

import base64
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

from panel.protocols import AdapterError
from panel.protocols.telemt import TelemtAdapter
from panel.telemt import MemoryTelemt

JOURNAL = {
    "current": {
        "document": {"schema": 1, "upstream": {"provider": "router"}},
        "digest": "d" * 64,
        "operation_id": "op-1",
        "applied_at": 1761400000.25,
        "upstreams": [{"type": "socks5", "address": "xray-router-ingress:45103", "username": "telemt",
                       "weight": 1, "enabled": True, "note": "ключ"}],
    },
    "previous": None,
    "direct_upstreams": [{"type": "direct", "weight": 1, "enabled": True, "scopes": "", "ratio": 1e-05}],
}


def read_outcome(adapter):
    try:
        return {"kind": "ok", "value": adapter._journal_read()}
    except AdapterError as exc:
        return {"kind": "error", "message": str(exc), "code": exc.code}


def main():
    directory = Path(tempfile.mkdtemp(prefix="wp5-journal-"))
    path = directory / "telemt-egress.json"
    adapter = TelemtAdapter(MemoryTelemt(), public_host="proxy.example.com", journal_path=path)
    missing = read_outcome(adapter)
    adapter._journal_write(JOURNAL)
    written = path.read_bytes()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    leftovers = sorted(p.name for p in directory.iterdir())
    back = read_outcome(adapter)
    path.write_text("{not json")
    corrupt = read_outcome(adapter)
    path.write_text("[1]")
    listed = read_outcome(adapter)
    json.dump({"generator": "panel/crates/managers/tests/fixtures/record_journal.py", "journal": JOURNAL,
               "written_b64": base64.b64encode(written).decode(), "mode": mode, "files_after_write": leftovers,
               "read_missing": missing, "read_back": back, "read_corrupt": corrupt, "read_list": listed},
              sys.stdout, indent=1, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
