"""Who this panel is: one GUID per database, minted on first use (spec §4), and the
release version it reports to a central panel."""
from __future__ import annotations

import time
import uuid
from pathlib import Path

GUID_KEY = "panel_guid"
MASTER_KEY = "fleet_master_guid"


def read_setting(db, key: str) -> str | None:
    row = db.execute("SELECT value FROM panel_settings WHERE key=?", (key,)).fetchone()
    return None if row is None else row["value"]


def write_setting(db, key: str, value: str | None) -> None:
    if value is None:
        db.execute("DELETE FROM panel_settings WHERE key=?", (key,))
        return
    db.execute(
        "INSERT INTO panel_settings(key,value,updated_at) VALUES(?,?,?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, int(time.time())),
    )


def read_panel_version(path: Path) -> str:
    """The release's VERSION, or "dev" when the file is missing, unreadable or empty:
    a bad mode on a copied file must never keep the panel from starting."""
    try:
        return path.read_text().strip() or "dev"
    except OSError:
        return "dev"


def ensure_guid(database) -> str:
    with database.transaction() as db:
        found = read_setting(db, GUID_KEY)
        if found:
            return found
        value = str(uuid.uuid4())
        write_setting(db, GUID_KEY, value)
        return value
