"""One SQLite boundary for the panel: connections, pragmas and explicit transactions."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class DatabaseError(RuntimeError):
    pass


class Database:
    def __init__(self, path: Path, *, timeout: float = 10.0):
        self.path = Path(path)
        self.timeout = timeout
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            self._enable_wal(db)

    def _enable_wal(self, db) -> None:
        """Switch the file to WAL, waiting out whoever else holds it.

        Two processes open this database, so a cold start can collide. SQLite does not
        run the busy handler for a journal-mode change: the pragma fails outright while
        another connection holds the file, which used to kill the panel or the fleet
        ingress at startup. The pragma also reports the mode it ended up in, so a
        refusal that does not raise is caught too — silently staying in rollback mode
        would cost every reader its concurrency.
        """
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                mode = db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            except sqlite3.OperationalError:
                mode = None
            if mode == "wal":
                return
            if time.monotonic() >= deadline:
                raise DatabaseError(
                    f"could not enable write-ahead logging on {self.path}: the database stayed locked"
                )
            time.sleep(0.05)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=self.timeout)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        # Temporary storage in memory, never in a temp directory: the panel runs as an
        # unprivileged user on a read-only root filesystem, where SQLite may find no writable
        # temp directory at all. A statement journal that outgrows SQLite's in-memory
        # threshold (64 KiB) would then spill to disk and fail with "disk I/O error" — seen
        # on a central unlinking a node whose cascaded generations carried a few hundred KB.
        db.execute("PRAGMA temp_store=MEMORY")
        return db

    @contextmanager
    def transaction(self):
        """BEGIN IMMEDIATE … COMMIT, or ROLLBACK on any exception; the connection is closed after."""
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
