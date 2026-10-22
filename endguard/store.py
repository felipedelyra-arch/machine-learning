"""Local append-only audit store (SQLite, 0600). Not tamper-proof against a local admin/owner."""
from __future__ import annotations

import json
import os
import sqlite3
import time

MIGRATIONS = [
    "CREATE TABLE decisions (decision_id TEXT PRIMARY KEY, ts REAL, rule_id TEXT, severity TEXT, action TEXT, body TEXT)",
    "CREATE TABLE health (ts REAL, body TEXT)",
    "CREATE TRIGGER decisions_no_update BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    # v4..v6: append-only for both tables. Guards against bugs/other code paths, NOT against the file owner.
    "CREATE TRIGGER decisions_no_delete BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER health_no_update BEFORE UPDATE ON health BEGIN SELECT RAISE(ABORT, 'append-only'); END",
    "CREATE TRIGGER health_no_delete BEFORE DELETE ON health BEGIN SELECT RAISE(ABORT, 'append-only'); END",
]


class Store:
    def __init__(self, path: str):
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)   # also tightens a pre-existing DB
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("BEGIN IMMEDIATE")
        ver = self.db.execute("PRAGMA user_version").fetchone()[0]
        for i, sql in enumerate(MIGRATIONS[ver:], start=ver):
            self.db.execute(sql)
            self.db.execute(f"PRAGMA user_version = {i + 1}")
        self.db.execute("COMMIT")

    def add_decision(self, d) -> None:
        body = d.to_dict()
        self.db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,?)",
                        (body["decision_id"], body["ts"], body["rule_id"], body["severity"], body["action"],
                         json.dumps(body)))

    def add_health(self, status: dict) -> None:
        self.db.execute("INSERT INTO health VALUES (?,?)", (time.time(), json.dumps(status)))

    def decisions(self, limit: int = 20) -> list[dict]:
        rows = self.db.execute("SELECT body FROM decisions ORDER BY ts DESC LIMIT ?", (limit,))
        return [json.loads(r[0]) for r in rows]

    def last_health(self) -> dict | None:
        r = self.db.execute("SELECT ts, body FROM health ORDER BY ts DESC LIMIT 1").fetchone()
        return {"recorded_at": r[0], **json.loads(r[1])} if r else None
