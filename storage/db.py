"""
SQLite storage. Each run is saved as a scan with its own id,
so you can compare runs or rebuild a report without re-scanning.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from core.models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label      TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER,
    node_id    TEXT,
    type       TEXT,
    value      TEXT,
    source     TEXT,
    parent     TEXT,
    confidence REAL,
    depth      INTEGER,
    tier       TEXT,
    meta       TEXT,
    found_at   TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS edges (
    scan_id INTEGER,
    parent_node TEXT,
    child_node  TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


class Storage:
    def __init__(self, path: str = "zerosint.db") -> None:
        self.con = sqlite3.connect(path)
        self.con.executescript(SCHEMA)
        self.con.commit()

    def new_scan(self, label: str) -> int:
        cur = self.con.execute(
            "INSERT INTO scans(label, created_at) VALUES (?, ?)",
            (label, datetime.now(timezone.utc).isoformat()),
        )
        self.con.commit()
        return cur.lastrowid

    def save(self, scan_id: int, results: dict[str, Finding],
             edges: list[tuple[str, str]]) -> None:
        rows = [
            (
                scan_id, f.node_id, f.type, f.value, f.source, f.parent,
                f.confidence, f.depth, f.meta.get("tier", "low"),
                json.dumps(f.meta, ensure_ascii=False), f.found_at,
            )
            for f in results.values()
        ]
        self.con.executemany(
            """INSERT INTO findings
               (scan_id, node_id, type, value, source, parent,
                confidence, depth, tier, meta, found_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        self.con.executemany(
            "INSERT INTO edges(scan_id, parent_node, child_node) VALUES (?,?,?)",
            [(scan_id, p, c) for p, c in edges],
        )
        self.con.commit()

    def close(self) -> None:
        self.con.close()
