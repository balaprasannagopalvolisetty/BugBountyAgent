from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from aegis_bounty.models import Asset, ChainHypothesis, HttpExchange, Observation

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    scan_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (scan_id, hostname)
);
CREATE TABLE IF NOT EXISTS exchanges (
    scan_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (scan_id, request_id)
);
CREATE TABLE IF NOT EXISTS observations (
    scan_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS chains (
    scan_id TEXT NOT NULL,
    chain_index INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (scan_id, chain_index)
);
"""


class EvidenceStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.connection = sqlite3.connect(path)
        self.connection.executescript(SCHEMA)

    def close(self) -> None:
        self.connection.commit()
        self.connection.close()

    def __enter__(self) -> EvidenceStore:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def start_scan(self, scan_id: str, project: str, started_at: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO scans(scan_id, project, started_at) VALUES (?, ?, ?)",
            (scan_id, project, started_at),
        )
        self.connection.commit()

    def finish_scan(self, scan_id: str, finished_at: str) -> None:
        self.connection.execute(
            "UPDATE scans SET finished_at = ? WHERE scan_id = ?", (finished_at, scan_id)
        )
        self.connection.commit()

    def add_asset(self, scan_id: str, asset: Asset) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO assets VALUES (?, ?, ?)",
            (scan_id, asset.hostname, asset.model_dump_json()),
        )
        self.connection.commit()

    def add_exchange(self, scan_id: str, exchange: HttpExchange) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO exchanges VALUES (?, ?, ?)",
            (scan_id, exchange.request_id, exchange.model_dump_json()),
        )
        self.connection.commit()

    def add_observations(self, scan_id: str, observations: list[Observation]) -> int:
        before = self.connection.total_changes
        self.connection.executemany(
            "INSERT OR IGNORE INTO observations VALUES (?, ?, ?)",
            [(scan_id, item.fingerprint, item.model_dump_json()) for item in observations],
        )
        self.connection.commit()
        return self.connection.total_changes - before

    def add_chains(self, scan_id: str, chains: list[ChainHypothesis]) -> None:
        self.connection.executemany(
            "INSERT OR REPLACE INTO chains VALUES (?, ?, ?)",
            [(scan_id, index, chain.model_dump_json()) for index, chain in enumerate(chains)],
        )
        self.connection.commit()

    def observations(self, scan_id: str) -> list[Observation]:
        rows = self.connection.execute(
            "SELECT data FROM observations WHERE scan_id = ? ORDER BY fingerprint", (scan_id,)
        ).fetchall()
        return [Observation.model_validate_json(row[0]) for row in rows]

    def exchanges(self, scan_id: str) -> list[HttpExchange]:
        rows = self.connection.execute(
            "SELECT data FROM exchanges WHERE scan_id = ? ORDER BY request_id", (scan_id,)
        ).fetchall()
        return [HttpExchange.model_validate_json(row[0]) for row in rows]

    def assets(self, scan_id: str) -> list[Asset]:
        rows = self.connection.execute(
            "SELECT data FROM assets WHERE scan_id = ? ORDER BY hostname", (scan_id,)
        ).fetchall()
        return [Asset.model_validate_json(row[0]) for row in rows]

    def chains(self, scan_id: str) -> list[ChainHypothesis]:
        rows = self.connection.execute(
            "SELECT data FROM chains WHERE scan_id = ? ORDER BY chain_index", (scan_id,)
        ).fetchall()
        return [ChainHypothesis.model_validate_json(row[0]) for row in rows]

    def latest_scan_id(self) -> str:
        row = self.connection.execute(
            "SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ValueError(f"no scans found in {self.path}")
        return str(row[0])

    def scan_metadata(self, scan_id: str) -> dict[str, str | None]:
        row = self.connection.execute(
            "SELECT project, started_at, finished_at FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"scan not found: {scan_id}")
        return dict(zip(("project", "started_at", "finished_at"), row, strict=True))

    def export(self, scan_id: str) -> dict[str, object]:
        return {
            "scan_id": scan_id,
            "scan": self.scan_metadata(scan_id),
            "assets": [item.model_dump(mode="json") for item in self.assets(scan_id)],
            "exchanges": [item.model_dump(mode="json") for item in self.exchanges(scan_id)],
            "observations": [item.model_dump(mode="json") for item in self.observations(scan_id)],
            "chains": [item.model_dump(mode="json") for item in self.chains(scan_id)],
        }

    def export_json(self, scan_id: str) -> str:
        return json.dumps(self.export(scan_id), indent=2, sort_keys=True)
