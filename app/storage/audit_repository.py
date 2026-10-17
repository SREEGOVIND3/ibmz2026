"""Append-only audit event store in SQLite (implements ``AuditStore``).

The hash chain itself is computed and verified by ``AuditService``; this class
only persists events and guarantees, inside one transaction, that each new
event extends the current head (``prev_hash`` must equal the stored head, or
the genesis hash for the first event). Together with ``UNIQUE(prev_hash)`` this
rejects forks and lost-update races, including from a second process.

Events are stored as canonical JSON, so ``iter_events`` returns exactly what
was appended and ``AuditService.verify`` can recompute every hash.

This is tamper-EVIDENT storage, not tamper-proof (see ``database.py``).
"""
from __future__ import annotations

import json
import sqlite3
from typing import Iterator, Mapping, Optional

from .database import Database, StorageError

# Must equal app.services.audit_service.GENESIS_HASH (asserted in tests).
GENESIS_HASH = "0" * 64
_BATCH = 500
_REQUIRED = ("event_id", "timestamp", "prev_hash", "hash")


def _dumps(event: Mapping) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _loads(text: str) -> dict:
    try:
        event = json.loads(text)
    except ValueError as exc:
        raise StorageError("audit row is unreadable") from exc
    if not isinstance(event, dict):
        raise StorageError("audit row is unreadable")
    return event


class AuditRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ---------------------------------------------------------- AuditStore API
    def append(self, event: Mapping) -> None:
        for key in _REQUIRED:
            if not isinstance(event.get(key), str) or not event[key]:
                raise StorageError(f"audit event is missing '{key}'")
        request_id = event.get("request_id")
        if request_id is not None and not isinstance(request_id, str):
            raise StorageError("audit event 'request_id' must be a string")
        try:
            body = _dumps(event)
        except (TypeError, ValueError) as exc:
            raise StorageError(f"audit event is not serialisable: {type(exc).__name__}") from exc
        with self._db.transaction() as conn:
            row = conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            head = row["hash"] if row else GENESIS_HASH
            if event["prev_hash"] != head:
                raise StorageError("audit chain conflict: prev_hash does not match the stored head")
            try:
                conn.execute(
                    """INSERT INTO audit_events
                       (event_id, request_id, timestamp, prev_hash, hash, event_json)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (event["event_id"], request_id, event["timestamp"],
                     event["prev_hash"], event["hash"], body),
                )
            except sqlite3.IntegrityError as exc:
                raise StorageError("audit append rejected: duplicate event id or hash") from exc

    def last_hash(self) -> Optional[str]:
        row = self._db.fetchone("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1")
        return row["hash"] if row else None

    def iter_events(self) -> Iterator[dict]:
        """Oldest first. Reads in batches so the DB lock is never held while
        the caller processes an event."""
        last_seq = 0
        while True:
            rows = self._db.fetchall(
                "SELECT seq, event_json FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?",
                (last_seq, _BATCH),
            )
            if not rows:
                return
            for row in rows:
                last_seq = row["seq"]
                yield _loads(row["event_json"])

    # ------------------------------------------------------------- query extras
    def count(self, request_id: Optional[str] = None) -> int:
        if request_id is None:
            return int(self._db.fetchone("SELECT COUNT(*) FROM audit_events")[0])
        return int(self._db.fetchone(
            "SELECT COUNT(*) FROM audit_events WHERE request_id = ?", (request_id,)
        )[0])

    def list_events(self, *, limit: int = 50, offset: int = 0, request_id: Optional[str] = None) -> list:
        """Newest first."""
        limit, offset = max(1, min(int(limit), 1000)), max(0, int(offset))
        if request_id is None:
            rows = self._db.fetchall(
                "SELECT event_json FROM audit_events ORDER BY seq DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        else:
            rows = self._db.fetchall(
                """SELECT event_json FROM audit_events WHERE request_id = ?
                   ORDER BY seq DESC LIMIT ? OFFSET ?""",
                (request_id, limit, offset),
            )
        return [_loads(r["event_json"]) for r in rows]

    def get(self, event_id: str) -> Optional[dict]:
        row = self._db.fetchone("SELECT event_json FROM audit_events WHERE event_id = ?", (event_id,))
        return _loads(row["event_json"]) if row else None
