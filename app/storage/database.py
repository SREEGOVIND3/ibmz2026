"""SQLite connection management and schema for ConsentShield.

Responsibility
    Own the single SQLite connection, serialise access to it, create/verify the
    schema, and give the repositories a small transaction helper. No business
    logic and no knowledge of what the repositories store.

Design notes
    * Standard library only (``sqlite3``), so there is no wheel to break on s390x.
      SQLite files are byte-order independent. Behaviour on the real s390x target
      is UNVERIFIED until it is run there.
    * One connection guarded by an ``RLock`` and shared by all repositories
      (``check_same_thread=False``). FastAPI runs sync endpoints in a thread pool,
      so this is required. It is a deliberate MVP choice: simple and correct,
      not high-throughput.
    * ``BEGIN IMMEDIATE`` transactions; ``synchronous=FULL`` so an acknowledged
      audit record survives a crash; WAL where the filesystem supports it
      (not network filesystems).
    * ``audit_events`` carries BEFORE UPDATE / BEFORE DELETE triggers that abort.
      That stops accidental or application-level edits. It is NOT tamper-proof:
      anyone who can write the file can drop the triggers. Tamper-EVIDENCE comes
      from the hash chain in ``audit_service`` plus an external anchor.
    * Transactions nest by joining the outer one (no savepoints). Do not call
      other locks (e.g. the audit service lock) from inside a transaction in a
      different order than the pipeline does, or you risk a deadlock.
    * Error messages carry exception type names only, never SQL parameters, so
      sensitive values cannot leak through exceptions.

Environment
    CONSENTSHIELD_DB_PATH   database file (default ``var/consentshield.db``);
                            ``:memory:`` is allowed for tests.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Mapping, Optional, Sequence

SCHEMA_VERSION = 1
ENV_DB_PATH = "CONSENTSHIELD_DB_PATH"
DEFAULT_DB_PATH = "var/consentshield.db"


class StorageError(RuntimeError):
    """Any storage failure. Messages never include stored values."""


_SCHEMA: tuple = (
    # Approved field profiles (hashes and statistics only; never raw values).
    """CREATE TABLE IF NOT EXISTS baseline_profiles (
        schema_path  TEXT PRIMARY KEY,
        profile_json TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    )""",
    # Append-only, hash-chained audit events. UNIQUE(prev_hash) makes a fork
    # of the chain impossible at the database level.
    """CREATE TABLE IF NOT EXISTS audit_events (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id   TEXT NOT NULL UNIQUE,
        request_id TEXT,
        timestamp  TEXT NOT NULL,
        prev_hash  TEXT NOT NULL UNIQUE,
        hash       TEXT NOT NULL UNIQUE,
        event_json TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_events(request_id)",
    """CREATE TRIGGER IF NOT EXISTS audit_events_no_update
       BEFORE UPDATE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
       BEFORE DELETE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    # Quarantined raw values: AES-256-GCM ciphertext + clear metadata.
    """CREATE TABLE IF NOT EXISTS quarantine_items (
        item_id        TEXT PRIMARY KEY,
        request_id     TEXT NOT NULL,
        schema_path    TEXT NOT NULL,
        path_json      TEXT NOT NULL,
        kind           TEXT,
        reason         TEXT NOT NULL,
        status         TEXT NOT NULL DEFAULT 'PENDING'
                       CHECK (status IN ('PENDING','APPROVED','REJECTED','UPDATED')),
        enc_version    INTEGER NOT NULL,
        nonce          BLOB NOT NULL,
        ciphertext     BLOB NOT NULL,
        created_at     TEXT NOT NULL,
        decided_at     TEXT,
        decided_by     TEXT,
        decision_label TEXT,
        decision_note  TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_items(status, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_quarantine_request ON quarantine_items(request_id)",
)


def resolve_db_path(env: Optional[Mapping[str, str]] = None) -> str:
    env = os.environ if env is None else env
    return env.get(ENV_DB_PATH) or DEFAULT_DB_PATH


class Database:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._depth = 0
        memory = self.path == ":memory:"
        fresh = False
        if not memory:
            target = Path(self.path).expanduser()
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise StorageError(f"cannot create database directory: {type(exc).__name__}") from exc
            fresh = not target.exists()
            self.path = str(target)
        try:
            self._conn = sqlite3.connect(
                self.path, check_same_thread=False, isolation_level=None, timeout=5.0
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA synchronous=FULL")
            self.journal_mode = "memory" if memory else str(
                self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            )
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open database: {type(exc).__name__}") from exc
        self._migrate()
        if fresh:
            try:  # best effort: the file holds ciphertext and audit data
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    # ------------------------------------------------------------------ schema
    def _migrate(self) -> None:
        with self._lock:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise StorageError(
                    f"database schema version {version} is newer than supported {SCHEMA_VERSION}"
                )
            if version < SCHEMA_VERSION:
                with self.transaction() as conn:
                    for statement in _SCHEMA:
                        conn.execute(statement)
                    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @property
    def schema_version(self) -> int:
        return int(self.fetchone("PRAGMA user_version")[0])

    # -------------------------------------------------------------- operations
    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block atomically. Re-entrant: an inner call joins the outer one."""
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield self._conn
                finally:
                    self._depth -= 1
                return
            try:
                self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise StorageError(f"cannot start transaction: {type(exc).__name__}") from exc
            self._depth = 1
            try:
                yield self._conn
            except BaseException as exc:
                self._depth = 0
                self._rollback()
                if isinstance(exc, sqlite3.Error):
                    raise StorageError(f"database error: {type(exc).__name__}") from exc
                raise
            self._depth = 0
            try:
                self._conn.execute("COMMIT")
            except sqlite3.Error as exc:
                self._rollback()
                raise StorageError(f"commit failed: {type(exc).__name__}") from exc

    def _rollback(self) -> None:
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def execute(self, sql: str, params: Sequence = ()) -> int:
        """Run one write statement (its own transaction unless one is open)."""
        try:
            with self._lock:
                return self._conn.execute(sql, params).rowcount
        except sqlite3.Error as exc:
            raise StorageError(f"database error: {type(exc).__name__}") from exc

    def fetchall(self, sql: str, params: Sequence = ()) -> list:
        try:
            with self._lock:
                return self._conn.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"database error: {type(exc).__name__}") from exc

    def fetchone(self, sql: str, params: Sequence = ()):
        try:
            with self._lock:
                return self._conn.execute(sql, params).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"database error: {type(exc).__name__}") from exc

    def ping(self) -> bool:
        return self.fetchone("SELECT 1")[0] == 1

    def integrity_check(self) -> str:
        return str(self.fetchone("PRAGMA integrity_check")[0])

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
