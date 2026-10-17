"""Encrypted quarantine store (implements ``QuarantineStore``).

What is stored
    * Raw quarantined values, encrypted with AES-256-GCM (``cryptography``),
      one random 96-bit nonce per item. The associated data binds each
      ciphertext to its item id, request id and schema path, so a ciphertext
      moved to another row fails authentication.
    * Clear-text metadata the analyst needs: ids, schema path, concrete path,
      kind, the policy reason string, status and the analyst decision.
      Metadata never contains the raw value. Schema/field names are stored in
      clear (they are also in the audit log); a JSON *key* that is itself
      sensitive would therefore be visible. Known limitation.

Keys
    ``CONSENTSHIELD_QUARANTINE_KEY`` = ``hex:<64 hex chars>`` or
    ``base64:<44 chars>`` (exactly 32 bytes). It must be a different secret from
    ``CONSENTSHIELD_HMAC_KEY`` and is never stored next to the ciphertext. There
    is no default: the loader fails closed. Software key held in the process
    environment: this is NOT hardware-backed key protection, and no IBM crypto
    hardware or key service is used by this module.

Analyst workflow
    ``record_decision`` is allowed once per item (PENDING -> APPROVED / REJECTED
    / UPDATED). APPROVE = analyst judges the quarantine unwarranted (field is
    safe); REJECT = quarantine confirmed (field is sensitive); UPDATE =
    reclassified with a ``label``. Notes are stored in clear: analysts must not
    paste raw values into them.

``reveal`` decrypts and is a privileged call: it is deliberately not exposed by
the HTTP API in ``main.py``.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import ConfigError
from ..schemas import QuarantineItem
from .database import Database, StorageError

ENV_KEY = "CONSENTSHIELD_QUARANTINE_KEY"
ENC_VERSION = 1
_NONCE_BYTES = 12
STATUSES = ("PENDING", "APPROVED", "REJECTED", "UPDATED")
_DECISIONS = {"APPROVE": "APPROVED", "REJECT": "REJECTED", "UPDATE": "UPDATED"}
MAX_NOTE_LEN = 500
MAX_LABEL_LEN = 64
MAX_ANALYST_LEN = 128


class QuarantineNotFound(StorageError):
    pass


class QuarantineAlreadyDecided(StorageError):
    pass


@dataclass(frozen=True)
class QuarantineRecord:
    item_id: str
    request_id: str
    schema_path: str
    path: tuple
    kind: Optional[str]
    reason: str
    status: str
    created_at: str
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_label: Optional[str] = None
    decision_note: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["path"] = list(self.path)
        return d


def generate_key_hex() -> str:
    """A fresh ``hex:`` key string, e.g. for ``export CONSENTSHIELD_QUARANTINE_KEY=...``."""
    return "hex:" + os.urandom(32).hex()


def load_quarantine_key(env: Optional[Mapping[str, str]] = None) -> bytes:
    """Fail closed: no default key, exactly 32 bytes."""
    env = os.environ if env is None else env
    raw = env.get(ENV_KEY)
    if not raw:
        raise ConfigError(f"{ENV_KEY} is not set")
    try:
        if raw.startswith("hex:"):
            key = bytes.fromhex(raw[4:])
        elif raw.startswith("base64:"):
            key = base64.b64decode(raw[7:], validate=True)
        else:
            raise ConfigError(f"{ENV_KEY} must start with 'hex:' or 'base64:'")
    except (ValueError, binascii.Error) as exc:
        raise ConfigError(f"{ENV_KEY} is not valid hex/base64") from exc
    if len(key) != 32:
        raise ConfigError(f"{ENV_KEY} must decode to exactly 32 bytes")
    return key


def _aad(item_id: str, request_id: str, schema_path: str) -> bytes:
    return f"consentshield/quarantine/v{ENC_VERSION}|{item_id}|{request_id}|{schema_path}".encode("utf-8")


def _kind_text(kind: Any) -> Optional[str]:
    if kind is None:
        return None
    return str(getattr(kind, "value", kind))


_COLUMNS = (
    "item_id, request_id, schema_path, path_json, kind, reason, status, created_at, "
    "decided_at, decided_by, decision_label, decision_note"
)


def _record(row: sqlite3.Row) -> QuarantineRecord:
    try:
        path = tuple(json.loads(row["path_json"]))
    except (TypeError, ValueError) as exc:
        raise StorageError("quarantine row is unreadable") from exc
    return QuarantineRecord(
        item_id=row["item_id"], request_id=row["request_id"], schema_path=row["schema_path"],
        path=path, kind=row["kind"], reason=row["reason"], status=row["status"],
        created_at=row["created_at"], decided_at=row["decided_at"], decided_by=row["decided_by"],
        decision_label=row["decision_label"], decision_note=row["decision_note"],
    )


class QuarantineRepository:
    def __init__(
        self,
        db: Database,
        key: bytes,
        *,
        clock: Optional[Callable[[], datetime]] = None,
        id_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise StorageError("quarantine key must be exactly 32 bytes")
        self._db = db
        self._aead = AESGCM(bytes(key))
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._new_id = id_factory or (lambda: "q-" + uuid.uuid4().hex[:16])

    def _now(self) -> str:
        return self._clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ------------------------------------------------------ QuarantineStore API
    def store(self, request_id: str, items: Sequence[QuarantineItem]) -> None:
        """Encrypt and persist all items atomically (all or none)."""
        if not items:
            return
        now = self._now()
        rows = []
        for item in items:
            item_id = self._new_id()
            try:
                plaintext = json.dumps({"value": item.raw_value}).encode("ascii")
                path_json = json.dumps(list(item.path))
            except (TypeError, ValueError) as exc:
                raise StorageError(f"quarantined value is not serialisable: {type(exc).__name__}") from exc
            nonce = os.urandom(_NONCE_BYTES)
            ciphertext = self._aead.encrypt(nonce, plaintext, _aad(item_id, request_id, item.schema_path))
            rows.append((
                item_id, request_id, item.schema_path, path_json, _kind_text(item.kind),
                item.reason, "PENDING", ENC_VERSION, nonce, ciphertext, now,
            ))
        with self._db.transaction() as conn:
            conn.executemany(
                """INSERT INTO quarantine_items
                   (item_id, request_id, schema_path, path_json, kind, reason, status,
                    enc_version, nonce, ciphertext, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )

    # ------------------------------------------------------------------ queries
    def list(self, *, status: Optional[str] = None, limit: int = 50, offset: int = 0) -> list:
        """Metadata only (never ciphertext or plaintext), newest first."""
        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        limit, offset = max(1, min(int(limit), 500)), max(0, int(offset))
        if status is None:
            rows = self._db.fetchall(
                f"SELECT {_COLUMNS} FROM quarantine_items ORDER BY created_at DESC, item_id LIMIT ? OFFSET ?",
                (limit, offset),
            )
        else:
            rows = self._db.fetchall(
                f"""SELECT {_COLUMNS} FROM quarantine_items WHERE status = ?
                    ORDER BY created_at DESC, item_id LIMIT ? OFFSET ?""",
                (status, limit, offset),
            )
        return [_record(r) for r in rows]

    def count(self, status: Optional[str] = None) -> int:
        if status is None:
            return int(self._db.fetchone("SELECT COUNT(*) FROM quarantine_items")[0])
        return int(self._db.fetchone(
            "SELECT COUNT(*) FROM quarantine_items WHERE status = ?", (status,)
        )[0])

    def get(self, item_id: str) -> Optional[QuarantineRecord]:
        row = self._db.fetchone(f"SELECT {_COLUMNS} FROM quarantine_items WHERE item_id = ?", (item_id,))
        return _record(row) if row else None

    def reveal(self, item_id: str) -> Any:
        """Decrypt and return the raw quarantined value. Privileged."""
        row = self._db.fetchone(
            """SELECT item_id, request_id, schema_path, enc_version, nonce, ciphertext
               FROM quarantine_items WHERE item_id = ?""",
            (item_id,),
        )
        if row is None:
            raise QuarantineNotFound("quarantine item not found")
        if row["enc_version"] != ENC_VERSION:
            raise StorageError(f"unsupported quarantine encryption version {row['enc_version']}")
        try:
            plaintext = self._aead.decrypt(
                bytes(row["nonce"]), bytes(row["ciphertext"]),
                _aad(row["item_id"], row["request_id"], row["schema_path"]),
            )
            return json.loads(plaintext.decode("ascii"))["value"]
        except InvalidTag as exc:
            raise StorageError(
                "quarantined value failed authentication (wrong key or altered record)"
            ) from exc
        except (ValueError, KeyError) as exc:
            raise StorageError("quarantined value is unreadable") from exc

    # ---------------------------------------------------------------- decisions
    def record_decision(
        self,
        item_id: str,
        decision: str,
        analyst: str,
        *,
        note: Optional[str] = None,
        label: Optional[str] = None,
    ) -> QuarantineRecord:
        if decision not in _DECISIONS:
            raise ValueError(f"decision must be one of {sorted(_DECISIONS)}")
        if not analyst or len(analyst) > MAX_ANALYST_LEN:
            raise ValueError("analyst is required and must be at most 128 characters")
        if note is not None and len(note) > MAX_NOTE_LEN:
            raise ValueError(f"note must be at most {MAX_NOTE_LEN} characters")
        if label is not None and (not label or len(label) > MAX_LABEL_LEN):
            raise ValueError(f"label must be 1-{MAX_LABEL_LEN} characters")
        if decision == "UPDATE" and not label:
            raise ValueError("UPDATE requires a label")
        with self._db.transaction() as conn:
            row = conn.execute(
                "SELECT status FROM quarantine_items WHERE item_id = ?", (item_id,)
            ).fetchone()
            if row is None:
                raise QuarantineNotFound("quarantine item not found")
            if row["status"] != "PENDING":
                raise QuarantineAlreadyDecided("quarantine item already has a decision")
            conn.execute(
                """UPDATE quarantine_items
                   SET status = ?, decided_at = ?, decided_by = ?, decision_label = ?, decision_note = ?
                   WHERE item_id = ?""",
                (_DECISIONS[decision], self._now(), analyst, label, note, item_id),
            )
        record = self.get(item_id)
        if record is None:  # unreachable unless the row vanished concurrently
            raise StorageError("quarantine item disappeared")
        return record
