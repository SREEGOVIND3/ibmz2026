"""Tamper-EVIDENT audit log (SHA-256 hash chain). Not tamper-proof.

Detects: modified records, reordered records, deleted middle records.
Does NOT detect, without an external anchor: truncation of the tail, or a
rewrite of the whole chain by someone who can write the store. ``verify`` takes
``expected_head`` / ``expected_count`` (kept somewhere the attacker cannot
write) to close those gaps.

Only whitelisted fields can be written, and values must be JSON primitives or
lists of primitives, so raw payload data cannot be logged by accident.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional

from ..schemas import AuditStore

GENESIS_HASH = "0" * 64

ALLOWED_FIELDS = frozenset({
    "request_id", "field_path", "drift", "validators", "classifier_probability",
    "span_labels", "severity", "action", "outcome", "reason", "raw_value_stored",
    "payload_forwarded", "flag_for_review", "source_system", "purpose", "destination",
})


class AuditError(RuntimeError):
    pass


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    head: Optional[str]
    reason: str = ""
    first_bad_index: Optional[int] = None


def _canonical(event: Mapping) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(event_without_hash: Mapping, prev_hash: str) -> str:
    return hashlib.sha256((prev_hash + _canonical(event_without_hash)).encode("ascii")).hexdigest()


def _is_primitive(v) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


class AuditService:
    def __init__(
        self,
        store: AuditStore,
        *,
        clock: Optional[Callable[[], datetime]] = None,
        id_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        self._store = store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._new_id = id_factory or (lambda: "evt-" + uuid.uuid4().hex[:16])
        self._lock = threading.Lock()  # single-process only

    def record(self, fields: Mapping) -> dict:
        unknown = set(fields) - ALLOWED_FIELDS
        if unknown:
            raise AuditError(f"field(s) not allowed in audit events: {sorted(unknown)}")
        for key, value in fields.items():
            ok = _is_primitive(value) or (
                isinstance(value, (list, tuple)) and all(_is_primitive(v) for v in value)
            )
            if not ok:
                raise AuditError(f"audit field '{key}' must be a primitive or list of primitives")
        with self._lock:
            event = {k: (list(v) if isinstance(v, tuple) else v) for k, v in fields.items()}
            event["event_id"] = self._new_id()
            event["timestamp"] = self._clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            prev = self._store.last_hash() or GENESIS_HASH
            event["prev_hash"] = prev
            event["hash"] = compute_hash({k: v for k, v in event.items() if k != "hash"}, prev)
            self._store.append(event)
            return event

    def verify(self, *, expected_head: Optional[str] = None, expected_count: Optional[int] = None) -> VerifyResult:
        prev, count = GENESIS_HASH, 0
        for index, event in enumerate(self._store.iter_events()):
            body = {k: v for k, v in event.items() if k != "hash"}
            if event.get("prev_hash") != prev:
                return VerifyResult(False, count, None, "chain link broken (record removed, reordered or altered)", index)
            if compute_hash(body, prev) != event.get("hash"):
                return VerifyResult(False, count, None, "record contents do not match their hash", index)
            prev, count = event["hash"], count + 1
        head = prev if count else None
        if expected_count is not None and count != expected_count:
            return VerifyResult(False, count, head, f"expected {expected_count} records, found {count}")
        if expected_head is not None and head != expected_head:
            return VerifyResult(False, count, head, "head hash differs from the external anchor")
        return VerifyResult(True, count, head)
