"""Apply policy decisions to a copy of the payload.

Never mutates the caller's payload. Raw quarantined values are returned in
``QuarantineItem`` objects (repr-hidden) for the quarantine store to ENCRYPT;
this service neither logs nor persists them. Any inconsistency raises
``EnforcementError`` so the pipeline fails closed.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import re
from typing import Any, Sequence

from ..schemas import (
    Action, EnforcementResult, Kind, Leaf, PolicyDecision, PolicyResult, QuarantineItem,
)
from .normalization_service import get_at, set_at
from .profiling_service import value_text

TOKEN_PREFIX = "tok_"
_PLACEHOLDER = re.compile(r"\[(?:MASKED|REDACTED)_[A-Z_]+\]|tok_[0-9a-f]{32}")
_REMOVED = object()


class EnforcementError(RuntimeError):
    pass


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and _PLACEHOLDER.fullmatch(value) is not None


def strip_placeholders(text: str) -> str:
    """Remove our own mask/redaction/token markers before rescanning."""
    return _PLACEHOLDER.sub("", text)


def _prune(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _prune(v) for k, v in node.items() if v is not _REMOVED}
    if isinstance(node, list):
        return [_prune(v) for v in node if v is not _REMOVED]
    return node


def _contains_sentinel(node: Any) -> bool:
    if node is _REMOVED:
        return True
    if isinstance(node, dict):
        return any(_contains_sentinel(v) for v in node.values())
    if isinstance(node, list):
        return any(_contains_sentinel(v) for v in node)
    return False


class EnforcementService:
    def __init__(self, hmac_key: bytes) -> None:
        if len(hmac_key) < 16:
            raise EnforcementError("HMAC key must be at least 16 bytes")
        self._key = hmac.new(hmac_key, b"consentshield/token/v1", hashlib.sha256).digest()

    def tokenize(self, kind: Kind, text: str) -> str:
        """Deterministic keyed pseudonym (NOT anonymization)."""
        digest = hmac.new(self._key, f"{kind.name}:{text}".encode("utf-8"), hashlib.sha256)
        return TOKEN_PREFIX + digest.hexdigest()[:32]

    def enforce(self, payload: dict, leaves: Sequence[Leaf], result: PolicyResult) -> EnforcementResult:
        if result.payload_quarantined:
            trigger = next(d for d in result.decisions if d.action is Action.QUARANTINE_PAYLOAD)
            item = QuarantineItem("*", (), trigger.kind, trigger.reason, copy.deepcopy(payload))
            return EnforcementResult(
                sanitized_payload=None, payload_quarantined=True, quarantined=[item],
                applied=[(d.schema_path, d.action) for d in result.decisions],
            )

        sanitized = copy.deepcopy(payload)
        by_schema: dict = {}
        for leaf in leaves:
            by_schema.setdefault(leaf.schema_path, []).append(leaf)

        quarantined: list = []
        removed: list = []
        applied: list = []
        for d in result.decisions:
            applied.append((d.schema_path, d.action))
            if d.action is Action.ALLOW:
                continue
            targets = by_schema.get(d.schema_path, [])
            if d.action in (Action.MASK, Action.TOKENIZE):
                kind = d.kind or Kind.UNKNOWN_SENSITIVE
                for leaf in targets:
                    text = value_text(leaf.value)
                    if text is not None:
                        removed.append(text)
                    new = (
                        f"[MASKED_{kind.name}]" if d.action is Action.MASK
                        else self.tokenize(kind, text or "")
                    )
                    set_at(sanitized, leaf.path, new)
            elif d.action is Action.QUARANTINE_FIELD:
                for leaf in targets:
                    text = value_text(leaf.value)
                    if text is not None:
                        removed.append(text)
                    quarantined.append(
                        QuarantineItem(d.schema_path, leaf.path, d.kind, d.reason, leaf.value)
                    )
                    set_at(sanitized, leaf.path, _REMOVED)
            elif d.action is Action.REDACT_SPAN:
                self._redact(sanitized, d, removed)
            else:
                raise EnforcementError(f"unsupported action {d.action.value}")

        sanitized = _prune(sanitized)
        if _contains_sentinel(sanitized):  # defensive: must be unreachable
            raise EnforcementError("internal error: removal marker left in payload")
        return EnforcementResult(
            sanitized_payload=sanitized, payload_quarantined=False,
            quarantined=quarantined, removed_texts=removed, applied=applied,
        )

    @staticmethod
    def _redact(sanitized: dict, decision: PolicyDecision, removed: list) -> None:
        by_path: dict = {}
        for finding in decision.spans:
            by_path.setdefault(finding.located.path, []).append(finding)
        for path, findings in by_path.items():
            text = get_at(sanitized, path)
            if not isinstance(text, str):
                raise EnforcementError("span redaction target is not a string")
            ordered = sorted(findings, key=lambda f: (f.located.hit.start, -f.located.hit.end))
            merged: list = []  # [start, end, kind]
            for f in ordered:
                s, e = f.located.hit.start, f.located.hit.end
                if e > len(text):
                    raise EnforcementError("span offset outside text")
                if merged and s < merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], e)
                else:
                    merged.append([s, e, f.kind])
            pieces, cursor = [], 0
            for s, e, kind in merged:
                pieces.append(text[cursor:s])
                pieces.append(f"[REDACTED_{kind.name}]")
                removed.append(text[s:e])
                cursor = e
            pieces.append(text[cursor:])
            set_at(sanitized, path, "".join(pieces))
