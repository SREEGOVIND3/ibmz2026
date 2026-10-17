"""Mandatory post-enforcement rescan. FAILS CLOSED.

Rules: block if the payload was quarantined/non-forwardable; if any unauthorized
finding at MEDIUM+ remains; if any removed/redacted value is still present
(substring check, whitespace/hyphen-insensitive); or if the rescan itself raises
(including a *required* detector failing). Violations never contain raw values.
Optional-detector failures are reported in ``detector_errors`` but do not block.
"""
from __future__ import annotations

import re
from typing import Optional

from ..schemas import EnforcementResult, Kind, Leaf, RevalidationResult, Severity
from .detection_service import DetectionService
from .enforcement_service import strip_placeholders
from .normalization_service import flatten
from .policy_service import PolicyEngine
from .profiling_service import Profiler
from .risk_service import RiskService
from ..config import Limits

_NORMALIZE = re.compile(r"[\s\-]+")


def _norm(text: str) -> str:
    return _NORMALIZE.sub("", text).lower()


class RevalidationService:
    def __init__(
        self,
        profiler: Profiler,
        detection: DetectionService,
        risk: RiskService,
        policy: PolicyEngine,
        *,
        limits: Limits = Limits(),
        leak_min_len: int = 6,
        block_on_classifier_only: bool = False,
    ) -> None:
        self._profiler = profiler
        self._detection = detection
        self._risk = risk
        self._policy = policy
        self._limits = limits
        self._leak_min_len = leak_min_len
        self._block_classifier_only = block_on_classifier_only

    def revalidate(self, enforcement: EnforcementResult, purpose: str, destination: str) -> RevalidationResult:
        if enforcement.payload_quarantined or enforcement.sanitized_payload is None:
            return RevalidationResult(False, ["payload is quarantined or has no sanitized form"])
        try:
            return self._scan(enforcement, purpose, destination)
        except Exception as exc:  # fail closed on ANY rescan failure
            return RevalidationResult(False, [f"revalidation error: {type(exc).__name__}"])

    def _scan(self, enforcement, purpose, destination) -> RevalidationResult:
        payload = enforcement.sanitized_payload
        leaves = []
        for leaf in flatten(payload, self._limits):
            value = leaf.value
            if isinstance(value, str):
                value = strip_placeholders(value)
                if not value.strip():
                    continue
            leaves.append(Leaf(leaf.schema_path, leaf.path, value))

        profiles = self._profiler.profile(leaves)
        detections = self._detection.detect(leaves, profiles, {})
        assessments = self._risk.assess(detections, {})

        violations: list = []
        errors: list = []
        for path, det in detections.items():
            errors.extend(f"{path}: {e}" for e in det.errors)
            a = assessments[path]
            if a.field_kind is not None and a.field_severity >= Severity.MEDIUM:
                counts = a.field_kind is not Kind.UNKNOWN_SENSITIVE or self._block_classifier_only
                if counts and not self._policy.is_authorized(a.field_kind, purpose, destination):
                    violations.append(
                        f"{path}: restricted {a.field_kind.name} remains in field (severity {a.field_severity.name})"
                    )
            for f in a.span_findings:
                if f.severity >= Severity.MEDIUM and not self._policy.is_authorized(f.kind, purpose, destination):
                    violations.append(
                        f"{path}: restricted {f.kind.name} span remains (severity {f.severity.name})"
                    )

        remaining = [(l.schema_path, _norm(l.value)) for l in leaves if isinstance(l.value, str)]
        seen: set = set()
        for raw in enforcement.removed_texts:
            needle = _norm(raw)
            if len(needle) < self._leak_min_len:
                continue
            for path, hay in remaining:
                if needle in hay and (path, needle) not in seen:
                    seen.add((path, needle))
                    violations.append(f"{path}: a removed value is still present")
        return RevalidationResult(passed=not violations, violations=violations, detector_errors=errors)
