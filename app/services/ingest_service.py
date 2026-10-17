"""Envelope validation and pipeline orchestration (kept free of HTTP concerns).

Order: parse -> flatten -> profile -> drift -> detect -> risk -> policy ->
enforce -> revalidate -> quarantine store -> AUDIT -> forward.
Safety properties:
  * any unexpected exception blocks forwarding (fail closed);
  * audit is written BEFORE forwarding, and an audit failure blocks forwarding;
  * the sanitized payload is returned only if it was actually forwarded.
"""
from __future__ import annotations

import re
import uuid
from typing import Callable, Mapping, Optional, Sequence

from ..config import Limits, Settings
from ..schemas import (
    Action, AuditStore, BaselineStore, DriftReport, FieldClassifier, IngestRequest,
    Outcome, PipelineResult, QuarantineStore, SpanDetector, Validators,
)
from .audit_service import AuditService
from .detection_service import DetectionService
from .drift_service import DriftService
from .enforcement_service import EnforcementService
from .normalization_service import flatten
from .policy_service import PolicyEngine
from .profiling_service import Profiler, merge_profiles
from .revalidation_service import RevalidationService
from .risk_service import RiskService

_ID = re.compile(r"[A-Za-z0-9._:\-]+")
_FORWARD_OUTCOMES = (Outcome.FORWARD_UNCHANGED, Outcome.FORWARD_SANITIZED)


class IngestError(ValueError):
    """Invalid envelope. Messages never include payload values."""


def parse_request(data: Mapping, limits: Limits = Limits()) -> IngestRequest:
    if not isinstance(data, Mapping):
        raise IngestError("request body must be a JSON object")

    def text(key: str, required: bool = True) -> Optional[str]:
        value = data.get(key)
        if value is None:
            if required:
                raise IngestError(f"'{key}' is required")
            return None
        if not isinstance(value, str) or not value.strip():
            raise IngestError(f"'{key}' must be a non-empty string")
        if len(value) > limits.max_id_len or not _ID.fullmatch(value):
            raise IngestError(f"'{key}' has invalid characters or is too long")
        return value

    payload = data.get("payload")
    if not isinstance(payload, dict):
        raise IngestError("'payload' must be a JSON object")
    return IngestRequest(
        request_id=text("request_id", required=False) or "req-" + uuid.uuid4().hex[:12],
        source_system=text("source_system"),
        purpose=text("processing_purpose"),
        destination=text("destination"),
        payload=payload,
    )


class IngestService:
    def __init__(
        self,
        *,
        settings: Settings,
        baseline: BaselineStore,
        profiler: Profiler,
        drift: DriftService,
        detection: DetectionService,
        risk: RiskService,
        policy: PolicyEngine,
        enforcement: EnforcementService,
        revalidation: RevalidationService,
        audit: AuditService,
        forward: Callable[[dict, IngestRequest], None],
        quarantine: Optional[QuarantineStore] = None,
    ) -> None:
        self._s = settings
        self._baseline = baseline
        self._profiler = profiler
        self._drift = drift
        self._detection = detection
        self._risk = risk
        self._policy = policy
        self._enforcement = enforcement
        self._revalidation = revalidation
        self._audit = audit
        self._forward = forward
        self._quarantine = quarantine

    # ------------------------------------------------------------------ baseline
    def approve_baseline(self, payload: dict) -> int:
        """Merge a known-good payload into the baseline; returns fields updated."""
        profiles = self._profiler.profile(flatten(payload, self._s.limits))
        existing = self._baseline.load_all()
        for path, profile in profiles.items():
            self._baseline.save(merge_profiles(existing[path], profile) if path in existing else profile)
        return len(profiles)

    # -------------------------------------------------------------------- handle
    def handle(self, data: Mapping) -> PipelineResult:
        req = parse_request(data, self._s.limits)  # IngestError -> caller (HTTP 422)
        outcome, error = Outcome.BLOCKED, None
        decisions: list = []
        detections: dict = {}
        report = DriftReport({}, [])
        enforcement = reval = None
        try:
            leaves = flatten(req.payload, self._s.limits)
            profiles = self._profiler.profile(leaves)
            report = self._drift.detect(profiles, self._baseline.load_all())
            detections = self._detection.detect(leaves, profiles, report.evidence)
            assessments = self._risk.assess(detections, report.evidence)
            result = self._policy.decide(assessments, report.evidence, req.purpose, req.destination)
            decisions = result.decisions
            enforcement = self._enforcement.enforce(req.payload, leaves, result)
            if enforcement.quarantined and self._quarantine is not None:
                self._quarantine.store(req.request_id, enforcement.quarantined)
            if enforcement.payload_quarantined:
                outcome = Outcome.QUARANTINED
            else:
                reval = self._revalidation.revalidate(enforcement, req.purpose, req.destination)
                if reval.passed:
                    changed = any(d.action is not Action.ALLOW for d in decisions)
                    outcome = Outcome.FORWARD_SANITIZED if changed else Outcome.FORWARD_UNCHANGED
        except Exception as exc:  # fail closed
            outcome, error = Outcome.BLOCKED, f"pipeline_error: {type(exc).__name__}"

        will_forward = outcome in _FORWARD_OUTCOMES
        try:  # no audit, no forward
            ids = self._write_audit(
                req, decisions, detections, report.evidence, outcome, will_forward, reval, error
            )
        except Exception as exc:
            return PipelineResult(
                req.request_id, Outcome.BLOCKED, self._actions(decisions), None,
                reval.passed if reval else False, False, [], [m.schema_path for m in report.missing],
                list(reval.violations) if reval else [], f"audit_error: {type(exc).__name__}",
            )

        forwarded = False
        if will_forward:
            try:
                self._forward(enforcement.sanitized_payload, req)
                forwarded = True
            except Exception as exc:
                outcome, error = Outcome.FORWARD_FAILED, f"forward_error: {type(exc).__name__}"
                try:
                    ids.append(self._audit.record({
                        "request_id": req.request_id, "field_path": "*", "outcome": outcome.value,
                        "action": Action.BLOCK_FORWARD.value, "payload_forwarded": False,
                        "reason": error,
                    })["event_id"])
                except Exception:
                    pass
        return PipelineResult(
            request_id=req.request_id,
            outcome=outcome,
            actions=self._actions(decisions),
            sanitized_payload=enforcement.sanitized_payload if forwarded else None,
            revalidated=bool(reval and reval.passed),
            forwarded=forwarded,
            audit_event_ids=ids,
            missing_fields=[m.schema_path for m in report.missing],
            violations=list(reval.violations) if reval else [],
            error=error,
        )

    # ------------------------------------------------------------------- helpers
    @staticmethod
    def _actions(decisions: Sequence) -> list:
        return [
            {
                "field_path": d.schema_path, "action": d.action.value,
                "severity": d.severity.name, "reason": d.reason,
                "flag_for_review": d.flag_for_review,
            }
            for d in decisions
        ]

    def _write_audit(self, req, decisions, detections, drift, outcome, forwarded, reval, error) -> list:
        t = self._s.thresholds
        ids: list = []
        for d in decisions:
            det = detections.get(d.schema_path)
            ids.append(self._audit.record({
                "request_id": req.request_id,
                "field_path": d.schema_path,
                "drift": drift[d.schema_path].drift_type.value if d.schema_path in drift else "NO_DRIFT",
                "validators": sorted(n for n, r in (det.validator_hits if det else {}).items() if r >= t.validator_medium),
                "classifier_probability": det.classifier_probability if det else None,
                "span_labels": sorted({s.hit.label for s in det.spans}) if det else [],
                "severity": d.severity.name,
                "action": d.action.value,
                "reason": d.reason,
                "raw_value_stored": d.action in (Action.QUARANTINE_FIELD, Action.QUARANTINE_PAYLOAD)
                and self._quarantine is not None,
                "payload_forwarded": forwarded,
                "flag_for_review": d.flag_for_review,
            })["event_id"])
        final_action = {
            Outcome.QUARANTINED: Action.QUARANTINE_PAYLOAD.value,
            Outcome.BLOCKED: Action.BLOCK_FORWARD.value,
        }.get(outcome, "FORWARD")
        reason = error or ("; ".join(reval.violations)[:500] if reval and reval.violations else outcome.value)
        ids.append(self._audit.record({
            "request_id": req.request_id, "field_path": "*", "outcome": outcome.value,
            "action": final_action, "reason": reason, "payload_forwarded": forwarded,
            "source_system": req.source_system, "purpose": req.purpose, "destination": req.destination,
        })["event_id"])
        return ids
