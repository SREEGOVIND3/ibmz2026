"""Explainable, purpose- and destination-aware policy decisions.

One decision per schema path. When field-level and span-level rules both fire,
the most restrictive action wins (QUARANTINE_PAYLOAD > QUARANTINE_FIELD >
MASK/TOKENIZE > REDACT_SPAN > ALLOW).

Decision table (see also DEFAULT_POLICY in config.py):
  authorized kind                          -> ALLOW (flag if drifted)
  unauthorized, new/renamed field          -> HIGH+: QUARANTINE_FIELD; MEDIUM: medium_action
  unauthorized, known field, major shift   -> QUARANTINE_FIELD
  unauthorized, known field, no drift      -> HIGH+: QUARANTINE_FIELD; MEDIUM: medium_action
  low risk (any drift)                     -> ALLOW (+ flag for review if drifted)
  unauthorized free-text spans             -> REDACT_SPAN (QUARANTINE_FIELD if repeated HIGH+)
  payload-quarantine kind at HIGH+         -> QUARANTINE_PAYLOAD
"""
from __future__ import annotations

from typing import Iterable, Mapping

from ..schemas import (
    ACTION_PRIORITY, NEW_TYPES, SHIFT_TYPES, Action, DriftEvidence, DriftType,
    Kind, PolicyDecision, PolicyResult, RiskAssessment, Severity,
)


class PolicyError(ValueError):
    pass


def _kinds(names: Iterable[str]) -> frozenset:
    try:
        return frozenset(Kind[n] for n in names)
    except KeyError as exc:
        raise PolicyError(f"unknown kind in policy: {exc.args[0]}") from exc


class PolicyEngine:
    def __init__(self, policy: Mapping) -> None:
        self._never = _kinds(policy.get("never_allow", []))
        self._payload_kinds = _kinds(policy.get("payload_quarantine_kinds", []))
        self._repeat = int(policy.get("repeat_quarantine_threshold", 3))
        medium = policy.get("medium_action", "MASK")
        if medium not in ("MASK", "TOKENIZE"):
            raise PolicyError("medium_action must be MASK or TOKENIZE")
        self._medium = Action(medium)
        self._shift_without_evidence = bool(policy.get("quarantine_on_shift_without_evidence", False))
        self._allow = {
            purpose: {dest: _kinds(kinds) for dest, kinds in dests.items()}
            for purpose, dests in policy.get("allow", {}).items()
        }

    # ------------------------------------------------------------ authorization
    def allowed_kinds(self, purpose: str, destination: str) -> frozenset:
        dests = self._allow.get(purpose, {})
        kinds = dests.get(destination, dests.get("*", frozenset()))
        return kinds - self._never

    def is_authorized(self, kind: Kind, purpose: str, destination: str) -> bool:
        return kind is not Kind.UNKNOWN_SENSITIVE and kind in self.allowed_kinds(purpose, destination)

    # ----------------------------------------------------------------- decision
    def decide(
        self,
        assessments: Mapping[str, RiskAssessment],
        drift: Mapping[str, DriftEvidence],
        purpose: str,
        destination: str,
    ) -> PolicyResult:
        decisions = []
        for path, a in assessments.items():
            dt = drift[path].drift_type if path in drift else DriftType.NO_DRIFT
            decisions.append(self._decide_one(a, dt, purpose, destination))
        return PolicyResult(
            decisions=decisions,
            payload_quarantined=any(d.action is Action.QUARANTINE_PAYLOAD for d in decisions),
        )

    def _decide_one(self, a, dt, purpose, destination) -> PolicyDecision:
        auth = lambda k: self.is_authorized(k, purpose, destination)  # noqa: E731
        drifted = dt is not DriftType.NO_DRIFT
        prefix = [e for e in a.evidence]

        def decision(action, severity, kind, why, flag=False, spans=()):
            reason = "; ".join(prefix + ([why] if why else []) + [f"action {action.value}"])
            if kind is not None:
                reason = f"kind {kind.name}; " + reason
            return PolicyDecision(a.schema_path, action, severity, kind, reason, flag, spans)

        # 1. Payload-level quarantine
        triggers = []
        if a.field_kind in self._payload_kinds and a.field_severity >= Severity.HIGH:
            triggers.append((a.field_severity, a.field_kind))
        triggers += [
            (f.severity, f.kind) for f in a.span_findings
            if f.kind in self._payload_kinds and f.severity >= Severity.HIGH
        ]
        if triggers:
            sev, kind = max(triggers, key=lambda t: t[0])
            return decision(Action.QUARANTINE_PAYLOAD, sev, kind, "payload-quarantine kind present", True)

        # 2. Field-level candidate
        fk, fs = a.field_kind, a.field_severity
        field_action, field_why = Action.ALLOW, ""
        if fk is None or fs < Severity.MEDIUM:
            if drifted and dt in SHIFT_TYPES and self._shift_without_evidence:
                field_action, field_why = Action.QUARANTINE_FIELD, "major shift without evidence (policy)"
            elif drifted:
                field_why = "drift without sensitive evidence; flagged for review"
        elif auth(fk):
            field_why = "kind authorized for purpose/destination"
        else:
            field_why = "kind not authorized for purpose/destination"
            if dt in SHIFT_TYPES:
                field_action = Action.QUARANTINE_FIELD
            elif fs >= Severity.HIGH:
                field_action = Action.QUARANTINE_FIELD
            else:
                field_action = self._medium

        # 3. Span-level candidate
        span_action, span_why, span_targets = Action.ALLOW, "", ()
        blocked = [f for f in a.span_findings if f.severity >= Severity.MEDIUM and not auth(f.kind)]
        if blocked:
            high = [f for f in blocked if f.severity >= Severity.HIGH]
            if len(high) >= self._repeat:
                span_action, span_why = Action.QUARANTINE_FIELD, f"{len(high)} high-risk spans (repeated)"
            else:
                span_action, span_why = Action.REDACT_SPAN, f"{len(blocked)} unauthorized span(s)"
            span_targets = tuple(blocked)

        # 4. Most restrictive wins
        if ACTION_PRIORITY[span_action] > ACTION_PRIORITY[field_action]:
            top = max(blocked, key=lambda f: f.severity)
            return decision(
                span_action, top.severity, top.kind, span_why, drifted,
                span_targets if span_action is Action.REDACT_SPAN else (),
            )
        flag = drifted or field_action is not Action.ALLOW
        return decision(field_action, a.severity, a.kind, field_why, flag)
