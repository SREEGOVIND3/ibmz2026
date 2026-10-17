"""Interpret detector evidence as severity + data kind (no authorization here).

Detectors emit labels and scores. This service maps them to ``Kind`` and applies
detector-specific thresholds; scores are never merged into one number.
Authorization (is this kind allowed for this purpose/destination?) is the
policy service's job.
"""
from __future__ import annotations

from collections import Counter
from typing import Mapping, Optional

from ..config import Thresholds
from ..schemas import (
    DriftEvidence, DriftType, Kind, RiskAssessment, Severity, SpanFinding,
)

CRITICAL_KINDS = frozenset(
    {Kind.GOVERNMENT_ID, Kind.CARD_NUMBER, Kind.CREDENTIAL, Kind.MEDICAL_RECORD}
)

DEFAULT_VALIDATOR_KINDS = {
    "EMAIL": Kind.CONTACT,
    "PHONE": Kind.CONTACT,
    "PAN": Kind.GOVERNMENT_ID,
    "AADHAAR": Kind.GOVERNMENT_ID,
    "CARD": Kind.CARD_NUMBER,
    "IFSC": Kind.BANK_ACCOUNT,
    "API_KEY": Kind.CREDENTIAL,
    "IPV4": Kind.NETWORK,
}

DEFAULT_LABEL_KINDS = {
    "PERSON": Kind.PERSONAL,
    "DATE_OF_BIRTH": Kind.PERSONAL,
    "EMAIL_ADDRESS": Kind.CONTACT,
    "PHONE_NUMBER": Kind.CONTACT,
    "GOVERNMENT_ID": Kind.GOVERNMENT_ID,
    "CREDIT_CARD_NUMBER": Kind.CARD_NUMBER,
    "BANK_ACCOUNT": Kind.BANK_ACCOUNT,
    "MEDICAL_RECORD": Kind.MEDICAL_RECORD,
    "DIAGNOSIS": Kind.HEALTH,
    "PASSWORD": Kind.CREDENTIAL,
    "API_KEY": Kind.CREDENTIAL,
}

_NONE, _MEDIUM, _STRONG = 0, 1, 2


def _band(value: float, high: float, medium: float) -> int:
    return _STRONG if value >= high else _MEDIUM if value >= medium else _NONE


def severity_for(kind: Kind, strength: int, drifted: bool) -> Severity:
    if strength == _NONE:
        return Severity.LOW
    if kind in CRITICAL_KINDS:
        return Severity.CRITICAL if strength == _STRONG else Severity.HIGH
    if strength == _STRONG and drifted:
        return Severity.HIGH
    return Severity.MEDIUM


class RiskService:
    def __init__(
        self,
        thresholds: Thresholds = Thresholds(),
        validator_kinds: Optional[Mapping[str, Kind]] = None,
        label_kinds: Optional[Mapping[str, Kind]] = None,
    ) -> None:
        self._t = thresholds
        self._validator_kinds = dict(validator_kinds or DEFAULT_VALIDATOR_KINDS)
        self._label_kinds = dict(label_kinds or DEFAULT_LABEL_KINDS)

    def kind_for_label(self, label: str) -> Kind:
        if label in self._label_kinds:
            return self._label_kinds[label]
        try:
            return Kind[label]
        except KeyError:
            return Kind.UNKNOWN_SENSITIVE

    def assess(self, detections: Mapping, drift: Mapping[str, DriftEvidence]) -> dict:
        t = self._t
        out: dict = {}
        for path, det in detections.items():
            dt = drift[path].drift_type if path in drift else DriftType.NO_DRIFT
            drifted = dt is not DriftType.NO_DRIFT
            evidence: list = []
            if drifted:
                detail = drift[path].detail
                evidence.append(f"{dt.value}" + (f" ({detail})" if detail else ""))

            candidates: list = []  # (severity, is_known_kind, kind)
            for name, ratio in det.validator_hits.items():
                strength = _band(ratio, t.validator_high, t.validator_medium)
                if strength:
                    kind = self._validator_kinds.get(name, Kind.UNKNOWN_SENSITIVE)
                    evidence.append(f"validator {name} hit ratio {ratio:.2f}")
                    candidates.append(
                        (severity_for(kind, strength, drifted), kind is not Kind.UNKNOWN_SENSITIVE, kind)
                    )
            prob = det.classifier_probability
            if prob is not None:
                strength = _band(prob, t.classifier_high, t.classifier_medium)
                if strength:
                    evidence.append(f"field classifier probability {prob:.2f}")
                    candidates.append(
                        (severity_for(Kind.UNKNOWN_SENSITIVE, strength, drifted), False, Kind.UNKNOWN_SENSITIVE)
                    )
            field_sev, field_kind = Severity.LOW, None
            if candidates:
                best = max(candidates, key=lambda c: (c[0], c[1]))
                field_sev, field_kind = best[0], best[2]

            findings: list = []
            for located in det.spans:
                strength = _band(located.hit.score, t.span_high, t.span_medium)
                if not strength:
                    continue
                kind = self.kind_for_label(located.hit.label)
                findings.append(SpanFinding(located, severity_for(kind, strength, drifted), kind))
            if findings:
                counts = Counter(f.located.hit.label for f in findings)
                evidence.append(
                    "text spans: " + ", ".join(f"{k} x{v}" for k, v in sorted(counts.items()))
                )

            severity, kind = field_sev, field_kind
            for f in findings:
                if f.severity > severity:
                    severity, kind = f.severity, f.kind
            out[path] = RiskAssessment(
                schema_path=path, severity=severity, kind=kind,
                field_severity=field_sev, field_kind=field_kind,
                span_findings=findings, drift=dt, evidence=tuple(evidence),
                classifier_probability=prob,
            )
        return out
