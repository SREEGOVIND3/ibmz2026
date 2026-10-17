"""Run independent detectors and keep each result separate.

* Profile-level validator hit ratios come from the profiler (no re-computation).
* Span detectors (deterministic scanners, GLiNER) implement ``SpanDetector``.
  A detector with ``required=True`` that raises makes detection FAIL CLOSED;
  an optional one (e.g. GLiNER) is recorded in ``errors`` and skipped, so the
  deterministic boundary keeps working without it.
* The classifier is optional and receives the profile + drift type; which
  features it uses (including validator ratios) is its own decision. If it
  reuses validator output it is not an independent second opinion.
"""
from __future__ import annotations

from typing import Mapping, Optional, Sequence

from ..schemas import (
    DriftEvidence, DriftType, FieldClassifier, FieldDetection, Leaf,
    LocatedSpan, SpanDetector,
)


class DetectionError(RuntimeError):
    pass


class DetectionService:
    def __init__(
        self,
        span_detectors: Sequence[SpanDetector],
        classifier: Optional[FieldClassifier] = None,
        *,
        min_span_text_len: int = 4,
    ) -> None:
        self._detectors = list(span_detectors)
        self._classifier = classifier
        self._min_len = min_span_text_len

    def detect(
        self,
        leaves: Sequence[Leaf],
        profiles: Mapping,
        drift: Mapping[str, DriftEvidence],
    ) -> dict:
        out: dict = {}
        for path, profile in profiles.items():
            det = FieldDetection(schema_path=path, validator_hits=dict(profile.validator_hits))
            if self._classifier is not None:
                dt = drift[path].drift_type if path in drift else DriftType.NO_DRIFT
                try:
                    prob, why = self._classifier.predict(profile, dt)
                    det.classifier_probability = float(prob)
                    det.classifier_explanation = tuple(why)
                except Exception as exc:  # classifier is optional
                    det.errors.append(f"classifier: {type(exc).__name__}")
            out[path] = det

        for leaf in leaves:
            if not isinstance(leaf.value, str) or len(leaf.value) < self._min_len:
                continue
            det = out[leaf.schema_path]
            text_like = profiles[leaf.schema_path].is_text_like
            for detector in self._detectors:
                if detector.text_only and not text_like:
                    continue
                try:
                    hits = list(detector.detect(leaf.value))
                except Exception as exc:
                    if detector.required:
                        # Message deliberately excludes the text being scanned.
                        raise DetectionError(
                            f"required detector '{detector.name}' failed: {type(exc).__name__}"
                        ) from exc
                    det.errors.append(f"{detector.name}: {type(exc).__name__}")
                    continue
                for hit in hits:
                    if 0 <= hit.start < hit.end <= len(leaf.value) and 0.0 <= hit.score <= 1.0:
                        det.spans.append(LocatedSpan(leaf.path, hit))
                    elif detector.required:
                        raise DetectionError(
                            f"required detector '{detector.name}' returned an invalid span"
                        )
                    else:
                        det.errors.append(f"{detector.name}: invalid span dropped")
        return out
