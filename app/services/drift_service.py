"""Compare current field profiles with the approved baseline.

Drift is *evidence that raises priority*; it never proves a violation. With an
empty baseline (cold start) every field is NEW_FIELD: bootstrap the baseline
from known-good payloads first.
"""
from __future__ import annotations

from ..config import DriftConfig
from ..schemas import DriftEvidence, DriftReport, DriftType, FieldProfile


def _ratio_similarity(x: float, y: float) -> float:
    hi, lo = max(x, y), min(x, y)
    return 1.0 if hi == 0 else lo / hi


class DriftService:
    def __init__(self, cfg: DriftConfig = DriftConfig()) -> None:
        self._cfg = cfg

    def detect(self, current: dict, baseline: dict) -> DriftReport:
        found: dict = {}
        new_paths = [p for p in current if p not in baseline]
        missing_paths = [p for p in baseline if p not in current]

        for path, profile in current.items():
            if path in baseline:
                found[path] = self._compare(profile, baseline[path])

        pairs = sorted(
            (
                (self._similarity(current[n], baseline[m]), n, m)
                for n in new_paths
                for m in missing_paths
            ),
            reverse=True,
        )
        used_new: set = set()
        used_missing: set = set()
        for sim, n, m in pairs:
            if sim < self._cfg.rename_similarity:
                break
            if n in used_new or m in used_missing:
                continue
            found[n] = DriftEvidence(
                n, DriftType.RENAME_MATCH,
                f"values resemble missing baseline field '{m}' (similarity {sim:.2f})",
                renamed_from=m,
            )
            used_new.add(n)
            used_missing.add(m)

        for n in new_paths:
            if n not in found:
                found[n] = DriftEvidence(n, DriftType.NEW_FIELD, "field absent from baseline")

        ordered = {p: found[p] for p in current}  # keep payload order
        missing = [
            DriftEvidence(m, DriftType.MISSING_FIELD, "baseline field absent from payload")
            for m in missing_paths
            if m not in used_missing
        ]
        return DriftReport(evidence=ordered, missing=missing)

    # ------------------------------------------------------------------ helpers
    def _compare(self, cur: FieldProfile, base: FieldProfile) -> DriftEvidence:
        cfg = self._cfg
        path = cur.schema_path

        newly = sorted(
            n for n, r in cur.validator_hits.items()
            if r >= cfg.pattern_current_min and base.validator_hits.get(n, 0.0) <= cfg.pattern_baseline_max
        )
        if newly:
            return DriftEvidence(
                path, DriftType.VALUE_PATTERN_SHIFT,
                "values now match validator(s): " + ", ".join(newly),
            )

        if cur.json_type != base.json_type and "null" not in (cur.json_type, base.json_type):
            return DriftEvidence(
                path, DriftType.TYPE_SHIFT, f"type {base.json_type} -> {cur.json_type}"
            )

        reasons = []
        if abs(cur.digit_ratio - base.digit_ratio) >= cfg.digit_ratio_delta:
            reasons.append(f"digit ratio {base.digit_ratio:.2f} -> {cur.digit_ratio:.2f}")
        if abs(cur.entropy - base.entropy) >= cfg.entropy_delta:
            reasons.append(f"entropy {base.entropy:.2f} -> {cur.entropy:.2f}")
        hi, lo = max(cur.mean_length, base.mean_length), min(cur.mean_length, base.mean_length)
        if hi - lo >= cfg.length_min_delta and (lo == 0 or hi / lo >= cfg.length_factor):
            reasons.append(f"mean length {base.mean_length:.0f} -> {cur.mean_length:.0f}")
        if reasons:
            return DriftEvidence(path, DriftType.DISTRIBUTION_SHIFT, "; ".join(reasons))

        return DriftEvidence(path, DriftType.NO_DRIFT)

    @staticmethod
    def _similarity(cur: FieldProfile, base: FieldProfile) -> float:
        """Statistical resemblance used only for rename matching (0..1)."""
        if cur.json_type != base.json_type:
            return 0.0
        parts = [
            _ratio_similarity(cur.mean_length, base.mean_length),
            1.0 - abs(cur.digit_ratio - base.digit_ratio),
            1.0 - abs(cur.alpha_ratio - base.alpha_ratio),
            1.0 - abs(cur.symbol_ratio - base.symbol_ratio),
            1.0 - min(1.0, abs(cur.entropy - base.entropy) / 5.0),
        ]
        score = sum(parts) / len(parts)
        shared = {n for n, r in cur.validator_hits.items() if r >= 0.4} & {
            n for n, r in base.validator_hits.items() if r >= 0.4
        }
        return min(1.0, score + 0.1) if shared else score
