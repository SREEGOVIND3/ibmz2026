"""Lightweight, explainable field-risk classifier for ConsentShield.

Responsibility
    Estimate P(field carries sensitive data) from the field name/path, a small
    sample of its values, validator evidence and drift category, and explain
    the estimate with per-feature contributions.

Design notes
    * Training uses scikit-learn logistic regression (imported lazily inside
      ``fit``). *Inference uses numpy only* and the model is stored as JSON
      (weights + config), so there is no pickle and no byte-order dependence
      when a model trained on x86 is loaded on s390x. Cross-platform loading is
      UNVERIFIED until it is run on the target.
    * Name features are hashed character n-grams (crc32, stable across
      platforms) so ``guardian_uid`` shares n-grams with ``uid``.
    * Features are grouped (name / value / drift / structure) so the ablation
      notebook can switch groups off.
    * Probabilities are NOT calibrated; thresholds are tuned on validation data.
    * Never stores or logs raw values; only aggregate statistics are used.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from app.detectors import validators as V

DRIFT_CATEGORIES = ("NO_DRIFT", "NEW_FIELD", "TYPE_SHIFT", "DISTRIBUTION_SHIFT", "RENAME_MATCH")
FORMAT_VERSION = 1

_VALUE_FEATURES = (
    ["v_len", "v_entropy", "v_digit", "v_alpha", "v_symbol", "v_space", "v_json_numeric"]
    + [f"v_val_{n.lower()}" for n in V.VALIDATOR_NAMES]
    + ["v_embedded_any"]
)
_DRIFT_FEATURES = ["d_new_field", "d_type_shift", "d_dist_shift", "d_rename_match"]
_STRUCT_FEATURES = ["s_depth"]
NUMERIC_FEATURES: Tuple[str, ...] = tuple(_VALUE_FEATURES + _DRIFT_FEATURES + _STRUCT_FEATURES)


@dataclass(frozen=True)
class ClassifierConfig:
    n_hash: int = 2048
    ngram_min: int = 2
    ngram_max: int = 4
    C: float = 1.0
    seed: int = 13
    max_sample: int = 50
    threshold_high: float = 0.70
    threshold_medium: float = 0.40
    use_name: bool = True
    use_value: bool = True
    use_drift: bool = True
    use_structure: bool = True


@dataclass
class FieldObservation:
    """What the classifier sees about one field.

    ``values`` is a small sample of JSON leaf values for the field path (one
    value per request at gateway time, more when profiled from a baseline).
    ``drift_category`` comes from the drift service (or the data generator).
    """

    field_path: str
    values: Sequence[Any] = field(default_factory=list)
    drift_category: str = "NO_DRIFT"


@dataclass(frozen=True)
class Contribution:
    feature: str
    contribution: float  # weight * feature value, in log-odds


@dataclass(frozen=True)
class FieldRisk:
    probability: float
    band: str  # HIGH / MEDIUM / LOW
    contributions: Tuple[Contribution, ...]
    model_version: str

    def summary(self, k: int = 3) -> str:
        top = ", ".join(f"{c.feature} {c.contribution:+.2f}" for c in self.contributions[:k])
        return f"field classifier p={self.probability:.2f} ({self.band}); top: {top}"


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #
def _segments(field_path: str) -> List[str]:
    return [s.replace("[]", "") for s in field_path.split(".") if s.replace("[]", "")]


def _tokens(segment: str) -> List[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", segment)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def name_features(field_path: str, ngram_min: int = 2, ngram_max: int = 4) -> List[str]:
    """Hashable name features: char n-grams, whole tokens, parent tokens."""
    segs = _segments(field_path)
    if not segs:
        return []
    feats: List[str] = []
    for tok in _tokens(segs[-1]):
        feats.append(f"t:{tok}")
        padded = f" {tok} "
        for n in range(ngram_min, ngram_max + 1):
            for i in range(len(padded) - n + 1):
                feats.append(f"n:{padded[i:i + n]}")
    if len(segs) > 1:
        for tok in _tokens(segs[-2]):
            feats.append(f"p:{tok}")
    return list(dict.fromkeys(feats))  # dedupe, keep order


def _hash(feature: str, n_hash: int) -> int:
    return zlib.crc32(feature.encode("utf-8")) % n_hash


def _value_stats(values: Sequence[Any], max_sample: int) -> Dict[str, float]:
    texts: List[str] = []
    numeric_typed = 0
    seen = 0
    for v in values:
        t = V.to_text(v)
        if t is None or not t.strip():
            continue
        seen += 1
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            numeric_typed += 1
        texts.append(t[:256])
        if seen >= max_sample:
            break
    out = {name: 0.0 for name in _VALUE_FEATURES}
    if not texts:
        return out
    n = len(texts)
    lens = [len(t) for t in texts]
    out["v_len"] = min(1.0, math.log1p(sum(lens) / n) / math.log1p(256))
    out["v_entropy"] = min(1.0, (sum(V.shannon_entropy(t) for t in texts) / n) / 6.0)
    total_chars = max(1, sum(lens))
    out["v_digit"] = sum(c.isdigit() for t in texts for c in t) / total_chars
    out["v_alpha"] = sum(c.isalpha() for t in texts for c in t) / total_chars
    out["v_space"] = sum(c.isspace() for t in texts for c in t) / total_chars
    out["v_symbol"] = max(0.0, 1.0 - out["v_digit"] - out["v_alpha"] - out["v_space"])
    out["v_json_numeric"] = numeric_typed / n
    whole = V.field_hit_ratios(texts, embedded=False, max_values=max_sample)
    for name, ratio in whole.items():
        out[f"v_val_{name.lower()}"] = ratio
    emb = V.field_hit_ratios(texts, embedded=True, max_values=max_sample)
    out["v_embedded_any"] = max(emb.values()) if emb else 0.0
    return out


class FieldRiskClassifier:
    """Logistic-regression field-risk model with numpy-only inference."""

    def __init__(self, config: Optional[ClassifierConfig] = None):
        self.config = config or ClassifierConfig()
        self.coef_: Optional[np.ndarray] = None
        self.intercept_: float = 0.0
        self.meta: Dict[str, Any] = {}

    # -- feature construction ------------------------------------------------
    @property
    def n_features(self) -> int:
        return self.config.n_hash + len(NUMERIC_FEATURES)

    def featurize(self, obs: FieldObservation) -> Tuple[Dict[int, List[str]], np.ndarray]:
        """Return (hash index -> name features, numeric vector)."""
        cfg = self.config
        hashed: Dict[int, List[str]] = {}
        if cfg.use_name:
            for f in name_features(obs.field_path, cfg.ngram_min, cfg.ngram_max):
                hashed.setdefault(_hash(f, cfg.n_hash), []).append(f)
        numeric = np.zeros(len(NUMERIC_FEATURES), dtype=np.float64)
        idx = {n: i for i, n in enumerate(NUMERIC_FEATURES)}
        if cfg.use_value:
            for name, val in _value_stats(obs.values, cfg.max_sample).items():
                numeric[idx[name]] = val
        if cfg.use_drift:
            numeric[idx["d_new_field"]] = float(obs.drift_category == "NEW_FIELD")
            numeric[idx["d_type_shift"]] = float(obs.drift_category == "TYPE_SHIFT")
            numeric[idx["d_dist_shift"]] = float(obs.drift_category == "DISTRIBUTION_SHIFT")
            numeric[idx["d_rename_match"]] = float(obs.drift_category == "RENAME_MATCH")
        if cfg.use_structure:
            numeric[idx["s_depth"]] = min(1.0, len(_segments(obs.field_path)) / 6.0)
        return hashed, numeric

    def _design_matrix(self, observations: Sequence[FieldObservation]):
        from scipy import sparse  # lazy: only needed for training

        rows: List[int] = []
        cols: List[int] = []
        data: List[float] = []
        for r, obs in enumerate(observations):
            hashed, numeric = self.featurize(obs)
            for c in hashed:
                rows.append(r)
                cols.append(c)
                data.append(1.0)
            for j, val in enumerate(numeric):
                if val != 0.0:
                    rows.append(r)
                    cols.append(self.config.n_hash + j)
                    data.append(float(val))
        return sparse.csr_matrix(
            (data, (rows, cols)), shape=(len(observations), self.n_features), dtype=np.float64
        )

    # -- training ------------------------------------------------------------
    def fit(
        self,
        observations: Sequence[FieldObservation],
        labels: Sequence[int],
        sample_weight: Optional[Sequence[float]] = None,
    ) -> "FieldRiskClassifier":
        if len(observations) != len(labels):
            raise ValueError(f"{len(observations)} observations but {len(labels)} labels")
        y = np.asarray(labels, dtype=int)
        if set(np.unique(y)) != {0, 1}:
            raise ValueError("Training labels must contain both classes 0 and 1")
        try:
            from sklearn.linear_model import LogisticRegression
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise ImportError(
                "scikit-learn is required to train FieldRiskClassifier (inference does not need it)"
            ) from exc
        X = self._design_matrix(observations)
        model = LogisticRegression(
            C=self.config.C,
            solver="liblinear",
            class_weight="balanced",
            random_state=self.config.seed,
            max_iter=1000,
        )
        model.fit(X, y, sample_weight=sample_weight)
        self.coef_ = np.asarray(model.coef_[0], dtype=np.float64)
        self.intercept_ = float(model.intercept_[0])
        self.meta = {"n_train": int(len(y)), "n_positive": int(y.sum())}
        return self

    # -- inference -----------------------------------------------------------
    def _require_fitted(self) -> np.ndarray:
        if self.coef_ is None:
            raise RuntimeError("FieldRiskClassifier is not fitted or loaded")
        return self.coef_

    @property
    def model_version(self) -> str:
        coef = self._require_fitted()
        blob = json.dumps(
            {"c": [round(float(x), 6) for x in coef], "b": round(self.intercept_, 6),
             "cfg": asdict(self.config)},
            sort_keys=True,
        )
        return "fieldclf-" + hashlib.sha256(blob.encode()).hexdigest()[:12]

    def _logit(self, obs: FieldObservation) -> Tuple[float, Dict[int, List[str]], np.ndarray]:
        coef = self._require_fitted()
        hashed, numeric = self.featurize(obs)
        logit = self.intercept_ + float(np.dot(coef[self.config.n_hash:], numeric))
        for idx in hashed:
            logit += float(coef[idx])
        return logit, hashed, numeric

    @staticmethod
    def _sigmoid(x: float) -> float:
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-x))
        e = math.exp(x)
        return e / (1.0 + e)

    def band_for(self, probability: float) -> str:
        if probability >= self.config.threshold_high:
            return "HIGH"
        if probability >= self.config.threshold_medium:
            return "MEDIUM"
        return "LOW"

    def predict_proba(self, observations: Sequence[FieldObservation]) -> np.ndarray:
        return np.array([self._sigmoid(self._logit(o)[0]) for o in observations])

    def predict(self, obs: FieldObservation, top_k: int = 6) -> FieldRisk:
        """Probability, band and the top contributions (by absolute value)."""
        coef = self._require_fitted()
        logit, hashed, numeric = self._logit(obs)
        p = self._sigmoid(logit)
        contribs: List[Contribution] = []
        for idx, feats in hashed.items():
            label = "name:" + ("|".join(sorted(feats)) if len(feats) <= 2 else feats[0] + "|+")
            contribs.append(Contribution(label, float(coef[idx])))
        for j, name in enumerate(NUMERIC_FEATURES):
            if numeric[j] != 0.0:
                contribs.append(Contribution(name, float(coef[self.config.n_hash + j] * numeric[j])))
        contribs.sort(key=lambda c: abs(c.contribution), reverse=True)
        return FieldRisk(p, self.band_for(p), tuple(contribs[:top_k]), self.model_version)

    # -- introspection -------------------------------------------------------
    def numeric_weights(self) -> Dict[str, float]:
        coef = self._require_fitted()
        return {n: float(coef[self.config.n_hash + j]) for j, n in enumerate(NUMERIC_FEATURES)}

    def name_ngram_weights(self, field_names: Sequence[str]) -> Dict[str, float]:
        """Weight of each name feature occurring in ``field_names`` (hash collisions possible)."""
        coef = self._require_fitted()
        out: Dict[str, float] = {}
        for fname in field_names:
            for f in name_features(fname, self.config.ngram_min, self.config.ngram_max):
                out[f] = float(coef[_hash(f, self.config.n_hash)])
        return out

    # -- persistence (JSON, no pickle) ---------------------------------------
    def save(self, path: str | Path) -> None:
        coef = self._require_fitted()
        payload = {
            "format_version": FORMAT_VERSION,
            "config": asdict(self.config),
            "numeric_features": list(NUMERIC_FEATURES),
            "intercept": self.intercept_,
            "coef": [float(x) for x in coef],
            "meta": self.meta,
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "FieldRiskClassifier":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if raw.get("format_version") != FORMAT_VERSION:
            raise ValueError(f"Unsupported model format {raw.get('format_version')!r}")
        if raw.get("numeric_features") != list(NUMERIC_FEATURES):
            raise ValueError("Model feature layout does not match this code version")
        cfg = dict(raw["config"])
        cfg["ngram_min"], cfg["ngram_max"] = int(cfg["ngram_min"]), int(cfg["ngram_max"])
        model = cls(ClassifierConfig(**cfg))
        coef = np.asarray(raw["coef"], dtype=np.float64)
        if coef.shape[0] != model.n_features:
            raise ValueError(f"Expected {model.n_features} weights, found {coef.shape[0]}")
        model.coef_ = coef
        model.intercept_ = float(raw["intercept"])
        model.meta = dict(raw.get("meta", {}))
        return model
