"""Pluggable free-text span detector for ConsentShield (GLiNER + fallback).

Responsibility
    Find sensitive spans (label, offsets, confidence) inside free-text fields.
    GLiNER says *what* sensitive content is present; it never decides whether
    the content is authorized (that is the policy engine's job).

Design notes
    * GLiNER is OPTIONAL and feature-flagged. Compatibility with s390x/LinuxONE
      is UNVERIFIED until the package and checkpoint are loaded and run there.
      ``build_text_detector`` therefore degrades to the deterministic
      validator detector and reports exactly why (``DetectorStatus``).
    * No default model is hard-coded: set ``CONSENTSHIELD_GLINER_MODEL`` to a
      local directory (preferred on an offline LinuxONE box) or a model id.
    * Spans never contain the matched text, and the module never logs input.
    * Inference failures raise ``DetectorRuntimeError``; callers must treat that
      as fail-closed (block or quarantine), never as "no PII found".

Environment variables
    CONSENTSHIELD_GLINER_ENABLED   "1"/"true" to try GLiNER (default: off)
    CONSENTSHIELD_GLINER_MODEL     local path or model id (required if enabled)
    CONSENTSHIELD_GLINER_ONNX      "1" to load the ONNX build (needs onnx file)
    CONSENTSHIELD_GLINER_ONNX_FILE ONNX file name inside the model dir
    CONSENTSHIELD_GLINER_THRESHOLD minimum confidence (default 0.50)
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple

from app.detectors import validators as V


class DetectorRuntimeError(RuntimeError):
    """The detector was available but failed while scanning a text."""


# Canonical labels (architecture) -> sensitivity category.
LABEL_TO_CATEGORY: Dict[str, str] = {
    "PERSON": "IDENTITY",
    "EMAIL_ADDRESS": V.Category.CONTACT,
    "PHONE_NUMBER": V.Category.CONTACT,
    "DATE_OF_BIRTH": "IDENTITY",
    "GOVERNMENT_ID": V.Category.GOVERNMENT_ID,
    "CREDIT_CARD_NUMBER": V.Category.FINANCIAL,
    "BANK_ACCOUNT": V.Category.FINANCIAL,
    "MEDICAL_RECORD": "HEALTH",
    "DIAGNOSIS": "HEALTH",
    "PASSWORD": V.Category.CREDENTIAL,
    "API_KEY": V.Category.CREDENTIAL,
}
DEFAULT_LABELS: Tuple[str, ...] = tuple(LABEL_TO_CATEGORY)

# GLiNER works with natural-language label prompts.
_PROMPTS: Dict[str, str] = {
    "PERSON": "person name",
    "EMAIL_ADDRESS": "email address",
    "PHONE_NUMBER": "phone number",
    "DATE_OF_BIRTH": "date of birth",
    "GOVERNMENT_ID": "government id number",
    "CREDIT_CARD_NUMBER": "credit card number",
    "BANK_ACCOUNT": "bank account number",
    "MEDICAL_RECORD": "medical record number",
    "DIAGNOSIS": "medical diagnosis",
    "PASSWORD": "password",
    "API_KEY": "api key",
}


@dataclass(frozen=True)
class TextSpan:
    """A detected sensitive span. Offsets are character indices into the input."""

    label: str
    start: int
    end: int
    score: float
    source: str  # "gliner" | "validators"
    model_version: str

    @property
    def category(self) -> str:
        return LABEL_TO_CATEGORY.get(self.label) or _VALIDATOR_LABEL_CATEGORY.get(self.label, "OTHER")


_VALIDATOR_LABEL_CATEGORY = {v.entity_label: v.category for v in V.get_validators()}


@dataclass(frozen=True)
class DetectorStatus:
    backend: str  # "gliner" | "validators"
    gliner_requested: bool
    gliner_available: bool
    reason: str
    model_version: str


@dataclass(frozen=True)
class GlinerConfig:
    enabled: bool = False
    model: Optional[str] = None
    use_onnx: bool = False
    onnx_file: Optional[str] = None
    threshold: float = 0.50
    labels: Tuple[str, ...] = DEFAULT_LABELS
    chunk_chars: int = 1000
    chunk_overlap: int = 100
    max_text_chars: int = 20000

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "GlinerConfig":
        e = os.environ if env is None else env
        truthy = {"1", "true", "yes", "on"}
        return cls(
            enabled=e.get("CONSENTSHIELD_GLINER_ENABLED", "0").strip().lower() in truthy,
            model=e.get("CONSENTSHIELD_GLINER_MODEL") or None,
            use_onnx=e.get("CONSENTSHIELD_GLINER_ONNX", "0").strip().lower() in truthy,
            onnx_file=e.get("CONSENTSHIELD_GLINER_ONNX_FILE") or None,
            threshold=float(e.get("CONSENTSHIELD_GLINER_THRESHOLD", "0.50")),
        )


class TextDetector(Protocol):
    source: str
    model_version: str

    def detect(self, text: str) -> List[TextSpan]: ...


# --------------------------------------------------------------------------- #
# Deterministic fallback
# --------------------------------------------------------------------------- #
class ValidatorTextDetector:
    """Fallback detector: validator hits as spans (score 1.0, deterministic)."""

    source = "validators"
    model_version = "validators-v1"

    def detect(self, text: str) -> List[TextSpan]:
        return [
            TextSpan(h.entity_label, h.start, h.end, 1.0, self.source, self.model_version)
            for h in V.scan_text(text)
        ]


# --------------------------------------------------------------------------- #
# GLiNER wrapper
# --------------------------------------------------------------------------- #
def chunk_offsets(n_chars: int, size: int, overlap: int) -> List[Tuple[int, int]]:
    """Overlapping [start, end) windows covering ``n_chars`` characters."""
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("require size > 0 and 0 <= overlap < size")
    if n_chars <= size:
        return [(0, n_chars)]
    step = size - overlap
    windows, start = [], 0
    while True:
        end = min(start + size, n_chars)
        windows.append((start, end))
        if end == n_chars:
            return windows
        start += step


def _dedupe(spans: List[TextSpan]) -> List[TextSpan]:
    """Keep the highest-score span among overlapping spans with the same label."""
    kept: List[TextSpan] = []
    for s in sorted(spans, key=lambda x: (-x.score, x.start)):
        if not any(k.label == s.label and s.start < k.end and k.start < s.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda x: (x.start, x.end))


class GlinerDetector:
    """Lazy-loading GLiNER wrapper. Pass ``model=`` to inject a loaded/fake model."""

    source = "gliner"

    def __init__(self, config: GlinerConfig, model: Any = None):
        self.config = config
        self._model = model
        self._lock = threading.Lock()
        self._prompt_to_label = {_PROMPTS[l]: l for l in config.labels if l in _PROMPTS}
        unknown = [l for l in config.labels if l not in _PROMPTS]
        if unknown:
            raise ValueError(f"Unsupported labels: {unknown}; supported: {sorted(_PROMPTS)}")
        self.model_version = self._describe_version()

    def _describe_version(self) -> str:
        try:
            from importlib import metadata
            pkg = metadata.version("gliner")
        except Exception:
            pkg = "unknown"
        return f"gliner[{pkg}]:{self.config.model or 'injected'}"

    def load(self) -> None:
        """Load the model once (idempotent). Raises ImportError / RuntimeError on failure."""
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            if not self.config.model:
                raise RuntimeError("CONSENTSHIELD_GLINER_MODEL is not set")
            from gliner import GLiNER  # optional dependency

            kwargs: Dict[str, Any] = {}
            if self.config.use_onnx:
                kwargs["load_onnx_model"] = True
                if self.config.onnx_file:
                    kwargs["onnx_model_file"] = self.config.onnx_file
            self._model = GLiNER.from_pretrained(self.config.model, **kwargs)

    def detect(self, text: str) -> List[TextSpan]:
        if not text or not text.strip():
            return []
        if len(text) > self.config.max_text_chars:
            raise DetectorRuntimeError(
                f"Text of {len(text)} chars exceeds max_text_chars={self.config.max_text_chars}"
            )
        try:
            self.load()
            prompts = [_PROMPTS[l] for l in self.config.labels]
            spans: List[TextSpan] = []
            for lo, hi in chunk_offsets(len(text), self.config.chunk_chars, self.config.chunk_overlap):
                for ent in self._model.predict_entities(
                    text[lo:hi], prompts, threshold=self.config.threshold
                ):
                    label = self._prompt_to_label.get(str(ent["label"]).lower())
                    if label is None:
                        continue
                    spans.append(
                        TextSpan(label, lo + int(ent["start"]), lo + int(ent["end"]),
                                 float(ent["score"]), self.source, self.model_version)
                    )
            return _dedupe(spans)
        except DetectorRuntimeError:
            raise
        except Exception as exc:  # never swallow: callers must fail closed
            raise DetectorRuntimeError(f"GLiNER inference failed: {type(exc).__name__}") from exc


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def build_text_detector(config: Optional[GlinerConfig] = None) -> Tuple[TextDetector, DetectorStatus]:
    """Return (detector, status). Falls back to validators with an explicit reason."""
    cfg = config or GlinerConfig.from_env()
    fallback = ValidatorTextDetector()
    if not cfg.enabled:
        return fallback, DetectorStatus("validators", False, False,
                                        "GLiNER disabled (CONSENTSHIELD_GLINER_ENABLED not set)",
                                        fallback.model_version)
    detector = GlinerDetector(cfg)
    try:
        detector.load()
    except ImportError:
        reason = "gliner package not importable on this platform"
    except Exception as exc:
        reason = f"GLiNER failed to load: {type(exc).__name__}: {str(exc)[:120]}"
    else:
        return detector, DetectorStatus("gliner", True, True, "loaded", detector.model_version)
    return fallback, DetectorStatus("validators", True, False, reason, fallback.model_version)
