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
# Deterministic fallback + Contextual Heuristics
# --------------------------------------------------------------------------- #
import re

_CONTEXT_PATTERNS = [
    # 1. Credentials, Passwords, PINs, Secrets, Tokens, API Keys
    (
        re.compile(r"(?i)\b(?:password|passwd|pwd|passcode|pass|secret\s*key|secret|client\s*secret|auth\s*token|access\s*token|bearer|api\s*key|apikey|api_key|token|pin\s*code|atm\s*pin|pin)\s*(?:for\s+[\w.-]+)?\s*(?:is|:|=|-|\s)\s*([A-Za-z0-9!@#$%^&*()_+\-={}|;:<>.?]{4,64})\b"),
        "PASSWORD",
    ),
    (
        re.compile(r"\b(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)\b"),
        "API_KEY",
    ),
    (
        re.compile(r"\b(sk-[a-zA-Z0-9]{20,})\b"),
        "API_KEY",
    ),
    (
        re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})\b"),
        "API_KEY",
    ),
    (
        re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        "API_KEY",
    ),
    (
        re.compile(r"\b(AIza[0-9A-Za-z-_]{35})\b"),
        "API_KEY",
    ),

    # 2. Government & National IDs (Aadhaar, PAN, Passport, DL, SSN, Voter ID)
    (
        re.compile(r"(?i)\b(?:aadhaar|aadhar|uidai|uid|adhar)\s*(?:card|number|no|num)?\s*(?:is|:|=|-)?\s*([2-9]\d{3}[ -]?\d{4}[ -]?\d{4})\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"\b([xX*]{4}[ -]?[xX*]{4}[ -]?\d{4})\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"(?i)\b(?:pan\s*(?:card|number|no|num)?)\s*(?:is|:|=|-)?\s*([A-Za-z]{5}\d{4}[A-Za-z])\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"\b([a-zA-Z]{5}[0-9]{4}[a-zA-Z])\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"(?i)\b(?:passport\s*(?:number|no|num)?)\s*(?:is|:|=|-)?\s*([A-Za-z][0-9]{7,8})\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"\b([A-PR-WYa-pr-wy][1-9]\d{7})\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"(?i)\b(?:driving\s*licen[sc]e|dl\s*(?:no|number)?)\s*(?:is|:|=|-)?\s*([A-Za-z]{2}[0-9]{2}[ -]?[0-9]{7,11})\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"(?i)\b(?:ssn|social\s*security\s*(?:no|number)?)\s*(?:is|:|=|-)?\s*(\d{3}[ -]?\d{2}[ -]?\d{4}|\d{9})\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"\b(\d{3}-\d{2}-\d{4})\b"),
        "GOVERNMENT_ID",
    ),
    (
        re.compile(r"(?i)\b(?:voter\s*id|epic\s*no)\s*(?:is|:|=|-)?\s*([A-Za-z]{3}[0-9]{7})\b"),
        "GOVERNMENT_ID",
    ),

    # 3. Financial (Bank Account, Credit/Debit Cards, UPI IDs, CVV)
    (
        re.compile(r"(?i)\b(?:account\s*(?:number|no|num)?|acct|a/c\s*(?:no|num|number)?|bank\s*acc(?:ount)?|savings\s*account)\s*(?:is|for\s+[\w.-]+|:|=|-)?\s*(\d{8,18})\b"),
        "BANK_ACCOUNT",
    ),
    (
        re.compile(r"(?i)\b([a-zA-Z0-9_.-]+@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|apl|upi|axl|ibl|barodampay|pnb|allbank|axisbank|dbs|federal|hdfcbank|icici|indus|kbl|kotak|sbi|yesbank))\b"),
        "BANK_ACCOUNT",
    ),
    (
        re.compile(r"(?i)\b(?:upi\s*id|vpa)\s*(?:is|:|=|-)?\s*([a-zA-Z0-9_.-]+@[a-zA-Z0-9]+)\b"),
        "BANK_ACCOUNT",
    ),
    (
        re.compile(r"(?i)\b(?:card\s*(?:number|no|num)?|credit\s*card|debit\s*card)\s*(?:is|:|=|-)?\s*(\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})\b"),
        "CREDIT_CARD_NUMBER",
    ),
    (
        re.compile(r"(?i)\b(?:cvv|cvc|security\s*code)\s*(?:is|:|=|-)?\s*(\d{3,4})\b"),
        "CREDIT_CARD_NUMBER",
    ),

    # 4. Dates & Personal Identifiers (DOB, Explicit Name introductions)
    (
        re.compile(r"(?i)\b(?:dob|date\s*of\s*birth|birth\s*date|born\s*(?:on)?)\s*(?:is|:|=|-)?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b"),
        "DATE_OF_BIRTH",
    ),
    (
        re.compile(r"(?i)\b(?:patient\s*(?:name)?|my\s*name\s*is|name\s*(?:is|:))\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b"),
        "PERSON",
    ),
    (
        re.compile(r"\b(Dr\.\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"),
        "PERSON",
    ),

    # 5. Medical Records & Diagnoses
    (
        re.compile(r"(?i)\b(?:mrn|uhid|patient\s*id|medical\s*record\s*(?:no|number)?|health\s*id|opd|ipd)\s*(?:is|:|=|-)?\s*([A-Za-z0-9/-]{4,20})\b"),
        "MEDICAL_RECORD",
    ),
    (
        re.compile(r"(?i)\b(?:diagnos(?:is\s*(?:is|:)|ed\s*with)|suffering\s*from|medical\s*condition\s*(?:is|:)|prescribed|tested\s*positive\s*for)\s+([A-Za-z0-9\s-]{3,35})\b"),
        "DIAGNOSIS",
    ),
]


class ValidatorTextDetector:
    """Fallback detector: validator hits as spans (score 1.0, deterministic) + contextual patterns."""

    source = "validators"
    model_version = "validators-v1"

    def detect(self, text: str) -> List[TextSpan]:
        raw_spans = [
            TextSpan(h.entity_label, h.start, h.end, 1.0, self.source, self.model_version)
            for h in V.scan_text(text)
        ]
        context_spans: List[TextSpan] = []
        for rx, label in _CONTEXT_PATTERNS:
            for m in rx.finditer(text):
                start, end = m.start(1), m.end(1)
                context_spans.append(TextSpan(label, start, end, 0.98, "contextual_rule", self.model_version))

        # Merge: if contextual span overlaps a validator hit, contextual span takes priority if it's more specific
        combined = []
        for v in raw_spans:
            if not any(max(v.start, c.start) < min(v.end, c.end) for c in context_spans):
                combined.append(v)
        combined.extend(context_spans)
        return _dedupe(combined)


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
