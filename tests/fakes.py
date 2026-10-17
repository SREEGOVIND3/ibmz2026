"""TEST-ONLY fakes. These are NOT the production detectors/stores
(validators.py, gliner_detector.py, *_repository.py are separate, later files).
The 'AADHAAR' fake here is a shape check only: no Verhoeff, no real Luhn."""
from __future__ import annotations

import re

from app.config import DEFAULT_POLICY, Settings
from app.schemas import SpanHit
from app.services.audit_service import AuditService
from app.services.detection_service import DetectionService
from app.services.drift_service import DriftService
from app.services.enforcement_service import EnforcementService
from app.services.ingest_service import IngestService
from app.services.policy_service import PolicyEngine
from app.services.profiling_service import Profiler
from app.services.revalidation_service import RevalidationService
from app.services.risk_service import RiskService

KEY = b"unit-test-key-0123456789abcdef"

VALIDATORS = {
    "AADHAAR": lambda t: re.fullmatch(r"[2-9]\d{11}", t) is not None,
    "EMAIL": lambda t: re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.]+", t) is not None,
    "CARD": lambda t: re.fullmatch(r"\d{16}", t) is not None,
}

SPAN_PATTERNS = {
    "GOVERNMENT_ID": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
    "EMAIL_ADDRESS": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "CREDIT_CARD_NUMBER": r"\b\d{16}\b",
}


class RegexSpanDetector:
    def __init__(self, name="fake_regex", patterns=None, required=True, text_only=False, score=0.95):
        self.name, self.required, self.text_only = name, required, text_only
        self._patterns = {k: re.compile(v) for k, v in (patterns or SPAN_PATTERNS).items()}
        self._score = score

    def detect(self, text):
        return [
            SpanHit(m.start(), m.end(), label, self._score, self.name)
            for label, rx in self._patterns.items()
            for m in rx.finditer(text)
        ]


class ExplodingDetector:
    def __init__(self, required: bool, name="exploding"):
        self.name, self.required, self.text_only = name, required, False

    def detect(self, text):
        raise RuntimeError("model unavailable: " + text)  # message must never surface


class FixedClassifier:
    def __init__(self, probability):
        self._p = probability

    def predict(self, profile, drift):
        return self._p, [f"fixed {self._p}"]


class MemoryAuditStore:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(dict(event))

    def last_hash(self):
        return self.events[-1]["hash"] if self.events else None

    def iter_events(self):
        return iter(self.events)


class MemoryBaseline:
    def __init__(self):
        self.profiles = {}

    def load_all(self):
        return dict(self.profiles)

    def save(self, profile):
        self.profiles[profile.schema_path] = profile


class ListQuarantine:
    def __init__(self):
        self.stored = []

    def store(self, request_id, items):
        self.stored.append((request_id, list(items)))


BASELINE_PAYLOADS = [
    {
        "patient": {"id": "PT-88213", "age": 34, "notes": "Patient reports fever and mild cough since yesterday."},
        "visit": {"date": "2026-10-17", "symptoms": ["fever", "cough"]},
    },
    {
        "patient": {"id": "PT-90117", "age": 52, "notes": "Follow up visit, patient feels better after rest."},
        "visit": {"date": "2026-10-18", "symptoms": ["headache"]},
    },
]


def make_pipeline(
    *, detectors=None, classifier=None, policy=None, forward=None,
    quarantine=True, bootstrap=True, audit_store=None, id_start=0,
):
    settings = Settings(hmac_key=KEY, policy=policy or DEFAULT_POLICY)
    profiler = Profiler(KEY, VALIDATORS)
    detection = DetectionService(detectors if detectors is not None else [RegexSpanDetector()], classifier)
    risk = RiskService(settings.thresholds)
    engine = PolicyEngine(settings.policy)
    store = audit_store or MemoryAuditStore()
    counter = iter(range(id_start, 10**6))
    audit = AuditService(store, id_factory=lambda: f"evt-{next(counter)}")
    forwarded: list = []
    quarantine_store = ListQuarantine() if quarantine else None
    service = IngestService(
        settings=settings, baseline=MemoryBaseline(), profiler=profiler,
        drift=DriftService(settings.drift), detection=detection, risk=risk, policy=engine,
        enforcement=EnforcementService(KEY),
        revalidation=RevalidationService(profiler, detection, risk, engine, limits=settings.limits),
        audit=audit,
        forward=forward or (lambda payload, req: forwarded.append(payload)),
        quarantine=quarantine_store,
    )
    if bootstrap:
        for p in BASELINE_PAYLOADS:
            service.approve_baseline(p)
    return {
        "service": service, "forwarded": forwarded, "audit_store": store, "audit": audit,
        "quarantine": quarantine_store, "profiler": profiler, "detection": detection,
        "risk": risk, "policy": engine, "settings": settings, "baseline": service._baseline,
    }


def envelope(payload, purpose="ai_triage", destination="risk_scoring_model", request_id="req-001"):
    return {
        "request_id": request_id, "source_system": "hospital_emr",
        "processing_purpose": purpose, "destination": destination, "payload": payload,
    }
