"""Shared internal contracts for ConsentShield (standard library only).

Internal pipeline types are plain dataclasses so the enforcement path has no
third-party dependency risk on s390x. Pydantic request/response models for the
HTTP layer belong in the API layer (main.py), not here.

Design rule: detectors report *labels and scores*; the risk service maps labels
to ``Kind``; the policy service decides authorization; enforcement transforms.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any, Callable, Iterable, Mapping, Optional, Protocol, Sequence

Path = tuple  # tuple[str | int, ...] - concrete location inside the payload


class DriftType(str, Enum):
    NEW_FIELD = "NEW_FIELD"
    MISSING_FIELD = "MISSING_FIELD"
    TYPE_SHIFT = "TYPE_SHIFT"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    VALUE_PATTERN_SHIFT = "VALUE_PATTERN_SHIFT"
    RENAME_MATCH = "RENAME_MATCH"
    NO_DRIFT = "NO_DRIFT"


NEW_TYPES = frozenset({DriftType.NEW_FIELD, DriftType.RENAME_MATCH})
SHIFT_TYPES = frozenset(
    {DriftType.TYPE_SHIFT, DriftType.DISTRIBUTION_SHIFT, DriftType.VALUE_PATTERN_SHIFT}
)


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Kind(str, Enum):
    """Data category assigned by the risk service (not by detectors)."""

    GOVERNMENT_ID = "GOVERNMENT_ID"
    CARD_NUMBER = "CARD_NUMBER"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    CREDENTIAL = "CREDENTIAL"
    MEDICAL_RECORD = "MEDICAL_RECORD"
    HEALTH = "HEALTH"
    CONTACT = "CONTACT"
    PERSONAL = "PERSONAL"
    NETWORK = "NETWORK"
    UNKNOWN_SENSITIVE = "UNKNOWN_SENSITIVE"


class Action(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    TOKENIZE = "TOKENIZE"
    REDACT_SPAN = "REDACT_SPAN"
    QUARANTINE_FIELD = "QUARANTINE_FIELD"
    QUARANTINE_PAYLOAD = "QUARANTINE_PAYLOAD"
    BLOCK_FORWARD = "BLOCK_FORWARD"


ACTION_PRIORITY = {
    Action.ALLOW: 0,
    Action.REDACT_SPAN: 1,
    Action.MASK: 2,
    Action.TOKENIZE: 2,
    Action.QUARANTINE_FIELD: 3,
    Action.QUARANTINE_PAYLOAD: 4,
    Action.BLOCK_FORWARD: 5,
}


class Outcome(str, Enum):
    FORWARD_UNCHANGED = "FORWARD_UNCHANGED"
    FORWARD_SANITIZED = "FORWARD_SANITIZED"
    QUARANTINED = "QUARANTINED"
    BLOCKED = "BLOCKED"
    FORWARD_FAILED = "FORWARD_FAILED"


# --------------------------------------------------------------------- intake
@dataclass(frozen=True)
class IngestRequest:
    request_id: str
    source_system: str
    purpose: str
    destination: str
    payload: dict = field(repr=False)


@dataclass(frozen=True)
class Leaf:
    """One scalar value. ``schema_path`` has array indexes collapsed to ``[]``;
    ``path`` is the concrete location. ``value`` is raw data: never log it."""

    schema_path: str
    path: Path
    value: Any = field(repr=False)


# ------------------------------------------------------------------ profiling
@dataclass
class FieldProfile:
    schema_path: str
    json_type: str
    count: int
    mean_length: float
    digit_ratio: float
    alpha_ratio: float
    symbol_ratio: float
    whitespace_ratio: float
    entropy: float
    validator_hits: dict = field(default_factory=dict)  # validator name -> hit ratio
    types_seen: tuple = ()
    value_hashes: tuple = ()  # keyed, truncated; never raw values
    is_text_like: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["types_seen"] = list(self.types_seen)
        d["value_hashes"] = list(self.value_hashes)
        return d

    @classmethod
    def from_dict(cls, d: Mapping) -> "FieldProfile":
        data = dict(d)
        data["types_seen"] = tuple(data.get("types_seen", ()))
        data["value_hashes"] = tuple(data.get("value_hashes", ()))
        data["validator_hits"] = dict(data.get("validator_hits", {}))
        return cls(**data)


# ---------------------------------------------------------------------- drift
@dataclass
class DriftEvidence:
    schema_path: str
    drift_type: DriftType
    detail: str = ""
    renamed_from: Optional[str] = None


@dataclass
class DriftReport:
    evidence: dict  # schema_path -> DriftEvidence (for fields in the payload)
    missing: list   # DriftEvidence(MISSING_FIELD) for baseline fields absent now


# ------------------------------------------------------------------ detection
@dataclass(frozen=True)
class SpanHit:
    start: int
    end: int
    label: str
    score: float
    detector: str
    model_version: str = ""


@dataclass(frozen=True)
class LocatedSpan:
    path: Path
    hit: SpanHit


@dataclass
class FieldDetection:
    schema_path: str
    validator_hits: dict = field(default_factory=dict)
    classifier_probability: Optional[float] = None
    classifier_explanation: tuple = ()
    spans: list = field(default_factory=list)   # list[LocatedSpan]
    errors: list = field(default_factory=list)  # optional-detector failures


# ----------------------------------------------------------------------- risk
@dataclass(frozen=True)
class SpanFinding:
    located: LocatedSpan
    severity: Severity
    kind: Kind


@dataclass
class RiskAssessment:
    schema_path: str
    severity: Severity
    kind: Optional[Kind]
    field_severity: Severity
    field_kind: Optional[Kind]
    span_findings: list
    drift: DriftType
    evidence: tuple
    classifier_probability: Optional[float] = None


# --------------------------------------------------------------------- policy
@dataclass
class PolicyDecision:
    schema_path: str
    action: Action
    severity: Severity
    kind: Optional[Kind]
    reason: str
    flag_for_review: bool = False
    spans: tuple = ()  # tuple[SpanFinding] when action is REDACT_SPAN


@dataclass
class PolicyResult:
    decisions: list
    payload_quarantined: bool = False


# ----------------------------------------------------------------- enforcement
@dataclass
class QuarantineItem:
    schema_path: str
    path: Path
    kind: Optional[Kind]
    reason: str
    raw_value: Any = field(repr=False, default=None)  # encrypt before persisting


@dataclass
class EnforcementResult:
    sanitized_payload: Optional[dict]
    payload_quarantined: bool
    quarantined: list = field(default_factory=list)
    removed_texts: list = field(default_factory=list, repr=False)  # raw; leak check only
    applied: list = field(default_factory=list)  # (schema_path, Action)

    @property
    def forwardable(self) -> bool:
        return self.sanitized_payload is not None and not self.payload_quarantined


@dataclass
class RevalidationResult:
    passed: bool
    violations: list = field(default_factory=list)       # never contain raw values
    detector_errors: list = field(default_factory=list)


@dataclass
class PipelineResult:
    request_id: str
    outcome: Outcome
    actions: list
    sanitized_payload: Optional[dict]
    revalidated: bool
    forwarded: bool
    audit_event_ids: list
    missing_fields: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    error: Optional[str] = None


# ------------------------------------------------------------------ interfaces
class SpanDetector(Protocol):
    """Deterministic scanners and GLiNER both implement this.

    ``required``: failure must fail closed (deterministic detectors).
    ``text_only``: only run on free-text fields (ML detectors).
    """

    name: str
    required: bool
    text_only: bool

    def detect(self, text: str) -> Sequence[SpanHit]: ...


class FieldClassifier(Protocol):
    def predict(self, profile: FieldProfile, drift: DriftType) -> tuple:
        """Return (probability, explanation list)."""


class BaselineStore(Protocol):
    def load_all(self) -> dict: ...
    def save(self, profile: FieldProfile) -> None: ...


class AuditStore(Protocol):
    def append(self, event: dict) -> None: ...
    def last_hash(self) -> Optional[str]: ...
    def iter_events(self) -> Iterable[dict]: ...


class QuarantineStore(Protocol):
    def store(self, request_id: str, items: Sequence[QuarantineItem]) -> None: ...


Validators = Mapping[str, Callable[[str], bool]]
