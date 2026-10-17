"""ConsentShield gateway: FastAPI composition root and HTTP layer.

Responsibility
    Build every service, repository and detector, wire them together, and expose
    the HTTP API. Business logic stays in ``app/services``; this file only
    validates HTTP input, maps results to status codes and enforces who may call
    the analyst endpoints.

Run
    uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000

Required environment (the app refuses to start without the first two)
    CONSENTSHIELD_HMAC_KEY         >= 16 bytes; ``hex:<hex>`` or a plain string
    CONSENTSHIELD_QUARANTINE_KEY   exactly 32 bytes (``hex:`` / ``base64:``);
                                   must differ from the HMAC key
Optional
    CONSENTSHIELD_ANALYST_TOKEN    >= 16 chars. Unset => analyst endpoints answer 503.
    CONSENTSHIELD_DB_PATH          default ``var/consentshield.db``
    CONSENTSHIELD_MAX_BODY_BYTES   default 1048576 (checked via Content-Length only)
    CONSENTSHIELD_GLINER_*         see ``app/detectors/gliner_detector.py``

Endpoint access
    public    : POST /ingest, GET /health, GET /platform, POST /downstream/risk-score
                (/ingest has no caller authentication in this MVP; put it behind
                your own network controls or a reverse proxy)
    analyst   : everything else, ``Authorization: Bearer <CONSENTSHIELD_ANALYST_TOKEN>``

Wiring decisions worth knowing
    * The deterministic validator scanner is always installed as a REQUIRED span
      detector. GLiNER is added as an OPTIONAL, text-only detector only when it
      actually loads (``build_text_detector`` reports why not otherwise).
    * Validator names and span labels are mapped to ``Kind`` explicitly below,
      because the real validator names (``AADHAAR_VERHOEFF`` ...) differ from the
      defaults in ``risk_service``; relying on the defaults would silently
      downgrade an Aadhaar number to ``UNKNOWN_SENSITIVE``.
    * The field-risk classifier is NOT wired (BLOCKED): ``DetectionService``
      passes it a ``FieldProfile`` (hashes only), while ``FieldRiskClassifier``
      needs raw sample values. See the build notes.
    * The downstream receiver is the in-process ``MockDownstream`` (SIMULATED).
    * Error responses never echo request bodies; logs carry exception type names
      only.
"""
from __future__ import annotations

import hmac
import logging
import os
import platform
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from importlib import metadata
from typing import Any, Callable, Literal, Mapping, Optional, Sequence

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .config import ConfigError, Settings, load_settings
from .detectors import validators as V
from .detectors.gliner_detector import (
    DetectorStatus, ValidatorTextDetector, build_text_detector, GlinerConfig,
)
from .downstream.mock_ai import MockDownstream, create_router
from .schemas import Kind, Outcome, PipelineResult, SpanHit
from .services.audit_service import AuditService
from .services.detection_service import DetectionService
from .services.drift_service import DriftService
from .services.enforcement_service import EnforcementService
from .services.ingest_service import IngestError, IngestService
from .services.normalization_service import NormalizationError, flatten
from .services.policy_service import PolicyEngine
from .services.profiling_service import Profiler
from .services.revalidation_service import RevalidationService
from .services.risk_service import DEFAULT_LABEL_KINDS, DEFAULT_VALIDATOR_KINDS, RiskService
from .storage.audit_repository import AuditRepository
from .storage.baseline_repository import BaselineRepository
from .storage.database import Database, StorageError, resolve_db_path
from .storage.quarantine_repository import (
    QuarantineAlreadyDecided, QuarantineNotFound, QuarantineRepository, STATUSES,
    load_quarantine_key,
)

log = logging.getLogger("consentshield")

ENV_ANALYST_TOKEN = "CONSENTSHIELD_ANALYST_TOKEN"
ENV_MAX_BODY = "CONSENTSHIELD_MAX_BODY_BYTES"
DEFAULT_MAX_BODY = 1_048_576

# ---------------------------------------------------------------- kind mapping
# Real validator names (see detectors/validators.py) -> Kind. Extends the
# risk-service defaults rather than replacing them.
VALIDATOR_KINDS = {
    **DEFAULT_VALIDATOR_KINDS,
    "AADHAAR_VERHOEFF": Kind.GOVERNMENT_ID,
    "CREDIT_CARD_LUHN": Kind.CARD_NUMBER,
    "API_KEY_HEURISTIC": Kind.CREDENTIAL,
}
# Span labels emitted by the validator scanner that the defaults do not know.
LABEL_KINDS = {
    **DEFAULT_LABEL_KINDS,
    "BANK_BRANCH_CODE": Kind.BANK_ACCOUNT,
    "IP_ADDRESS": Kind.NETWORK,
}


# -------------------------------------------------------------- detector glue
class _TextDetectorAdapter:
    """Adapt a text detector (returns ``TextSpan``) to the ``SpanDetector``
    protocol the detection service expects (returns ``SpanHit``)."""

    def __init__(self, inner: Any, *, name: str, required: bool, text_only: bool) -> None:
        self._inner = inner
        self.name, self.required, self.text_only = name, required, text_only

    def detect(self, text: str) -> list:
        return [
            SpanHit(s.start, s.end, s.label, s.score, self.name, s.model_version)
            for s in self._inner.detect(text)
        ]


def build_span_detectors(env: Mapping[str, str]) -> tuple:
    """Return (detectors, DetectorStatus). The deterministic scanner is always
    present and required; GLiNER is optional and only added if it loaded."""
    detectors = [_TextDetectorAdapter(ValidatorTextDetector(), name="validators", required=True, text_only=False)]
    inner, status = build_text_detector(GlinerConfig.from_env(dict(env)))
    if status.backend == "gliner":
        detectors.append(_TextDetectorAdapter(inner, name="gliner", required=False, text_only=True))
    return detectors, status


# ---------------------------------------------------------------- app state
class AppState:
    def __init__(
        self, *, settings: Settings, db: Database, owns_db: bool, baseline: BaselineRepository,
        quarantine: QuarantineRepository, audit_repo: AuditRepository, audit: AuditService,
        ingest: IngestService, mock: MockDownstream, detector_names: list,
        text_status: Optional[DetectorStatus], analyst_token: Optional[bytes], max_body: int,
    ) -> None:
        self.settings, self.db, self.owns_db = settings, db, owns_db
        self.baseline, self.quarantine, self.audit_repo, self.audit = baseline, quarantine, audit_repo, audit
        self.ingest, self.mock = ingest, mock
        self.detector_names, self.text_status = detector_names, text_status
        self.analyst_token, self.max_body = analyst_token, max_body


def _load_analyst_token(env: Mapping[str, str]) -> Optional[bytes]:
    raw = env.get(ENV_ANALYST_TOKEN)
    if not raw:
        return None
    if len(raw) < 16:
        raise ConfigError(f"{ENV_ANALYST_TOKEN} must be at least 16 characters")
    return raw.encode("utf-8")


def _load_max_body(env: Mapping[str, str]) -> int:
    raw = env.get(ENV_MAX_BODY)
    if not raw:
        return DEFAULT_MAX_BODY
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{ENV_MAX_BODY} must be an integer") from exc
    if value < 1024:
        raise ConfigError(f"{ENV_MAX_BODY} must be at least 1024")
    return value


def build_state(
    env: Optional[Mapping[str, str]] = None,
    *,
    db: Optional[Database] = None,
    span_detectors: Optional[Sequence] = None,
    forward: Optional[Callable] = None,
) -> AppState:
    """Create and wire everything. Raises ``ConfigError`` on bad configuration."""
    env = os.environ if env is None else env
    settings = load_settings(env)
    quarantine_key = load_quarantine_key(env)
    if hmac.compare_digest(quarantine_key, settings.hmac_key):
        raise ConfigError("CONSENTSHIELD_QUARANTINE_KEY must differ from CONSENTSHIELD_HMAC_KEY")
    token, max_body = _load_analyst_token(env), _load_max_body(env)

    owns_db = db is None
    database = db or Database(resolve_db_path(env))
    try:
        if span_detectors is None:
            detectors, text_status = build_span_detectors(env)
        else:
            detectors, text_status = list(span_detectors), None

        validators = {v.name: v.matches_value for v in V.get_validators()}
        profiler = Profiler(settings.hmac_key, validators)
        detection = DetectionService(detectors, None)  # classifier: see module docstring
        risk = RiskService(settings.thresholds, validator_kinds=VALIDATOR_KINDS, label_kinds=LABEL_KINDS)
        policy = PolicyEngine(settings.policy)

        baseline = BaselineRepository(database)
        quarantine = QuarantineRepository(database, quarantine_key)
        audit_repo = AuditRepository(database)
        audit = AuditService(audit_repo)
        mock = MockDownstream()

        ingest = IngestService(
            settings=settings, baseline=baseline, profiler=profiler,
            drift=DriftService(settings.drift), detection=detection, risk=risk, policy=policy,
            enforcement=EnforcementService(settings.hmac_key),
            revalidation=RevalidationService(profiler, detection, risk, policy, limits=settings.limits),
            audit=audit,
            forward=forward or (lambda payload, req: mock.receive(payload, request_id=req.request_id, via="gateway")),
            quarantine=quarantine,
        )
    except Exception:
        if owns_db:
            database.close()
        raise
    return AppState(
        settings=settings, db=database, owns_db=owns_db, baseline=baseline, quarantine=quarantine,
        audit_repo=audit_repo, audit=audit, ingest=ingest, mock=mock,
        detector_names=[d.name for d in detectors], text_status=text_status,
        analyst_token=token, max_body=max_body,
    )


# ------------------------------------------------------------------- schemas
class IngestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: Optional[str] = None
    source_system: str
    processing_purpose: str
    destination: str
    payload: dict[str, Any]


class ActionOut(BaseModel):
    field_path: str
    action: str
    severity: str
    reason: str
    flag_for_review: bool = False


class IngestResponse(BaseModel):
    request_id: str
    decision: str
    actions: list[ActionOut]
    sanitized_payload: Optional[dict[str, Any]] = None
    revalidated: bool
    forwarded: bool
    audit_event_id: Optional[str] = None  # the final summary event of this request
    audit_event_ids: list[str]
    missing_fields: list[str]
    violations: list[str]
    error: Optional[str] = None


class BaselineBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: dict[str, Any]


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["APPROVE", "REJECT", "UPDATE"]
    analyst: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:@\-]+$")
    label: Optional[str] = Field(default=None, max_length=64)
    note: Optional[str] = Field(default=None, max_length=500)


_STATUS_FOR_OUTCOME = {
    Outcome.FORWARD_UNCHANGED: 200,
    Outcome.FORWARD_SANITIZED: 200,
    Outcome.QUARANTINED: 202,   # accepted for review, NOT forwarded
    Outcome.FORWARD_FAILED: 502,
}


def _http_status(result: PipelineResult) -> int:
    if result.outcome is Outcome.BLOCKED:
        return 500 if result.error else 403
    return _STATUS_FOR_OUTCOME[result.outcome]


def _to_response(result: PipelineResult) -> IngestResponse:
    ids = list(result.audit_event_ids)
    return IngestResponse(
        request_id=result.request_id,
        decision=result.outcome.value,
        actions=[ActionOut(**a) for a in result.actions],
        sanitized_payload=result.sanitized_payload,
        revalidated=result.revalidated,
        forwarded=result.forwarded,
        audit_event_id=ids[-1] if ids else None,
        audit_event_ids=ids,
        missing_fields=list(result.missing_fields),
        violations=list(result.violations),
        error=result.error,
    )


# ---------------------------------------------------------------------- auth
def _state(request: Request) -> AppState:
    return request.app.state.cs


def require_analyst(request: Request) -> None:
    token = _state(request).analyst_token
    if token is None:
        raise HTTPException(503, f"analyst API disabled: {ENV_ANALYST_TOKEN} is not set")
    header = request.headers.get("authorization", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode("utf-8"), token):
        raise HTTPException(401, "invalid or missing analyst token", headers={"WWW-Authenticate": "Bearer"})


# -------------------------------------------------------------------- helpers
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pkg_version(name: str) -> Optional[str]:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _platform_info(state: AppState) -> dict:
    machine = platform.machine()
    status = state.text_status
    return {
        "machine": machine,
        "is_s390x": machine == "s390x",
        "byteorder": sys.byteorder,
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "os": platform.system(),
        "kernel": platform.release(),
        "sqlite": __import__("sqlite3").sqlite_version,
        "database_journal_mode": state.db.journal_mode,
        "packages": {n: _pkg_version(n) for n in ("fastapi", "pydantic", "cryptography", "numpy")},
        "span_detectors": state.detector_names,
        "text_backend": None if status is None else {
            "backend": status.backend, "gliner_requested": status.gliner_requested,
            "gliner_available": status.gliner_available, "reason": status.reason,
            "model_version": status.model_version,
        },
        "field_classifier": "not wired",
        "downstream": "simulated (in-process mock)",
        "notes": ["Architecture comes from platform.machine(); no hardware-crypto or "
                  "confidential-computing claim is made."],
    }


def _sanitized_validation_errors(exc: RequestValidationError) -> list:
    """Drop ``input``/``ctx`` so a rejected payload is never echoed back."""
    return [{"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors()]


# ----------------------------------------------------------------- app factory
def create_app(
    env: Optional[Mapping[str, str]] = None,
    *,
    db: Optional[Database] = None,
    span_detectors: Optional[Sequence] = None,
    forward: Optional[Callable] = None,
) -> FastAPI:
    state = build_state(env, db=db, span_detectors=span_detectors, forward=forward)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            if state.owns_db:
                state.db.close()

    app = FastAPI(title="ConsentShield Gateway", version="0.1.0", lifespan=lifespan)
    app.state.cs = state
    app.include_router(create_router(state.mock))

    # ------------------------------------------------------ errors / middleware
    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": _sanitized_validation_errors(exc)}, status_code=422)

    @app.exception_handler(IngestError)
    async def _ingest_error(_: Request, exc: IngestError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(StorageError)
    async def _storage_error(_: Request, exc: StorageError) -> JSONResponse:
        log.error("storage error: %s", type(exc).__name__)
        return JSONResponse({"detail": "storage error"}, status_code=500)

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error: %s", type(exc).__name__)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    @app.middleware("http")
    async def _limit_body(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None:
            try:
                too_big = int(length) > state.max_body
            except ValueError:
                return JSONResponse({"detail": "invalid Content-Length"}, status_code=400)
            if too_big:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    # ------------------------------------------------------------------ public
    @app.get("/health")
    def health() -> JSONResponse:
        try:
            ok = state.db.ping()
        except StorageError:
            ok = False
        return JSONResponse(
            {"status": "ok" if ok else "degraded", "database": "ok" if ok else "unavailable", "time": _now()},
            status_code=200 if ok else 503,
        )

    @app.get("/platform")
    def platform_info() -> dict:
        return _platform_info(state)

    @app.post("/ingest", response_model=IngestResponse)
    def ingest(body: IngestBody) -> JSONResponse:
        result = state.ingest.handle(body.model_dump())
        return JSONResponse(_to_response(result).model_dump(mode="json"), status_code=_http_status(result))

    # ----------------------------------------------------------------- analyst
    @app.post("/baseline/update", dependencies=[Depends(require_analyst)])
    def baseline_update(body: BaselineBody) -> dict:
        try:  # reject unusable payloads before anything is audited or written
            flatten(body.payload, state.settings.limits)
        except NormalizationError:
            raise HTTPException(422, "payload rejected by normalization limits")
        request_id = "baseline-" + uuid.uuid4().hex[:12]
        state.audit.record({
            "request_id": request_id, "field_path": "*", "action": "BASELINE_APPROVE",
            "reason": "baseline approval submitted",
        })
        return {"request_id": request_id, "fields_updated": state.ingest.approve_baseline(body.payload),
                "baseline_fields": state.baseline.count()}

    @app.get("/quarantine", dependencies=[Depends(require_analyst)])
    def quarantine_list(
        status: Optional[Literal["PENDING", "APPROVED", "REJECTED", "UPDATED"]] = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
    ) -> dict:
        items = state.quarantine.list(status=status, limit=limit, offset=offset)
        return {"total": state.quarantine.count(status), "statuses": list(STATUSES),
                "items": [i.to_dict() for i in items]}

    @app.post("/quarantine/{item_id}/decision", dependencies=[Depends(require_analyst)])
    def quarantine_decision(item_id: str, body: DecisionBody) -> dict:
        if body.decision == "UPDATE" and body.label not in Kind.__members__:
            raise HTTPException(422, f"UPDATE requires 'label' to be one of {sorted(Kind.__members__)}")
        if body.decision != "UPDATE" and body.label is not None:
            raise HTTPException(422, "'label' is only valid with UPDATE")
        record = state.quarantine.get(item_id)
        if record is None:
            raise HTTPException(404, "quarantine item not found")
        if record.status != "PENDING":
            raise HTTPException(409, "quarantine item already has a decision")
        reason = f"analyst decision submitted for quarantine item {item_id} by {body.analyst}"
        if body.label:
            reason += f"; label {body.label}"
        state.audit.record({  # audit first: no trail, no effect
            "request_id": record.request_id, "field_path": record.schema_path,
            "action": f"ANALYST_{body.decision}", "reason": reason,
        })
        try:
            updated = state.quarantine.record_decision(
                item_id, body.decision, body.analyst, note=body.note, label=body.label
            )
        except QuarantineNotFound:
            raise HTTPException(404, "quarantine item not found")
        except QuarantineAlreadyDecided:
            raise HTTPException(409, "quarantine item already has a decision")
        return updated.to_dict()

    @app.get("/audit", dependencies=[Depends(require_analyst)])
    def audit_list(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        request_id: Optional[str] = Query(None, max_length=128),
    ) -> dict:
        return {"total": state.audit_repo.count(request_id),
                "events": state.audit_repo.list_events(limit=limit, offset=offset, request_id=request_id)}

    @app.get("/audit/verify", dependencies=[Depends(require_analyst)])
    def audit_verify(
        expected_head: Optional[str] = Query(None, min_length=64, max_length=64),
        expected_count: Optional[int] = Query(None, ge=0),
    ) -> dict:
        result = state.audit.verify(expected_head=expected_head, expected_count=expected_count)
        return {"ok": result.ok, "checked": result.checked, "head": result.head,
                "reason": result.reason, "first_bad_index": result.first_bad_index,
                "anchored": expected_head is not None or expected_count is not None}

    @app.get("/downstream/received", dependencies=[Depends(require_analyst)])
    def downstream_received(
        via: Optional[Literal["gateway", "http"]] = None, limit: int = Query(50, ge=1, le=1000)
    ) -> dict:
        return {"total_received": state.mock.total_received, "entries": state.mock.received(via=via, limit=limit)}

    return app
