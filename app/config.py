"""Configuration and default policy. Secrets come from the environment only."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping, Optional


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Thresholds:
    validator_high: float = 0.80
    validator_medium: float = 0.40
    classifier_high: float = 0.70
    classifier_medium: float = 0.40
    span_high: float = 0.75
    span_medium: float = 0.50


@dataclass(frozen=True)
class DriftConfig:
    rename_similarity: float = 0.85
    digit_ratio_delta: float = 0.30
    entropy_delta: float = 1.5      # bits per character
    length_factor: float = 3.0
    length_min_delta: float = 10.0  # ignore length change on tiny strings
    pattern_baseline_max: float = 0.10
    pattern_current_min: float = 0.40


@dataclass(frozen=True)
class Limits:
    max_depth: int = 32
    max_leaves: int = 5000
    max_string_len: int = 100_000
    max_id_len: int = 128


# Illustrative default. Edit per deployment; unknown purposes authorize nothing.
DEFAULT_POLICY: dict = {
    # Kinds that are never authorized for any purpose/destination.
    "never_allow": ["CREDENTIAL"],
    # Kinds (at HIGH+ severity) that quarantine the WHOLE payload.
    # NOTE: the architecture's decision table also lists government ID and
    # medical ID here, but its own API example redacts/quarantines those at
    # field level. Add them to this list to follow the table literally.
    "payload_quarantine_kinds": ["CREDENTIAL", "CARD_NUMBER"],
    # Unauthorized HIGH+ spans in one field at/above this count -> QUARANTINE_FIELD.
    "repeat_quarantine_threshold": 3,
    # Action for medium-risk unauthorized fields: MASK or TOKENIZE.
    "medium_action": "MASK",
    # Known field, major shift, no sensitive evidence: quarantine anyway?
    "quarantine_on_shift_without_evidence": False,
    # purpose -> destination ("*" = any) -> kinds that may be forwarded.
    "allow": {
        "ai_triage": {"risk_scoring_model": ["HEALTH", "PERSONAL"], "*": ["HEALTH"]},
        "fraud_detection": {"*": ["CONTACT", "BANK_ACCOUNT"]},
        "support": {"*": ["CONTACT"]},
    },
}


@dataclass(frozen=True)
class Settings:
    hmac_key: bytes = field(repr=False)
    thresholds: Thresholds = Thresholds()
    drift: DriftConfig = DriftConfig()
    limits: Limits = Limits()
    policy: Mapping = field(default_factory=lambda: DEFAULT_POLICY)


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    """Fail closed: there is deliberately no default HMAC key."""
    env = os.environ if env is None else env
    raw = env.get("CONSENTSHIELD_HMAC_KEY")
    if not raw:
        raise ConfigError("CONSENTSHIELD_HMAC_KEY is not set")
    if raw.startswith("hex:"):
        try:
            key = bytes.fromhex(raw[4:])
        except ValueError as exc:
            raise ConfigError("CONSENTSHIELD_HMAC_KEY has invalid hex") from exc
    else:
        key = raw.encode("utf-8")
    if len(key) < 16:
        raise ConfigError("CONSENTSHIELD_HMAC_KEY must be at least 16 bytes")
    return Settings(hmac_key=key)
