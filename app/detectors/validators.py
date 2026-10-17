"""Deterministic, high-precision identifier validators for ConsentShield.

Responsibility
    * Decide whether a value (whole-field mode) or a span inside free text
      (embedded mode) looks like a known sensitive identifier.
    * Report *evidence* (validator name, category, offsets, hit ratios). Policy
      decisions live elsewhere (policy_service).

Design notes
    * Standard library only: no wheels, so nothing to break on s390x.
    * Hits carry offsets, never the raw matched text, so callers can log them
      without leaking the value.
    * Checksums (Luhn, Verhoeff) cut false positives; regexes alone are not
      used for Aadhaar or card numbers.
    * Known limits: only ASCII digits are handled, obfuscated values (digits
      spelled out, base64, zero-width characters) are not detected, and the
      API-key detector is a heuristic, so expect some false positives
      (long hex hashes) and false negatives (short or low-entropy secrets).
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


class Category:
    """Shared sensitivity categories (also used by the text detector)."""

    GOVERNMENT_ID = "GOVERNMENT_ID"
    FINANCIAL = "FINANCIAL"
    CREDENTIAL = "CREDENTIAL"
    CONTACT = "CONTACT"
    NETWORK = "NETWORK"


# Lower number wins when two validators hit overlapping spans.
_CATEGORY_PRIORITY = {
    Category.GOVERNMENT_ID: 0,
    Category.CREDENTIAL: 1,
    Category.FINANCIAL: 1,
    Category.CONTACT: 2,
    Category.NETWORK: 3,
}


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #
def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0.0 for an empty string)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)


# --------------------------------------------------------------------------- #
# Checksums
# --------------------------------------------------------------------------- #
def luhn_valid(number: str) -> bool:
    """Luhn check over the digits of ``number`` (needs at least 2 digits)."""
    digits = [int(c) for c in _digits(number)]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_append(payload_digits: str) -> str:
    """Return ``payload_digits`` plus the Luhn check digit (test/data helper)."""
    base = _digits(payload_digits)
    for check in range(10):
        if luhn_valid(base + str(check)):
            return base + str(check)
    raise ValueError("unreachable: a Luhn check digit always exists")


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(number: str) -> bool:
    """Verhoeff check over the digits of ``number``."""
    digits = _digits(number)
    if len(digits) < 2:
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_append(payload_digits: str) -> str:
    """Return ``payload_digits`` plus its Verhoeff check digit (test/data helper)."""
    base = _digits(payload_digits)
    c = 0
    for i, ch in enumerate(reversed(base)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return base + str(_VERHOEFF_INV[c])


# --------------------------------------------------------------------------- #
# Individual checks (each receives a candidate already matched by a regex)
# --------------------------------------------------------------------------- #
def _check_aadhaar(candidate: str) -> bool:
    d = _digits(candidate)
    return len(d) == 12 and d[0] in "23456789" and verhoeff_valid(d)


def _check_card(candidate: str) -> bool:
    d = _digits(candidate)
    return 13 <= len(d) <= 19 and len(set(d)) > 1 and luhn_valid(d)


_PAN_4TH = "ABCFGHJLPTK"


def _check_pan(candidate: str) -> bool:
    return len(candidate) == 10 and candidate[3] in _PAN_4TH


def _check_phone(candidate: str) -> bool:
    return 10 <= len(_digits(candidate)) <= 15


def _check_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_KNOWN_KEY_PREFIX = re.compile(r"(?:sk-|AKIA|gh[pousr]_|xox[abprs]-|AIza)")


def _check_api_key(candidate: str) -> bool:
    if _UUID_RE.fullmatch(candidate):
        return False
    if _KNOWN_KEY_PREFIX.match(candidate) and len(candidate) >= 20:
        return True
    if len(candidate) < 24:
        return False
    has_lower = any(c.islower() for c in candidate)
    has_upper = any(c.isupper() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    return has_digit and (has_lower or has_upper) and (
        has_lower + has_upper + has_digit >= 2
    ) and shannon_entropy(candidate) >= 3.5


def _always(_: str) -> bool:
    return True


# --------------------------------------------------------------------------- #
# Validator objects
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ValidatorHit:
    """One validator match inside a text. Never stores the matched text."""

    validator: str
    entity_label: str
    category: str
    start: int
    end: int

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class Validator:
    name: str
    entity_label: str
    category: str
    pattern: "re.Pattern[str]"
    check: Callable[[str], bool]

    def matches_value(self, value: str) -> bool:
        """True when the *entire* (stripped) value is a valid identifier."""
        v = value.strip()
        return bool(v) and self.pattern.fullmatch(v) is not None and self.check(v)

    def find(self, text: str) -> List[ValidatorHit]:
        """All valid occurrences inside ``text`` (offsets only)."""
        hits: List[ValidatorHit] = []
        for m in self.pattern.finditer(text):
            if self.check(m.group(0)):
                hits.append(
                    ValidatorHit(self.name, self.entity_label, self.category, m.start(), m.end())
                )
        return hits


_NOT_WORD = r"(?![\w])"

_VALIDATORS: Tuple[Validator, ...] = (
    Validator(
        "EMAIL", "EMAIL_ADDRESS", Category.CONTACT,
        re.compile(
            r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}(?![\w\-])"
        ),
        _always,
    ),
    Validator(
        "PHONE", "PHONE_NUMBER", Category.CONTACT,
        re.compile(
            r"(?<![\w+])(?:"
            r"(?:(?:\+91|0091|91|0)[ -]?)?[6-9]\d{4}[ -]?\d{5}"        # Indian mobile
            r"|\+\d{1,3}[ -]?\d{2,5}[ -]?\d{3,5}[ -]?\d{3,5}"          # E.164-like
            r")" + _NOT_WORD
        ),
        _check_phone,
    ),
    Validator(
        "PAN", "GOVERNMENT_ID", Category.GOVERNMENT_ID,
        re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])"),
        _check_pan,
    ),
    Validator(
        "AADHAAR_VERHOEFF", "GOVERNMENT_ID", Category.GOVERNMENT_ID,
        re.compile(
            r"(?<!\d)(?<!\d[ -])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)"
        ),
        _check_aadhaar,
    ),
    Validator(
        "CREDIT_CARD_LUHN", "CREDIT_CARD_NUMBER", Category.FINANCIAL,
        re.compile(r"(?<!\d)(?<!\d[ -])\d(?:[ -]?\d){12,18}(?![ -]?\d)"),
        _check_card,
    ),
    Validator(
        "IFSC", "BANK_BRANCH_CODE", Category.FINANCIAL,
        re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])"),
        _always,
    ),
    Validator(
        "API_KEY_HEURISTIC", "API_KEY", Category.CREDENTIAL,
        re.compile(r"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+/=]{20,}(?![A-Za-z0-9_\-+/=])"),
        _check_api_key,
    ),
    Validator(
        "IPV4", "IP_ADDRESS", Category.NETWORK,
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
        _check_ipv4,
    ),
)

REGISTRY: Dict[str, Validator] = {v.name: v for v in _VALIDATORS}
VALIDATOR_NAMES: Tuple[str, ...] = tuple(REGISTRY)


def get_validators(names: Optional[Iterable[str]] = None) -> Tuple[Validator, ...]:
    """Return validators by name (all of them when ``names`` is None)."""
    if names is None:
        return _VALIDATORS
    selected = []
    for n in names:
        if n not in REGISTRY:
            raise KeyError(f"Unknown validator {n!r}; known: {', '.join(VALIDATOR_NAMES)}")
        selected.append(REGISTRY[n])
    return tuple(selected)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def to_text(value: Any) -> Optional[str]:
    """Convert a JSON leaf to text; None for null/containers (not scanned)."""
    if value is None or isinstance(value, (list, dict)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def classify_value(value: Any, names: Optional[Iterable[str]] = None) -> List[str]:
    """Names of validators for which the whole value is a valid identifier."""
    text = to_text(value)
    if text is None:
        return []
    return [v.name for v in get_validators(names) if v.matches_value(text)]


def scan_text(
    text: str,
    names: Optional[Iterable[str]] = None,
    resolve_overlaps: bool = True,
) -> List[ValidatorHit]:
    """Find identifiers embedded in free text; returns hits sorted by offset.

    With ``resolve_overlaps`` the higher-priority category wins (government ID
    over financial/credential over contact over network), then the longer span.
    """
    if not text:
        return []
    hits: List[ValidatorHit] = []
    for v in get_validators(names):
        hits.extend(v.find(text))
    if resolve_overlaps:
        hits = _resolve(hits)
    return sorted(hits, key=lambda h: (h.start, h.end))


def _resolve(hits: Sequence[ValidatorHit]) -> List[ValidatorHit]:
    ranked = sorted(hits, key=lambda h: (_CATEGORY_PRIORITY.get(h.category, 9), -h.length, h.start))
    chosen: List[ValidatorHit] = []
    for h in ranked:
        if all(h.end <= c.start or h.start >= c.end for c in chosen):
            chosen.append(h)
    return chosen


def field_hit_ratios(
    values: Iterable[Any],
    embedded: bool = False,
    names: Optional[Iterable[str]] = None,
    max_values: int = 200,
) -> Dict[str, float]:
    """Fraction of sampled values on which each validator fires.

    ``embedded=False`` requires the whole value to match (structured fields);
    ``embedded=True`` counts a value if the validator finds the identifier
    anywhere inside it (free-text fields). Null and container values are
    skipped. Only the first ``max_values`` usable values are sampled, so the
    result is deterministic.
    """
    selected = get_validators(names)
    texts: List[str] = []
    for value in values:
        t = to_text(value)
        if t is not None and t.strip():
            texts.append(t)
        if len(texts) >= max_values:
            break
    if not texts:
        return {v.name: 0.0 for v in selected}
    ratios: Dict[str, float] = {}
    for v in selected:
        if embedded:
            count = sum(1 for t in texts if v.find(t))
        else:
            count = sum(1 for t in texts if v.matches_value(t))
        ratios[v.name] = count / len(texts)
    return ratios
