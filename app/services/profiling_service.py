"""Per-field statistical profiles over the values seen for one schema path.

Validator hit ratios are computed across ALL values of a field in the payload
(e.g. every element of an array), so a ratio is only fractional for arrays or
merged baselines. Raw values are never stored: only keyed, truncated hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import math
from collections import Counter
from typing import Any, Optional, Sequence

from ..schemas import FieldProfile, Leaf, Validators
from .normalization_service import json_type

TEXT_MIN_LEN = 20
TEXT_MIN_WHITESPACE = 0.05
MAX_HASHES = 5


def shannon_entropy(text: str) -> float:
    """Bits per character."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def value_text(value: Any) -> Optional[str]:
    """String form used for statistics and validators (None for JSON null)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return repr(value) if isinstance(value, float) else str(value)


def _ratios(text: str) -> tuple:
    n = len(text)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    digits = sum(c.isdigit() for c in text)
    alpha = sum(c.isalpha() for c in text)
    space = sum(c.isspace() for c in text)
    return digits / n, alpha / n, (n - digits - alpha - space) / n, space / n


def _text_like(json_kind: str, mean_len: float, ws: float) -> bool:
    return json_kind == "string" and mean_len >= TEXT_MIN_LEN and ws >= TEXT_MIN_WHITESPACE


class Profiler:
    def __init__(
        self,
        hmac_key: bytes,
        validators: Validators,
        *,
        max_hashes: int = MAX_HASHES,
    ) -> None:
        # Domain-separated subkey so the profile-hash key differs from the token key.
        self._key = hmac.new(hmac_key, b"consentshield/profile/v1", hashlib.sha256).digest()
        self._validators = dict(validators)
        self._max_hashes = max_hashes

    def _hash(self, text: str) -> str:
        return hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def profile(self, leaves: Sequence[Leaf]) -> dict:
        groups: dict = {}
        for leaf in leaves:
            groups.setdefault(leaf.schema_path, []).append(leaf)
        return {path: self._profile_group(path, items) for path, items in groups.items()}

    def _profile_group(self, schema_path: str, items: Sequence[Leaf]) -> FieldProfile:
        types = [json_type(i.value) for i in items]
        dominant = Counter(types).most_common(1)[0][0]
        texts = [t for t in (value_text(i.value) for i in items) if t is not None]
        n = len(texts)

        if n:
            lengths = [len(t) for t in texts]
            per_value = [_ratios(t) for t in texts]
            mean_len = sum(lengths) / n
            digit, alpha, symbol, ws = (sum(r[k] for r in per_value) / n for k in range(4))
            entropy = sum(shannon_entropy(t) for t in texts) / n
        else:
            mean_len = digit = alpha = symbol = ws = entropy = 0.0

        hits: dict = {}
        scored = [
            value_text(i.value) for i in items
            if i.value is not None and not isinstance(i.value, bool)
        ]
        for name, check in self._validators.items():
            # Exceptions propagate on purpose: a broken validator must not
            # silently read as "no hit" (fail open).
            matched = sum(1 for t in scored if check(t))
            if matched:
                hits[name] = matched / len(scored)

        hashes: list = []
        for t in texts:
            h = self._hash(t)
            if h not in hashes:
                hashes.append(h)
            if len(hashes) >= self._max_hashes:
                break

        return FieldProfile(
            schema_path=schema_path,
            json_type=dominant,
            count=len(items),
            mean_length=mean_len,
            digit_ratio=digit,
            alpha_ratio=alpha,
            symbol_ratio=symbol,
            whitespace_ratio=ws,
            entropy=entropy,
            validator_hits=hits,
            types_seen=tuple(sorted(set(types))),
            value_hashes=tuple(hashes),
            is_text_like=_text_like(dominant, mean_len, ws),
        )


def merge_profiles(a: FieldProfile, b: FieldProfile) -> FieldProfile:
    """Count-weighted merge, used when an analyst approves new baseline data."""
    total = a.count + b.count
    if total == 0:
        return a
    wa, wb = a.count / total, b.count / total

    def mix(x: float, y: float) -> float:
        return x * wa + y * wb

    names = set(a.validator_hits) | set(b.validator_hits)
    hits = {n: mix(a.validator_hits.get(n, 0.0), b.validator_hits.get(n, 0.0)) for n in names}
    hashes = list(a.value_hashes)
    for h in b.value_hashes:
        if h not in hashes and len(hashes) < MAX_HASHES:
            hashes.append(h)
    mean_len, ws = mix(a.mean_length, b.mean_length), mix(a.whitespace_ratio, b.whitespace_ratio)
    kind = a.json_type if a.count >= b.count else b.json_type
    return FieldProfile(
        schema_path=a.schema_path,
        json_type=kind,
        count=total,
        mean_length=mean_len,
        digit_ratio=mix(a.digit_ratio, b.digit_ratio),
        alpha_ratio=mix(a.alpha_ratio, b.alpha_ratio),
        symbol_ratio=mix(a.symbol_ratio, b.symbol_ratio),
        whitespace_ratio=ws,
        entropy=mix(a.entropy, b.entropy),
        validator_hits=hits,
        types_seen=tuple(sorted(set(a.types_seen) | set(b.types_seen))),
        value_hashes=tuple(hashes),
        is_text_like=_text_like(kind, mean_len, ws),
    )
