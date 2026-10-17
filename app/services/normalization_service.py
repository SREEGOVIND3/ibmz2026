"""JSON flattening into stable schema paths plus path helpers.

Schema path rules: nested keys are joined with ``.``; list indexes collapse to
``[]`` so ``visits[0].notes`` and ``visits[1].notes`` share ``visits[].notes``.
Special characters in keys (``. [ ] \\``) are backslash-escaped so that
``{"a.b": 1}`` and ``{"a": {"b": 1}}`` cannot collide.
"""
from __future__ import annotations

import re
from typing import Any

from ..config import Limits
from ..schemas import Leaf, Path


class NormalizationError(ValueError):
    pass


_ESCAPE = re.compile(r"([.\[\]\\])")


def _escape(key: str) -> str:
    return _ESCAPE.sub(r"\\\1", key)


def json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):  # before int: bool is a subclass of int
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    raise NormalizationError(f"unsupported value type: {type(value).__name__}")


def flatten(payload: Any, limits: Limits = Limits()) -> list:
    """Return one ``Leaf`` per scalar. Empty containers produce no leaves."""
    if not isinstance(payload, (dict, list)):
        raise NormalizationError("payload must be a JSON object or array")
    leaves: list = []

    def walk(node: Any, schema: str, path: Path, depth: int) -> None:
        if depth > limits.max_depth:
            raise NormalizationError(f"payload nesting exceeds {limits.max_depth}")
        if isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise NormalizationError("object keys must be strings")
                child_schema = f"{schema}.{_escape(key)}" if schema else _escape(key)
                walk(child, child_schema, path + (key,), depth + 1)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{schema}[]", path + (index,), depth + 1)
        else:
            if json_type(node) == "string" and len(node) > limits.max_string_len:
                raise NormalizationError(
                    f"string value exceeds {limits.max_string_len} characters"
                )
            if len(leaves) >= limits.max_leaves:
                raise NormalizationError(f"payload exceeds {limits.max_leaves} values")
            leaves.append(Leaf(schema_path=schema, path=path, value=node))

    walk(payload, "", (), 0)
    return leaves


def get_at(root: Any, path: Path) -> Any:
    node = root
    for part in path:
        node = node[part]
    return node


def set_at(root: Any, path: Path, value: Any) -> None:
    if not path:
        raise NormalizationError("cannot replace the root")
    get_at(root, path[:-1])[path[-1]] = value
