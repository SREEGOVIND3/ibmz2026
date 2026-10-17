"""Approved baseline field profiles in SQLite (implements ``BaselineStore``).

Stores only ``FieldProfile`` statistics and keyed hash prefixes, never raw
values. A row that cannot be parsed raises ``StorageError`` instead of being
skipped: an unreadable baseline must stop the pipeline (fail closed), not make
every field look new or, worse, silently known.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable, Optional

from ..schemas import FieldProfile
from .database import Database, StorageError


class BaselineRepository:
    def __init__(self, db: Database, *, clock: Optional[Callable[[], datetime]] = None) -> None:
        self._db = db
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def load_all(self) -> dict:
        profiles: dict = {}
        for row in self._db.fetchall("SELECT schema_path, profile_json FROM baseline_profiles"):
            profiles[row["schema_path"]] = self._parse(row["profile_json"])
        return profiles

    def get(self, schema_path: str) -> Optional[FieldProfile]:
        row = self._db.fetchone(
            "SELECT profile_json FROM baseline_profiles WHERE schema_path = ?", (schema_path,)
        )
        return self._parse(row["profile_json"]) if row else None

    def save(self, profile: FieldProfile) -> None:
        """Insert or replace the profile for ``profile.schema_path``."""
        try:
            body = json.dumps(profile.to_dict(), sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise StorageError(f"profile is not serialisable: {type(exc).__name__}") from exc
        now = self._clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._db.execute(
            """INSERT INTO baseline_profiles (schema_path, profile_json, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(schema_path) DO UPDATE SET
                   profile_json = excluded.profile_json,
                   updated_at   = excluded.updated_at""",
            (profile.schema_path, body, now),
        )

    def count(self) -> int:
        return int(self._db.fetchone("SELECT COUNT(*) FROM baseline_profiles")[0])

    @staticmethod
    def _parse(text: str) -> FieldProfile:
        try:
            return FieldProfile.from_dict(json.loads(text))
        except (TypeError, ValueError, KeyError) as exc:
            raise StorageError(f"baseline profile row is unreadable: {type(exc).__name__}") from exc
