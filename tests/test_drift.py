import unittest

from app.schemas import DriftType
from app.services.drift_service import DriftService
from app.services.normalization_service import flatten
from app.services.profiling_service import Profiler
from tests.fakes import BASELINE_PAYLOADS, KEY, VALIDATORS


class DriftTests(unittest.TestCase):
    def setUp(self):
        self.prof = Profiler(KEY, VALIDATORS)
        self.svc = DriftService()
        from app.services.profiling_service import merge_profiles
        base: dict = {}
        for p in BASELINE_PAYLOADS:
            for path, pr in self.prof.profile(flatten(p)).items():
                base[path] = merge_profiles(base[path], pr) if path in base else pr
        self.base = base

    def run_drift(self, payload):
        return self.svc.detect(self.prof.profile(flatten(payload)), self.base)

    def base_payload(self, **overrides):
        p = {
            "patient": {"id": "PT-55555", "age": 40, "notes": "Patient reports fever and mild cough since today."},
            "visit": {"date": "2026-10-19", "symptoms": ["fever"]},
        }
        for k, v in overrides.items():
            p["patient"][k] = v
        return p

    def test_clean_payload_has_no_drift(self):
        r = self.run_drift(self.base_payload())
        self.assertTrue(all(e.drift_type is DriftType.NO_DRIFT for e in r.evidence.values()), r.evidence)
        self.assertEqual(r.missing, [])

    def test_new_field(self):
        p = self.base_payload()
        p["patient"]["guardian_note"] = "x" * 3
        r = self.run_drift(p)
        self.assertIs(r.evidence["patient.guardian_note"].drift_type, DriftType.NEW_FIELD)

    def test_type_shift(self):
        r = self.run_drift(self.base_payload(age="forty"))
        self.assertIs(r.evidence["patient.age"].drift_type, DriftType.TYPE_SHIFT)

    def test_value_pattern_shift_beats_other_signals(self):
        r = self.run_drift(self.base_payload(id="234567890123"))
        self.assertIs(r.evidence["patient.id"].drift_type, DriftType.VALUE_PATTERN_SHIFT)

    def test_distribution_shift_on_notes(self):
        notes = "Patient reports fever. Reference 99887766554433221100 998877665544 attached for lab."
        r = self.run_drift(self.base_payload(notes=notes))
        self.assertIs(r.evidence["patient.notes"].drift_type, DriftType.DISTRIBUTION_SHIFT)

    def test_missing_field(self):
        p = self.base_payload()
        del p["patient"]["id"]
        r = self.run_drift(p)
        self.assertEqual([m.schema_path for m in r.missing], ["patient.id"])

    def test_rename_match(self):
        p = self.base_payload()
        p["patient"]["pid"] = p["patient"].pop("id")
        r = self.run_drift(p)
        ev = r.evidence["patient.pid"]
        self.assertIs(ev.drift_type, DriftType.RENAME_MATCH)
        self.assertEqual(ev.renamed_from, "patient.id")
        self.assertEqual(r.missing, [])

    def test_empty_baseline_everything_new(self):
        r = self.svc.detect(self.prof.profile(flatten(self.base_payload())), {})
        self.assertTrue(all(e.drift_type is DriftType.NEW_FIELD for e in r.evidence.values()))


if __name__ == "__main__":
    unittest.main()
