import unittest

from app.schemas import EnforcementResult
from app.services.revalidation_service import RevalidationService
from tests.fakes import ExplodingDetector, RegexSpanDetector, make_pipeline


def reval_for(parts, sanitized, removed=(), quarantined=False, purpose="ai_triage"):
    svc = RevalidationService(
        parts["profiler"], parts["detection"], parts["risk"], parts["policy"],
    )
    enf = EnforcementResult(sanitized, quarantined, removed_texts=list(removed))
    return svc.revalidate(enf, purpose, "risk_scoring_model")


class RevalidationTests(unittest.TestCase):
    def setUp(self):
        self.parts = make_pipeline()

    def test_clean_payload_passes(self):
        r = reval_for(self.parts, {"notes": "Patient reports fever and cough today."})
        self.assertTrue(r.passed, r.violations)

    def test_placeholders_do_not_trigger_findings(self):
        payload = {"a": "[MASKED_GOVERNMENT_ID]", "b": "tok_" + "ab12" * 8, "c": "Aadhaar [REDACTED_GOVERNMENT_ID] given"}
        self.assertTrue(reval_for(self.parts, payload).passed)

    def test_remaining_restricted_span_blocks(self):
        r = reval_for(self.parts, {"notes": "Guardian Aadhaar: 2345 6789 0123 listed here"})
        self.assertFalse(r.passed)
        self.assertTrue(any("GOVERNMENT_ID" in v for v in r.violations))
        self.assertFalse(any("2345" in v for v in r.violations))  # no raw value in message

    def test_remaining_restricted_field_blocks(self):
        r = reval_for(self.parts, {"guardian_uid": "234567890123"})
        self.assertFalse(r.passed)

    def test_authorized_kind_may_remain(self):
        r = reval_for(self.parts, {"c": "mail jane@example.org now please ok"}, purpose="support")
        self.assertTrue(r.passed, r.violations)

    def test_removed_value_still_present_blocks_even_if_reformatted(self):
        r = reval_for(self.parts, {"memo": "ref 2345-6789-0123x"}, removed=["2345 6789 0123"])
        self.assertFalse(r.passed)
        self.assertTrue(any("removed value" in v for v in r.violations))

    def test_short_removed_values_ignored(self):
        r = reval_for(self.parts, {"memo": "age 34 years old"}, removed=["34"])
        self.assertTrue(r.passed)

    def test_quarantined_or_missing_payload_blocks(self):
        self.assertFalse(reval_for(self.parts, None, quarantined=True).passed)
        self.assertFalse(reval_for(self.parts, {"a": 1}, quarantined=True).passed)

    def test_required_detector_failure_fails_closed(self):
        parts = make_pipeline(detectors=[ExplodingDetector(required=True)])
        r = reval_for(parts, {"notes": "Patient reports fever and cough today."})
        self.assertFalse(r.passed)
        self.assertIn("revalidation error", r.violations[0])
        self.assertNotIn("Patient", " ".join(r.violations))

    def test_optional_detector_failure_does_not_block_but_is_reported(self):
        parts = make_pipeline(detectors=[RegexSpanDetector(), ExplodingDetector(required=False)])
        r = reval_for(parts, {"notes": "Patient reports fever and cough today."})
        self.assertTrue(r.passed)
        self.assertTrue(r.detector_errors)


if __name__ == "__main__":
    unittest.main()
