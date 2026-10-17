"""End-to-end: canary values must never reach downstream, audit, or results."""
import json
import unittest

from app.schemas import Outcome
from app.services.ingest_service import IngestError, parse_request
from tests.fakes import (
    ExplodingDetector, MemoryAuditStore, RegexSpanDetector, envelope, make_pipeline,
)

AADHAAR = "234567890123"          # canary government ID (guardian_uid)
AADHAAR_SPACED = "3456 7890 1234"  # canary embedded in notes
EMAIL = "canary.jane@example.org"
CARD = "4111111111111111"

ATTACK = {
    "patient": {
        "id": "PT-88213", "age": 34,
        "notes": f"Patient reports fever. Guardian Aadhaar: {AADHAAR_SPACED}. Mail {EMAIL} please.",
    },
    "visit": {"date": "2026-10-17", "symptoms": ["fever", "cough"]},
    "guardian_uid": AADHAAR,
}


def blob(obj) -> str:
    return json.dumps(obj, default=str)


class NoLeakageTests(unittest.TestCase):
    def assert_no_canaries(self, text, canaries=(AADHAAR, "3456", "7890 1234", EMAIL, CARD)):
        for c in canaries:
            self.assertNotIn(c, text, f"canary leaked: {c[:4]}...")

    def test_attack_is_sanitized_forwarded_and_clean_everywhere(self):
        p = make_pipeline()
        result = p["service"].handle(envelope(ATTACK))
        self.assertIs(result.outcome, Outcome.FORWARD_SANITIZED)
        self.assertTrue(result.forwarded and result.revalidated)

        downstream = blob(p["forwarded"])
        self.assertEqual(len(p["forwarded"]), 1)
        self.assert_no_canaries(downstream)
        self.assertNotIn("guardian_uid", downstream)
        self.assertIn("[REDACTED_GOVERNMENT_ID]", downstream)
        self.assertIn("[REDACTED_CONTACT]", downstream)  # email unauthorized for ai_triage
        self.assertEqual(p["forwarded"][0]["patient"]["age"], 34)  # safe data preserved

        self.assert_no_canaries(blob(p["audit_store"].events), (AADHAAR, "3456", EMAIL))
        self.assert_no_canaries(repr(result) + blob(result.actions), (AADHAAR, "3456", EMAIL))
        self.assertTrue(p["audit"].verify().ok)

        # Raw value is retained ONLY in the quarantine store (to be encrypted later)
        (req_id, items), = p["quarantine"].stored
        self.assertEqual(items[0].raw_value, AADHAAR)
        self.assertNotIn(AADHAAR, repr(items))

        by_field = {a["field_path"]: a for a in result.actions}
        self.assertEqual(by_field["guardian_uid"]["action"], "QUARANTINE_FIELD")
        self.assertEqual(by_field["patient.notes"]["action"], "REDACT_SPAN")
        self.assertIn("NEW_FIELD", by_field["guardian_uid"]["reason"])

    def test_clean_payload_forwards_unchanged(self):
        p = make_pipeline()
        clean = {
            "patient": {"id": "PT-1", "age": 41, "notes": "Patient reports fever and mild cough since today."},
            "visit": {"date": "2026-10-20", "symptoms": ["fever"]},
        }
        result = p["service"].handle(envelope(clean))
        self.assertIs(result.outcome, Outcome.FORWARD_UNCHANGED)
        self.assertEqual(p["forwarded"], [clean])

    def test_card_number_quarantines_payload_nothing_forwarded(self):
        p = make_pipeline()
        payload = {"patient": {"id": "PT-1", "age": 41, "notes": f"Paid using card {CARD} today ok."}}
        result = p["service"].handle(envelope(payload))
        self.assertIs(result.outcome, Outcome.QUARANTINED)
        self.assertFalse(result.forwarded)
        self.assertIsNone(result.sanitized_payload)
        self.assertEqual(p["forwarded"], [])
        self.assert_no_canaries(blob(p["audit_store"].events) + repr(result), (CARD,))
        self.assertEqual(p["quarantine"].stored[0][1][0].path, ())

    def test_optional_model_failure_does_not_open_the_boundary(self):
        p = make_pipeline(detectors=[RegexSpanDetector(), ExplodingDetector(required=False)])
        result = p["service"].handle(envelope(ATTACK))
        self.assertTrue(result.forwarded)
        self.assert_no_canaries(blob(p["forwarded"]))

    def test_required_detector_failure_blocks(self):
        p = make_pipeline(detectors=[ExplodingDetector(required=True)])
        result = p["service"].handle(envelope(ATTACK))
        self.assertIs(result.outcome, Outcome.BLOCKED)
        self.assertEqual(p["forwarded"], [])
        self.assertIsNone(result.sanitized_payload)
        self.assertIn("pipeline_error", result.error)
        self.assert_no_canaries(blob(p["audit_store"].events) + repr(result) + result.error)

    def test_detector_that_dies_only_during_revalidation_blocks(self):
        class DiesOnSecondCall(RegexSpanDetector):
            calls = 0
            def detect(self, text):
                DiesOnSecondCall.calls += 1
                if DiesOnSecondCall.calls > 2:  # detection pass used the first calls
                    raise RuntimeError("late failure")
                return super().detect(text)
        p = make_pipeline(detectors=[DiesOnSecondCall()])
        DiesOnSecondCall.calls = 0
        result = p["service"].handle(envelope({"patient": {
            "id": "PT-1", "age": 3, "notes": f"Aadhaar {AADHAAR_SPACED} listed for the patient."}}))
        self.assertIs(result.outcome, Outcome.BLOCKED)
        self.assertEqual(p["forwarded"], [])
        self.assertTrue(result.violations)

    def test_audit_failure_blocks_forwarding(self):
        class FailingStore(MemoryAuditStore):
            def append(self, event):
                raise OSError("disk full")
        p = make_pipeline(audit_store=FailingStore())
        result = p["service"].handle(envelope({"patient": {"id": "PT-1", "age": 4, "notes": "Patient reports fever and mild cough since today."}}))
        self.assertFalse(result.forwarded)
        self.assertEqual(p["forwarded"], [])
        self.assertIs(result.outcome, Outcome.BLOCKED)
        self.assertIn("audit_error", result.error)

    def test_forward_failure_is_reported_not_raised(self):
        def bad_forward(payload, req):
            raise ConnectionError("downstream down")
        p = make_pipeline(forward=bad_forward)
        result = p["service"].handle(envelope(ATTACK))
        self.assertIs(result.outcome, Outcome.FORWARD_FAILED)
        self.assertFalse(result.forwarded)
        self.assertIsNone(result.sanitized_payload)
        self.assertTrue(p["audit"].verify().ok)

    def test_missing_baseline_is_handled_and_still_redacts(self):
        p = make_pipeline(bootstrap=False)
        result = p["service"].handle(envelope(ATTACK))
        self.assertTrue(result.forwarded)
        self.assert_no_canaries(blob(p["forwarded"]))

    def test_missing_fields_reported(self):
        p = make_pipeline()
        result = p["service"].handle(envelope({"patient": {"id": "PT-1", "age": 5}}))
        self.assertIn("visit.date", result.missing_fields)

    def test_empty_payload(self):
        p = make_pipeline()
        result = p["service"].handle(envelope({}))
        self.assertTrue(result.forwarded)
        self.assertEqual(p["forwarded"], [{}])

    def test_deep_and_oversized_payloads_blocked_not_crashed(self):
        p = make_pipeline()
        deep = cur = {}
        for _ in range(40):
            cur["x"] = {}
            cur = cur["x"]
        cur["v"] = AADHAAR
        result = p["service"].handle(envelope(deep))
        self.assertIs(result.outcome, Outcome.BLOCKED)
        self.assertEqual(p["forwarded"], [])
        big = {"a": ["x"] * 6000}
        self.assertIs(p["service"].handle(envelope(big)).outcome, Outcome.BLOCKED)

    def test_unicode_and_array_leaks(self):
        p = make_pipeline()
        payload = {"patient": {"id": "PT-1", "age": 4,
                   "notes": f"Pâtient 日本語 reports fever; Aadhaar {AADHAAR_SPACED} ✓ noted."},
                   "visit": {"date": "2026-10-17", "symptoms": [f"fever {EMAIL}", "cough"]}}
        result = p["service"].handle(envelope(payload))
        self.assertTrue(result.forwarded, result.violations)
        self.assert_no_canaries(blob(p["forwarded"]))
        self.assertIn("日本語", p["forwarded"][0]["patient"]["notes"])

    def test_concurrent_requests_keep_audit_chain_valid(self):
        import threading
        p = make_pipeline()
        clean = {"patient": {"id": "PT-1", "age": 41, "notes": "Patient reports fever and mild cough since today."}}
        threads = [threading.Thread(target=p["service"].handle, args=(envelope(clean, request_id=f"r{i}"),)) for i in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(len(p["forwarded"]), 8)
        self.assertTrue(p["audit"].verify().ok)


class EnvelopeTests(unittest.TestCase):
    def test_valid_and_generated_id(self):
        req = parse_request({"source_system": "a", "processing_purpose": "b", "destination": "c", "payload": {}})
        self.assertTrue(req.request_id.startswith("req-"))

    def test_rejections_never_echo_values(self):
        bad = [
            "not a dict",
            {"source_system": "a", "processing_purpose": "b", "destination": "c", "payload": []},
            {"source_system": "a", "processing_purpose": "b", "payload": {}},
            {"source_system": "", "processing_purpose": "b", "destination": "c", "payload": {}},
            {"request_id": "bad id!", "source_system": "a", "processing_purpose": "b", "destination": "c", "payload": {}},
            {"request_id": "x" * 500, "source_system": "a", "processing_purpose": "b", "destination": "c", "payload": {}},
            {"source_system": 5, "processing_purpose": "b", "destination": "c", "payload": {"k": AADHAAR}},
        ]
        for data in bad:
            with self.assertRaises(IngestError) as ctx:
                parse_request(data)
            self.assertNotIn(AADHAAR, str(ctx.exception))

    def test_handle_raises_ingest_error_for_bad_envelope(self):
        p = make_pipeline()
        with self.assertRaises(IngestError):
            p["service"].handle({"payload": {"k": AADHAAR}})
        self.assertEqual(p["forwarded"], [])


if __name__ == "__main__":
    unittest.main()
