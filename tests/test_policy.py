import unittest

from app.config import DEFAULT_POLICY
from app.schemas import Action, DriftType, Kind, Severity
from app.services.detection_service import DetectionError, DetectionService
from app.services.drift_service import DriftService
from app.services.normalization_service import flatten
from app.services.policy_service import PolicyEngine, PolicyError
from app.services.profiling_service import Profiler
from app.services.risk_service import RiskService
from tests.fakes import (
    KEY, VALIDATORS, ExplodingDetector, FixedClassifier, RegexSpanDetector,
)


def run(payload, baseline_payload=None, *, detectors=None, classifier=None,
        purpose="ai_triage", destination="risk_scoring_model", policy=None):
    prof = Profiler(KEY, VALIDATORS)
    base = prof.profile(flatten(baseline_payload)) if baseline_payload else {}
    leaves = flatten(payload)
    profiles = prof.profile(leaves)
    report = DriftService().detect(profiles, base)
    det = DetectionService(detectors if detectors is not None else [RegexSpanDetector()], classifier)
    detections = det.detect(leaves, profiles, report.evidence)
    assess = RiskService().assess(detections, report.evidence)
    engine = PolicyEngine(policy or DEFAULT_POLICY)
    return engine.decide(assess, report.evidence, purpose, destination), assess, detections


def by_path(result):
    return {d.schema_path: d for d in result.decisions}


KNOWN = {"patient": {"id": "PT-1", "notes": "Patient reports fever and mild cough since yesterday."}}


class DetectionTests(unittest.TestCase):
    def test_required_detector_failure_fails_closed_without_leaking_text(self):
        with self.assertRaises(DetectionError) as ctx:
            run({"n": "sensitive-canary-text"}, detectors=[ExplodingDetector(required=True)])
        self.assertNotIn("canary", str(ctx.exception))

    def test_optional_detector_failure_is_recorded_not_fatal(self):
        _, _, det = run(
            {"n": "234567890123 appears here"},
            detectors=[RegexSpanDetector(), ExplodingDetector(required=False)],
        )
        self.assertTrue(det["n"].spans)  # deterministic detector still worked
        self.assertTrue(any("exploding" in e for e in det["n"].errors))
        self.assertNotIn("234567890123", " ".join(det["n"].errors))

    def test_invalid_span_from_optional_dropped_from_required_fatal(self):
        class Bad(RegexSpanDetector):
            def detect(self, text):
                from app.schemas import SpanHit
                return [SpanHit(0, len(text) + 5, "GOVERNMENT_ID", 0.9, self.name)]
        _, _, det = run({"n": "abcdefgh"}, detectors=[Bad(required=False)])
        self.assertEqual(det["n"].spans, [])
        with self.assertRaises(DetectionError):
            run({"n": "abcdefgh"}, detectors=[Bad(required=True)])

    def test_text_only_detector_skips_non_text_fields(self):
        ml = RegexSpanDetector(name="ml", required=False, text_only=True)
        _, _, det = run({"code": "234567890123", "notes": "Patient said 234567890123 is the number."}, detectors=[ml])
        self.assertEqual(det["code"].spans, [])
        self.assertTrue(det["notes"].spans)

    def test_classifier_failure_is_optional(self):
        class Boom:
            def predict(self, p, d): raise ValueError("x")
        _, _, det = run({"a": "b"}, classifier=Boom())
        self.assertIsNone(det["a"].classifier_probability)


class DecisionTableTests(unittest.TestCase):
    def test_clean_known_payload_allows_everything(self):
        res, _, _ = run(KNOWN, KNOWN)
        self.assertTrue(all(d.action is Action.ALLOW and not d.flag_for_review for d in res.decisions))

    def test_new_low_risk_field_allowed_and_flagged(self):
        res, _, _ = run({**KNOWN, "extra": "ok"}, KNOWN)
        d = by_path(res)["extra"]
        self.assertIs(d.action, Action.ALLOW)
        self.assertTrue(d.flag_for_review)

    def test_new_field_government_id_is_quarantined_with_reason(self):
        payload = {"patient": {**KNOWN["patient"], "guardian_uid": "234567890123"}}
        res, assess, _ = run(payload, KNOWN)
        d = by_path(res)["patient.guardian_uid"]
        self.assertIs(d.action, Action.QUARANTINE_FIELD)
        self.assertIs(d.kind, Kind.GOVERNMENT_ID)
        self.assertIs(assess["patient.guardian_uid"].severity, Severity.CRITICAL)
        self.assertIn("NEW_FIELD", d.reason)
        self.assertIn("AADHAAR", d.reason)
        self.assertFalse(res.payload_quarantined)

    def test_span_in_free_text_is_redacted(self):
        payload = {"patient": {"id": "PT-1", "notes": "Patient reports fever. Guardian Aadhaar: 2345 6789 0123."}}
        res, _, _ = run(payload, KNOWN)
        d = by_path(res)["patient.notes"]
        self.assertIs(d.action, Action.REDACT_SPAN)
        self.assertEqual(len(d.spans), 1)

    def test_repeated_high_spans_quarantine_the_field(self):
        text = "ids 2345 6789 0123 and 3456 7890 1234 and 4567 8901 2345 recorded"
        res, _, _ = run({"patient": {"id": "PT-1", "notes": text}}, KNOWN)
        self.assertIs(by_path(res)["patient.notes"].action, Action.QUARANTINE_FIELD)

    def test_card_number_quarantines_whole_payload(self):
        payload = {"patient": {"id": "PT-1", "notes": "paid with 4111111111111111 yesterday ok"}}
        res, _, _ = run(payload, KNOWN)
        self.assertTrue(res.payload_quarantined)
        self.assertIs(by_path(res)["patient.notes"].action, Action.QUARANTINE_PAYLOAD)

    def test_government_id_follows_table_if_configured(self):
        policy = {**DEFAULT_POLICY, "payload_quarantine_kinds": ["CREDENTIAL", "CARD_NUMBER", "GOVERNMENT_ID"]}
        payload = {"patient": {"id": "PT-1", "notes": "Aadhaar 2345 6789 0123 given"}}
        res, _, _ = run(payload, KNOWN, policy=policy)
        self.assertTrue(res.payload_quarantined)

    def test_authorization_is_purpose_and_destination_aware(self):
        payload = {"c": "mail jane@example.org now please ok"}
        deny, _, _ = run(payload, purpose="ai_triage")
        self.assertIs(by_path(deny)["c"].action, Action.REDACT_SPAN)
        allow, _, _ = run(payload, purpose="support", destination="helpdesk")
        self.assertIs(by_path(allow)["c"].action, Action.ALLOW)
        unknown, _, _ = run(payload, purpose="marketing", destination="x")
        self.assertIs(by_path(unknown)["c"].action, Action.REDACT_SPAN)

    def test_medium_new_field_masks_or_tokenizes(self):
        payload = {**KNOWN, "mystery": "abc"}
        res, _, _ = run(payload, KNOWN, classifier=FixedClassifier(0.5))
        self.assertIs(by_path(res)["mystery"].action, Action.MASK)
        policy = {**DEFAULT_POLICY, "medium_action": "TOKENIZE"}
        res, _, _ = run(payload, KNOWN, classifier=FixedClassifier(0.5), policy=policy)
        self.assertIs(by_path(res)["mystery"].action, Action.TOKENIZE)

    def test_high_classifier_new_field_quarantined(self):
        res, _, _ = run({**KNOWN, "mystery": "abc"}, KNOWN, classifier=FixedClassifier(0.95))
        self.assertIs(by_path(res)["mystery"].action, Action.QUARANTINE_FIELD)

    def test_known_field_shift_without_evidence_flag_only_by_default(self):
        base = {"code": "ABCDEFGHIJ"}
        cur = {"code": "1234567890"}  # digit-ratio shift, no validator hit
        res, _, _ = run(cur, base)
        d = by_path(res)["code"]
        self.assertIs(d.action, Action.ALLOW)
        self.assertTrue(d.flag_for_review)
        policy = {**DEFAULT_POLICY, "quarantine_on_shift_without_evidence": True}
        res, _, _ = run(cur, base, policy=policy)
        self.assertIs(by_path(res)["code"].action, Action.QUARANTINE_FIELD)

    def test_credential_in_known_field_is_never_allowed(self):
        policy = {**DEFAULT_POLICY, "allow": {"ai_triage": {"*": ["CREDENTIAL", "HEALTH"]}}}
        engine = PolicyEngine(policy)
        self.assertFalse(engine.is_authorized(Kind.CREDENTIAL, "ai_triage", "x"))
        self.assertTrue(engine.is_authorized(Kind.HEALTH, "ai_triage", "x"))
        self.assertFalse(engine.is_authorized(Kind.UNKNOWN_SENSITIVE, "ai_triage", "x"))

    def test_policy_validation(self):
        with self.assertRaises(PolicyError):
            PolicyEngine({"never_allow": ["NOPE"]})
        with self.assertRaises(PolicyError):
            PolicyEngine({"medium_action": "DELETE"})


if __name__ == "__main__":
    unittest.main()
