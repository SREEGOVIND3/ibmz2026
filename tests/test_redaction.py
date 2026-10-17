import copy
import unittest

from app.schemas import (
    Action, Kind, LocatedSpan, PolicyDecision, PolicyResult, Severity, SpanFinding, SpanHit,
)
from app.services.enforcement_service import (
    EnforcementError, EnforcementService, is_placeholder, strip_placeholders,
)
from app.services.normalization_service import flatten
from tests.fakes import KEY


def finding(path, start, end, kind=Kind.GOVERNMENT_ID, label="GOVERNMENT_ID"):
    return SpanFinding(LocatedSpan(path, SpanHit(start, end, label, 0.9, "t")), Severity.CRITICAL, kind)


def decision(path, action, kind=Kind.GOVERNMENT_ID, spans=()):
    return PolicyDecision(path, action, Severity.HIGH, kind, "r", True, tuple(spans))


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.svc = EnforcementService(KEY)

    def enforce(self, payload, decisions, quarantined=False):
        return self.svc.enforce(payload, flatten(payload), PolicyResult(decisions, quarantined))

    def test_does_not_mutate_input(self):
        payload = {"a": "secret-value-1", "b": "keep"}
        before = copy.deepcopy(payload)
        self.enforce(payload, [decision("a", Action.MASK)])
        self.assertEqual(payload, before)

    def test_mask_and_tokenize(self):
        payload = {"a": "secret-value-1", "b": "secret-value-1"}
        out = self.enforce(payload, [decision("a", Action.MASK), decision("b", Action.TOKENIZE)])
        self.assertEqual(out.sanitized_payload["a"], "[MASKED_GOVERNMENT_ID]")
        self.assertTrue(out.sanitized_payload["b"].startswith("tok_"))
        self.assertIn("secret-value-1", out.removed_texts)

    def test_tokenize_is_deterministic_keyed_and_kind_separated(self):
        other = EnforcementService(b"another-key-0123456789abcdef")
        t1 = self.svc.tokenize(Kind.PERSONAL, "Jane")
        self.assertEqual(t1, self.svc.tokenize(Kind.PERSONAL, "Jane"))
        self.assertNotEqual(t1, other.tokenize(Kind.PERSONAL, "Jane"))
        self.assertNotEqual(t1, self.svc.tokenize(Kind.CONTACT, "Jane"))
        self.assertNotIn("Jane", t1)

    def test_short_key_rejected(self):
        with self.assertRaises(EnforcementError):
            EnforcementService(b"short")

    def test_redact_single_and_overlapping_spans(self):
        text = "Aadhaar 2345 6789 0123 end"
        payload = {"n": text}
        spans = [finding(("n",), 8, 22), finding(("n",), 12, 22), finding(("n",), 20, 22)]
        out = self.enforce(payload, [decision("n", Action.REDACT_SPAN, spans=spans)])
        self.assertEqual(out.sanitized_payload["n"], "Aadhaar [REDACTED_GOVERNMENT_ID] end")
        self.assertEqual(out.removed_texts, ["2345 6789 0123"])

    def test_redact_multiple_spans_and_list_items(self):
        payload = {"msgs": ["call 98765 now", "clean"]}
        spans = [finding(("msgs", 0), 5, 10, Kind.CONTACT, "PHONE_NUMBER")]
        out = self.enforce(payload, [decision("msgs[]", Action.REDACT_SPAN, Kind.CONTACT, spans)])
        self.assertEqual(out.sanitized_payload["msgs"], ["call [REDACTED_CONTACT] now", "clean"])

    def test_redact_bad_offset_or_type_fails_closed(self):
        with self.assertRaises(EnforcementError):
            self.enforce({"n": "abc"}, [decision("n", Action.REDACT_SPAN, spans=[finding(("n",), 0, 99)])])
        with self.assertRaises(EnforcementError):
            self.enforce({"n": 5}, [decision("n", Action.REDACT_SPAN, spans=[finding(("n",), 0, 1)])])

    def test_quarantine_field_removes_and_prunes_list_elements(self):
        payload = {"keep": 1, "uid": "234567890123", "ids": ["a1", "b2", "c3"]}
        out = self.enforce(payload, [decision("uid", Action.QUARANTINE_FIELD), decision("ids[]", Action.QUARANTINE_FIELD)])
        self.assertEqual(out.sanitized_payload, {"keep": 1, "ids": []})
        self.assertEqual(len(out.quarantined), 4)
        self.assertEqual(out.quarantined[0].raw_value, "234567890123")
        self.assertNotIn("234567890123", repr(out.quarantined[0]))  # repr-hidden

    def test_quarantine_payload_returns_no_forwardable_payload(self):
        out = self.enforce({"a": "card"}, [decision("a", Action.QUARANTINE_PAYLOAD)], quarantined=True)
        self.assertIsNone(out.sanitized_payload)
        self.assertFalse(out.forwardable)
        self.assertEqual(out.quarantined[0].path, ())

    def test_placeholder_helpers(self):
        tok = self.svc.tokenize(Kind.PERSONAL, "x")
        self.assertTrue(is_placeholder(tok))
        self.assertTrue(is_placeholder("[MASKED_CONTACT]"))
        self.assertFalse(is_placeholder("tok_zz"))
        self.assertEqual(strip_placeholders("a [REDACTED_GOVERNMENT_ID] b").strip(), "a  b")


if __name__ == "__main__":
    unittest.main()
