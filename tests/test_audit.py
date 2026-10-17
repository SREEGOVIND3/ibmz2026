import copy
import json
import unittest
from datetime import datetime, timezone

from app.services.audit_service import GENESIS_HASH, AuditError, AuditService
from tests.fakes import MemoryAuditStore


def make(n=4):
    store = MemoryAuditStore()
    ids = iter(range(1000))
    svc = AuditService(
        store, clock=lambda: datetime(2026, 10, 17, 0, 25, tzinfo=timezone.utc),
        id_factory=lambda: f"evt-{next(ids)}",
    )
    for i in range(n):
        svc.record({"request_id": f"r{i}", "field_path": "a.b", "action": "ALLOW", "severity": "LOW"})
    return svc, store


class AuditTests(unittest.TestCase):
    def test_chain_links_and_verifies(self):
        svc, store = make()
        self.assertEqual(store.events[0]["prev_hash"], GENESIS_HASH)
        self.assertEqual(store.events[1]["prev_hash"], store.events[0]["hash"])
        res = svc.verify()
        self.assertTrue(res.ok)
        self.assertEqual(res.checked, 4)
        self.assertEqual(store.events[0]["timestamp"], "2026-10-17T00:25:00Z")

    def test_empty_chain_verifies(self):
        self.assertTrue(AuditService(MemoryAuditStore()).verify().ok)

    def test_modified_record_detected(self):
        svc, store = make()
        store.events[1]["action"] = "QUARANTINE_FIELD"
        res = svc.verify()
        self.assertFalse(res.ok)
        self.assertEqual(res.first_bad_index, 1)

    def test_deleted_middle_record_detected(self):
        svc, store = make()
        del store.events[1]
        self.assertFalse(svc.verify().ok)

    def test_reordered_records_detected(self):
        svc, store = make()
        store.events[1], store.events[2] = store.events[2], store.events[1]
        self.assertFalse(svc.verify().ok)

    def test_tail_truncation_undetected_without_anchor_detected_with_it(self):
        svc, store = make()
        anchor = svc.verify()
        del store.events[-1]
        self.assertTrue(svc.verify().ok)  # documented limitation
        self.assertFalse(svc.verify(expected_count=anchor.checked).ok)
        self.assertFalse(svc.verify(expected_head=anchor.head).ok)

    def test_whole_chain_rewrite_caught_only_by_anchor(self):
        svc, store = make()
        anchor = svc.verify().head
        forged = MemoryAuditStore()
        forged_svc = AuditService(forged)
        forged_svc.record({"request_id": "evil", "action": "ALLOW"})
        self.assertTrue(forged_svc.verify().ok)
        self.assertFalse(forged_svc.verify(expected_head=anchor).ok)

    def test_non_whitelisted_or_structured_fields_rejected(self):
        svc, _ = make(0)
        with self.assertRaises(AuditError):
            svc.record({"request_id": "r", "raw_value": "234567890123"})
        with self.assertRaises(AuditError):
            svc.record({"request_id": "r", "reason": {"nested": "payload"}})

    def test_events_are_json_serialisable(self):
        _, store = make(1)
        json.dumps(store.events[0])


if __name__ == "__main__":
    unittest.main()
