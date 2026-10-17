import json
import unittest

from app.config import Limits
from app.services.normalization_service import NormalizationError, flatten, get_at, set_at
from app.services.profiling_service import Profiler, merge_profiles, shannon_entropy
from tests.fakes import KEY, VALIDATORS


class FlattenTests(unittest.TestCase):
    def test_paths_and_array_collapse(self):
        leaves = flatten({"a": {"b": 1}, "v": [{"n": "x"}, {"n": "y"}], "t": ["p", "q"]})
        self.assertEqual([l.schema_path for l in leaves], ["a.b", "v[].n", "v[].n", "t[]", "t[]"])
        self.assertEqual(leaves[1].path, ("v", 0, "n"))
        self.assertEqual(leaves[2].path, ("v", 1, "n"))

    def test_key_escaping_prevents_collision(self):
        dotted = flatten({"a.b": 1})[0].schema_path
        nested = flatten({"a": {"b": 1}})[0].schema_path
        self.assertNotEqual(dotted, nested)

    def test_limits(self):
        with self.assertRaises(NormalizationError):
            flatten({"a": {"b": {"c": 1}}}, Limits(max_depth=2))
        with self.assertRaises(NormalizationError):
            flatten({"a": [1, 2, 3]}, Limits(max_leaves=2))
        with self.assertRaises(NormalizationError):
            flatten({"a": "x" * 11}, Limits(max_string_len=10))

    def test_rejects_non_container_and_unsupported(self):
        with self.assertRaises(NormalizationError):
            flatten("just a string")
        with self.assertRaises(NormalizationError):
            flatten({"a": b"bytes"})

    def test_empty_and_null(self):
        self.assertEqual(flatten({}), [])
        self.assertEqual(flatten({"a": None})[0].value, None)

    def test_get_set(self):
        d = {"a": [{"b": 1}]}
        set_at(d, ("a", 0, "b"), 2)
        self.assertEqual(get_at(d, ("a", 0, "b")), 2)


class ProfilerTests(unittest.TestCase):
    def setUp(self):
        self.p = Profiler(KEY, VALIDATORS)

    def test_validator_ratio_over_array_and_numbers(self):
        prof = self.p.profile(flatten({"ids": ["234567890123", "hello", 234567890123, "x"]}))["ids[]"]
        self.assertAlmostEqual(prof.validator_hits["AADHAAR"], 0.5)
        self.assertEqual(prof.json_type, "string")

    def test_no_raw_values_in_profile(self):
        secret = "234567890123"
        prof = self.p.profile(flatten({"uid": secret}))["uid"]
        self.assertNotIn(secret, json.dumps(prof.to_dict()))
        self.assertEqual(len(prof.value_hashes), 1)

    def test_hash_is_keyed(self):
        other = Profiler(b"a-different-key-0123456789abcd", VALIDATORS)
        a = self.p.profile(flatten({"uid": "v"}))["uid"].value_hashes
        b = other.profile(flatten({"uid": "v"}))["uid"].value_hashes
        self.assertNotEqual(a, b)

    def test_text_like_and_entropy(self):
        prof = self.p.profile(flatten({"n": "Patient reports fever and mild cough today."}))["n"]
        self.assertTrue(prof.is_text_like)
        self.assertGreater(prof.entropy, 2.0)
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_broken_validator_fails_loudly(self):
        def boom(_): raise RuntimeError("x")
        with self.assertRaises(RuntimeError):
            Profiler(KEY, {"B": boom}).profile(flatten({"a": "b"}))

    def test_merge_roundtrip(self):
        a = self.p.profile(flatten({"n": 10}))["n"]
        b = self.p.profile(flatten({"n": [1, 2, 3]}))["n[]"]
        b.schema_path = "n"
        m = merge_profiles(a, b)
        self.assertEqual(m.count, 4)
        again = type(m).from_dict(m.to_dict())
        self.assertEqual(again, m)


if __name__ == "__main__":
    unittest.main()
