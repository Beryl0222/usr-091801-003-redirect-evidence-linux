"""规则引擎单元测试：跨源重组、版本差异、确定性复现。"""

import unittest

import rules


def _ev(eid, source, etype, account, ts, payload):
    return {
        "event_id": eid,
        "source_system": source,
        "source_ref": f"{source}:{eid}",
        "event_type": etype,
        "account_id": account,
        "occurred_at": ts,
        "payload": payload,
    }


def fragment_events(account="acc1"):
    return [
        _ev("e0", "profile_scanner", "profile_field", account, "2026-09-10T12:00:00+00:00",
            {"text": "片段 www", "fragment": {"key": "k", "seq": 0, "text": "www"}}),
        _ev("e1", "live_snapshot", "image_summary", account, "2026-09-10T12:01:00+00:00",
            {"text": "片段 .dianzan88", "fragment": {"key": "k", "seq": 1, "text": ".dianzan88"}}),
        _ev("e2", "comment_scanner", "comment", account, "2026-09-10T12:02:00+00:00",
            {"text": "片段 .com/x", "fragment": {"key": "k", "seq": 2, "text": ".com/x"}}),
    ]


class RuleEngineTest(unittest.TestCase):
    def test_normalize_codewords_and_separators(self):
        out = rules.normalize("三打不溜 点 dianzan88 点卡姆", rules.get_rules("v2"), leet=False)
        self.assertEqual(out, "www.dianzan88.com")

    def test_leet_does_not_corrupt_digits_in_domain(self):
        out = rules.normalize("www.huanpi163.net", rules.get_rules("v2"), leet=False)
        self.assertEqual(out, "www.huanpi163.net")

    def test_assemble_split_url_across_sources(self):
        result = rules.analyze(fragment_events(), "v2")
        asm = result["assemblies"][0]
        self.assertEqual(asm["text"], "www.dianzan88.com/x")
        self.assertTrue(asm["valid_url"])
        self.assertEqual(asm["domain"], "dianzan88.com")
        self.assertTrue(asm["risk"])
        self.assertEqual(len(asm["sources"]), 3)

    def test_suggestion_meets_threshold(self):
        result = rules.analyze(fragment_events(), "v2")
        cand = result["candidates"][0]
        self.assertGreaterEqual(cand["score"], rules.RULES_V2["threshold"])
        self.assertEqual(cand["decision"], "suggest")

    def test_report_context_differs_between_versions(self):
        events = [
            _ev("r0", "profile_scanner", "profile_field", "acc2", "2026-09-11T09:05:00+00:00",
                 {"text": "举报骗子站 www.huanpi163",
                  "fragment": {"key": "r", "seq": 0, "text": "www.huanpi163"}}),
            _ev("r1", "comment_scanner", "comment", "acc2", "2026-09-11T09:10:00+00:00",
                 {"text": "谨防上当 .net",
                  "fragment": {"key": "r", "seq": 1, "text": ".net"}}),
        ]
        v1 = rules.analyze(events, "v1")
        v2 = rules.analyze(events, "v2")
        self.assertEqual(v1["candidates"][0]["decision"], "suggest")  # 56 >= 55
        self.assertEqual(v2["candidates"][0]["decision"], "below_threshold")  # 30 < 50
        self.assertTrue(v2["assemblies"][0]["report_context"])

    def test_verified_merchant_reduces_score(self):
        events = fragment_events("shop1")
        events.append(_ev("m", "profile_scanner", "profile_field", "shop1",
                          "2026-09-10T11:00:00+00:00",
                          {"text": "备案商户", "verified_merchant": True}))
        result = rules.analyze(events, "v2")
        cand = next(c for c in result["candidates"] if c["account_id"] == "shop1")
        self.assertLess(cand["score"], rules.RULES_V2["threshold"])

    def test_replay_is_deterministic_with_snapshot(self):
        events = fragment_events()
        result = rules.analyze(events, "v1")
        reproduced, consistent, drifted = rules.replay(events, "v1", result["params"])
        self.assertTrue(consistent)
        self.assertEqual(
            [(c["account_id"], c["score"]) for c in reproduced["candidates"]],
            [(c["account_id"], c["score"]) for c in result["candidates"]],
        )
        self.assertEqual(drifted, {})

    def test_rules_v1_immutable_when_v2_changes(self):
        self.assertEqual(rules.RULES_V1["threshold"], 55)
        self.assertEqual(rules.RULES_V2["threshold"], 50)
        self.assertNotIn("点卡姆", rules.RULES_V1["codewords"])
        self.assertIn("点卡姆", rules.RULES_V2["codewords"])


if __name__ == "__main__":
    unittest.main()
