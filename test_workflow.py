"""工作流单元测试：去重、改名、双人确认、申诉、冻结快照、复现。"""

import json
import unittest

from store import Store
from workflow import Workflow, WorkflowError


def event(eid="e1", source="comment_scanner", ref="ref-1", etype="comment",
          account="acc1", ts="2026-09-10T12:00:00+00:00", payload=None):
    return {
        "event_id": eid,
        "source_system": source,
        "source_ref": ref,
        "event_type": etype,
        "account_id": account,
        "occurred_at": ts,
        "payload": payload or {"text": "x"},
    }


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.wf = Workflow(self.store)
        self.store.create_case("C1", "测试案件", "2027-01-01T00:00:00+00:00")

    def test_duplicate_report_ingested_once(self):
        first = self.wf.ingest(event(payload={"text": "原文"}), case_id="C1")
        second = self.wf.ingest(event(payload={"text": "重复推送的不同描述"}), case_id="C1")
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertEqual(len(self.store.events_for_case("C1")), 1)

    def test_rename_keeps_identity_and_history(self):
        self.wf.ingest(event(eid="n1", etype="profile_nickname",
                             payload={"platform": "dy", "nickname": "旧昵称"}), case_id="C1")
        self.wf.ingest(event(eid="n2", ts="2026-09-12T08:00:00+00:00",
                             etype="profile_nickname",
                             payload={"platform": "dy", "nickname": "新昵称"}), case_id="C1")
        history = self.store.name_history("acc1")
        self.assertEqual([h["nickname"] for h in history], ["旧昵称", "新昵称"])
        self.assertIsNotNone(history[0]["valid_to"])
        self.assertIsNone(history[1]["valid_to"])
        actions = {r["action"] for r in self.store.audit_log(50, entity_id="acc1")}
        self.assertIn("account.rename", actions)

    def test_share_clue_does_not_duplicate_event(self):
        self.store.create_case("C2", "另一案")
        self.wf.ingest(event(), case_id="C1")
        shared = self.wf.share_clue("C2", "e1")
        again = self.wf.share_clue("C2", "e1")
        self.assertTrue(shared["shared"])
        self.assertFalse(again["shared"])
        self.assertEqual([c["case_id"] for c in self.store.cases_for_event("e1")], ["C1", "C2"])
        self.assertEqual(len(self.store.query("SELECT * FROM events")), 1)

    def test_two_distinct_reviewers_required_to_freeze(self):
        self._seed_fox_case()
        analysis = self.wf.run_analysis("C1", "v2")
        link_id = analysis["link_ids"][0]

        self.assertFalse(self.wf.confirm("C1", link_id, "alice")["frozen"])
        self.assertFalse(self.wf.confirm("C1", link_id, "alice")["frozen"])
        done = self.wf.confirm("C1", link_id, "bob")
        self.assertTrue(done["frozen"])

        freeze = self.store.get_freeze(done["freeze_id"])
        snapshot = json.loads(freeze["snapshot_json"])
        self.assertEqual(snapshot["rule_params"]["threshold"], 50)
        self.assertIn("source_ref", json.dumps(snapshot, ensure_ascii=False))
        self.assertNotIn("raw_material", json.dumps(snapshot))

    def test_confirmed_link_cannot_be_confirmed_again(self):
        link = self._suggested_link()
        self.wf.confirm("C1", link, "alice")
        self.wf.confirm("C1", link, "bob")
        with self.assertRaises(WorkflowError):
            self.wf.confirm("C1", link, "carol")

    def test_appeal_reverse_retains_freeze_and_audit(self):
        link = self._suggested_link()
        self.wf.confirm("C1", link, "alice")
        frozen = self.wf.confirm("C1", link, "bob")
        appeal_id = self.wf.appeal("C1", link, "误判", "bob")["appeal_id"]
        result = self.wf.resolve_appeal(appeal_id, "reversed", "alice")
        self.assertTrue(result["audit_retained"])
        self.assertEqual(self.store.get_link(link)["status"], "reversed")
        self.assertIsNotNone(self.store.get_freeze(frozen["freeze_id"]))
        self.assertEqual(self.store.get_case("C1")["status"], "已纠正")
        # 已撤销的关联不可再确认
        with self.assertRaises(WorkflowError):
            self.wf.confirm("C1", link, "carol")

    def test_transfer_requires_freeze(self):
        link = self._suggested_link()
        with self.assertRaises(WorkflowError):
            self.wf.transfer("C1", "frz_nope", "外单位", "bob")
        self.wf.confirm("C1", link, "alice")
        frozen = self.wf.confirm("C1", link, "bob")
        pkg = self.wf.transfer("C1", frozen["freeze_id"], "市公安局网安支队", "bob")
        self.assertIn("manifest_sha256", pkg["manifest"])

    def test_replay_uses_historical_threshold(self):
        self._seed_report_context_case()
        old = self.wf.run_analysis("C1", "v1")
        replay = self.wf.replay_analysis(old["analysis_id"])
        self.assertTrue(replay["snapshot_consistent"])
        self.assertEqual(replay["params_snapshot"]["threshold"], 55)
        self.assertEqual(replay["reproduced_top_score"], 56)
        # 用 v2 再分析不影响历史快照
        self.wf.run_analysis("C1", "v2")
        replay2 = self.wf.replay_analysis(old["analysis_id"])
        self.assertEqual(replay2["params_snapshot"]["threshold"], 55)

    def test_append_only_tables_reject_mutation(self):
        self.wf.ingest(event(), case_id="C1")
        for sql in ("DELETE FROM events", "UPDATE events SET payload='{}'"):
            with self.assertRaises(Exception):
                self.store.execute(sql)

    # -- helpers -------------------------------------------------------
    def _suggested_link(self):
        self._seed_fox_case()
        return self.wf.run_analysis("C1", "v2")["link_ids"][0]

    def _seed_fox_case(self):
        for eid, source, ts, frag_text, text in [
            ("f0", "profile_scanner", "2026-09-10T12:00:00+00:00", "www", "www"),
            ("f1", "comment_scanner", "2026-09-10T12:02:00+00:00", ".dianzan88", ".dianzan88"),
            ("f2", "favorite_scanner", "2026-09-10T12:03:00+00:00", ".com/x", ".com/x"),
        ]:
            self.wf.ingest(event(
                eid=eid, source=source, ref=f"ref-{eid}", ts=ts,
                etype="profile_field" if source == "profile_scanner" else (
                    "comment" if source == "comment_scanner" else "favorite_entry"),
                payload={"text": text, "fragment": {"key": "k", "seq": int(eid[1]), "text": frag_text}},
            ), case_id="C1")

    def _seed_report_context_case(self):
        self.wf.ingest(event(
            eid="r0", source="profile_scanner", ref="rr0", etype="profile_field",
            account="acc2", ts="2026-09-11T09:05:00+00:00",
            payload={"text": "举报骗子 www.huanpi163",
                     "fragment": {"key": "r", "seq": 0, "text": "www.huanpi163"}},
        ), case_id="C1")
        self.wf.ingest(event(
            eid="r1", source="comment_scanner", ref="rr1",
            account="acc2", ts="2026-09-11T09:10:00+00:00",
            payload={"text": "谨防 .net", "fragment": {"key": "r", "seq": 1, "text": ".net"}},
        ), case_id="C1")


if __name__ == "__main__":
    unittest.main()
