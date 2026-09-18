"""领域不变量测试：不复制素材、自动关联不处罚、双人确认、申诉留痕、规则快照复现。"""

import unittest

from app import models as m
from app.core import CoreService
from app.store import Store

SYS = {"id": "sys-ingest", "role": "system"}
R1 = {"id": "rev-001", "role": "reviewer"}
R2 = {"id": "rev-002", "role": "reviewer"}
S1 = {"id": "sup-001", "role": "supervisor"}
AU = {"id": "aud-001", "role": "auditor"}

T0 = "2026-09-10T20:00:00+00:00"


def make_core():
    return CoreService(Store())


def make_case(core, title="测试案件"):
    return core.create_case(SYS, {"title": title})["case_id"]


def event(case_id, seq=1, **overrides):
    payload = {
        "source_system": "live-detect",
        "source_event_id": f"src-{seq}",
        "event_type": "text",
        "channel": "评论",
        "occurred_at": T0,
        "digest": "评论含站外引导",
        "content_hash": f"hash-{seq}",
        "locator": f"live://room/1/comment/{seq}",
        "account_id": "acc-A-001",
        "case_id": case_id,
    }
    payload.update(overrides)
    return payload


def ingest_path_case(core, case_id, account="acc-A-001"):
    """入库一组足以构成导流路径的片段（得分 7，渠道 5 个）。"""
    core.ingest_event(SYS, event(case_id, 1, channel="昵称", event_type="text",
                                 digest='昵称含拆分网址片段[1/2]: "hxekle"',
                                 content_hash="h-nick", account_id=account,
                                 nickname="夜行者K"))
    core.ingest_event(SYS, event(case_id, 2, channel="评论",
                                 digest='评论含拆分网址片段[2/2]: ".cc/9f"',
                                 content_hash="h-cmt", account_id=account,
                                 occurred_at="2026-09-10T20:05:00+00:00"))
    core.ingest_event(SYS, event(case_id, 3, channel="音频", event_type="audio_transcript",
                                 digest="口播暗语引导查看主页昵称", content_hash="h-aud",
                                 account_id=account,
                                 occurred_at="2026-09-10T20:10:00+00:00"))
    core.ingest_event(SYS, event(case_id, 4, channel="收藏夹", event_type="account_relation",
                                 digest="收藏夹新增站外引流客服号", content_hash="h-rel",
                                 account_id=account, related_account_id="acc-B-002",
                                 relation_type="收藏",
                                 occurred_at="2026-09-10T20:12:00+00:00"))
    core.ingest_event(SYS, event(case_id, 5, channel="直播瞬间", event_type="image_summary",
                                 digest="画面角落短时二维码", content_hash="h-img",
                                 account_id=account,
                                 occurred_at="2026-09-10T20:15:00+00:00"))


class IngestTest(unittest.TestCase):
    def test_duplicate_event_is_idempotent(self):
        core = make_core()
        case_id = make_case(core)
        first = core.ingest_event(SYS, event(case_id, 1))
        again = core.ingest_event(SYS, event(case_id, 1))
        self.assertFalse(first["deduplicated"])
        self.assertTrue(again["deduplicated"])
        self.assertEqual(first["fragment"]["fragment_id"], again["fragment"]["fragment_id"])
        self.assertEqual(len(core.store.fragments), 1)

    def test_same_content_merges_into_one_fragment(self):
        core = make_core()
        case_id = make_case(core)
        core.ingest_event(SYS, event(case_id, 1, content_hash="same"))
        merged = core.ingest_event(SYS, event(case_id, 2, content_hash="same"))
        self.assertTrue(merged["deduplicated"])
        self.assertEqual(merged["fragment"]["report_count"], 2)
        self.assertEqual(len(core.store.fragments), 1)

    def test_raw_material_is_rejected(self):
        core = make_core()
        case_id = make_case(core)
        with self.assertRaises(m.DomainError) as ctx:
            core.ingest_event(SYS, event(case_id, 1, raw_content="原始视频流"))
        self.assertEqual(ctx.exception.code, "RAW_MATERIAL_REJECTED")
        self.assertEqual(ctx.exception.http_status, 400)

    def test_rename_keeps_attribution_and_history(self):
        core = make_core()
        case_id = make_case(core)
        core.ingest_event(SYS, event(case_id, 1, nickname="夜行者K"))
        core.ingest_event(SYS, event(case_id, 2, content_hash="h2", nickname="清风徐来"))
        account = core.store.accounts["acc-A-001"]
        self.assertEqual(account["nickname"], "清风徐来")
        self.assertEqual(account["nickname_history"][0]["nickname"], "夜行者K")
        fragments = list(core.store.fragments.values())
        self.assertEqual({f["account_id"] for f in fragments}, {"acc-A-001"})
        self.assertEqual(fragments[0]["nickname_at_event"], "夜行者K")
        self.assertEqual(fragments[1]["nickname_at_event"], "清风徐来")
        actions = [e["action"] for e in core.store.audit]
        self.assertIn("账号改名", actions)


class AnalysisTest(unittest.TestCase):
    def test_auto_association_only_suggests(self):
        core = make_core()
        case_id = make_case(core)
        ingest_path_case(core, case_id)
        result = core.analyze_case(SYS, case_id)
        case = core.store.cases[case_id]
        self.assertEqual(case["status"], m.CASE_PENDING_INITIAL)
        self.assertEqual(len(result["suggestions"]), 1)
        sug = result["suggestions"][0]
        self.assertEqual(sug["status"], m.SUGGESTION_PENDING)
        self.assertEqual(sug["reassembled_urls"], ["hxekle.cc/9f"])
        # 自动关联不得直接处罚：没有冻结、没有移送、账号无任何处置字段
        self.assertIsNone(case["freeze"])
        self.assertNotIn("sanction", core.store.accounts["acc-A-001"])
        self.assertFalse(any(f["frozen"] for f in core.store.fragments.values()))

    def test_path_is_time_ordered(self):
        core = make_core()
        case_id = make_case(core)
        ingest_path_case(core, case_id)
        analysis = core.analyze_case(SYS, case_id)["analysis"]
        times = [s["occurred_at"] for s in analysis["path"]["steps"]]
        self.assertEqual(times, sorted(times))

    def test_single_fragment_never_passes(self):
        core = make_core()
        case_id = make_case(core)
        core.ingest_event(SYS, event(case_id, 1, channel="音频", event_type="audio_transcript"))
        result = core.analyze_case(SYS, case_id)
        self.assertEqual(result["suggestions"], [])
        self.assertEqual(core.store.cases[case_id]["status"], m.CASE_COLLECTING)


class ConfirmFreezeTransferTest(unittest.TestCase):
    def setUp(self):
        self.core = make_core()
        self.case_id = make_case(self.core)
        ingest_path_case(self.core, self.case_id)
        self.sug = self.core.analyze_case(SYS, self.case_id)["suggestions"][0]

    def test_same_person_cannot_confirm_twice(self):
        self.core.confirm_suggestion(R1, self.sug["suggestion_id"])
        with self.assertRaises(m.DomainError) as ctx:
            self.core.confirm_suggestion(R1, self.sug["suggestion_id"])
        self.assertEqual(ctx.exception.code, "DUPLICATE_CONFIRM")

    def test_auditor_cannot_confirm(self):
        with self.assertRaises(m.DomainError) as ctx:
            self.core.confirm_suggestion(AU, self.sug["suggestion_id"])
        self.assertEqual(ctx.exception.http_status, 403)

    def test_two_person_confirm_then_freeze_with_retention(self):
        self.core.confirm_suggestion(R1, self.sug["suggestion_id"])
        self.assertEqual(self.core.store.cases[self.case_id]["status"], m.CASE_PENDING_REVIEW)
        self.core.confirm_suggestion(S1, self.sug["suggestion_id"])
        self.assertEqual(self.sug["status"], m.SUGGESTION_CONFIRMED)
        freeze = self.core.freeze_case(S1, self.case_id)
        self.assertEqual(self.core.store.cases[self.case_id]["status"], m.CASE_FROZEN)
        self.assertTrue(freeze["retention_until"] > freeze["frozen_at"])
        self.assertEqual(freeze["retention_days"], 180)
        self.assertTrue(all(self.core.store.fragments[f]["frozen"] for f in freeze["fragment_ids"]))

    def test_freeze_requires_two_person_confirmation(self):
        self.core.confirm_suggestion(R1, self.sug["suggestion_id"])
        with self.assertRaises(m.DomainError) as ctx:
            self.core.freeze_case(R1, self.case_id)
        self.assertEqual(ctx.exception.code, "NO_CONFIRMED_SUGGESTION")

    def test_frozen_evidence_survives_purge(self):
        self.core.confirm_suggestion(R1, self.sug["suggestion_id"])
        self.core.confirm_suggestion(S1, self.sug["suggestion_id"])
        self.core.freeze_case(S1, self.case_id)
        report = self.core.purge_expired(S1)
        self.assertEqual(report["purged"], [])
        self.assertEqual(len(report["retained"]), 5)
        self.assertTrue(all("冻结" in r["reason"] for r in report["retained"]))

    def test_transfer_requires_freeze_then_dispatch(self):
        with self.assertRaises(m.DomainError):
            self.core.create_transfer_package(S1, self.case_id)
        self.core.confirm_suggestion(R1, self.sug["suggestion_id"])
        self.core.confirm_suggestion(S1, self.sug["suggestion_id"])
        self.core.freeze_case(S1, self.case_id)
        package = self.core.create_transfer_package(S1, self.case_id)
        self.assertEqual(package["conclusions"][0]["suggestion_id"], self.sug["suggestion_id"])
        self.core.dispatch_package(S1, package["package_id"],
                                   {"recipient": "网安支队", "receipt_id": "WS-2026-001"})
        self.assertEqual(self.core.store.cases[self.case_id]["status"], m.CASE_TRANSFERRED)


class AppealTest(unittest.TestCase):
    def setUp(self):
        self.core = make_core()
        self.case_id = make_case(self.core)
        ingest_path_case(self.core, self.case_id)
        self.sug = self.core.analyze_case(SYS, self.case_id)["suggestions"][0]
        self.core.confirm_suggestion(R1, self.sug["suggestion_id"])

    def test_appeal_upheld_revokes_but_audit_stays(self):
        appeal = self.core.file_appeal(R2, self.sug["suggestion_id"],
                                       {"reason": "收藏关系系误关联"})
        self.assertEqual(self.core.store.cases[self.case_id]["status"], m.CASE_APPEALING)
        resolved = self.core.resolve_appeal(S1, appeal["appeal_id"],
                                            {"uphold": True, "note": "确认误关联"})
        self.assertEqual(resolved["status"], m.APPEAL_UPHELD)
        self.assertEqual(self.sug["status"], m.SUGGESTION_REVOKED)
        self.assertEqual(self.core.store.cases[self.case_id]["status"], m.CASE_CORRECTED)
        # 撤销不删除：建议仍可查询，审计链完整
        view = self.core.get_suggestion(AU, self.sug["suggestion_id"])
        self.assertEqual(view["suggestion"]["status"], m.SUGGESTION_REVOKED)
        actions = [e["action"] for e in self.core.store.audit]
        for expected in ("线索入库", "自动关联分析", "初审确认", "申诉受理", "申诉成立-关联撤销"):
            self.assertIn(expected, actions)
        self.assertTrue(self.core.store.verify_audit())

    def test_appeal_rejected_restores_prior_status(self):
        appeal = self.core.file_appeal(R2, self.sug["suggestion_id"], {"reason": "存疑"})
        self.core.resolve_appeal(S1, appeal["appeal_id"], {"uphold": False})
        self.assertEqual(self.core.store.cases[self.case_id]["status"], m.CASE_PENDING_REVIEW)
        self.assertEqual(self.sug["status"], m.SUGGESTION_PENDING)

    def test_filer_cannot_resolve_own_appeal(self):
        appeal = self.core.file_appeal(R2, self.sug["suggestion_id"], {"reason": "存疑"})
        with self.assertRaises(m.DomainError) as ctx:
            self.core.resolve_appeal(R2, appeal["appeal_id"], {"uphold": True})
        self.assertEqual(ctx.exception.code, "SELF_RESOLVE")

    def test_original_confirmer_must_recuse(self):
        appeal = self.core.file_appeal(R2, self.sug["suggestion_id"], {"reason": "存疑"})
        with self.assertRaises(m.DomainError) as ctx:
            self.core.resolve_appeal(R1, appeal["appeal_id"], {"uphold": True})
        self.assertEqual(ctx.exception.code, "CONFLICT_OF_INTEREST")


class RuleVersionTest(unittest.TestCase):
    def test_upgrade_only_affects_new_analyses_and_old_decision_reproduces(self):
        core = make_core()
        old_case = make_case(core, "旧案")
        ingest_path_case(core, old_case)
        old = core.analyze_case(SYS, old_case)
        self.assertEqual(old["analysis"]["rule_version"], "v1")

        core.create_rules(S1, {"min_score": 8})
        self.assertEqual(core.store.current_rule_version, "v2")

        replay = core.reproduce_analysis(AU, old["analysis"]["analysis_id"])
        self.assertTrue(replay["reproduced"])
        self.assertEqual(replay["rule_version"], "v1")
        self.assertEqual(replay["current_rule_version"], "v2")
        self.assertEqual(replay["threshold_snapshot"]["min_score"], 4)

        # 同样的片段在新规则下不再构成建议：升级只影响新分析
        new_case = make_case(core, "新案")
        ingest_path_case(core, new_case, account="acc-C-003")
        fresh = core.analyze_case(SYS, new_case)
        self.assertEqual(fresh["analysis"]["rule_version"], "v2")
        self.assertEqual(fresh["suggestions"], [])

    def test_old_rule_version_is_never_modified(self):
        core = make_core()
        before = dict(core.store.rules["v1"])
        core.create_rules(S1, {"min_score": 8})
        self.assertEqual(core.store.rules["v1"], before)


class RedactionTest(unittest.TestCase):
    def setUp(self):
        self.core = make_core()
        self.case_id = make_case(self.core)
        ingest_path_case(self.core, self.case_id)
        self.sug = self.core.analyze_case(SYS, self.case_id)["suggestions"][0]

    def test_reviewer_sees_digest_but_masked_account(self):
        view = self.core.get_case(R1, self.case_id)
        fragment = view["fragments"][0]
        self.assertTrue(fragment["digest"])
        self.assertTrue(fragment["locator"])
        self.assertNotEqual(fragment["account_id"], "acc-A-001")
        self.assertIn("***", fragment["account_id"])

    def test_supervisor_sees_full_identifiers(self):
        view = self.core.get_case(S1, self.case_id)
        self.assertEqual(view["fragments"][0]["account_id"], "acc-A-001")

    def test_auditor_sees_process_not_content(self):
        view = self.core.get_case(AU, self.case_id)
        fragment = view["fragments"][0]
        self.assertIsNone(fragment["digest"])
        self.assertIsNone(fragment["locator"])
        self.assertIsNone(fragment["nickname_at_event"])
        self.assertTrue(fragment["content_hash"])
        suggestion = view["suggestions"][0]
        self.assertEqual(suggestion["reassembled_urls"], [])
        self.assertEqual(suggestion["reassembled_url_count"], 1)
        self.assertEqual(suggestion["status"], m.SUGGESTION_PENDING)

    def test_system_role_cannot_read_conclusions(self):
        with self.assertRaises(m.DomainError) as ctx:
            self.core.get_case(SYS, self.case_id)
        self.assertEqual(ctx.exception.http_status, 403)


class SharedClueTest(unittest.TestCase):
    def test_cross_case_shared_clue_participates_in_analysis(self):
        core = make_core()
        source = make_case(core, "源案件")
        ingest_path_case(core, source)
        shared_fragment = core.store.cases[source]["fragment_ids"][3]  # 收藏夹关系
        target = make_case(core, "关联案件")
        link = core.link_shared_clue(R1, target, {"fragment_id": shared_fragment})
        self.assertEqual(link["from_case_id"], source)
        core.ingest_event(SYS, event(target, 91, channel="昵称",
                                     digest='昵称含拆分网址片段[1/2]: "hxekle"',
                                     account_id="acc-B-002"))
        core.ingest_event(SYS, event(target, 92, channel="音频", event_type="audio_transcript",
                                     digest="口播暗语", content_hash="h-aud-9",
                                     account_id="acc-B-002"))
        result = core.analyze_case(SYS, target)
        self.assertEqual(len(result["suggestions"]), 1)
        self.assertIn(shared_fragment, result["suggestions"][0]["evidence_fragment_ids"])
        view = core.get_case(R1, target)
        self.assertEqual(view["shared_clues"][0]["fragment"]["fragment_id"], shared_fragment)


class AuditTest(unittest.TestCase):
    def test_chain_is_valid_and_tamper_evident(self):
        core = make_core()
        case_id = make_case(core)
        core.ingest_event(SYS, event(case_id, 1))
        self.assertTrue(core.store.verify_audit())
        core.store.audit[-1]["detail"]["channel"] = "篡改"
        self.assertFalse(core.store.verify_audit())


if __name__ == "__main__":
    unittest.main()
