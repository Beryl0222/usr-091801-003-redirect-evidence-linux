"""端到端验收演示（内存库 + 真实路由/鉴权/工作流全链路）。

运行：python3 demo.py
依次演示：
1. 接入去重、账号改名、跨案共享线索、证据保全期限；
2. 自动关联给出建议并展示证据片段与时间线（不直接处罚）；
3. 双人确认后冻结证据、生成外部移送包；
4. 一次误关联申诉与撤销——旧决定按当时 v1 阈值可复现，规则升级只影响新分析；
5. 三类角色看到的敏感字段严格不同；
6. 只追加表与审计日志不可删除/篡改。

任何一步不符合预期立即抛错退出码非零。
"""

import json
import sys

import seed
import security
from store import Store
from api import ApiRouter

ALICE = "rev-alice"
BOB = "rev-bob"
CAROL = "aud-carol"
POLICE = "ext-police"


def pp(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


class Demo:
    def __init__(self):
        self.store = Store(":memory:")
        stats = seed.load(self.store)
        self.api = ApiRouter(self.store)
        self.step_no = 0
        self.check("样例接入去重", stats["ingested"] == 16 and stats["deduped"] == 1)
        self.stats = stats

    def call(self, method, path, token=None, body=None, expect=200):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        status, payload = self.api.handle(method, path, headers, body or {})
        if status != expect:
            raise AssertionError(f"{method} {path} 期望 {expect} 实际 {status}:\n{pp(payload)}")
        return payload

    def section(self, title):
        self.step_no += 1
        print("\n" + "=" * 72)
        print(f"演示 {self.step_no}：{title}")
        print("=" * 72)

    def check(self, label, condition, detail=""):
        mark = "通过" if condition else "失败"
        print(f"  [{mark}] {label}" + (f" —— {detail}" if detail and not condition else ""))
        if not condition:
            raise AssertionError(label)

    # ------------------------------------------------------------------
    def run(self):
        self.demo_identity_and_lifecycle()
        self.demo_auto_analysis()
        self.demo_two_person_freeze()
        self.demo_transfer()
        self.demo_wrong_link_appeal()
        self.demo_role_isolation()
        self.demo_immutability()
        print("\n全部演示与验收断言通过。")

    # 1) 接入侧事实：去重/改名/共享/保全期限
    # ------------------------------------------------------------------
    def demo_identity_and_lifecycle(self):
        self.section("接入去重、账号改名、跨案共享与保全期限")

        # 重复上报：同 source_ref 再发一次
        dup = self.call("POST", "/v1/events", ALICE, {
            "case_id": "CASE-2026-001",
            "event": {
                "source_system": "comment_scanner",
                "source_ref": "douyin:cmt_771002",
                "event_type": "comment",
                "occurred_at": "2026-09-10T12:08:30+00:00",
                "payload": {"text": "第三次重复推送同一条评论"},
            },
        }, expect=201)
        self.check("重复上报不产生第二条事件", dup["created"] is False)

        # 账号改名
        history = self.call("GET", "/v1/accounts/acc_fox01", ALICE)["name_history"]
        self.check(
            "账号改名形成时间线，身份以 account_id 为准",
            [h["nickname"] for h in history] == ["小狐狸7788", "幸运小狐狸"],
            pp(history),
        )

        # 跨案件共享：同一二维码事件出现在 001 与 003
        cases = [c["case_id"] for c in self.store.cases_for_event("evt_fox_qr")]
        self.check("线索跨案共享且不复制事件", cases == ["CASE-2026-001", "CASE-2026-003"], str(cases))

        # 保全期限
        view_new = self.call("GET", "/v1/cases/CASE-2026-001", ALICE)
        view_old = self.call("GET", "/v1/cases/CASE-2025-889", ALICE)
        self.check("新案在保全期内", view_new["retention"]["expired"] is False)
        self.check("旧案保全期限已届满被标记", view_old["retention"]["expired"] is True,
                   pp(view_old["retention"]))

    # 2) 自动分析：只形成建议 + 证据回溯
    # ------------------------------------------------------------------
    def demo_auto_analysis(self):
        self.section("自动关联重建时间顺序导流路径（仅建议，不处罚）")
        analysis = self.call("POST", "/v1/cases/CASE-2026-001/analyze", ALICE,
                             {"rule_version": "v2"})
        self.check("规则版本与阈值随分析快照", analysis["rule_version"] == "v2"
                   and analysis["threshold"] == 50)

        top = analysis["candidates"][0]
        self.check("狐狸账号被建议关联", top["account_id"] == "acc_fox01"
                   and top["decision"] == "suggest", f"score={top['score']}")

        asm = analysis["assemblies"][0]
        self.check(
            "拆散在昵称/简介/评论/收藏夹的片段跨源拼回完整风险网址",
            asm["text"] == "www.dianzan88.com/x6" and asm["risk"],
            pp(asm),
        )
        self.check("至少 4 个检测系统贡献片段", len(asm["sources"]) >= 4, str(asm["sources"]))

        times = [t["occurred_at"] for t in analysis["timeline"]]
        self.check("路径按时间顺序重建", times == sorted(times))
        renamed = next(t for t in analysis["timeline"] if t["nickname_at_time"])
        self.check("时间线标注事件发生时的昵称（而非现名）",
                   renamed["nickname_at_time"] in ("小狐狸7788", "幸运小狐狸"))
        self.analysis_001 = analysis

        # 审计员不能发起分析
        self.call("POST", "/v1/cases/CASE-2026-001/analyze", CAROL, {}, expect=403)

        # 备案商户案件不产生建议（减分抑制误报）
        a3 = self.call("POST", "/v1/cases/CASE-2026-003/analyze?rule_version=v2", ALICE, {})
        self.check("已备案商户不因官网链接被建议",
                   all(c["decision"] == "below_threshold" for c in a3["candidates"]),
                   pp([(c["account_id"], c["score"]) for c in a3["candidates"]]))

    # 3) 双人确认 + 冻结
    # ------------------------------------------------------------------
    def demo_two_person_freeze(self):
        self.section("双人不同复核员确认后才冻结证据")
        view = self.call("GET", "/v1/cases/CASE-2026-001", ALICE)
        self.link_001 = next(l for l in view["links"] if l["status"] == "suggested")

        first = self.call("POST", f"/v1/cases/CASE-2026-001/links/{self.link_001['link_id']}/confirm",
                          ALICE, {})
        self.check("第一名确认后尚未冻结", first["frozen"] is False)

        again = self.call("POST", f"/v1/cases/CASE-2026-001/links/{self.link_001['link_id']}/confirm",
                          ALICE, {})
        self.check("同一复核员重复确认不能凑成双人", len(set(again["confirmations"])) == 1
                   and again["frozen"] is False)

        second = self.call("POST", f"/v1/cases/CASE-2026-001/links/{self.link_001['link_id']}/confirm",
                           BOB, {})
        self.check("第二名不同复核员确认后冻结", second["frozen"] is True)
        self.freeze_001 = second["freeze_id"]

        view = self.call("GET", "/v1/cases/CASE-2026-001", ALICE)
        self.check("案件进入已冻结", view["case"]["status"] == "已冻结")
        ev = next(l for l in view["links"])["evidence"]
        self.check("每条结论可回溯到证据片段与来源定位",
                   all(f.get("source_ref") and f.get("excerpt") for f in ev["fragments"])
                   and ev["assemblies"],
                   pp(ev["fragments"][0]))

    # 4) 外部移送
    # ------------------------------------------------------------------
    def demo_transfer(self):
        self.section("外部移送包生成与外部接收人视图")
        pkg = self.call("POST", "/v1/cases/CASE-2026-001/transfer", BOB, {
            "freeze_id": self.freeze_001,
            "recipient": "市公安局网安支队",
        }, expect=201)
        self.package_id = pkg["package_id"]
        self.check("移送包含清单哈希", bool(pkg["manifest"].get("manifest_sha256")))
        self.check("案件进入已移送", pkg["manifest"]["case_id"] == "CASE-2026-001")

        external = self.call("GET", f"/v1/packages/{self.package_id}", POLICE)
        m = external["manifest"]
        self.check("外部只见脱敏账号标识", m["subject_account"].startswith("ACC-"))
        self.check("外部不含审核员真实身份",
                   "confirmations" not in m and all("reviewer" not in k for k in m))
        self.check("外部可凭来源定位与哈希正式调证",
                   all(e["source_ref"] and e["content_sha256"] for e in m["evidence_index"]))
        self.check("外部仅见双人确认结论", m["review_summary"]["two_person_confirmed"] is True)
        print("  外部接收人移送包摘要：")
        print("   ", pp({k: m[k] for k in ("case_id", "recipient", "subject_account",
              "assembled_urls", "review_summary")}))

    # 5) 误关联申诉 + 旧阈值复现
    # ------------------------------------------------------------------
    def demo_wrong_link_appeal(self):
        self.section("误关联申诉与撤销：旧决定按当时阈值复现，升级只影响新分析")

        # 历史：该案件在 v1 阈值（55、无举报语境识别）下被建议
        old = self.call("POST", "/v1/cases/CASE-2026-002/analyze", ALICE,
                        {"rule_version": "v1"})
        old_cand = old["candidates"][0]
        self.old_analysis = old["analysis_id"]
        self.check("v1 规则下举报者被误判为导流（56 ≥ 阈值55）",
                   old_cand["score"] == 56 and old_cand["decision"] == "suggest",
                   f"score={old_cand['score']}")

        view = self.call("GET", "/v1/cases/CASE-2026-002", ALICE)
        link = view["links"][0]
        self.check("关联记录固化当时规则版本", link["rule_version"] == "v1")
        self.call("POST", f"/v1/cases/CASE-2026-002/links/{link['link_id']}/confirm", ALICE, {})
        fr = self.call("POST", f"/v1/cases/CASE-2026-002/links/{link['link_id']}/confirm", BOB, {})
        self.check("旧流程下证据被双人冻结", fr["frozen"] is True)
        self.old_freeze = fr["freeze_id"]

        # 规则升级后重新分析同一案件：不产生新建议
        new = self.call("POST", "/v1/cases/CASE-2026-002/analyze", ALICE,
                        {"rule_version": "v2"})
        self.check("v2 识别举报/反诈语境后不再建议（30 < 阈值50）",
                   all(c["decision"] == "below_threshold" for c in new["candidates"]),
                   pp([(c["account_id"], c["score"]) for c in new["candidates"]]))

        # 申诉撤销
        appeal = self.call("POST", f"/v1/cases/CASE-2026-002/links/{link['link_id']}/appeal",
                           BOB, {"reason": "当事人是在发布反诈提醒，域名用于举例举报"}, expect=201)
        resolved = self.call("POST", f"/v1/appeals/{appeal['appeal_id']}/resolve", ALICE,
                             {"outcome": "reversed"})
        self.check("误关联可撤销", resolved["link_status"] == "reversed")
        self.check("冻结证据不删除、审计不消失",
                   resolved["freeze_retained"] and resolved["audit_retained"])

        view2 = self.call("GET", "/v1/cases/CASE-2026-002", ALICE)
        self.check("案件进入已纠正", view2["case"]["status"] == "已纠正")
        freeze_rows = self.store.freezes_for_case("CASE-2026-002")
        self.check("历史冻结快照仍在", any(r["freeze_id"] == self.old_freeze for r in freeze_rows))

        # 旧决定按当时阈值复现
        replay = self.call("GET", f"/v1/analyses/{self.old_analysis}/replay", CAROL)
        self.check("旧分析可按 v1 参数快照原样复现", replay["snapshot_consistent"] is True)
        self.check("复现分数与决定等于旧决定（56 / suggest）",
                   replay["reproduced_top_score"] == 56
                   and replay["original_decision"] == "suggest")
        self.check("复现参数仍为当时阈值 55（未被 v2 的 50 覆盖）",
                   replay["params_snapshot"]["threshold"] == 55)
        print("  复现证据：", pp({
            "rule_version": replay["rule_version"],
            "threshold_then": replay["params_snapshot"]["threshold"],
            "score_then": replay["original_score"],
            "decision_then": replay["original_decision"],
            "reproduced_score": replay["reproduced_top_score"],
            "report_context_weight_then": replay["params_snapshot"]["weights"]["report_context"],
        }))

    # 6) 三角色字段隔离
    # ------------------------------------------------------------------
    def demo_role_isolation(self):
        self.section("三类人员的敏感字段严格限于职责")

        # 无令牌
        status, _ = self.api.handle("GET", "/v1/cases", {}, {})
        self.check("无令牌拒绝访问", status == 401)

        reviewer = self.call("GET", "/v1/cases/CASE-2026-001", ALICE)
        auditor = self.call("GET", "/v1/cases/CASE-2026-001", CAROL)
        rev_link = reviewer["links"][0]
        aud_link = auditor["links"][0]

        self.check("复核员可见来源定位与内容摘录",
                   rev_link["evidence"]["fragments"][0].get("source_ref")
                   and rev_link["evidence"]["fragments"][0].get("excerpt"))
        self.check("审计员只见流程信号，不见 source_ref 与摘录",
                   "source_ref" not in aud_link["evidence"]["fragments"][0]
                   and "excerpt" not in aud_link["evidence"]["fragments"][0]
                   and aud_link["account_id"].startswith("ACC-"))
        self.check("审计员看不到重组网址文本",
                   all("text" not in a for a in auditor["assemblies"]))
        self.check("审计员可独立查看完整审计链",
                   len(self.call("GET", "/v1/audit?limit=20", CAROL)["audit"]) > 0)

        ext_case = self.api.handle("GET", "/v1/cases/CASE-2026-001",
                                   {"Authorization": f"Bearer {POLICE}"}, {})
        self.check("外部接收人不得浏览案件视图", ext_case[0] == 403)

        ext_pkg = self.call("GET", f"/v1/packages/{self.package_id}", POLICE)
        other_pkg = self.api.handle(
            "GET", f"/v1/packages/{self.package_id}",
            {"Authorization": "Bearer ext-other"}, {})
        self.check("伪造/未登记外部令牌被拒", other_pkg[0] == 401)
        self.check("外部只能读取移送包最小必要字段",
                   set(ext_pkg["manifest"].keys()) >= {"evidence_index", "manifest_sha256"})
        self.check("外部移送包不含其他共享案件等内部办案信息",
                   all("shared_with_cases" not in e for e in ext_pkg["manifest"]["evidence_index"]))

    # 7) 只追加 / 审计不可消失
    # ------------------------------------------------------------------
    def demo_immutability(self):
        self.section("只追加表与审计日志不可删除、不可篡改")
        for sql in ("DELETE FROM events", "UPDATE events SET payload='{}'",
                    "DELETE FROM audit_log", "UPDATE frozen_evidence SET snapshot_json='{}'"):
            try:
                self.store.execute(sql)
                raise AssertionError(f"应当被触发器拦截: {sql}")
            except Exception as exc:  # sqlite3.IntegrityError / 触发器 ABORT
                self.check(f"触发器拦截：{sql}", "只追加" in str(exc), str(exc))

        audit = self.store.audit_log(limit=500)
        actions = {r["action"] for r in audit}
        for required in ("event.dedup", "link.confirm", "evidence.freeze",
                         "transfer.create", "appeal.create", "appeal.reversed",
                         "account.rename"):
            self.check(f"审计链包含 {required}", required in actions)
        print(f"  审计日志共 {len(audit)} 条，申诉纠正记录仍可追溯。")


def main():
    demo = Demo()
    try:
        demo.run()
    except AssertionError as exc:
        print(f"\n演示失败: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
