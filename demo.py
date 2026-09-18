"""交付演示：误关联申诉、外部移送、旧决定按当时阈值复现、三角色字段可见性。

运行: python3 demo.py
覆盖项目要求的全部事件样例：同一内容重复上报、账号改名、跨案件共享线索、
证据保全期限、规则升级只影响新分析。
"""

import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from app.core import CoreService
from app.http_api import Api
from app.store import Store
from service import Handler

SYS = ("sys-ingest", "system")
R1 = ("rev-101", "reviewer")
R2 = ("rev-102", "reviewer")
S1 = ("sup-201", "supervisor")
AU = ("aud-301", "auditor")

FAILURES = []


def section(title):
    print(f"\n== {title} " + "=" * max(2, 62 - len(title) * 2))


def check(label, condition, detail=""):
    print(f"  {'✅' if condition else '❌'} {label}" + (f" — {detail}" if detail else ""))
    if not condition:
        FAILURES.append(label)


def show(obj, keys=None):
    if keys:
        obj = {k: obj.get(k) for k in keys}
    print("  " + json.dumps(obj, ensure_ascii=False, indent=2).replace("\n", "\n  "))


class Client:
    def __init__(self, port):
        self.port = port

    def call(self, method, path, actor=None, payload=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if actor:
            headers["X-Actor-Id"], headers["X-Actor-Role"] = actor
        body = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        return resp.status, data


def event(case_id, seq, channel, etype, digest, account, minute, **extra):
    payload = {
        "source_system": "live-detect",
        "source_event_id": f"det-{seq}",
        "event_type": etype,
        "channel": channel,
        "occurred_at": f"2026-09-10T20:{minute:02d}:00+00:00",
        "digest": digest,
        "content_hash": f"hash-{seq}",
        "locator": f"live://room/8848/frag/{seq}",
        "account_id": account,
        "case_id": case_id,
    }
    payload.update(extra)
    return payload


def main():
    Handler.api = Api(CoreService(Store()))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        run(Client(server.server_port))
    finally:
        server.shutdown()
        server.server_close()
    if FAILURES:
        print(f"\n演示失败 {len(FAILURES)} 项: {FAILURES}")
        raise SystemExit(1)
    print("\n全部演示项通过。")


def run(c):
    section("1. 线索入库：只收定位/摘要/哈希，重复上报合并，改名留痕")
    _, case = c.call("POST", "/cases", SYS, {"title": "直播间拆分网址导流案"})
    c1 = case["case_id"]
    check("案件创建", c1 is not None, f"{c1} 状态 {case['status']}")

    account_a = "acc-A-001"
    _, r = c.call("POST", "/events", SYS, event(
        c1, 1, "昵称", "text", '昵称含拆分网址片段[1/2]: "hxekle"', account_a, 0,
        nickname="夜行者K"))
    frag_nick = r["fragment"]["fragment_id"]
    _, r = c.call("POST", "/events", SYS, event(
        c1, 2, "评论", "text", '评论含拆分网址片段[2/2]: ".cc/9f"', account_a, 5))
    frag_cmt = r["fragment"]["fragment_id"]
    # 同一内容重复上报（同一来源事件号）：幂等合并
    _, dup = c.call("POST", "/events", SYS, event(
        c1, 2, "评论", "text", '评论含拆分网址片段[2/2]: ".cc/9f"', account_a, 5))
    check("同一事件重复上报幂等", dup["deduplicated"] and dup["fragment"]["fragment_id"] == frag_cmt,
          f"片段 {frag_cmt} 不重复创建")
    # 同一内容经不同来源事件再次上报：按内容哈希合并，上报次数累加
    _, merged = c.call("POST", "/events", SYS, event(
        c1, 200, "评论", "text", '评论含拆分网址片段[2/2]: ".cc/9f"', account_a, 5,
        content_hash="hash-2"))
    check("同一内容重复上报被合并", merged["deduplicated"]
          and merged["fragment"]["fragment_id"] == frag_cmt,
          f"片段 {frag_cmt} report_count={merged['fragment']['report_count']}")
    # 账号改名：夜行者K → 清风徐来，归属不变
    _, r = c.call("POST", "/events", SYS, event(
        c1, 3, "音频", "audio_transcript", "口播暗语“走老地方”，引导查看主页昵称",
        account_a, 10, nickname="清风徐来"))
    check("账号改名后事件仍归属同一账号", r["fragment"]["account_id"] == account_a,
          "昵称 夜行者K→清风徐来，片段记录当时昵称")
    c.call("POST", "/events", SYS, event(
        c1, 4, "收藏夹", "account_relation", "收藏夹新增站外引流客服号", account_a, 12,
        related_account_id="acc-B-002", relation_type="收藏"))
    c.call("POST", "/events", SYS, event(
        c1, 5, "直播瞬间", "image_summary", "画面角落短时二维码，扫码跳转站外", account_a, 15))
    # 原始素材直接拒绝
    status, rejected = c.call("POST", "/events", SYS, event(
        c1, 6, "正文", "text", "x", account_a, 16, raw_content="原始视频"))
    check("携带原始素材的载荷被拒绝", status == 400 and rejected["error"]["code"] == "RAW_MATERIAL_REJECTED")

    section("2. 自动关联：重建时间序路径，只形成建议，不直接处罚")
    _, analyzed = c.call("POST", f"/cases/{c1}/analyze", SYS)
    analysis = analyzed["analysis"]
    sug = analyzed["suggestions"][0]
    check("路径按时间排序", [s["occurred_at"] for s in analysis["path"]["steps"]]
          == sorted(s["occurred_at"] for s in analysis["path"]["steps"]),
          f"{len(analysis['path']['steps'])} 步")
    check("拆分网址被重组", sug["reassembled_urls"] == ["hxekle.cc/9f"],
          f"结论「{sug['conclusion']}」得分 {sug['score']}≥阈值 {sug['threshold']}")
    _, case_view = c.call("GET", f"/cases/{c1}", R1)
    check("自动关联不直接处罚", case_view["status"] == "待初审" and case_view["freeze"] is None,
          "案件仅进入待初审，无冻结、无账号处置")

    section("3. 双人确认：同一人重复确认被拒绝")
    c.call("POST", f"/suggestions/{sug['suggestion_id']}/confirm", R1)
    status, err = c.call("POST", f"/suggestions/{sug['suggestion_id']}/confirm", R1)
    check("同一人员二次确认被拒绝", status == 409 and err["error"]["code"] == "DUPLICATE_CONFIRM")
    status, err = c.call("POST", f"/suggestions/{sug['suggestion_id']}/confirm", AU)
    check("审计员无权确认", status == 403)
    _, sug_view = c.call("POST", f"/suggestions/{sug['suggestion_id']}/confirm", S1)
    check("复核员+主管双人确认完成", sug_view["status"] == "已确认",
          f"确认人 {[x['actor_id'] for x in sug_view['confirmations']]}")

    section("4. 证据冻结与保全期限")
    _, freeze = c.call("POST", f"/cases/{c1}/freeze", S1)
    check("双人确认后冻结成功", freeze["retention_until"] > freeze["frozen_at"],
          f"保全期 {freeze['retention_days']} 天，至 {freeze['retention_until']}")
    _, retention = c.call("GET", f"/cases/{c1}/retention", AU)
    check("保全报告全部在保", all(i["in_retention"] for i in retention["items"]))
    _, purge = c.call("POST", "/maintenance/purge", S1)
    check("保全期限内清除被拒绝", purge["purged"] == [] and len(purge["retained"]) == 5,
          purge["retained"][0]["reason"])

    section("5. 外部移送")
    _, package = c.call("POST", f"/cases/{c1}/transfer-packages", S1)
    pkg_id = package["package_id"]
    _, dispatched = c.call("POST", f"/transfer-packages/{pkg_id}/dispatch", S1,
                           {"recipient": "网安支队", "receipt_id": "WS-2026-0918-01"})
    check("移送包已送达外部机构", dispatched["status"] == "已移送",
          f"接收方 {dispatched['recipient']} 回执 {dispatched['receipt_id']}")
    _, case_view = c.call("GET", f"/cases/{c1}", S1)
    check("案件状态已移送", case_view["status"] == "已移送")
    _, pkg_full = c.call("GET", f"/transfer-packages/{pkg_id}", S1)
    check("移送包含结论+证据定位+哈希（供外部调证，不含原始素材）",
          pkg_full["conclusions"][0]["evidence"][0]["locator"].startswith("live://")
          and "content_hash" in pkg_full["conclusions"][0]["evidence"][0])

    section("6. 跨案件共享线索与误关联申诉")
    _, case2 = c.call("POST", "/cases", SYS, {"title": "收藏夹关联误报案"})
    c2 = case2["case_id"]
    _, case1_view = c.call("GET", f"/cases/{c1}", S1)
    fav_fragment = next(f for f in case1_view["fragments"] if f["channel"] == "收藏夹")
    c.call("POST", f"/cases/{c2}/shared-clues", R2,
           {"fragment_id": fav_fragment["fragment_id"], "note": "同一收藏关系交叉出现"})
    c.call("POST", "/events", SYS, event(
        c2, 91, "昵称", "text", '昵称含拆分网址片段[1/2]: "hxekle"', "acc-B-002", 20,
        nickname="清风客"))
    c.call("POST", "/events", SYS, event(
        c2, 92, "音频", "audio_transcript", "口播提到“老地方”（语境为游戏组队）",
        "acc-B-002", 25))
    _, analyzed2 = c.call("POST", f"/cases/{c2}/analyze", SYS)
    sug2 = analyzed2["suggestions"][0]
    check("共享线索参与新案件分析并形成建议", sug2["subject_account_id"] == "acc-B-002",
          f"建议 {sug2['suggestion_id']} 命中共享的收藏夹片段")
    c.call("POST", f"/suggestions/{sug2['suggestion_id']}/confirm", R2)
    _, appeal = c.call("POST", f"/suggestions/{sug2['suggestion_id']}/appeals", R2,
                       {"reason": "账号B为普通用户，收藏关系与昵称巧合导致误关联"})
    _, case2_view = c.call("GET", f"/cases/{c2}", R2)
    check("申诉受理后案件进入申诉中", case2_view["status"] == "申诉中")
    status, err = c.call("POST", f"/appeals/{appeal['appeal_id']}/resolve", R2,
                         {"uphold": True})
    check("申诉人不能处理自己的申诉", status == 409 and err["error"]["code"] == "SELF_RESOLVE")
    _, resolved = c.call("POST", f"/appeals/{appeal['appeal_id']}/resolve", S1,
                         {"uphold": True, "note": "核实为误关联"})
    check("申诉成立，误关联撤销", resolved["status"] == "已成立")
    _, case2_view = c.call("GET", f"/cases/{c2}", AU)
    check("案件已纠正，建议状态已撤销（记录保留未删除）",
          case2_view["status"] == "已纠正"
          and case2_view["suggestions"][0]["status"] == "已撤销")
    _, audit2 = c.call("GET", f"/cases/{c2}/audit", AU)
    actions = [e["action"] for e in audit2]
    check("误关联可撤销但审计不能消失",
          all(a in actions for a in ("自动关联分析", "初审确认", "申诉受理", "申诉成立-关联撤销")),
          f"审计 {len(audit2)} 条完整保留")

    section("7. 规则升级只影响新分析，旧决定按当时阈值复现")
    _, rules = c.call("POST", "/rules", S1, {"min_score": 8})
    check("规则升级", rules["version"] == "v2" and rules["supersedes"] == "v1",
          "min_score 4→8")
    _, replay = c.call("POST", f"/analyses/{analysis['analysis_id']}/reproduce", AU)
    check("旧决定按当时阈值复现", replay["reproduced"] and replay["rule_version"] == "v1",
          f"快照 min_score={replay['threshold_snapshot']['min_score']}，当前 v2 为 8")
    _, case3 = c.call("POST", "/cases", SYS, {"title": "新规则下的同类案件"})
    c3 = case3["case_id"]
    for i, (ch, et, dg) in enumerate([
        ("昵称", "text", '昵称含拆分网址片段[1/2]: "hxekle"'),
        ("评论", "text", '评论含拆分网址片段[2/2]: ".cc/9f"'),
        ("音频", "audio_transcript", "口播暗语"),
        ("收藏夹", "account_relation", "收藏引流号"),
        ("直播瞬间", "image_summary", "短时二维码"),
    ]):
        c.call("POST", "/events", SYS, event(c3, 100 + i, ch, et, dg, "acc-C-003", 30 + i))
    _, analyzed3 = c.call("POST", f"/cases/{c3}/analyze", SYS)
    check("同样片段在新规则下不再构成建议", analyzed3["suggestions"] == []
          and analyzed3["analysis"]["rule_version"] == "v2",
          f"得分 {analyzed3['analysis']['result']['score']}<8")

    section("8. 三类人员看到的敏感字段严格限于各自职责")
    _, reviewer_view = c.call("GET", f"/cases/{c1}", R1)
    _, supervisor_view = c.call("GET", f"/cases/{c1}", S1)
    _, auditor_view = c.call("GET", f"/cases/{c1}", AU)
    frag_r = reviewer_view["fragments"][0]
    frag_s = supervisor_view["fragments"][0]
    frag_a = auditor_view["fragments"][0]
    check("复核员：可见摘要与来源，账号脱敏",
          bool(frag_r["digest"]) and "***" in frag_r["account_id"],
          f"account_id={frag_r['account_id']}")
    check("主管：可见完整账号标识（移送决策需要）",
          frag_s["account_id"] == account_a)
    check("审计员：摘要/定位/昵称不可见，仅见哈希与过程",
          frag_a["digest"] is None and frag_a["locator"] is None
          and frag_a["nickname_at_event"] is None and bool(frag_a["content_hash"]))
    sug_a = auditor_view["suggestions"][0]
    check("审计员：重组网址不可见，仅见计数",
          sug_a["reassembled_urls"] == [] and sug_a["reassembled_url_count"] == 1)
    _, pkg_auditor = c.call("GET", f"/transfer-packages/{pkg_id}", AU)
    check("审计员看移送包仅元数据", "conclusions" not in pkg_auditor
          and pkg_auditor["conclusion_count"] == 1)
    status, _ = c.call("GET", f"/cases/{c1}", SYS)
    check("检测系统账号不可见案件结论", status == 403)

    section("9. 审计链整体校验")
    _, verify = c.call("GET", "/audit/verify", AU)
    check("哈希链完整未被篡改", verify["valid"], f"共 {verify['entries']} 条审计记录")


if __name__ == "__main__":
    main()
