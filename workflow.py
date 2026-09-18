"""案件协查工作流：接入、分析、双人确认、冻结、移送、申诉、复现。

所有状态变更均经 Store 落审计；自动关联只产生 `suggested` 建议，
冻结与移送必须两名不同复核员；申诉可撤销关联，但只追加表与审计不变。
"""

import hashlib
import json
from datetime import datetime, timezone

import rules
from store import now_iso


class WorkflowError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _event_dict(row):
    return {
        "event_id": row["event_id"],
        "case_id": row["case_id"],
        "source_system": row["source_system"],
        "source_ref": row["source_ref"],
        "event_type": row["event_type"],
        "account_id": row["account_id"],
        "occurred_at": row["occurred_at"],
        "ingested_at": row["ingested_at"],
        "payload": json.loads(row["payload"]),
        "dedup_hash": row["dedup_hash"],
    }


class Workflow:
    def __init__(self, store):
        self.store = store

    # ---------- 接入 ----------
    def ingest(self, event, case_id=None, actor="ingest"):
        required = ("source_system", "source_ref", "event_type", "occurred_at")
        missing = [k for k in required if not event.get(k)]
        if missing:
            raise WorkflowError(f"事件缺少必填字段: {','.join(missing)}", 422)

        row, created, already_linked = self.store.ingest_event(event, case_id, actor)
        result = _event_dict(row)

        # 昵称即身份事件：维护改名时间线（身份以 account_id 为准）
        account_id = event.get("account_id")
        nickname = event.get("payload", {}).get("nickname")
        if account_id and nickname:
            self.store.upsert_account_name(
                account_id,
                event.get("payload", {}).get("platform", "unknown"),
                nickname,
                event["occurred_at"],
                actor,
            )
        result["created"] = created
        result["already_linked"] = already_linked
        return result

    def share_clue(self, case_id, event_id, actor="reviewer"):
        """跨案件共享线索：引用同一事件，不复制。"""
        if not self.store.get_event(event_id):
            raise WorkflowError("事件不存在", 404)
        if not self.store.get_case(case_id):
            raise WorkflowError("案件不存在", 404)
        added = self.store.link_event_to_case(case_id, event_id, actor)
        return {"event_id": event_id, "case_id": case_id, "shared": added}

    # ---------- 分析 ----------
    def _name_at(self):
        rows = self.store.query(
            "SELECT account_id,nickname,valid_from,valid_to FROM account_names"
        )
        history = {}
        for r in rows:
            history.setdefault(r["account_id"], []).append(dict(r))

        def resolve(account_id, ts):
            if not account_id:
                return None
            for item in history.get(account_id, []):
                if item["valid_from"] <= ts and (
                    item["valid_to"] is None or item["valid_to"] > ts
                ):
                    return item["nickname"]
            return history.get(account_id, [{}])[-1].get("nickname")

        return resolve

    def run_analysis(self, case_id, rule_version="v2", actor="engine"):
        case = self.store.get_case(case_id)
        if not case:
            raise WorkflowError("案件不存在", 404)
        rows = self.store.events_for_case(case_id)
        events = [_event_dict(r) for r in rows]
        result = rules.analyze(events, rule_version, self._name_at())

        analysis_id = self.store.save_analysis(
            case_id, rule_version, result["params"],
            max((c["score"] for c in result["candidates"]), default=0),
            "suggest" if any(c["decision"] == "suggest" for c in result["candidates"])
            else "below_threshold",
            result,
        )

        link_ids = []
        for cand in result["candidates"]:
            if cand["decision"] != "suggest":
                continue
            open_link = self.store.query_one(
                "SELECT * FROM links WHERE case_id=? AND account_id=?"
                " AND status='suggested' ORDER BY created_at DESC LIMIT 1",
                (case_id, cand["account_id"]),
            )
            evidence = self._evidence_view(cand, result)
            if open_link:
                pending = self.store.confirmations(open_link["link_id"])
                if pending:
                    # 已进入双人确认流程的建议不再被重新分析改写
                    link_ids.append(open_link["link_id"])
                    continue
                self.store.execute(
                    "UPDATE links SET analysis_id=?,score=?,rule_version=?,"
                    "evidence_json=?,decided_at=NULL,decided_by=NULL WHERE link_id=?",
                    (
                        analysis_id, cand["score"], rule_version,
                        json.dumps(evidence, ensure_ascii=False), open_link["link_id"],
                    ),
                )
                self.store.audit(
                    actor, "link.reanalyze", "link", open_link["link_id"],
                    {"score": cand["score"], "rule_version": rule_version,
                     "analysis_id": analysis_id},
                )
                link_ids.append(open_link["link_id"])
            else:
                link_ids.append(
                    self.store.create_link(
                        case_id, analysis_id, cand["account_id"], "redirect_url",
                        cand["score"], rule_version, evidence, actor,
                    )
                )

        if link_ids and case["status"] == "收集中":
            self.store.update_case_status(case_id, "待初审", actor,
                                          {"analysis_id": analysis_id})
        return {
            "analysis_id": analysis_id,
            "rule_version": rule_version,
            "threshold": result["params"]["threshold"],
            "candidates": result["candidates"],
            "assemblies": result["assemblies"],
            "timeline": result["timeline"],
            "link_ids": link_ids,
        }

    def _evidence_view(self, cand, result):
        """组织给复核员看的证据：每条结论都能回到片段与来源定位。"""
        event_index = {e["event_id"]: e for e in result["timeline"]}
        fragments = []
        for signal in cand["signals"]:
            event_id = signal.get("event_id")
            if not event_id:
                continue
            ev = event_index.get(event_id)
            if not ev:
                continue
            fragments.append({
                "event_id": event_id,
                "source_system": ev["source_system"],
                "source_ref": ev["source_ref"],
                "event_type": ev["event_type"],
                "occurred_at": ev["occurred_at"],
                "excerpt": ev["excerpt"],
                "weight": signal["weight"],
                "signal": signal["type"],
            })
        assemblies = [a for a in result["assemblies"] if a["key"] in cand["assemblies"]]
        return {
            "score": cand["score"],
            "fragments": fragments,
            "assemblies": assemblies,
            "timeline_event_ids": cand["timeline_event_ids"],
        }

    # ---------- 双人确认与冻结 ----------
    def confirm(self, case_id, link_id, reviewer):
        link = self.store.get_link(link_id)
        if not link or link["case_id"] != case_id:
            raise WorkflowError("关联不存在", 404)
        if link["status"] != "suggested":
            raise WorkflowError(f"关联状态为 {link['status']}，不可再确认", 409)

        reviewers = self.store.add_confirmation(link_id, case_id, reviewer)
        if len(set(reviewers)) < 2:
            self.store.update_case_status(
                case_id, "待复核", reviewer,
                {"link_id": link_id, "awaiting": "第二名不同复核员"},
            )
            return {"link_id": link_id, "confirmations": reviewers, "frozen": False}

        # 第二名不同复核员 → 冻结证据（只读快照，只存定位/摘要/哈希）
        self.store.set_link_status(link_id, "confirmed", reviewer,
                                   {"reviewers": sorted(set(reviewers))})
        freeze_id = self._freeze(case_id, link, reviewer)
        self.store.update_case_status(
            case_id, "已冻结", reviewer,
            {"link_id": link_id, "freeze_id": freeze_id},
        )
        return {"link_id": link_id, "confirmations": sorted(set(reviewers)),
                "frozen": True, "freeze_id": freeze_id}

    def _freeze(self, case_id, link, actor):
        analysis = self.store.get_analysis(link["analysis_id"])
        result = json.loads(analysis["result_json"])
        event_rows = self.store.events_for_case(case_id)
        event_refs = []
        for row in event_rows:
            d = _event_dict(row)
            event_refs.append({
                "event_id": d["event_id"],
                "source_system": d["source_system"],
                "source_ref": d["source_ref"],   # 定位信息，回源系统取原件
                "event_type": d["event_type"],
                "occurred_at": d["occurred_at"],
                "content_sha256": d["dedup_hash"],
                "excerpt": next(
                    (t["excerpt"] for t in result["timeline"]
                     if t["event_id"] == d["event_id"]),
                    None,
                ),
                "shared_with_cases": [c["case_id"] for c in self.store.cases_for_event(d["event_id"])],
            })
        case = self.store.get_case(case_id)
        snapshot = {
            "case_id": case_id,
            "link_id": link["link_id"],
            "account_id": link["account_id"],
            "frozen_at": now_iso(),
            "rule_version": link["rule_version"],
            "rule_params": json.loads(analysis["params_json"]),
            "score": link["score"],
            "evidence": json.loads(link["evidence_json"]),
            "events": event_refs,
            "name_history": [dict(r) for r in self.store.name_history(link["account_id"])],
            "confirmations": [dict(r) for r in self.store.confirmations(link["link_id"])],
            "retention_until": case["retention_until"],
            "note": "仅含定位信息、摘要与内容哈希；原始素材由来源系统保管",
        }
        return self.store.freeze_evidence(case_id, link["link_id"], snapshot, actor)

    # ---------- 移送 ----------
    def transfer(self, case_id, freeze_id, recipient, actor):
        case = self.store.get_case(case_id)
        if not case:
            raise WorkflowError("案件不存在", 404)
        freeze = self.store.get_freeze(freeze_id)
        if not freeze or freeze["case_id"] != case_id:
            raise WorkflowError("冻结证据不存在", 404)
        if case["status"] not in ("已冻结", "已移送"):
            raise WorkflowError("案件未经双人确认冻结，不得移送", 409)

        snapshot = json.loads(freeze["snapshot_json"])
        manifest = {
            "package_type": "redirect_evidence_referral",
            "case_id": case_id,
            "freeze_id": freeze_id,
            "recipient": recipient,
            "created_at": now_iso(),
            "rule_version": snapshot["rule_version"],
            "account_id": snapshot["account_id"],
            "events": snapshot["events"],
            "evidence": snapshot["evidence"],
            "confirmations": snapshot["confirmations"],
            "retention_until": snapshot["retention_until"],
        }
        canonical = json.dumps(manifest, ensure_ascii=False, sort_keys=True)
        manifest["manifest_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
        package_id = self.store.create_transfer(
            case_id, freeze_id, recipient, manifest, actor
        )
        self.store.update_case_status(case_id, "已移送", actor,
                                      {"package_id": package_id, "recipient": recipient})
        return {"package_id": package_id, "manifest": manifest}

    # ---------- 申诉 / 撤销 ----------
    def appeal(self, case_id, link_id, reason, actor):
        link = self.store.get_link(link_id)
        if not link or link["case_id"] != case_id:
            raise WorkflowError("关联不存在", 404)
        if link["status"] in ("reversed",):
            raise WorkflowError("关联已撤销", 409)
        appeal_id = self.store.create_appeal(case_id, link_id, reason, actor)
        self.store.update_case_status(case_id, "申诉中", actor,
                                      {"link_id": link_id, "appeal_id": appeal_id})
        return {"appeal_id": appeal_id, "status": "open"}

    def resolve_appeal(self, appeal_id, outcome, actor):
        """outcome: upheld（维持）/ reversed（误关联，撤销）。"""
        appeal = self.store.get_appeal(appeal_id)
        if not appeal:
            raise WorkflowError("申诉不存在", 404)
        if appeal["status"] != "open":
            raise WorkflowError("申诉已处理", 409)
        if outcome not in ("upheld", "reversed"):
            raise WorkflowError("outcome 必须为 upheld 或 reversed")

        link = self.store.get_link(appeal["link_id"])
        prior_case = self.store.get_case(appeal["case_id"])
        prior_status = prior_case["status"]
        if outcome == "reversed":
            self.store.set_link_status(
                link["link_id"], "reversed", actor,
                {"appeal_id": appeal_id, "reason": appeal["reason"]},
            )
            self.store.resolve_appeal(appeal_id, "reversed", actor)
            # 冻结记录与移送包是只追加的：不删除，状态进入“已纠正”
            self.store.update_case_status(
                appeal["case_id"], "已纠正", actor,
                {"link_id": link["link_id"], "appeal_id": appeal_id,
                 "frozen_evidence_retained": True},
            )
            return {"appeal_id": appeal_id, "outcome": "reversed",
                    "link_status": "reversed",
                    "audit_retained": True, "freeze_retained": True}

        self.store.resolve_appeal(appeal_id, "upheld", actor)
        restored = "已移送" if self.store.transfers_for_case(appeal["case_id"]) else "已冻结"
        self.store.update_case_status(
            appeal["case_id"], restored, actor,
            {"link_id": link["link_id"], "appeal_id": appeal_id,
             "prior_status": prior_status},
        )
        return {"appeal_id": appeal_id, "outcome": "upheld", "case_status": restored}

    # ---------- 历史复现 ----------
    def replay_analysis(self, analysis_id):
        row = self.store.get_analysis(analysis_id)
        if not row:
            raise WorkflowError("分析不存在", 404)
        params_snapshot = json.loads(row["params_json"])
        events = []
        for event_id in json.loads(row["result_json"])["input_event_ids"]:
            events.append(_event_dict(self.store.get_event(event_id)))
        result, consistent, drifted = rules.replay(
            events, row["rule_version"], params_snapshot
        )
        return {
            "analysis_id": analysis_id,
            "rule_version": row["rule_version"],
            "params_snapshot": params_snapshot,
            "reproduced": result,
            "snapshot_consistent": consistent,
            "params_drifted_from_current": drifted,
            "original_decision": row["decision"],
            "original_score": row["score"],
            "reproduced_top_score": max(
                (c["score"] for c in result["candidates"]), default=0
            ),
        }

    # ---------- 视图 ----------
    def case_view(self, case_id):
        case = self.store.get_case(case_id)
        if not case:
            raise WorkflowError("案件不存在", 404)
        rows = self.store.events_for_case(case_id)
        events = [_event_dict(r) for r in rows]
        latest = self.store.latest_analysis(case_id)
        timeline = assemblies = None
        if latest:
            result = json.loads(latest["result_json"])
            timeline = result["timeline"]
            assemblies = result["assemblies"]
        links = []
        for row in self.store.links_for_case(case_id):
            links.append({
                "link_id": row["link_id"],
                "account_id": row["account_id"],
                "kind": row["kind"],
                "score": row["score"],
                "status": row["status"],
                "rule_version": row["rule_version"],
                "analysis_id": row["analysis_id"],
                "created_at": row["created_at"],
                "decided_by": row["decided_by"],
                "confirmations": [r["reviewer"] for r in self.store.confirmations(row["link_id"])],
                "evidence": json.loads(row["evidence_json"]),
            })
        return {
            "case": dict(case),
            "retention": self._retention(case),
            "events": events,
            "timeline": timeline,
            "assemblies": assemblies,
            "latest_analysis_id": latest["analysis_id"] if latest else None,
            "links": links,
            "freezes": [
                {"freeze_id": r["freeze_id"], "link_id": r["link_id"],
                 "frozen_by": r["frozen_by"], "frozen_at": r["frozen_at"]}
                for r in self.store.freezes_for_case(case_id)
            ],
            "transfers": [
                {"package_id": r["package_id"], "recipient": r["recipient"],
                 "created_by": r["created_by"], "created_at": r["created_at"]}
                for r in self.store.transfers_for_case(case_id)
            ],
        }

    def _retention(self, case):
        if not case["retention_until"]:
            return {"until": None, "expired": False}
        until = datetime.fromisoformat(case["retention_until"])
        now = datetime.now(timezone.utc)
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return {"until": case["retention_until"], "expired": now > until}
