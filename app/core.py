"""案件协查核心业务。

贯穿全模块的硬约束：
1. 不复制原始私密素材——入库只收定位/摘要/哈希，含原始内容的载荷直接拒绝；
2. 自动关联只形成建议，没有任何自动处罚路径；
3. 冻结与移送必须双人确认（两名不同人员）；
4. 误关联可撤销，但审计链只增不减；
5. 规则升级只影响新分析，旧决定按当时阈值快照复现。
"""

import json
from datetime import datetime, timedelta, timezone

from . import models as m
from .redaction import (
    redact_analysis,
    redact_fragment,
    redact_package,
    redact_path,
    redact_suggestion,
)
from .rules import DEFAULT_RULE_V1, evaluate

EVENT_REQUIRED_FIELDS = (
    "source_system",
    "source_event_id",
    "event_type",
    "channel",
    "occurred_at",
    "digest",
    "content_hash",
    "locator",
    "account_id",
    "case_id",
)


def _parse_ts(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise m.bad_request("BAD_TIME", f"时间格式无效: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class CoreService:
    def __init__(self, store):
        self.store = store
        if not self.store.rules:
            ruleset = dict(DEFAULT_RULE_V1)
            ruleset["channel_weights"] = dict(ruleset["channel_weights"])
            ruleset["created_at"] = self.store.now()
            ruleset["supersedes"] = None
            self.store.rules[ruleset["version"]] = ruleset
            self.store.current_rule_version = ruleset["version"]
            self.store.append_audit(
                "system", m.ROLE_SYSTEM, "规则版本生效", detail={"version": ruleset["version"]}
            )

    # ---------- 基础校验 ----------

    def _require(self, actor, allowed):
        if actor["role"] not in allowed:
            raise m.forbidden("ROLE_NOT_ALLOWED", f"角色 {actor['role']} 无权执行该操作")

    def _require_personnel(self, actor):
        self._require(actor, m.PERSONNEL_ROLES)

    def _case(self, case_id):
        case = self.store.cases.get(case_id)
        if not case:
            raise m.not_found("CASE_NOT_FOUND", f"案件不存在: {case_id}")
        return case

    def _suggestion(self, suggestion_id):
        sug = self.store.suggestions.get(suggestion_id)
        if not sug:
            raise m.not_found("SUGGESTION_NOT_FOUND", f"关联建议不存在: {suggestion_id}")
        return sug

    def _audit(self, actor, action, case_id=None, subject_id=None, detail=None):
        return self.store.append_audit(actor["id"], actor["role"], action, case_id, subject_id, detail)

    # ---------- 案件 ----------

    def create_case(self, actor, payload):
        self._require(actor, {m.ROLE_SYSTEM, m.ROLE_REVIEWER, m.ROLE_SUPERVISOR})
        title = str((payload or {}).get("title") or "").strip()
        if not title:
            raise m.bad_request("MISSING_FIELD", "缺少字段: title")
        case_id = self.store.next_id("case")
        case = {
            "case_id": case_id,
            "title": title,
            "status": m.CASE_COLLECTING,
            "created_at": self.store.now(),
            "fragment_ids": [],
            "shared_clues": [],
            "analysis_ids": [],
            "suggestion_ids": [],
            "appeal_ids": [],
            "transfer_package_ids": [],
            "freeze": None,
        }
        self.store.cases[case_id] = case
        self._audit(actor, "案件创建", case_id=case_id, detail={"title": title})
        return case

    # ---------- 线索入库 ----------

    def ingest_event(self, actor, payload):
        """接收检测系统事件。幂等：同一来源事件重复上报不重复建片段。"""
        self._require(actor, {m.ROLE_SYSTEM})
        payload = payload or {}
        leaked = m.FORBIDDEN_EVENT_FIELDS & set(payload)
        if leaked:
            raise m.bad_request(
                "RAW_MATERIAL_REJECTED",
                "本服务不接收原始私密素材，仅接收定位信息、摘要与内容哈希",
            )
        missing = [k for k in EVENT_REQUIRED_FIELDS if not payload.get(k)]
        if missing:
            raise m.bad_request("MISSING_FIELD", "缺少字段: " + ",".join(missing))
        if payload["event_type"] not in m.EVENT_TYPES:
            raise m.bad_request("BAD_EVENT_TYPE", f"未知事件类型: {payload['event_type']}")
        case = self._case(payload["case_id"])
        occurred_at = _parse_ts(payload["occurred_at"]).isoformat()

        key = (payload["source_system"], payload["source_event_id"])
        if key in self.store.event_keys:
            event = self.store.events[self.store.event_keys[key]]
            fragment = self.store.fragments[event["fragment_id"]]
            self._audit(
                actor, "重复上报合并", case_id=case["case_id"],
                subject_id=fragment["fragment_id"],
                detail={"event_id": event["event_id"], "source_event_id": key[1]},
            )
            return {"event": event, "fragment": fragment, "deduplicated": True}

        account = self._upsert_account(actor, case["case_id"], payload)
        event_id = self.store.next_id("evt")

        hash_key = (case["case_id"], payload["content_hash"])
        if hash_key in self.store.fragment_hash_index:
            fragment = self.store.fragments[self.store.fragment_hash_index[hash_key]]
            fragment["report_count"] += 1
            fragment["event_ids"].append(event_id)
            event = self._record_event(event_id, fragment["fragment_id"], payload, occurred_at)
            self._audit(
                actor, "重复内容合并", case_id=case["case_id"],
                subject_id=fragment["fragment_id"],
                detail={"event_id": event_id, "report_count": fragment["report_count"]},
            )
            return {"event": event, "fragment": fragment, "deduplicated": True}

        fragment_id = self.store.next_id("frag")
        fragment = {
            "fragment_id": fragment_id,
            "case_id": case["case_id"],
            "event_ids": [event_id],
            "event_type": payload["event_type"],
            "channel": payload["channel"],
            "occurred_at": occurred_at,
            "source_system": payload["source_system"],
            "locator": payload["locator"],
            "digest": payload["digest"],
            "content_hash": payload["content_hash"],
            "account_id": payload["account_id"],
            "nickname_at_event": account["nickname"],
            "related_account_id": payload.get("related_account_id"),
            "relation_type": payload.get("relation_type"),
            "report_count": 1,
            "shared_to": [],
            "frozen": False,
            "retention_until": None,
        }
        self.store.fragments[fragment_id] = fragment
        self.store.fragment_hash_index[hash_key] = fragment_id
        case["fragment_ids"].append(fragment_id)
        event = self._record_event(event_id, fragment_id, payload, occurred_at)
        self._audit(
            actor, "线索入库", case_id=case["case_id"], subject_id=fragment_id,
            detail={"channel": fragment["channel"], "event_type": fragment["event_type"]},
        )
        return {"event": event, "fragment": fragment, "deduplicated": False}

    def _record_event(self, event_id, fragment_id, payload, occurred_at):
        event = {
            "event_id": event_id,
            "fragment_id": fragment_id,
            "source_system": payload["source_system"],
            "source_event_id": payload["source_event_id"],
            "event_type": payload["event_type"],
            "channel": payload["channel"],
            "occurred_at": occurred_at,
            "content_hash": payload["content_hash"],
            "received_at": self.store.now(),
        }
        self.store.events[event_id] = event
        self.store.event_keys[(event["source_system"], event["source_event_id"])] = event_id
        return event

    def _upsert_account(self, actor, case_id, payload):
        """账号改名不改归属：以 account_id 归并，昵称变化留痕，片段记录当时昵称。"""
        account_id = payload["account_id"]
        nickname = payload.get("nickname")
        account = self.store.accounts.get(account_id)
        if account is None:
            account = {"account_id": account_id, "nickname": nickname, "nickname_history": []}
            self.store.accounts[account_id] = account
        elif nickname and nickname != account["nickname"]:
            account["nickname_history"].append(
                {"nickname": account["nickname"], "changed_at": self.store.now()}
            )
            account["nickname"] = nickname
            self._audit(
                actor, "账号改名", case_id=case_id, subject_id=account_id,
                detail={"nickname_index": len(account["nickname_history"])},
            )
        return account

    # ---------- 自动关联（只形成建议） ----------

    def _case_fragments(self, case):
        fragments = [self.store.fragments[fid] for fid in case["fragment_ids"]]
        fragments += [self.store.fragments[l["fragment_id"]] for l in case["shared_clues"]]
        return fragments

    def analyze_case(self, actor, case_id):
        """用当前规则版本分析，阈值整体快照存进分析记录。只产出建议，不触碰账号。"""
        self._require(actor, {m.ROLE_SYSTEM, m.ROLE_REVIEWER, m.ROLE_SUPERVISOR})
        case = self._case(case_id)
        if case["status"] not in (m.CASE_COLLECTING, m.CASE_PENDING_INITIAL):
            raise m.conflict("CASE_STATUS", f"案件状态 {case['status']} 不允许发起分析")
        fragments = self._case_fragments(case)
        ruleset = self.store.rules[self.store.current_rule_version]
        snapshot = json.loads(json.dumps(ruleset, ensure_ascii=False))
        result = evaluate(fragments, ruleset)

        analysis_id = self.store.next_id("ana")
        analysis = {
            "analysis_id": analysis_id,
            "case_id": case_id,
            "rule_version": ruleset["version"],
            "threshold_snapshot": snapshot,
            "created_at": self.store.now(),
            "fragment_ids": [f["fragment_id"] for f in fragments],
            "result": {
                "passed": result["passed"],
                "score": result["score"],
                "channels": result["channels"],
            },
            "path": result["path"],
            "suggestion_ids": [],
        }
        self.store.analyses[analysis_id] = analysis
        case["analysis_ids"].append(analysis_id)
        self._audit(
            actor, "自动关联分析", case_id=case_id, subject_id=analysis_id,
            detail={
                "rule_version": ruleset["version"],
                "passed": result["passed"],
                "score": result["score"],
            },
        )

        suggestions = []
        if result["passed"]:
            suggestion = self._create_suggestion(case, analysis, fragments, result)
            suggestions.append(suggestion)
            case["status"] = m.CASE_PENDING_INITIAL
        return {"analysis": analysis, "suggestions": suggestions}

    def _create_suggestion(self, case, analysis, fragments, result):
        suggestion_id = self.store.next_id("sug")
        accounts = [f["account_id"] for f in fragments]
        subject = max(set(accounts), key=accounts.count) if accounts else None
        implicated = sorted(
            set(accounts) | {f["related_account_id"] for f in fragments if f.get("related_account_id")}
        )
        suggestion = {
            "suggestion_id": suggestion_id,
            "case_id": case["case_id"],
            "analysis_id": analysis["analysis_id"],
            "subject_account_id": subject,
            "implicated_account_ids": implicated,
            "conclusion": "存在跨片段隐蔽导流路径",
            "score": result["score"],
            "threshold": analysis["threshold_snapshot"]["min_score"],
            "rule_version": analysis["rule_version"],
            "evidence_fragment_ids": [s["fragment_id"] for s in result["path"]["steps"]],
            "reassembled_urls": result["path"]["reassembled_urls"],
            "status": m.SUGGESTION_PENDING,
            "confirmations": [],
            "created_at": self.store.now(),
        }
        self.store.suggestions[suggestion_id] = suggestion
        case["suggestion_ids"].append(suggestion_id)
        analysis["suggestion_ids"].append(suggestion_id)
        return suggestion

    def reproduce_analysis(self, actor, analysis_id):
        """按分析记录里的阈值快照复跑，验证旧决定在当时规则下仍然成立。"""
        self._require_personnel(actor)
        analysis = self.store.analyses.get(analysis_id)
        if not analysis:
            raise m.not_found("ANALYSIS_NOT_FOUND", f"分析记录不存在: {analysis_id}")
        fragments = [self.store.fragments[fid] for fid in analysis["fragment_ids"]]
        fresh = evaluate(fragments, analysis["threshold_snapshot"])
        recorded = analysis["result"]
        reproduced = (
            fresh["passed"] == recorded["passed"]
            and fresh["score"] == recorded["score"]
            and fresh["channels"] == recorded["channels"]
            and [s["fragment_id"] for s in fresh["path"]["steps"]]
            == [s["fragment_id"] for s in analysis["path"]["steps"]]
        )
        self._audit(
            actor, "决定复现", case_id=analysis["case_id"], subject_id=analysis_id,
            detail={"reproduced": reproduced, "rule_version": analysis["rule_version"]},
        )
        return {
            "analysis_id": analysis_id,
            "reproduced": reproduced,
            "rule_version": analysis["rule_version"],
            "current_rule_version": self.store.current_rule_version,
            "threshold_snapshot": analysis["threshold_snapshot"],
            "recorded": recorded,
            "replayed": {
                "passed": fresh["passed"],
                "score": fresh["score"],
                "channels": fresh["channels"],
                "path": redact_path(fresh["path"], actor["role"]),
            },
        }

    # ---------- 双人确认 ----------

    def confirm_suggestion(self, actor, suggestion_id):
        """两名不同人员确认后建议才生效；同一人重复确认被拒绝。"""
        self._require(actor, m.REVIEW_ROLES)
        sug = self._suggestion(suggestion_id)
        case = self._case(sug["case_id"])
        if case["status"] not in (m.CASE_PENDING_INITIAL, m.CASE_PENDING_REVIEW):
            raise m.conflict("CASE_STATUS", f"案件状态 {case['status']} 不允许确认")
        if sug["status"] != m.SUGGESTION_PENDING:
            raise m.conflict("SUGGESTION_STATUS", f"建议状态 {sug['status']} 不允许确认")
        if any(c["actor_id"] == actor["id"] for c in sug["confirmations"]):
            raise m.conflict("DUPLICATE_CONFIRM", "同一人员不得重复确认，须两名不同人员")
        sug["confirmations"].append(
            {"actor_id": actor["id"], "role": actor["role"], "at": self.store.now()}
        )
        if len(sug["confirmations"]) == 1:
            case["status"] = m.CASE_PENDING_REVIEW
            self._audit(actor, "初审确认", case_id=case["case_id"], subject_id=suggestion_id)
        else:
            sug["status"] = m.SUGGESTION_CONFIRMED
            self._audit(
                actor, "复核确认", case_id=case["case_id"], subject_id=suggestion_id,
                detail={"confirmers": [c["actor_id"] for c in sug["confirmations"]]},
            )
        return sug

    # ---------- 冻结与保全 ----------

    def freeze_case(self, actor, case_id):
        """双人确认完成后才能冻结；冻结时按分析快照中的保全期限设定到期时间。"""
        self._require(actor, m.REVIEW_ROLES)
        case = self._case(case_id)
        if case["status"] != m.CASE_PENDING_REVIEW:
            raise m.conflict("CASE_STATUS", f"案件状态 {case['status']} 不允许冻结")
        confirmed = [
            self.store.suggestions[sid]
            for sid in case["suggestion_ids"]
            if self.store.suggestions[sid]["status"] == m.SUGGESTION_CONFIRMED
        ]
        if not confirmed:
            raise m.conflict("NO_CONFIRMED_SUGGESTION", "尚无双人确认完成的关联建议")
        snapshot = self.store.analyses[confirmed[0]["analysis_id"]]["threshold_snapshot"]
        retention_days = snapshot["retention_days"]
        now = _parse_ts(self.store.now())
        retention_until = (now + timedelta(days=retention_days)).isoformat()
        fragment_ids = sorted({fid for s in confirmed for fid in s["evidence_fragment_ids"]})
        for fid in fragment_ids:
            fragment = self.store.fragments[fid]
            fragment["frozen"] = True
            fragment["retention_until"] = retention_until
        freeze = {
            "freeze_id": self.store.next_id("frz"),
            "frozen_at": now.isoformat(),
            "frozen_by": [c["actor_id"] for s in confirmed for c in s["confirmations"]],
            "retention_days": retention_days,
            "retention_until": retention_until,
            "fragment_ids": fragment_ids,
            "confirmed_suggestion_ids": [s["suggestion_id"] for s in confirmed],
        }
        case["freeze"] = freeze
        case["status"] = m.CASE_FROZEN
        self._audit(
            actor, "证据冻结", case_id=case_id, subject_id=freeze["freeze_id"],
            detail={"retention_until": retention_until, "fragment_count": len(fragment_ids)},
        )
        return freeze

    def purge_expired(self, actor):
        """保全期限内的冻结证据一律拒绝清除。"""
        self._require(actor, {m.ROLE_SUPERVISOR})
        now = _parse_ts(self.store.now())
        report = {"purged": [], "retained": []}
        referenced = {
            fid
            for sug in self.store.suggestions.values()
            if sug["status"] != m.SUGGESTION_REVOKED
            for fid in sug["evidence_fragment_ids"]
        }
        for fragment in list(self.store.fragments.values()):
            if fragment["frozen"]:
                report["retained"].append(
                    {"fragment_id": fragment["fragment_id"], "reason": "证据已冻结，保全期内不得清除"}
                )
                continue
            until = fragment["retention_until"]
            if until and now < _parse_ts(until):
                report["retained"].append(
                    {"fragment_id": fragment["fragment_id"], "reason": "保全期限内"}
                )
                continue
            if until and fragment["fragment_id"] in referenced:
                report["retained"].append(
                    {"fragment_id": fragment["fragment_id"], "reason": "被有效结论引用"}
                )
        return report

    # ---------- 移送 ----------

    def create_transfer_package(self, actor, case_id):
        """冻结后才能生成移送包；包内是结论、证据定位与哈希，供外部机构向来源系统调证。"""
        self._require(actor, m.REVIEW_ROLES)
        case = self._case(case_id)
        if case["status"] != m.CASE_FROZEN:
            raise m.conflict("CASE_STATUS", f"案件状态 {case['status']} 不允许生成移送包")
        confirmed = [
            self.store.suggestions[sid]
            for sid in case["suggestion_ids"]
            if self.store.suggestions[sid]["status"] == m.SUGGESTION_CONFIRMED
        ]
        conclusions = []
        for sug in confirmed:
            evidence = [
                {
                    "fragment_id": f["fragment_id"],
                    "channel": f["channel"],
                    "occurred_at": f["occurred_at"],
                    "source_system": f["source_system"],
                    "locator": f["locator"],
                    "content_hash": f["content_hash"],
                    "digest": f["digest"],
                }
                for f in (self.store.fragments[fid] for fid in sug["evidence_fragment_ids"])
            ]
            conclusions.append(
                {
                    "suggestion_id": sug["suggestion_id"],
                    "conclusion": sug["conclusion"],
                    "score": sug["score"],
                    "threshold": sug["threshold"],
                    "rule_version": sug["rule_version"],
                    "evidence": evidence,
                }
            )
        package = {
            "package_id": self.store.next_id("pkg"),
            "case_id": case_id,
            "created_at": self.store.now(),
            "created_by": actor["id"],
            "status": "待移送",
            "recipient": None,
            "receipt_id": None,
            "dispatched_at": None,
            "conclusions": conclusions,
            "audit_head": self.store.audit[-1]["hash"],
        }
        self.store.packages[package["package_id"]] = package
        case["transfer_package_ids"].append(package["package_id"])
        self._audit(
            actor, "移送包生成", case_id=case_id, subject_id=package["package_id"],
            detail={"conclusion_count": len(conclusions)},
        )
        return package

    def dispatch_package(self, actor, package_id, payload):
        self._require(actor, m.REVIEW_ROLES)
        package = self.store.packages.get(package_id)
        if not package:
            raise m.not_found("PACKAGE_NOT_FOUND", f"移送包不存在: {package_id}")
        if package["status"] != "待移送":
            raise m.conflict("PACKAGE_STATUS", f"移送包状态 {package['status']} 不允许移送")
        recipient = str((payload or {}).get("recipient") or "").strip()
        receipt_id = str((payload or {}).get("receipt_id") or "").strip()
        if not recipient or not receipt_id:
            raise m.bad_request("MISSING_FIELD", "缺少字段: recipient, receipt_id")
        package["recipient"] = recipient
        package["receipt_id"] = receipt_id
        package["dispatched_at"] = self.store.now()
        package["status"] = "已移送"
        case = self._case(package["case_id"])
        case["status"] = m.CASE_TRANSFERRED
        self._audit(
            actor, "外部移送", case_id=case["case_id"], subject_id=package_id,
            detail={"recipient": recipient, "receipt_id": receipt_id},
        )
        return package

    # ---------- 申诉与纠正 ----------

    def file_appeal(self, actor, suggestion_id, payload):
        """对疑似误关联提起申诉。冻结/移送后的更正须走专案流程，不在本接口。"""
        self._require(actor, m.REVIEW_ROLES)
        sug = self._suggestion(suggestion_id)
        case = self._case(sug["case_id"])
        if sug["status"] not in (m.SUGGESTION_PENDING, m.SUGGESTION_CONFIRMED):
            raise m.conflict("SUGGESTION_STATUS", f"建议状态 {sug['status']} 不允许申诉")
        if case["status"] not in (m.CASE_PENDING_INITIAL, m.CASE_PENDING_REVIEW):
            raise m.conflict("CASE_STATUS", f"案件状态 {case['status']} 不允许申诉")
        reason = str((payload or {}).get("reason") or "").strip()
        if not reason:
            raise m.bad_request("MISSING_FIELD", "缺少字段: reason")
        appeal = {
            "appeal_id": self.store.next_id("apl"),
            "case_id": case["case_id"],
            "suggestion_id": suggestion_id,
            "reason": reason,
            "filed_by": actor["id"],
            "filed_at": self.store.now(),
            "status": m.APPEAL_PENDING,
            "prior_case_status": case["status"],
            "resolved_by": None,
            "resolved_at": None,
            "resolution_note": None,
        }
        self.store.appeals[appeal["appeal_id"]] = appeal
        case["appeal_ids"].append(appeal["appeal_id"])
        case["status"] = m.CASE_APPEALING
        self._audit(
            actor, "申诉受理", case_id=case["case_id"], subject_id=appeal["appeal_id"],
            detail={"suggestion_id": suggestion_id, "reason": reason},
        )
        return appeal

    def resolve_appeal(self, actor, appeal_id, payload):
        """申诉处理人不得是申诉人本人，也不得是原确认人（回避）。"""
        self._require(actor, m.REVIEW_ROLES)
        appeal = self.store.appeals.get(appeal_id)
        if not appeal:
            raise m.not_found("APPEAL_NOT_FOUND", f"申诉不存在: {appeal_id}")
        if appeal["status"] != m.APPEAL_PENDING:
            raise m.conflict("APPEAL_STATUS", f"申诉状态 {appeal['status']} 不允许处理")
        if actor["id"] == appeal["filed_by"]:
            raise m.conflict("SELF_RESOLVE", "申诉人与处理人不得为同一人")
        sug = self._suggestion(appeal["suggestion_id"])
        if any(c["actor_id"] == actor["id"] for c in sug["confirmations"]):
            raise m.conflict("CONFLICT_OF_INTEREST", "原确认人须回避该申诉的处理")
        uphold = bool((payload or {}).get("uphold"))
        note = str((payload or {}).get("note") or "")
        case = self._case(appeal["case_id"])
        appeal["resolved_by"] = actor["id"]
        appeal["resolved_at"] = self.store.now()
        appeal["resolution_note"] = note
        if uphold:
            appeal["status"] = m.APPEAL_UPHELD
            sug["status"] = m.SUGGESTION_REVOKED
            case["status"] = m.CASE_CORRECTED
            self._audit(
                actor, "申诉成立-关联撤销", case_id=case["case_id"], subject_id=appeal["appeal_id"],
                detail={"revoked_suggestion": sug["suggestion_id"], "note": note},
            )
        else:
            appeal["status"] = m.APPEAL_REJECTED
            case["status"] = appeal["prior_case_status"]
            self._audit(
                actor, "申诉驳回", case_id=case["case_id"], subject_id=appeal["appeal_id"],
                detail={"note": note},
            )
        return appeal

    # ---------- 跨案件共享线索 ----------

    def link_shared_clue(self, actor, case_id, payload):
        self._require(actor, m.REVIEW_ROLES)
        case = self._case(case_id)
        fragment = self.store.fragments.get((payload or {}).get("fragment_id"))
        if not fragment:
            raise m.not_found("FRAGMENT_NOT_FOUND", "证据片段不存在")
        if fragment["case_id"] == case_id:
            raise m.conflict("SAME_CASE", "片段已属于本案件，无需共享")
        if case["status"] not in (m.CASE_COLLECTING, m.CASE_PENDING_INITIAL):
            raise m.conflict("CASE_STATUS", f"案件状态 {case['status']} 不允许引入共享线索")
        if any(l["fragment_id"] == fragment["fragment_id"] for l in case["shared_clues"]):
            raise m.conflict("DUPLICATE_LINK", "该线索已共享至本案件")
        link = {
            "fragment_id": fragment["fragment_id"],
            "from_case_id": fragment["case_id"],
            "linked_by": actor["id"],
            "linked_at": self.store.now(),
            "note": str((payload or {}).get("note") or ""),
        }
        case["shared_clues"].append(link)
        fragment["shared_to"].append(case_id)
        self._audit(
            actor, "跨案件共享线索", case_id=case_id, subject_id=fragment["fragment_id"],
            detail={"from_case_id": fragment["case_id"]},
        )
        return link

    # ---------- 规则版本 ----------

    def list_rules(self, actor):
        self._require_personnel(actor)
        return {
            "current": self.store.current_rule_version,
            "versions": list(self.store.rules.values()),
        }

    def create_rules(self, actor, payload):
        """规则升级生成新版本，旧版本与其快照永不修改，只影响之后的新分析。"""
        self._require(actor, {m.ROLE_SUPERVISOR})
        allowed = {
            "min_score",
            "min_distinct_channels",
            "window_hours",
            "retention_days",
            "channel_weights",
            "default_channel_weight",
        }
        overrides = {k: v for k, v in (payload or {}).items() if k in allowed}
        if not overrides:
            raise m.bad_request("EMPTY_RULE_CHANGE", "未提供任何规则变更")
        base = dict(self.store.rules[self.store.current_rule_version])
        base["channel_weights"] = dict(base["channel_weights"])
        base.update(overrides)
        base["version"] = f"v{len(self.store.rules) + 1}"
        base["supersedes"] = self.store.current_rule_version
        base["created_at"] = self.store.now()
        self.store.rules[base["version"]] = base
        self.store.current_rule_version = base["version"]
        self._audit(
            actor, "规则升级",
            detail={"version": base["version"], "supersedes": base["supersedes"], "changes": overrides},
        )
        return base

    # ---------- 只读视图（按角色脱敏） ----------

    def list_cases(self, actor):
        self._require_personnel(actor)
        return [
            {
                "case_id": c["case_id"],
                "title": c["title"],
                "status": c["status"],
                "created_at": c["created_at"],
            }
            for c in self.store.cases.values()
        ]

    def get_case(self, actor, case_id):
        self._require_personnel(actor)
        case = self._case(case_id)
        role = actor["role"]
        shared = [
            {**link, "fragment": redact_fragment(self.store.fragments[link["fragment_id"]], role)}
            for link in case["shared_clues"]
        ]
        return {
            "case_id": case["case_id"],
            "title": case["title"],
            "status": case["status"],
            "created_at": case["created_at"],
            "fragments": [
                redact_fragment(self.store.fragments[fid], role) for fid in case["fragment_ids"]
            ],
            "shared_clues": shared,
            "suggestions": [
                redact_suggestion(self.store.suggestions[sid], role)
                for sid in case["suggestion_ids"]
            ],
            "analyses": [
                redact_analysis(self.store.analyses[aid], role) for aid in case["analysis_ids"]
            ],
            "freeze": case["freeze"],
            "transfer_packages": [
                redact_package(self.store.packages[pid], role)
                for pid in case["transfer_package_ids"]
            ],
            "appeals": [dict(self.store.appeals[aid]) for aid in case["appeal_ids"]],
        }

    def get_suggestion(self, actor, suggestion_id):
        """每个结论对应的证据片段与来源，按角色脱敏。"""
        self._require_personnel(actor)
        sug = self._suggestion(suggestion_id)
        role = actor["role"]
        return {
            "suggestion": redact_suggestion(sug, role),
            "evidence": [
                redact_fragment(self.store.fragments[fid], role)
                for fid in sug["evidence_fragment_ids"]
            ],
        }

    def get_package(self, actor, package_id):
        self._require_personnel(actor)
        package = self.store.packages.get(package_id)
        if not package:
            raise m.not_found("PACKAGE_NOT_FOUND", f"移送包不存在: {package_id}")
        return redact_package(package, actor["role"])

    def get_case_audit(self, actor, case_id):
        self._require_personnel(actor)
        self._case(case_id)
        return [dict(e) for e in self.store.audit if e["case_id"] == case_id]

    def verify_audit(self, actor):
        self._require_personnel(actor)
        return {"valid": self.store.verify_audit(), "entries": len(self.store.audit)}

    def retention_report(self, actor, case_id):
        self._require_personnel(actor)
        case = self._case(case_id)
        now = _parse_ts(self.store.now())
        items = []
        for fid in case["fragment_ids"]:
            fragment = self.store.fragments[fid]
            until = fragment["retention_until"]
            items.append(
                {
                    "fragment_id": fid,
                    "frozen": fragment["frozen"],
                    "retention_until": until,
                    "in_retention": bool(until and now < _parse_ts(until)),
                }
            )
        return {"case_id": case_id, "items": items}
