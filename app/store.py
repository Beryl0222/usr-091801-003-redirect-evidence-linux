"""内存存储与只增不减的审计哈希链。

审计链是本案的核心约束之一：误关联可以撤销，但审计不能消失。
所有状态变更只追加新条目，不提供任何修改/删除审计的接口；
每条记录用前一条的哈希串联，篡改可被 verify_audit 检出。
"""

import hashlib
import json
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _entry_hash(entry_without_hash):
    payload = json.dumps(entry_without_hash, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Store:
    """进程内数据存储。时钟可注入，便于测试与复现。"""

    def __init__(self, clock=utcnow):
        self.clock = clock
        self.counters = {}
        self.events = {}               # event_id -> event
        self.event_keys = {}           # (source_system, source_event_id) -> event_id，幂等去重
        self.fragments = {}            # fragment_id -> 证据片段（只存定位/摘要/哈希）
        self.fragment_hash_index = {}  # (case_id, content_hash) -> fragment_id，同内容合并
        self.accounts = {}             # account_id -> 账号（含改名历史）
        self.cases = {}
        self.analyses = {}             # analysis_id -> 分析（含规则阈值快照）
        self.suggestions = {}
        self.appeals = {}
        self.packages = {}
        self.rules = {}                # version -> 规则集（旧版本永不修改）
        self.current_rule_version = None
        self.audit = []                # 只增不减

    def now(self):
        return self.clock()

    def next_id(self, prefix):
        self.counters[prefix] = self.counters.get(prefix, 0) + 1
        return f"{prefix}-{self.counters[prefix]:04d}"

    def append_audit(self, actor_id, role, action, case_id=None, subject_id=None, detail=None):
        """追加一条审计记录。detail 只允许放 id/状态/哈希等过程信息，不放内容。"""
        entry = {
            "seq": len(self.audit) + 1,
            "at": self.now(),
            "actor_id": actor_id,
            "role": role,
            "action": action,
            "case_id": case_id,
            "subject_id": subject_id,
            "detail": detail or {},
            "prev_hash": self.audit[-1]["hash"] if self.audit else GENESIS_HASH,
        }
        entry["hash"] = _entry_hash(entry)
        self.audit.append(entry)
        return entry

    def verify_audit(self):
        """重放整条链，任一环节被篡改都会校验失败。"""
        prev = GENESIS_HASH
        for entry in self.audit:
            if entry["prev_hash"] != prev:
                return False
            body = {k: v for k, v in entry.items() if k != "hash"}
            if _entry_hash(body) != entry["hash"]:
                return False
            prev = entry["hash"]
        return True
