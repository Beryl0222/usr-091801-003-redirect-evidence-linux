"""SQLite 只追加存储层。

事件、审计日志、冻结记录、移送包一经写入不可修改（由触发器拦截
UPDATE/DELETE）；案件、关联等可变状态的所有变更也同步写审计。
"""

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

APPEND_ONLY_TABLES = ("events", "audit_log", "frozen_evidence", "transfer_packages")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id        TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    status         TEXT NOT NULL,
    retention_until TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

-- 账号主体：允许改名，身份以 account_id 为准，昵称只追加历史
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    platform   TEXT NOT NULL,
    nickname   TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS account_names (
    account_id  TEXT NOT NULL,
    nickname    TEXT NOT NULL,
    valid_from  TEXT NOT NULL,
    valid_to    TEXT,
    PRIMARY KEY (account_id, valid_from)
);

-- 原始事件：只存定位/摘要/哈希，绝不保存原始私密素材
CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,
    case_id       TEXT,
    source_system TEXT NOT NULL,
    source_ref    TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    account_id    TEXT,
    occurred_at   TEXT NOT NULL,
    ingested_at   TEXT NOT NULL,
    payload       TEXT NOT NULL,
    dedup_hash    TEXT NOT NULL,
    UNIQUE(source_system, source_ref)
);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_account ON events(account_id);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at);

-- 案件与线索的多对多：跨案件共享线索（同一事件可被多个案件引用）
CREATE TABLE IF NOT EXISTS case_events (
    case_id  TEXT NOT NULL,
    event_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (case_id, event_id)
);

-- 每次规则分析的不可变快照
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id   TEXT PRIMARY KEY,
    case_id       TEXT NOT NULL,
    rule_version  TEXT NOT NULL,
    params_json   TEXT NOT NULL,
    score         REAL NOT NULL,
    decision      TEXT NOT NULL,
    result_json   TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    superseded_by TEXT
);

-- 自动关联只形成建议；suggested→confirmed/rejected/appealed
CREATE TABLE IF NOT EXISTS links (
    link_id        TEXT PRIMARY KEY,
    case_id        TEXT NOT NULL,
    analysis_id    TEXT,
    account_id     TEXT NOT NULL,
    kind           TEXT NOT NULL,
    score          REAL NOT NULL,
    rule_version   TEXT NOT NULL,
    status         TEXT NOT NULL,
    evidence_json  TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    decided_at     TEXT,
    decided_by     TEXT
);
CREATE INDEX IF NOT EXISTS idx_links_case ON links(case_id);

-- 双人确认：两个不同复核员；冻结即只读快照
CREATE TABLE IF NOT EXISTS confirmations (
    link_id     TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    reviewer    TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    PRIMARY KEY (link_id, reviewer)
);
CREATE TABLE IF NOT EXISTS frozen_evidence (
    freeze_id    TEXT PRIMARY KEY,
    case_id      TEXT NOT NULL,
    link_id      TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    frozen_by    TEXT NOT NULL,
    frozen_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS appeals (
    appeal_id   TEXT PRIMARY KEY,
    case_id     TEXT NOT NULL,
    link_id     TEXT NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT
);

CREATE TABLE IF NOT EXISTS transfer_packages (
    package_id   TEXT PRIMARY KEY,
    case_id      TEXT NOT NULL,
    freeze_id    TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Store:
    """线程安全的 SQLite 封装。"""

    def __init__(self, path=":memory:"):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._install_append_only_triggers()

    def _install_append_only_triggers(self):
        for table in APPEND_ONLY_TABLES:
            for verb in ("UPDATE", "DELETE"):
                self._conn.execute(
                    f"DROP TRIGGER IF EXISTS trg_{table.lower()}_no_{verb.lower()}"
                )
                self._conn.execute(
                    f"""
                    CREATE TRIGGER trg_{table}_no_{verb.lower()}
                    BEFORE {verb} ON {table}
                    BEGIN
                        SELECT RAISE(ABORT, '{table} 为只追加表，禁止 {verb}');
                    END
                    """
                )

    @property
    def lock(self):
        return self._lock

    def execute(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    # ---------- 审计 ----------
    def audit(self, actor, action, entity_type, entity_id, detail=None):
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log(ts,actor,action,entity_type,entity_id,detail_json)"
                " VALUES(?,?,?,?,?,?)",
                (
                    now_iso(),
                    actor,
                    action,
                    entity_type,
                    entity_id,
                    json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
                ),
            )
            self._conn.commit()

    # ---------- 案件 ----------
    def create_case(self, case_id, title, retention_until=None, actor="system"):
        ts = now_iso()
        self.execute(
            "INSERT INTO cases(case_id,title,status,retention_until,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?)",
            (case_id, title, "收集中", retention_until, ts, ts),
        )
        self.audit(actor, "case.create", "case", case_id, {"title": title})
        return self.get_case(case_id)

    def get_case(self, case_id):
        return self.query_one("SELECT * FROM cases WHERE case_id=?", (case_id,))

    def list_cases(self):
        return self.query("SELECT * FROM cases ORDER BY created_at")

    def update_case_status(self, case_id, status, actor="system", detail=None):
        self.execute(
            "UPDATE cases SET status=?, updated_at=? WHERE case_id=?",
            (status, now_iso(), case_id),
        )
        self.audit(actor, "case.status", "case", case_id, {"status": status, **(detail or {})})

    def touch_case(self, case_id, actor="system"):
        self.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (now_iso(), case_id))

    # ---------- 账号与改名 ----------
    def upsert_account_name(self, account_id, platform, nickname, valid_from, actor="system"):
        """记录账号名。与当前名不同则关闭旧名时段、追加新名（改名可审计）。"""
        with self._lock:
            account = self.query_one(
                "SELECT * FROM accounts WHERE account_id=?", (account_id,)
            )
            if account is None:
                self._conn.execute(
                    "INSERT INTO accounts(account_id,platform,nickname,updated_at) VALUES(?,?,?,?)",
                    (account_id, platform, nickname, now_iso()),
                )
                self._conn.execute(
                    "INSERT INTO account_names(account_id,nickname,valid_from) VALUES(?,?,?)",
                    (account_id, nickname, valid_from),
                )
                self._conn.commit()
                self.audit(actor, "account.seen", "account", account_id, {"nickname": nickname})
                return
            if account["nickname"] != nickname:
                self._conn.execute(
                    "UPDATE account_names SET valid_to=? WHERE account_id=? AND valid_to IS NULL",
                    (valid_from, account_id),
                )
                self._conn.execute(
                    "INSERT INTO account_names(account_id,nickname,valid_from) VALUES(?,?,?)",
                    (account_id, nickname, valid_from),
                )
                self._conn.execute(
                    "UPDATE accounts SET nickname=?, updated_at=? WHERE account_id=?",
                    (nickname, now_iso(), account_id),
                )
                self._conn.commit()
                self.audit(
                    actor,
                    "account.rename",
                    "account",
                    account_id,
                    {"from": account["nickname"], "to": nickname},
                )

    def name_history(self, account_id):
        return self.query(
            "SELECT nickname,valid_from,valid_to FROM account_names"
            " WHERE account_id=? ORDER BY valid_from",
            (account_id,),
        )

    # ---------- 事件接入（带去重） ----------
    def ingest_event(self, event, case_id=None, actor="ingest"):
        """写入一条检测事件。同一 (source_system, source_ref) 重复上报只保留一次。

        返回 (row_dict, created: bool, already_linked_to_case: bool)。
        """
        import hashlib

        canonical = json.dumps(event, ensure_ascii=False, sort_keys=True)
        dedup_hash = hashlib.sha256(canonical.encode()).hexdigest()
        event_id = event.get("event_id") or new_id("evt")
        with self._lock:
            existing = self.query_one(
                "SELECT event_id FROM events WHERE source_system=? AND source_ref=?",
                (event["source_system"], event["source_ref"]),
            )
            if existing is not None:
                linked = self.query_one(
                    "SELECT 1 FROM case_events WHERE case_id=? AND event_id=?",
                    (case_id, existing["event_id"]),
                ) if case_id else None
                self.audit(
                    actor,
                    "event.dedup",
                    "event",
                    existing["event_id"],
                    {"source_system": event["source_system"], "source_ref": event["source_ref"]},
                )
                return self.get_event(existing["event_id"]), False, linked is not None

            self._conn.execute(
                "INSERT INTO events(event_id,case_id,source_system,source_ref,event_type,"
                "account_id,occurred_at,ingested_at,payload,dedup_hash)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    case_id,
                    event["source_system"],
                    event["source_ref"],
                    event["event_type"],
                    event.get("account_id"),
                    event["occurred_at"],
                    now_iso(),
                    json.dumps(event.get("payload", {}), ensure_ascii=False),
                    dedup_hash,
                ),
            )
            if case_id:
                self._conn.execute(
                    "INSERT INTO case_events(case_id,event_id,linked_at) VALUES(?,?,?)",
                    (case_id, event_id, now_iso()),
                )
            self._conn.commit()
        self.audit(
            actor,
            "event.ingest",
            "event",
            event_id,
            {
                "source_system": event["source_system"],
                "source_ref": event["source_ref"],
                "event_type": event["event_type"],
                "case_id": case_id,
            },
        )
        return self.get_event(event_id), True, False

    def link_event_to_case(self, case_id, event_id, actor="system"):
        """把已接入的线索挂到另一案件：跨案件共享，不复制事件。"""
        with self._lock:
            exists = self.query_one(
                "SELECT 1 FROM case_events WHERE case_id=? AND event_id=?",
                (case_id, event_id),
            )
            if exists:
                return False
            self._conn.execute(
                "INSERT INTO case_events(case_id,event_id,linked_at) VALUES(?,?,?)",
                (case_id, event_id, now_iso()),
            )
            self._conn.commit()
        self.audit(
            actor, "case.link_event", "case", case_id, {"event_id": event_id}
        )
        return True

    def get_event(self, event_id):
        return self.query_one("SELECT * FROM events WHERE event_id=?", (event_id,))

    def events_for_case(self, case_id):
        return self.query(
            "SELECT e.* FROM events e JOIN case_events ce ON ce.event_id=e.event_id"
            " WHERE ce.case_id=? ORDER BY e.occurred_at",
            (case_id,),
        )

    def cases_for_event(self, event_id):
        return self.query(
            "SELECT c.* FROM cases c JOIN case_events ce ON ce.case_id=c.case_id"
            " WHERE ce.event_id=?",
            (event_id,),
        )

    # ---------- 分析快照 ----------
    def save_analysis(self, case_id, rule_version, params, score, decision, result):
        analysis_id = new_id("anl")
        self.execute(
            "INSERT INTO analyses(analysis_id,case_id,rule_version,params_json,score,"
            "decision,result_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                analysis_id,
                case_id,
                rule_version,
                json.dumps(params, ensure_ascii=False, sort_keys=True),
                score,
                decision,
                json.dumps(result, ensure_ascii=False),
                now_iso(),
            ),
        )
        return analysis_id

    def get_analysis(self, analysis_id):
        return self.query_one("SELECT * FROM analyses WHERE analysis_id=?", (analysis_id,))

    def latest_analysis(self, case_id):
        return self.query_one(
            "SELECT * FROM analyses WHERE case_id=? ORDER BY created_at DESC LIMIT 1",
            (case_id,),
        )

    # ---------- 关联建议 ----------
    def create_link(self, case_id, analysis_id, account_id, kind, score,
                    rule_version, evidence, actor="engine"):
        link_id = new_id("lnk")
        self.execute(
            "INSERT INTO links(link_id,case_id,analysis_id,account_id,kind,score,"
            "rule_version,status,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                link_id, case_id, analysis_id, account_id, kind, score,
                rule_version, "suggested",
                json.dumps(evidence, ensure_ascii=False), now_iso(),
            ),
        )
        self.audit(actor, "link.suggest", "link", link_id,
                   {"account_id": account_id, "score": score, "rule_version": rule_version})
        return link_id

    def get_link(self, link_id):
        return self.query_one("SELECT * FROM links WHERE link_id=?", (link_id,))

    def links_for_case(self, case_id):
        return self.query("SELECT * FROM links WHERE case_id=? ORDER BY score DESC", (case_id,))

    def set_link_status(self, link_id, status, actor, detail=None):
        self.execute("UPDATE links SET status=? WHERE link_id=?", (status, link_id))
        self.audit(actor, f"link.{status}", "link", link_id, detail or {})

    # ---------- 双人确认 / 冻结 / 申诉 / 移送 ----------
    def add_confirmation(self, link_id, case_id, reviewer):
        with self._lock:
            exists = self.query_one(
                "SELECT 1 FROM confirmations WHERE link_id=? AND reviewer=?",
                (link_id, reviewer),
            )
            if exists:
                return [
                    r["reviewer"]
                    for r in self._conn.execute(
                        "SELECT reviewer FROM confirmations WHERE link_id=? ORDER BY confirmed_at",
                        (link_id,),
                    )
                ]
            self._conn.execute(
                "INSERT INTO confirmations(link_id,case_id,reviewer,confirmed_at)"
                " VALUES(?,?,?,?)",
                (link_id, case_id, reviewer, now_iso()),
            )
            self._conn.commit()
        self.audit(reviewer, "link.confirm", "link", link_id, {"reviewer": reviewer})
        return [
            r["reviewer"]
            for r in self._conn.execute(
                "SELECT reviewer FROM confirmations WHERE link_id=? ORDER BY confirmed_at",
                (link_id,),
            )
        ]

    def confirmations(self, link_id):
        return self.query(
            "SELECT * FROM confirmations WHERE link_id=? ORDER BY confirmed_at", (link_id,)
        )

    def freeze_evidence(self, case_id, link_id, snapshot, actor):
        freeze_id = new_id("frz")
        self.execute(
            "INSERT INTO frozen_evidence(freeze_id,case_id,link_id,snapshot_json,"
            "frozen_by,frozen_at) VALUES(?,?,?,?,?,?)",
            (
                freeze_id, case_id, link_id,
                json.dumps(snapshot, ensure_ascii=False), actor, now_iso(),
            ),
        )
        self.audit(actor, "evidence.freeze", "freeze", freeze_id,
                   {"case_id": case_id, "link_id": link_id})
        return freeze_id

    def get_freeze(self, freeze_id):
        return self.query_one("SELECT * FROM frozen_evidence WHERE freeze_id=?", (freeze_id,))

    def freezes_for_case(self, case_id):
        return self.query("SELECT * FROM frozen_evidence WHERE case_id=?", (case_id,))

    def create_appeal(self, case_id, link_id, reason, actor):
        appeal_id = new_id("apl")
        self.execute(
            "INSERT INTO appeals(appeal_id,case_id,link_id,reason,status,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (appeal_id, case_id, link_id, reason, "open", now_iso()),
        )
        self.audit(actor, "appeal.create", "appeal", appeal_id,
                   {"case_id": case_id, "link_id": link_id, "reason": reason})
        return appeal_id

    def resolve_appeal(self, appeal_id, status, actor):
        self.execute(
            "UPDATE appeals SET status=?,resolved_at=?,resolved_by=? WHERE appeal_id=?",
            (status, now_iso(), actor, appeal_id),
        )
        self.audit(actor, f"appeal.{status}", "appeal", appeal_id, {})

    def get_appeal(self, appeal_id):
        return self.query_one("SELECT * FROM appeals WHERE appeal_id=?", (appeal_id,))

    def create_transfer(self, case_id, freeze_id, recipient, manifest, actor):
        package_id = new_id("pkg")
        self.execute(
            "INSERT INTO transfer_packages(package_id,case_id,freeze_id,recipient,"
            "manifest_json,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                package_id, case_id, freeze_id, recipient,
                json.dumps(manifest, ensure_ascii=False), actor, now_iso(),
            ),
        )
        self.audit(actor, "transfer.create", "package", package_id,
                   {"case_id": case_id, "recipient": recipient, "freeze_id": freeze_id})
        return package_id

    def get_transfer(self, package_id):
        return self.query_one(
            "SELECT * FROM transfer_packages WHERE package_id=?", (package_id,)
        )

    def transfers_for_case(self, case_id):
        return self.query("SELECT * FROM transfer_packages WHERE case_id=?", (case_id,))

    def audit_log(self, limit=200, entity_id=None):
        if entity_id:
            return self.query(
                "SELECT * FROM audit_log WHERE entity_id=? ORDER BY audit_id DESC LIMIT ?",
                (entity_id, limit),
            )
        return self.query("SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT ?", (limit,))

    def close(self):
        self._conn.close()
