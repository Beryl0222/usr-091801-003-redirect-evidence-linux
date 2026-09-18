"""HTTP API 路由：JSON over stdlib http.server。

路由方法返回 (status, dict)，由 service.Handler 负责序列化与鉴权头解析。
"""

import json
import re
from urllib.parse import urlparse

import security
from workflow import Workflow, WorkflowError

_CASE_PATH = re.compile(r"^/v1/cases/(?P<case>[^/]+)$")
_LINK_PATH = re.compile(
    r"^/v1/cases/(?P<case>[^/]+)/links/(?P<link>[^/]+)/(?P<action>confirm|appeal)$"
)
_ANALYZE_PATH = re.compile(r"^/v1/cases/(?P<case>[^/]+)/analyze$")
_SHARE_PATH = re.compile(r"^/v1/cases/(?P<case>[^/]+)/share$")
_TRANSFER_PATH = re.compile(r"^/v1/cases/(?P<case>[^/]+)/transfer$")
_REPLAY_PATH = re.compile(r"^/v1/analyses/(?P<analysis>[^/]+)/replay$")
_APPEAL_PATH = re.compile(r"^/v1/appeals/(?P<appeal>[^/]+)/resolve$")
_PACKAGE_PATH = re.compile(r"^/v1/packages/(?P<package>[^/]+)$")
_ACCOUNT_PATH = re.compile(r"^/v1/accounts/(?P<account>[^/]+)$")


class ApiRouter:
    def __init__(self, store):
        self.store = store
        self.wf = Workflow(store)

    def handle(self, method, path, headers, body):
        identity = security.authenticate(headers)
        if identity is None:
            return 401, {"error": "unauthorized", "message": "缺少或无效的 Bearer 令牌"}
        role, username = identity

        try:
            return self._route(method, path, body, role, username)
        except WorkflowError as exc:
            return exc.status, {"error": "workflow_error", "message": str(exc)}
        except KeyError as exc:
            return 422, {"error": "missing_field", "message": f"缺少字段: {exc.args[0]}"}

    def _route(self, method, path, body, role, username):
        parsed = urlparse(path)
        path = parsed.path
        query = dict(pair.split("=", 1) for pair in parsed.query.split("&") if "=" in pair)

        if method == "POST" and path == "/v1/events":
            self._require(role, (security.ROLE_REVIEWER,))
            event = body["event"] if "event" in body else body
            result = self.wf.ingest(event, body.get("case_id"), username)
            return 201, result

        if method == "POST" and path == "/v1/cases":
            self._require(role, (security.ROLE_REVIEWER,))
            case_id = body["case_id"]
            case = self.store.create_case(
                case_id, body["title"], body.get("retention_until"), username
            )
            return 201, dict(case)

        if method == "GET" and path == "/v1/cases":
            self._require(role, (security.ROLE_REVIEWER, security.ROLE_AUDITOR))
            return 200, {"cases": [dict(r) for r in self.store.list_cases()]}

        m = _CASE_PATH.match(path)
        if m and method == "GET":
            view = self.wf.case_view(m.group("case"))
            if role == security.ROLE_EXTERNAL:
                return 403, {"error": "forbidden", "message": "外部账号不得浏览案件视图"}
            return 200, security.redact_case_view(view, role)

        m = _ANALYZE_PATH.match(path)
        if m and method == "POST":
            self._require(role, (security.ROLE_REVIEWER,))
            version = body.get("rule_version", query.get("rule_version", "v2"))
            return 200, self.wf.run_analysis(m.group("case"), version, username)

        m = _LINK_PATH.match(path)
        if m and method == "POST" and m.group("action") == "confirm":
            self._require(role, (security.ROLE_REVIEWER,))
            return 200, self.wf.confirm(
                m.group("case"), m.group("link"), username
            )

        if m and method == "POST" and m.group("action") == "appeal":
            self._require(role, (security.ROLE_REVIEWER,))
            return 201, self.wf.appeal(
                m.group("case"), m.group("link"), body["reason"], username
            )

        m = _APPEAL_PATH.match(path)
        if m and method == "POST":
            self._require(role, (security.ROLE_REVIEWER,))
            return 200, self.wf.resolve_appeal(
                m.group("appeal"), body["outcome"], username
            )

        m = _SHARE_PATH.match(path)
        if m and method == "POST":
            self._require(role, (security.ROLE_REVIEWER,))
            return 200, self.wf.share_clue(
                m.group("case"), body["event_id"], username
            )

        m = _TRANSFER_PATH.match(path)
        if m and method == "POST":
            self._require(role, (security.ROLE_REVIEWER,))
            return 201, self.wf.transfer(
                m.group("case"), body["freeze_id"], body["recipient"], username
            )

        m = _REPLAY_PATH.match(path)
        if m and method == "GET":
            self._require(role, (security.ROLE_REVIEWER, security.ROLE_AUDITOR))
            return 200, self.wf.replay_analysis(m.group("analysis"))

        m = _PACKAGE_PATH.match(path)
        if m and method == "GET":
            row = self.store.get_transfer(m.group("package"))
            if not row:
                return 404, {"error": "not_found", "message": "移送包不存在"}
            view = security.redact_package(
                row, role,
                recipient_name=username if role == security.ROLE_EXTERNAL else None,
            )
            if view is None:
                return 403, {"error": "forbidden", "message": "无权查看该移送包"}
            return 200, view

        m = _ACCOUNT_PATH.match(path)
        if m and method == "GET":
            self._require(role, (security.ROLE_REVIEWER,))
            history = [dict(r) for r in self.store.name_history(m.group("account"))]
            if not history:
                return 404, {"error": "not_found", "message": "账号不存在"}
            return 200, {"account_id": m.group("account"), "name_history": history}

        if method == "GET" and path == "/v1/audit":
            self._require(role, (security.ROLE_AUDITOR,))
            rows = self.store.audit_log(
                limit=int(query.get("limit", 200)),
                entity_id=query.get("entity_id"),
            )
            return 200, {"audit": [dict(r) for r in rows]}

        return 404, {"error": "not_found", "message": f"无此路由: {method} {path}"}

    @staticmethod
    def _require(role, allowed):
        if not security.require(role, allowed):
            raise WorkflowError("当前角色无权执行该操作", 403)
