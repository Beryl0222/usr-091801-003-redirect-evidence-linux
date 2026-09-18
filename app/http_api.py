"""HTTP 路由层：先匹配路由（未知路径一律 404），再校验身份，最后执行。"""

import threading

from . import models as m


class Api:
    def __init__(self, core):
        self.core = core
        self._lock = threading.Lock()

    def handle(self, method, path, actor, payload):
        with self._lock:
            route = self._match(method, path)
            if route is None:
                raise m.not_found("ROUTE_NOT_FOUND", f"路由不存在: {method} {path}")
            self._check_actor(actor)
            return route(actor, payload or {})

    @staticmethod
    def _check_actor(actor):
        if not actor.get("id") or actor.get("role") not in m.ROLES:
            raise m.forbidden("UNAUTHENTICATED", "缺少有效的 X-Actor-Id / X-Actor-Role 头")

    def _match(self, method, path):
        seg = [s for s in path.split("/") if s]
        core = self.core

        if seg == ["cases"] and method == "POST":
            return lambda a, p: (201, core.create_case(a, p))
        if seg == ["cases"] and method == "GET":
            return lambda a, p: (200, core.list_cases(a))
        if len(seg) == 2 and seg[0] == "cases" and method == "GET":
            return lambda a, p: (200, core.get_case(a, seg[1]))
        if len(seg) == 3 and seg[0] == "cases" and method == "POST":
            case_id, action = seg[1], seg[2]
            if action == "analyze":
                return lambda a, p: (200, core.analyze_case(a, case_id))
            if action == "freeze":
                return lambda a, p: (200, core.freeze_case(a, case_id))
            if action == "transfer-packages":
                return lambda a, p: (201, core.create_transfer_package(a, case_id))
            if action == "shared-clues":
                return lambda a, p: (201, core.link_shared_clue(a, case_id, p))
            return None
        if len(seg) == 3 and seg[0] == "cases" and method == "GET":
            case_id, action = seg[1], seg[2]
            if action == "audit":
                return lambda a, p: (200, core.get_case_audit(a, case_id))
            if action == "retention":
                return lambda a, p: (200, core.retention_report(a, case_id))
            return None
        if seg == ["events"] and method == "POST":
            return lambda a, p: (201, core.ingest_event(a, p))
        if len(seg) == 3 and seg[0] == "analyses" and seg[2] == "reproduce" and method == "POST":
            return lambda a, p: (200, core.reproduce_analysis(a, seg[1]))
        if len(seg) == 2 and seg[0] == "suggestions" and method == "GET":
            return lambda a, p: (200, core.get_suggestion(a, seg[1]))
        if len(seg) == 3 and seg[0] == "suggestions" and method == "POST":
            suggestion_id, action = seg[1], seg[2]
            if action == "confirm":
                return lambda a, p: (200, core.confirm_suggestion(a, suggestion_id))
            if action == "appeals":
                return lambda a, p: (201, core.file_appeal(a, suggestion_id, p))
            return None
        if len(seg) == 3 and seg[0] == "appeals" and seg[2] == "resolve" and method == "POST":
            return lambda a, p: (200, core.resolve_appeal(a, seg[1], p))
        if len(seg) == 2 and seg[0] == "transfer-packages" and method == "GET":
            return lambda a, p: (200, core.get_package(a, seg[1]))
        if len(seg) == 3 and seg[0] == "transfer-packages" and seg[2] == "dispatch" and method == "POST":
            return lambda a, p: (200, core.dispatch_package(a, seg[1], p))
        if seg == ["audit", "verify"] and method == "GET":
            return lambda a, p: (200, core.verify_audit(a))
        if seg == ["rules"] and method == "GET":
            return lambda a, p: (200, core.list_rules(a))
        if seg == ["rules"] and method == "POST":
            return lambda a, p: (201, core.create_rules(a, p))
        if seg == ["maintenance", "purge"] and method == "POST":
            return lambda a, p: (200, core.purge_expired(a))
        return None
