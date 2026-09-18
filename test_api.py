"""API 与字段脱敏测试（直接走路由，无需监听端口）。"""

import json
import unittest

from api import ApiRouter
from store import Store

ALICE = "rev-alice"
BOB = "rev-bob"
CAROL = "aud-carol"
CAO = "rev-cao"
POLICE = "ext-police"


def fox_event(eid, source, etype, ts, payload, ref=None, account="acc_fox"):
    return {
        "event_id": eid,
        "source_system": source,
        "source_ref": ref or f"{source}:{eid}",
        "event_type": etype,
        "account_id": account,
        "occurred_at": ts,
        "payload": payload,
    }


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.api = ApiRouter(self.store)
        _, case = self.post("/v1/cases", ALICE,
                            {"case_id": "C1", "title": "API 测试案"}, expect=201)
        for ev in [
            fox_event("e0", "profile_scanner", "profile_field",
                      "2026-09-10T12:00:00+00:00",
                      {"text": "www", "fragment": {"key": "k", "seq": 0, "text": "www"}}),
            fox_event("e1", "live_snapshot", "image_summary",
                      "2026-09-10T12:01:00+00:00",
                      {"text": ".dianzan88",
                       "fragment": {"key": "k", "seq": 1, "text": ".dianzan88"},
                       "qr": {"duration_seconds": 1.2}}),
            fox_event("e2", "comment_scanner", "comment",
                      "2026-09-10T12:02:00+00:00",
                      {"text": ".com/x", "fragment": {"key": "k", "seq": 2, "text": ".com/x"}}),
        ]:
            self.post("/v1/events", ALICE, {"case_id": "C1", "event": ev}, expect=201)

    def call(self, method, path, token=None, body=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.api.handle(method, path, headers, body or {})

    def post(self, path, token, body, expect=200):
        status, payload = self.call("POST", path, token, body)
        self.assertEqual(status, expect, payload)
        return status, payload

    def get(self, path, token, expect=200):
        status, payload = self.call("GET", path, token)
        self.assertEqual(status, expect, payload)
        return payload

    def test_auth_required_and_role_gates(self):
        self.assertEqual(self.call("GET", "/v1/cases")[0], 401)
        self.assertEqual(self.call("GET", "/v1/cases", "bad-token")[0], 401)
        # 审计员只读，不能建案/分析
        self.assertEqual(self.call("POST", "/v1/cases", CAROL,
                                   {"case_id": "X", "title": "y"})[0], 403)
        # 外部账号不能列案
        self.assertEqual(self.call("GET", "/v1/cases", POLICE)[0], 403)

    def test_reviewer_sees_full_evidence(self):
        self.post("/v1/cases/C1/analyze", ALICE, {"rule_version": "v2"})
        view = self.get("/v1/cases/C1", ALICE)
        fragment = view["links"][0]["evidence"]["fragments"][0]
        self.assertIn("source_ref", fragment)
        self.assertIn("excerpt", fragment)
        self.assertEqual(view["assemblies"][0]["text"], "www.dianzan88.com/x")

    def test_auditor_redaction(self):
        self.post("/v1/cases/C1/analyze", ALICE, {"rule_version": "v2"})
        view = self.get("/v1/cases/C1", CAROL)
        link = view["links"][0]
        self.assertTrue(link["account_id"].startswith("ACC-"))
        self.assertNotIn("excerpt", link["evidence"]["fragments"][0])
        self.assertNotIn("source_ref", link["evidence"]["fragments"][0])
        self.assertNotIn("text", view["assemblies"][0])
        # 审计员可查审计日志，复核员不能
        self.assertEqual(self.call("GET", "/v1/audit", ALICE)[0], 403)
        audit = self.get("/v1/audit", CAROL)
        self.assertTrue(any(r["action"] == "link.suggest" for r in audit["audit"]))

    def test_two_person_flow_and_external_package(self):
        analysis = self.post("/v1/cases/C1/analyze", ALICE, {"rule_version": "v2"})[1]
        link_id = analysis["link_ids"][0]
        self.post(f"/v1/cases/C1/links/{link_id}/confirm", ALICE, {})
        frozen = self.post(f"/v1/cases/C1/links/{link_id}/confirm", BOB, {})[1]
        pkg = self.post("/v1/cases/C1/transfer", BOB,
                        {"freeze_id": frozen["freeze_id"],
                         "recipient": "市公安局网安支队"}, expect=201)[1]
        package_id = pkg["package_id"]

        ext = self.get(f"/v1/packages/{package_id}", POLICE)
        m = ext["manifest"]
        self.assertTrue(m["subject_account"].startswith("ACC-"))
        self.assertNotIn("confirmations", m)
        self.assertTrue(m["review_summary"]["two_person_confirmed"])
        self.assertNotIn("shared_with_cases", json.dumps(m, ensure_ascii=False))
        # 外部不能看别的路由
        self.assertEqual(self.call("GET", "/v1/cases/C1", POLICE)[0], 403)
        # 复核员看内部完整包
        internal = self.get(f"/v1/packages/{package_id}", ALICE)
        self.assertIn("confirmations", internal["manifest"])

    def test_audit_log_captures_actor_identity(self):
        self.post("/v1/cases/C1/analyze", ALICE, {"rule_version": "v2"})
        audit = self.get("/v1/audit?limit=50", CAROL)["audit"]
        self.assertTrue(any(r["actor"] == "alice" for r in audit))


if __name__ == "__main__":
    unittest.main()
