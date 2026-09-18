"""HTTP 接口冒烟测试：鉴权、路由、错误映射与角色脱敏。"""

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from app.core import CoreService
from app.http_api import Api
from app.store import Store
from service import Handler


def request(method, url, actor=None, role=None, payload=None):
    headers = {"Content-Type": "application/json"}
    if actor:
        headers["X-Actor-Id"] = actor
    if role:
        headers["X-Actor-Role"] = role
    data = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=2) as resp:
            return resp.status, json.load(resp)
    except HTTPError as err:
        body = json.loads(err.read().decode())
        err.close()
        return err.code, body


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Handler.api = Api(CoreService(Store()))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        Handler.api = None

    def test_unknown_route_404_without_auth(self):
        status, body = request("GET", f"{self.base}/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "ROUTE_NOT_FOUND")

    def test_known_route_requires_actor_headers(self):
        status, body = request("GET", f"{self.base}/cases")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "UNAUTHENTICATED")

    def test_bad_json_400(self):
        req = Request(f"{self.base}/cases", data=b"{bad", method="POST",
                      headers={"Content-Type": "application/json",
                               "X-Actor-Id": "r1", "X-Actor-Role": "reviewer"})
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=2)
        self.assertEqual(ctx.exception.code, 400)
        ctx.exception.close()

    def test_full_flow_over_http(self):
        _, case = request("POST", f"{self.base}/cases", "sys", "system",
                          {"title": "HTTP 流程案"})
        case_id = case["case_id"]
        for i, (channel, etype) in enumerate(
            [("昵称", "text"), ("评论", "text"), ("音频", "audio_transcript")], start=1
        ):
            status, _ = request("POST", f"{self.base}/events", "sys", "system", {
                "source_system": "live-detect", "source_event_id": f"http-{i}",
                "event_type": etype, "channel": channel,
                "occurred_at": f"2026-09-10T20:0{i}:00+00:00",
                "digest": "摘要", "content_hash": f"hh-{i}",
                "locator": f"live://x/{i}", "account_id": "acc-H-1", "case_id": case_id,
            })
            self.assertEqual(status, 201)
        _, analyzed = request("POST", f"{self.base}/cases/{case_id}/analyze", "r1", "reviewer")
        self.assertEqual(len(analyzed["suggestions"]), 1)
        sug_id = analyzed["suggestions"][0]["suggestion_id"]
        request("POST", f"{self.base}/suggestions/{sug_id}/confirm", "r1", "reviewer")
        status, _ = request("POST", f"{self.base}/suggestions/{sug_id}/confirm", "r1", "reviewer")
        self.assertEqual(status, 409)
        _, sug = request("POST", f"{self.base}/suggestions/{sug_id}/confirm", "s1", "supervisor")
        self.assertEqual(sug["status"], "已确认")
        _, freeze = request("POST", f"{self.base}/cases/{case_id}/freeze", "s1", "supervisor")
        self.assertTrue(freeze["retention_until"])
        # 审计员视图：摘要被遮蔽，哈希保留
        _, auditor_view = request("GET", f"{self.base}/cases/{case_id}", "a1", "auditor")
        self.assertIsNone(auditor_view["fragments"][0]["digest"])
        self.assertTrue(auditor_view["fragments"][0]["content_hash"])
        # 复核员视图：摘要可见，账号脱敏
        _, reviewer_view = request("GET", f"{self.base}/cases/{case_id}", "r1", "reviewer")
        self.assertTrue(reviewer_view["fragments"][0]["digest"])
        self.assertIn("***", reviewer_view["fragments"][0]["account_id"])
        # 审计链可校验
        _, verify = request("GET", f"{self.base}/audit/verify", "a1", "auditor")
        self.assertTrue(verify["valid"])


if __name__ == "__main__":
    unittest.main()
