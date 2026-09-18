"""隐蔽导流证据协查服务入口。"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.core import CoreService
from app.http_api import Api
from app.models import DomainError
from app.store import Store

SERVICE_ID = "redirect-evidence"
SERVICE_NAME = "隐蔽导流证据协查"

_default_api = None


def health_payload():
    """返回基础运行状态。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def default_api():
    global _default_api
    if _default_api is None:
        _default_api = Api(CoreService(Store()))
    return _default_api


class Handler(BaseHTTPRequestHandler):
    """健康检查 + 案件协查 API。"""

    api = None

    def _api(self):
        return type(self).api or default_api()

    def _send_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method):
        path = self.path.split("?", 1)[0]
        if method == "GET" and path == "/health":
            self._send_json(200, health_payload())
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": {"code": "BAD_JSON", "message": "请求体不是合法 JSON"}})
            return
        actor = {
            "id": self.headers.get("X-Actor-Id", ""),
            "role": self.headers.get("X-Actor-Role", ""),
        }
        try:
            status, obj = self._api().handle(method, path, actor, payload)
        except DomainError as error:
            status = error.http_status
            obj = {"error": {"code": error.code, "message": error.message}}
        self._send_json(status, obj)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        assert SERVICE_ID in json.dumps(health_payload())
        print("基础检查通过")
        return
    Handler.api = default_api()
    print(f"{SERVICE_NAME} 监听 0.0.0.0:{args.port}")
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
