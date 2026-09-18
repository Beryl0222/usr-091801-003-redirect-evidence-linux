"""隐蔽导流证据协查服务入口。

提供 /health 与 /v1/* JSON API。存储使用 SQLite（默认内存库，
--db 可指定文件）；--seed 启动时载入样例事件。
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from api import ApiRouter
from store import Store

SERVICE_ID = "redirect-evidence"
SERVICE_NAME = "隐蔽导流证据协查"


def health_payload():
    """返回基础运行状态。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def build_router(db_path=":memory:", seed_path=None):
    store = Store(db_path)
    if seed_path:
        import seed
        seed.load(store, seed_path)
    return ApiRouter(store)


class Handler(BaseHTTPRequestHandler):
    """健康检查 + JSON API。"""

    router = None

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        if method == "GET" and self.path.split("?", 1)[0] == "/health":
            self._write_json(200, health_payload())
            return
        if self.router is None:
            # 未挂载业务路由（如纯契约测试）：未知路径一律 404，不暴露内部状态
            self.send_error(404)
            return
        body = {}
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if raw:
                try:
                    body = json.loads(raw.decode())
                except json.JSONDecodeError:
                    self._write_json(400, {"error": "bad_json", "message": "请求体不是合法 JSON"})
                    return
        status, payload = self.router.handle(method, self.path, self.headers, body)
        self._write_json(status, payload)

    def _write_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default=":memory:", help="SQLite 文件路径，默认内存库")
    parser.add_argument("--seed", default=None, help="启动时载入的样例事件 JSON")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.check:
        router = build_router()
        assert router.handle("GET", "/health", {}, {})[0] == 200
        assert SERVICE_ID in json.dumps(health_payload())
        print("基础检查通过")
        return

    Handler.router = build_router(args.db, args.seed)
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
