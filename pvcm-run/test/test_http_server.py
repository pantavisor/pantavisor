#!/usr/bin/env python3
"""
Simple HTTP test server for PVCM HTTP bridge testing.
Serves on port 18080, handles GET/POST/PUT/DELETE.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class TestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[test-server] {format % args}")

    def _send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length)
        return b""

    def do_GET(self):
        if self.path == "/api/status":
            self._send_json(200, {"status": "ok", "uptime": 42})
        elif self.path == "/api/config":
            self._send_json(200, {"interval": 5, "mode": "auto"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        body = self._read_body()
        try:
            data = json.loads(body)
        except Exception:
            data = body.decode(errors="replace")
        self._send_json(201, {"received": data, "id": 1})

    def do_PUT(self):
        import time
        body = self._read_body()

        # /api/upload: accept large binary, simulate slow processing
        if self.path.startswith("/api/upload"):
            print(f"[test-server] upload: {len(body)} bytes, processing 3s...")
            time.sleep(3)
            self._send_json(200, {"uploaded": len(body), "path": self.path})
            return

        try:
            data = json.loads(body)
        except Exception:
            data = body.decode(errors="replace")
        self._send_json(200, {"updated": data})

    def do_DELETE(self):
        self._send_json(200, {"deleted": self.path})

if __name__ == "__main__":
    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("127.0.0.1", 18080), TestHandler)
    print("[test-server] listening on http://127.0.0.1:18080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
