#!/usr/bin/env python3
"""SSO2OAUTH daemon — curl_cffi powered local HTTP service.

Started by the Go supervisor (internal/infra/sso2oauth/supervisor.go).
Lifecycle:
  1. Go supervisor spawns this script with --port 0 (OS picks a free port).
  2. This script binds 127.0.0.1:port and prints "READY port=NNNNN" to stdout.
  3. Go supervisor reads the READY line, builds a Client at that URL.
  4. Go sends POST /convert with the SSO2OAUTH request (see 修改计划.md §16.4).
  5. This daemon runs the 9-phase flow via sso2oauth_flow.convert() and
     returns the JSON response.
  6. Go sends GET /shutdown to request graceful exit; the daemon exits
     within 1 second.

Endpoints:
  POST /convert  — run SSO→OAuth conversion (body: ConvertRequest JSON)
  GET  /health   — liveness probe (returns curl_cffi version)
  GET  /shutdown — request graceful shutdown
"""
import json
import sys
import os
import signal
import threading
import argparse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

try:
    import curl_cffi
    CFFI_VERSION = getattr(curl_cffi, "__version__", "unknown")
except ImportError:
    CFFI_VERSION = "not-installed"


class DaemonHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/convert":
            self._handle_convert()
        else:
            self._json_response(404, {"ok": False, "error_phase": "not_found", "error_message": "not found"})

    def do_GET(self):
        if self.path == "/health":
            self._json_response(200, {"status": "ok", "curl_cffi_version": CFFI_VERSION})
        elif self.path == "/shutdown":
            self._json_response(200, {"status": "shutting_down"})
            threading.Timer(1.0, lambda: os._exit(0)).start()
        else:
            self._json_response(404, {"ok": False, "error_phase": "not_found", "error_message": "not found"})

    def _handle_convert(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(body)
        except json.JSONDecodeError as e:
            self._json_response(400, {"ok": False, "error_phase": "invalid_request", "error_message": str(e)})
            return
        try:
            from sso2oauth_flow import convert
            result = convert(req)
        except ImportError as e:
            self._json_response(500, {"ok": False, "error_phase": "daemon_setup",
                                      "error_message": f"sso2oauth_flow not available: {e}"})
            return
        except Exception as e:
            self._json_response(500, {"ok": False, "error_phase": "exception", "error_message": str(e)})
            return
        self._json_response(200, result)

    def _json_response(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # 静默 — Go supervisor 管日志


def main():
    parser = argparse.ArgumentParser(description="SSO2OAUTH daemon")
    parser.add_argument("--port", type=int, default=0, help="port to listen on (0 = OS picks)")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DaemonHandler)
    actual_port = server.server_address[1]
    print(f"READY port={actual_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
