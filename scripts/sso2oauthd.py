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

Logging: writes structured JSON lines to the file specified by
SSO2OAUTH_LOG_FILE env (or --log-file arg). Default: ./data/sso2oauthd.log.
"""
import json
import sys
import os
import signal
import threading
import argparse
import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

try:
    import curl_cffi
    CFFI_VERSION = getattr(curl_cffi, "__version__", "unknown")
except ImportError:
    CFFI_VERSION = "not-installed"

# ── Simple file logger ──────────────────────────────────────────────
_log_file = None
_log_lock = threading.Lock()

def _log_init(filepath):
    global _log_file
    try:
        _log_file = open(filepath, "a", buffering=1)
    except Exception as e:
        _log_file = None
        print(f"[sso2oauthd] cannot open log file {filepath}: {e}", file=sys.stderr, flush=True)

def _log(level, msg, **extra):
    if _log_file is None:
        return
    entry = {"time": datetime.datetime.utcnow().isoformat() + "Z", "level": level, "msg": msg}
    entry.update(extra)
    with _log_lock:
        try:
            _log_file.write(json.dumps(entry, default=str) + "\n")
        except Exception:
            pass


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
            _log("WARN", "convert_invalid_json", error=str(e))
            self._json_response(400, {"ok": False, "error_phase": "invalid_request", "error_message": str(e)})
            return
        sso_hash = req.get("sso_token", "")[:12] + "..."
        proxy_count = len(req.get("proxy_pool") or [])
        _log("INFO", "convert_start", sso_hash=sso_hash, proxy_count=proxy_count, timeout_seconds=req.get("timeout_seconds"))
        try:
            from sso2oauth_flow import convert
            result = convert(req)
        except ImportError as e:
            _log("ERROR", "convert_daemon_setup_failed", error=str(e))
            self._json_response(500, {"ok": False, "error_phase": "daemon_setup",
                                      "error_message": f"sso2oauth_flow not available: {e}"})
            return
        except Exception as e:
            _log("ERROR", "convert_exception", error=str(e))
            self._json_response(500, {"ok": False, "error_phase": "exception", "error_message": str(e)})
            return
        ok = result.get("ok", False)
        error_phase = result.get("error_phase", "")
        _log("INFO" if ok else "WARN", "convert_done",
             sso_hash=sso_hash, ok=ok, error_phase=error_phase, phase_count=len(result.get("phases", [])))
        self._json_response(200, result)

    def _json_response(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # silence BaseHTTPRequestHandler's default stderr logging


def main():
    parser = argparse.ArgumentParser(description="SSO2OAUTH daemon")
    parser.add_argument("--port", type=int, default=0, help="port to listen on (0 = OS picks)")
    parser.add_argument("--log-file", default="", help="path to log file (or SSO2OAUTH_LOG_FILE env)")
    args = parser.parse_args()

    log_path = args.log_file or os.environ.get("SSO2OAUTH_LOG_FILE", "") or "./data/sso2oauthd.log"
    _log_init(log_path)
    _log("INFO", "daemon_starting", port=args.port, log_file=log_path)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DaemonHandler)
    actual_port = server.server_address[1]
    print(f"READY port={actual_port}", flush=True)
    _log("INFO", "daemon_ready", port=actual_port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _log("INFO", "daemon_stopped")


if __name__ == "__main__":
    main()
