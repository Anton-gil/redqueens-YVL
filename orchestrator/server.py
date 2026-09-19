"""Tiny backend so the frontend can DRIVE the demo (a START ATTACK button + target dropdown),
instead of being a passive dashboard that only polls a file.

Serves the repo statically (so /frontend/index.html and /orchestrator/state/state.json resolve) and
adds two endpoints:
  POST /api/start   body {"target": "all" | "adapter_donation" | "stale_price_multicall"}
                    -> launches the paced loop for that target (writes state.json the page polls)
  GET  /api/status  -> {"running": bool}

Run:  python3 -m orchestrator.server            # http://127.0.0.1:8799/frontend/index.html
"""

import json
import subprocess
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from agent import config

PROJECT_ROOT = str(config.PROJECT_ROOT)
PATTERNS = {"adapter_donation", "stale_price_multicall"}
_lock = threading.Lock()
_state = {"proc": None}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=PROJECT_ROOT, **k)

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        route = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        try:
            data = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except json.JSONDecodeError:
            data = {}

        if route == "/api/start":
            target = data.get("target", "all")
            with _lock:
                p = _state["proc"]
                if p and p.poll() is None:
                    return self._json(200, {"busy": True})
                cmd = [sys.executable, "-m", "orchestrator.loop", "--no-refresh", "--pace", "1.6"]
                if target in PATTERNS:
                    cmd += ["--only", target]
                _state["proc"] = subprocess.Popen(cmd, cwd=PROJECT_ROOT)
            return self._json(200, {"started": True, "target": target})

        if route == "/api/upload_attack":
            source = data.get("source", "")
            name = (data.get("name") or "").strip()
            if not source.strip() or "contract" not in source:
                return self._json(400, {"error": "provide Solidity source with a contract"})
            with _lock:
                p = _state["proc"]
                if p and p.poll() is None:
                    return self._json(200, {"busy": True})
                import tempfile
                tf = tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False, dir="/tmp")
                tf.write(source)
                tf.close()
                cmd = [sys.executable, "-m", "agent.custom_attack", tf.name]
                if name:
                    cmd.append(name)
                _state["proc"] = subprocess.Popen(cmd, cwd=PROJECT_ROOT)
            return self._json(200, {"started": True, "mode": "custom"})

        return self._json(404, {"error": "not found"})

    def do_GET(self):
        if self.path.split("?")[0] == "/api/status":
            p = _state["proc"]
            return self._json(200, {"running": bool(p and p.poll() is None)})
        return super().do_GET()

    def log_message(self, *a):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("Red Queen server -> http://127.0.0.1:%d/frontend/index.html" % port)
    print("(click START ATTACK in the page; Ctrl+C here to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
