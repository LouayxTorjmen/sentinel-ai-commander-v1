#!/usr/bin/env python3
"""
Thin HTTP wrapper around fastmcp-threatintel CLI.
Exposes POST /analyze for use by sentinel-ai-agents container.
"""
import json
import subprocess
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT    = int(os.getenv("THREATINTEL_WRAPPER_PORT", "8080"))
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "25"))

def extract_json(text: str) -> dict | None:
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except Exception:
            pass
    return None

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/analyze":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = json.loads(self.rfile.read(length) or b"{}")
        ioc    = body.get("ioc", "").strip()

        if not ioc:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"ioc required"}')
            return

        # Use system timeout to hard-kill if any single API hangs
        proc = subprocess.Popen(
            ["timeout", str(TIMEOUT), "threatintel", "analyze", ioc, "--output-format", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, _ = proc.communicate(timeout=TIMEOUT + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()

        parsed = extract_json(stdout)
        if parsed:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(parsed).encode())
        else:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(json.dumps({
                "error":   "timeout or no JSON in output",
                "raw":     stdout[:200] if stdout else "empty",
                "timeout": TIMEOUT,
            }).encode())

if __name__ == "__main__":
    print(f"ThreatIntel HTTP wrapper listening on :{PORT} (timeout={TIMEOUT}s)", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
