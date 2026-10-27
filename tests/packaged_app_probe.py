"""Exercise the real App supervisor with disposable data and a synthetic HA API.

Run as root with --network none --add-host supervisor:127.0.0.1. Also run
under the unchanged AppArmor profile on a capable host. This is not HAOS or
live LayerV acceptance: no external account, enrollment or action is used.
"""

import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


DATA = Path("/data")
assert not (DATA / "app-config.json").exists(), "Requires disposable App data"
assert not list((DATA / "pages").glob("*.json")), "Requires disposable App data"
assert DATA.joinpath("options.json").is_file(), "Mount disposable options read-only"
calls = []
state = {"entity_id": "switch.probe", "state": "off", "attributes": {"friendly_name": "Probe"}}


class SyntheticHA(BaseHTTPRequestHandler):
    def respond(self, payload):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer synthetic-supervisor-token":
            self.send_error(401)
        elif self.path == "/core/api/states":
            self.respond([state])
        elif self.path == "/core/api/services":
            self.respond([{"domain": "switch", "services": {
                "turn_on": {"target": {}, "fields": {}},
                "turn_off": {"target": {}, "fields": {}},
            }}])
        elif self.path == "/core/api/config":
            self.respond({"latitude": 33, "longitude": -111})
        else:
            self.send_error(404)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer synthetic-supervisor-token":
            self.send_error(401)
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if self.path != "/core/api/services/switch/turn_on" or body != {"entity_id": "switch.probe"}:
            self.send_error(400)
            return
        calls.append(body)
        state["state"] = "on"
        self.respond([])

    def log_message(self, *_args):
        pass


def request(method, path, payload=None, token="", port=8081, extra=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = dict(extra or {})
    if token:
        headers["X-Admin-Token"] = token
    if payload is not None:
        headers["Content-Type"] = "application/json"
        payload = json.dumps(payload)
    try:
        connection.request(method, path, payload, headers)
        response = connection.getresponse()
        body = response.read()
        if response.getheader("Content-Type", "").startswith("application/json"):
            body = json.loads(body)
        return response.status, body
    finally:
        connection.close()


def ready(process, expected):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        assert process.poll() is None, "App supervisor exited before readiness"
        try:
            status, body = request("GET", "/health")
            if status == 200 and body.get("status") == expected:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise AssertionError(f"App did not reach {expected}")


def start():
    return subprocess.Popen(
        [sys.executable, "/usr/local/bin/app_runner.py"],
        env={**os.environ, "SUPERVISOR_TOKEN": "synthetic-supervisor-token",
             "LAYERV_API_BASE_URL": "http://127.0.0.1:18099"},
    )


def stop(process):
    process.terminate()
    try:
        assert process.wait(timeout=15) == 0, "App did not shut down cleanly"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


ha = ThreadingHTTPServer(("127.0.0.1", 80), SyntheticHA)
threading.Thread(target=ha.serve_forever, daemon=True).start()
process = start()
try:
    ready(process, "setup_required")
    assert b"Connect to LayerV" in request("GET", "/admin")[1]
    # Loopback plus a forged ingress header must not impersonate Supervisor.
    assert request("GET", "/", port=8099,
                   extra={"X-Ingress-Path": "/api/hassio_ingress/synthetic/"})[0] == 403
    assert request("POST", "/api/onboarding/key", {"api_key": "synthetic-layerv-api-key"})[0] == 201
    ready(process, "ok")
    config = json.loads(DATA.joinpath("app-config.json").read_text())
    token = config["admin_token"]
    assert request("GET", "/api/admin/pages")[0] == 401
    assert request("GET", "/api/admin/discovery", token=token)[0] == 200
    page = {"id": "confined-probe", "title": "Confined probe", "resources": [
        {"id": "probe", "name": "Probe", "entity_id": "switch.probe", "domain": "switch",
         "actions": [{"id": "turn_on", "name": "Turn on", "service": "turn_on"}]}]}
    status, body = request("POST", "/api/admin/pages", page, token)
    assert status == 201, (status, body)
    status, body = request("POST", "/api/admin/pages/confined-probe/preview", {}, token)
    assert status == 200, (status, body)
    query = "?" + urlsplit(body["preview_url"]).query
    preview = "/api/admin/preview/confined-probe"
    assert request("GET", preview)[0] == 401
    assert request("GET", preview + query)[0] == 200
    status, body = request("POST", preview + "/probe/turn_on" + query, {})
    assert status == 200, (status, body)
    assert calls == [{"entity_id": "switch.probe"}]
    assert request("POST", preview + "/probe/unapproved" + query, {})[0] in (400, 404)
    assert len(calls) == 1, "Unapproved action reached HA"
    for path in ("guest/http.sock", "ha-guest/http.sock"):
        assert Path("/run/access-pages", path).is_socket()
    assert DATA.joinpath("policy-pages/confined-probe.json").is_file()
    stop(process)
    process = start()
    ready(process, "ok")
    restarted = json.loads(DATA.joinpath("app-config.json").read_text())
    assert restarted == config, "Restart changed retained identity or internal credentials"
    status, body = request("GET", "/api/admin/pages", token=token)
    assert status == 200 and [page["id"] for page in body["pages"]] == ["confined-probe"]
    print("Real App supervisor: onboarding, auth, discovery, policy, preview/action denial, restart and persistence: PASS")
finally:
    if process.poll() is None:
        stop(process)
    ha.shutdown()
    ha.server_close()
