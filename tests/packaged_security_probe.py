"""Disposable-container real-UID probe; run with no host /data mount.

    docker run --rm --user root --entrypoint python \
      -v "$PWD/tests/packaged_security_probe.py:/tmp/probe.py:ro" \
      access-pages-app:review /tmp/probe.py
"""

import hashlib
import http.client
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pages import PageStore

ROOT = Path("/run/access-pages")
DATA = Path("/data")
SOCKET = ROOT / "guest/http.sock"
BROKER = ROOT / "ha-guest/http.sock"
CAP_A = "page-capability-a-1234567890"
CAP_B = "page-capability-b-1234567890"
SECRET_A = "bootstrap-secret-a-1234567890"
SECRET_B = "bootstrap-secret-b-1234567890"
SECRET_V = "bootstrap-secret-v-1234567890"
GRANT_A = "grant_" + "a" * 16
GRANT_B = "grant_" + "b" * 16
GRANT_V = "grant_" + "v" * 16
NOW = datetime.now(timezone.utc)
events = {"emails": [], "actions": [], "admin_paths": [], "guest_events": []}
assert not list((DATA / "pages").glob("*.json")), "Probe requires disposable App data"
notices = Path("/app/third_party_licenses")
assert Path("/app/THIRD_PARTY_NOTICES.md").is_file()
assert Path("/app/LICENSE").is_file()
for license_file in (
    notices / "qurl-2.6.0-LICENSE",
    notices / "Go-1.26.6-and-1.26.8-LICENSE",
    notices / "Python-3.12.14-LICENSE",
    notices / "qurl-modules/github.com/layervai/qurl-connector@v0.14.0/LICENSE",
    notices / "qurl-modules/github.com/fatedier/yamux@v0.0.0-20250825093530-d0154be01cd6/LICENSE",
):
    assert license_file.is_file() and license_file.stat().st_size > 0, license_file
assert (notices / "Python-3.12.14-LICENSE").read_bytes() == Path(
    "/usr/local/lib/python3.12/LICENSE.txt"
).read_bytes()
assert (notices / "yamux-source/session.go").is_file()


def own(path, uid, gid, mode):
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def mkdir(path, uid, gid, mode):
    path.mkdir(parents=True, exist_ok=True)
    own(path, uid, gid, mode)


def grant(grant_id, secret, verification=False):
    return {
        "id": grant_id,
        "token_hash": hashlib.sha256(secret.encode()).hexdigest(),
        "created_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "credential_flow": "bootstrap-v1",
        "verification_required": verification,
    }


ROOT.mkdir(exist_ok=True)
own(ROOT, 0, 0, 0o755)
mkdir(ROOT / "guest", 2101, 2004, 0o2710)
mkdir(ROOT / "ha-guest", 2102, 2101, 0o2750)
mkdir(DATA / "pages", 2100, 2000, 0o2750)
mkdir(DATA / "policy-pages", 2104, 2001, 0o2750)
mkdir(DATA / "ha-broker-runtime", 0, 2102, 0o750)
mkdir(DATA / "ha-broker-runtime/guest-auth", 2102, 2102, 0o700)
mkdir(DATA / "admin-runtime", 2100, 2100, 0o700)
mkdir(DATA / "guest-runtime", 2100, 2100, 0o700)
mkdir(DATA / "secrets", 0, 2003, 0o750)
for path, owner, group, mode in (
    (DATA / "admin-runtime/smtp.json", 2100, 2100, 0o600),
    (DATA / "admin-runtime/admin-token", 2100, 2100, 0o600),
    (DATA / "secrets/layerv-api-key", 0, 2003, 0o640),
    (DATA / "page-capabilities.json", 0, 0, 0o600),
):
    path.write_text("synthetic-secret")
    own(path, owner, group, mode)

pages = PageStore(DATA / "pages", file_mode=0o640)
policy = PageStore(DATA / "policy-pages", file_mode=0o640)
resource_a = {
    "id": "garden",
    "name": "Garden light",
    "entity_id": "switch.garden",
    "domain": "switch",
    "actions": [{"id": "turn_on", "name": "On", "service": "turn_on"}],
}
resource_b = {
    "id": "porch",
    "name": "Porch light",
    "entity_id": "switch.porch",
    "domain": "switch",
    "actions": [{"id": "turn_on", "name": "On", "service": "turn_on"}],
}
page_a = pages.create(
    {
        "id": "page-a",
        "title": "Page A",
        "description": "A",
        "proximity": {"enabled": True, "radius_meters": 500},
        "resources": [resource_a],
        "access_grants": [grant(GRANT_A, SECRET_A), grant(GRANT_V, SECRET_V, True)],
    }
)
page_b = pages.create(
    {
        "id": "page-b",
        "title": "Page B",
        "description": "B",
        "resources": [resource_b],
        "access_grants": [grant(GRANT_B, SECRET_B)],
    }
)
for page in (page_a, page_b):
    page["access_grants"] = []
    policy.create(page)
for path in (DATA / "pages").glob("*.json"):
    own(path, 2100, 2000, 0o640)
for path in (DATA / "policy-pages").glob("*.json"):
    own(path, 2104, 2001, 0o640)
registry = DATA / "ha-broker-runtime/guest-page-capabilities.json"
registry.write_text(
    json.dumps(
        {
            "page-a": hashlib.sha256(CAP_A.encode()).hexdigest(),
            "page-b": hashlib.sha256(CAP_B.encode()).hexdigest(),
        }
    )
)
own(registry, 0, 2102, 0o640)


class HAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/states":
            data = [
                {
                    "entity_id": "switch.garden",
                    "state": "off",
                    "attributes": {"friendly_name": "Garden", "private": "secret"},
                },
                {"entity_id": "switch.porch", "state": "off", "attributes": {}},
            ]
        elif self.path == "/api/config":
            data = {"latitude": 33.0, "longitude": -111.0}
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = json.dumps(data).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/services/switch/turn_on":
            self.send_error(404)
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        events["actions"].append(body)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):
        pass


class AdminDelivery(BaseHTTPRequestHandler):
    def do_POST(self):
        events["admin_paths"].append(self.path)
        if self.headers.get("X-HA-Broker-Token") != "admin-broker-token":
            self.send_error(403)
            return
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/api/internal/email/guest-verification":
            assert set(data) == {"page_id", "grant_id", "code"}
            events["emails"].append(data)
        elif self.path == "/api/internal/guest-event":
            assert data["page_id"] in {"page-a", "page-b"}
            assert data["grant_id"] in {GRANT_A, GRANT_B, GRANT_V}
            assert data["event"] in {
                "initial_access", "action_success", "action_failed",
                "action_rate_limited", "unapproved_action_attempt",
                "verification_code_sent", "guest_email_verified", "verification_failed",
            }
            events["guest_events"].append(data)
        else:
            self.send_error(403)
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        events["admin_paths"].append(self.path)
        self.send_error(404)

    def log_message(self, *_args):
        pass


ha = ThreadingHTTPServer(("127.0.0.1", 18090), HAHandler)
admin = ThreadingHTTPServer(("127.0.0.1", 8081), AdminDelivery)
class ConnectorHealth(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


connector_health = ThreadingHTTPServer(("127.0.0.1", 8083), ConnectorHealth)
threading.Thread(target=ha.serve_forever, daemon=True).start()
threading.Thread(target=admin.serve_forever, daemon=True).start()
threading.Thread(target=connector_health.serve_forever, daemon=True).start()
processes = []


def spawn(command, env, uid, gid, groups):
    def drop():
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)

    process = subprocess.Popen(
        command,
        env={"PYTHONPATH": "/app", "PATH": "/usr/local/bin:/usr/bin:/bin", **env},
        preexec_fn=drop,
    )
    processes.append(process)
    return process


def wait_socket(path):
    for _ in range(150):
        if path.is_socket():
            return
        time.sleep(0.02)
    raise RuntimeError(f"socket absent: {path}")


def request(port, method, path, cookie="", payload=None, extra=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    headers = dict(extra or {})
    if cookie:
        headers["Cookie"] = "access_pages_guest=" + cookie
    if payload is not None:
        headers.update({"Content-Type": "application/json", "X-Guest-Request": "1"})
        payload = json.dumps(payload)
    connection.request(method, path, body=payload, headers=headers)
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


def wait_endpoint(port):
    for _ in range(150):
        try:
            return request(port, "GET", "/health")
        except ConnectionRefusedError:
            time.sleep(0.02)
    raise RuntimeError("endpoint absent")


try:
    broker_env = {
        "HA_BROKER_TOKEN": "guest-broker-token",
        "HA_BROKER_ADMIN_TOKEN": "admin-broker-token",
        "HA_BASE_URL": "http://127.0.0.1:18090",
        "HA_TOKEN": "raw-ha-token",
        "HA_BROKER_HOST": "127.0.0.1",
        "HA_BROKER_PORT": "8082",
        "HA_BROKER_GUEST_SOCKET": str(BROKER),
        "HA_BROKER_POLICY_DIR": str(DATA / "policy-pages"),
        "HA_GUEST_GRANTS_DIR": str(DATA / "pages"),
        "HA_GUEST_SESSION_DB": str(
            DATA / "ha-broker-runtime/guest-auth/sessions.sqlite3"
        ),
        "HA_GUEST_CAPABILITY_REGISTRY": str(registry),
    }
    broker = spawn(
        [sys.executable, "/app/ha_broker.py"], broker_env, 2102, 2001, [2000, 2102]
    )
    wait_socket(BROKER)
    guest_env = {
        "GUEST_SERVICE_SOCKET": str(SOCKET),
        "HA_BROKER_GUEST_SOCKET": str(BROKER),
    }
    guest = spawn([sys.executable, "/app/guest_service.py"], guest_env, 2101, 2101, [])
    wait_socket(SOCKET)
    forbidden_env = {
        "HA_TOKEN",
        "HA_BROKER_TOKEN",
        "HA_BROKER_ADMIN_TOKEN",
        "ADMIN_TOKEN",
        "POLICY_PUBLISH_TOKEN",
        "LAYERV_API_TOKEN",
        "SMTP_PASSWORD",
    }
    assert not (set(guest_env) & forbidden_env)

    def denied_as(uid, gid, groups, *, files=(), directories=(), sockets=()):
        def drop():
            os.setgroups(groups)
            os.setgid(gid)
            os.setuid(uid)

        script = r"""
import os, socket, sys
from pathlib import Path
import json
files, directories, sockets = map(json.loads, sys.argv[1:4])
for name in files:
    for flags in (os.O_RDONLY, os.O_WRONLY | os.O_APPEND):
        try:
            fd = os.open(name, flags)
        except PermissionError:
            continue
        else:
            os.close(fd)
            raise AssertionError('private file accessible: ' + name)
for name in directories:
    try:
        Path(name, 'intruder').symlink_to('/tmp/nonexistent')
    except PermissionError:
        pass
    else:
        raise AssertionError('private directory writable: ' + name)
for name in sockets:
    conn = socket.socket(socket.AF_UNIX)
    try:
        conn.connect(name)
    except PermissionError:
        pass
    else:
        raise AssertionError('private socket accessible: ' + name)
    finally:
        conn.close()
"""
        subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                json.dumps([str(item) for item in files]),
                json.dumps([str(item) for item in directories]),
                json.dumps([str(item) for item in sockets]),
            ],
            check=True,
            preexec_fn=drop,
        )

    denied_as(
        2101,
        2101,
        [],
        files=(
            DATA / "admin-runtime/smtp.json",
            DATA / "admin-runtime/admin-token",
            DATA / "secrets/layerv-api-key",
            DATA / "page-capabilities.json",
            DATA / "pages/page-a.json",
            DATA / "policy-pages/page-a.json",
            registry,
            Path(f"/proc/{broker.pid}/environ"),
        ),
        directories=(
            DATA / "pages",
            DATA / "policy-pages",
            DATA / "ha-broker-runtime",
            BROKER.parent,
        ),
    )
    denied_as(
        23000,
        23000,
        [2004],
        files=(DATA / "pages/page-a.json", registry),
        directories=(BROKER.parent,),
        sockets=(BROKER,),
    )
    denied_as(24000, 24000, [], directories=(SOCKET.parent,), sockets=(SOCKET, BROKER))
    endpoints = []
    endpoint_envs = []
    for page, cap, port in (("page-a", CAP_A, 18080), ("page-b", CAP_B, 18081)):
        env = {
            "HOST": "127.0.0.1",
            "PORT": str(port),
            "GATEWAY_BOUND_PAGE_ID": page,
            "PAGE_CAPABILITY_TOKEN": cap,
            "GUEST_ENDPOINT_GUEST_SERVICE_SOCKET": str(SOCKET),
        }
        if page == "page-a":
            # Deliberately supply retired settings; the binary must ignore them.
            env.update(
                {
                    "GUEST_ENDPOINT_TRANSPORT": "gateway",
                    "GUEST_ENDPOINT_UPSTREAM": "http://127.0.0.1:8081",
                }
            )
        endpoint_envs.append(env)
        endpoint = spawn(
            ["/usr/local/bin/access-pages-guest-endpoint"],
            env,
            23000 + port - 18080,
            23000 + port - 18080,
            [2004],
        )
        endpoints.append(endpoint)
        assert wait_endpoint(port)[0] == 200
        assert not (set(env) & forbidden_env)
    wrong_endpoint = spawn(
        ["/usr/local/bin/access-pages-guest-endpoint"],
        {
            "HOST": "127.0.0.1",
            "PORT": "18082",
            "GATEWAY_BOUND_PAGE_ID": "page-a",
            "PAGE_CAPABILITY_TOKEN": CAP_B,
            "GUEST_ENDPOINT_GUEST_SERVICE_SOCKET": str(SOCKET),
        },
        23002,
        23002,
        [2004],
    )
    assert wait_endpoint(18082)[0] == 200
    prefix_a = f"/g/page-a/{GRANT_A}/"
    prefix_v = f"/g/page-a/{GRANT_V}/"
    prefix_b = f"/g/page-b/{GRANT_B}/"

    def bootstrap(port, prefix, secret):
        status, headers, _ = request(port, "GET", prefix + "?bootstrap=" + secret)
        assert status == 303, (status, prefix)
        return headers["Set-Cookie"].split(";", 1)[0].split("=", 1)[1]

    session_a = bootstrap(18080, prefix_a, SECRET_A)
    session_b = bootstrap(18081, prefix_b, SECRET_B)
    session_v = bootstrap(18080, prefix_v, SECRET_V)
    assert request(18080, "GET", prefix_a + "api/access/page-a")[0] == 401
    assert (
        request(
            18080,
            "GET",
            prefix_a + "api/access/page-a",
            extra={"X-Admin-Token": "owner-token"},
        )[0]
        == 401
    )
    denied_as(
        2101,
        2101,
        [],
        files=(DATA / "ha-broker-runtime/guest-auth/sessions.sqlite3",),
        directories=(DATA / "ha-broker-runtime/guest-auth",),
    )
    snapshot = registry.read_bytes()
    registry.write_text('{"page-a":')
    assert request(18080, "GET", prefix_a + "api/access/page-a", session_a)[0] == 401
    registry.write_bytes(snapshot)
    policy_file = DATA / "policy-pages/page-a.json"
    saved_policy = policy_file.read_bytes()
    policy_file.write_text("not-json")
    assert request(18080, "GET", prefix_a + "api/access/page-a", session_a)[0] in (
        400,
        401,
    )
    policy_file.write_bytes(saved_policy)
    assert request(18082, "GET", prefix_a + "api/access/page-a", session_a)[0] == 403
    assert session_a != session_b != session_v
    status, _, shell = request(18080, "GET", prefix_a, session_a)
    assert status == 200 and b"layerv-wordmark.png" in shell

    def inspect_public_headers(cookie, expected_status):
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=8)
        headers = {"Cookie": "access_pages_guest=" + cookie} if cookie else {}
        connection.request("GET", prefix_a, headers=headers)
        response = connection.getresponse()
        raw = response.getheaders()
        assert response.status == expected_status, response.status
        response.read()
        connection.close()
        expected = {
            "content-security-policy": "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none';",
            "referrer-policy": "no-referrer",
            "x-content-type-options": "nosniff",
            "cache-control": "no-store",
        }
        for name, value in expected.items():
            matches = [actual for header, actual in raw if header.lower() == name]
            assert matches == [value], (name, matches)
        assert not any(header.lower() == "server" for header, _ in raw), raw
        assert not any(
            "BaseHTTP" in value or "Python/" in value
            for _, value in raw
        ), raw

    inspect_public_headers(session_a, 200)
    inspect_public_headers("", 401)
    assert request(18080, "GET", prefix_a + "static/access.js", session_a)[0] == 200
    assert request(18080, "GET", "/access/page-a?access_token=old")[0] == 404
    assert request(18080, "GET", "/api/access/page-a?access_token=old")[0] == 404
    assert (
        request(
            18080, "GET", prefix_a + "api/access/page-a?access_token=old", session_a
        )[0]
        == 400
    )
    assert request(18080, "GET", prefix_a + "api/access/page-a", session_b)[0] == 401
    for route in (
        "/admin",
        "/api/admin/pages",
        "/discovery",
        "/notifications",
        "/policy/publish",
    ):
        assert request(18080, "GET", route, session_a)[0] == 404
    assert request(18080, "GET", prefix_a + "api/access/page-a", session_a)[0] == 200
    status, _, body = request(18080, "GET", prefix_a + "api/access/page-a", session_a)
    view = json.loads(body)
    assert view["resources"][0]["id"] == "garden" and "private" not in json.dumps(view)
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 403
    assert not any(item["event"] == "initial_access" and item["grant_id"] == GRANT_V
                   for item in events["guest_events"])
    status, _, body = request(
        18080,
        "POST",
        prefix_v + "api/access/page-a/verification/send",
        session_v,
        {"replace": False},
    )
    assert status == 200 and json.loads(body)["sent"] and len(events["emails"]) == 1
    code = events["emails"][0]["code"]
    assert (
        request(
            18080,
            "POST",
            prefix_v + "api/access/page-a/verification/verify",
            session_v,
            {"code": code},
        )[0]
        == 200
    )
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 200
    action = prefix_a + "api/access/page-a/garden/turn_on"
    assert request(18080, "POST", action, session_a, {})[0] == 403
    far = {
        "latitude": 34.0,
        "longitude": -111.0,
        "accuracy_meters": 10,
        "measured_at": time.time(),
    }
    near = {**far, "latitude": 33.0}
    assert request(18080, "POST", action, session_a, {"proximity": far})[0] == 403
    assert request(18080, "POST", action, session_a, {"proximity": near})[0] == 200
    assert events["actions"] == [{"entity_id": "switch.garden"}]
    assert request(18080, "GET", prefix_b + "api/access/page-b", session_b)[0] == 404
    assert request(18081, "GET", prefix_b + "api/access/page-b", session_a)[0] == 401
    assert request(18081, "GET", prefix_b + "api/access/page-b", session_b)[0] == 200
    assert (
        request(
            18080,
            "GET",
            prefix_a + "api/access/page-a",
            session_a,
            extra={"X-Access-Pages-Page-ID": "page-b", "X-Page-Capability": CAP_B},
        )[0]
        == 200
    )
    page = pages.load("page-a")
    page["access_grants"] = [g for g in page["access_grants"] if g["id"] != GRANT_A]
    pages.replace("page-a", page)
    own(DATA / "pages/page-a.json", 2100, 2000, 0o640)
    assert request(18080, "GET", prefix_a + "api/access/page-a", session_a)[0] == 401
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 200
    published = policy.load("page-a")
    published["resources"] = []
    policy.replace("page-a", published)
    own(DATA / "policy-pages/page-a.json", 2104, 2001, 0o640)
    assert (
        request(
            18080,
            "POST",
            prefix_v + "api/access/page-a/garden/turn_on",
            session_v,
            {"proximity": near},
        )[0]
        == 404
    )
    guest.terminate()
    guest.wait(timeout=5)
    SOCKET.unlink()
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 502
    assert set(events["admin_paths"]) == {
        "/api/internal/email/guest-verification", "/api/internal/guest-event",
    }
    assert {"initial_access", "verification_code_sent", "guest_email_verified",
            "action_success"} <= {item["event"] for item in events["guest_events"]}
    guest = spawn([sys.executable, "/app/guest_service.py"], guest_env, 2101, 2101, [])
    wait_socket(SOCKET)
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 200
    broker.terminate()
    broker.wait(timeout=5)
    BROKER.unlink()
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 503
    broker = spawn(
        [sys.executable, "/app/ha_broker.py"], broker_env, 2102, 2001, [2000, 2102]
    )
    wait_socket(BROKER)
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 200
    endpoints[0].terminate()
    endpoints[0].wait(timeout=5)
    endpoints[0] = spawn(
        ["/usr/local/bin/access-pages-guest-endpoint"],
        endpoint_envs[0],
        23000,
        23000,
        [2004],
    )
    assert wait_endpoint(18080)[0] == 200
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 200
    guest.terminate()
    guest.wait(timeout=5)
    SOCKET.unlink()
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 502
    admin.shutdown()
    admin.server_close()
    def register_admin_activity():
        def drop():
            os.setgroups([2000])
            os.setgid(2000)
            os.setuid(2100)
        script = """
from pathlib import Path
from activity import GuestActivityStore
from pages import PageStore
page = PageStore(Path('/data/pages')).load('page-a')
store = GuestActivityStore(Path('/data/guest-runtime/guest-activity.sqlite3'))
for grant in page['access_grants']:
    store.register_guest('page-a', grant)
"""
        subprocess.run([sys.executable, "-c", script], check=True, preexec_fn=drop)
    register_admin_activity()
    gateway_env = {
        "HOST": "127.0.0.1",
        "PORT": "8081",
        "HA_BROKER_URL": "http://127.0.0.1:8082",
        "HA_BROKER_TOKEN": "admin-broker-token",
        "ADMIN_TOKEN": "owner-token",
        "GATEWAY_DATA_DIR": str(DATA),
        "ACTIVITY_DB_FILE": str(DATA / "guest-runtime/guest-activity.sqlite3"),
    }
    gateway = spawn([sys.executable, "/app/server.py"], gateway_env, 2100, 2000, [])
    for _ in range(150):
        try:
            admin_status, _, admin_body = request(8081, "GET", "/admin")
            break
        except ConnectionRefusedError:
            time.sleep(0.02)
    assert admin_status == 200 and b"Access Pages" in admin_body
    guest = spawn([sys.executable, "/app/guest_service.py"], guest_env, 2101, 2101, [])
    wait_socket(SOCKET)
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 200
    from activity import GuestActivityStore
    activity = GuestActivityStore(DATA / "guest-runtime/guest-activity.sqlite3")
    assert activity.guest_activity("page-a", GRANT_V)["guest"]["first_access_at"]
    guest.terminate()
    guest.wait(timeout=5)
    SOCKET.unlink()

    # Loopback reachability is not admin or broker authority for guest UID.
    def guest_loopback_denied():
        def drop():
            os.setgroups([])
            os.setgid(2101)
            os.setuid(2101)

        script = r"""
import http.client, socket
for port, route, method, headers in (
    (8081, '/api/admin/pages', 'GET', {}),
    (8081, '/api/internal/email/guest-verification', 'POST', {}),
    (8082, '/v1/states', 'POST', {'X-Broker-Role':'admin', 'X-Broker-Token':'page-capability-a-1234567890'}),
):
    c = http.client.HTTPConnection('127.0.0.1', port)
    c.request(method, route, headers=headers)
    r = c.getresponse(); assert r.status in (401, 403, 404), (port, route, r.status)
    r.read(); c.close()
s = socket.socket(socket.AF_UNIX)
s.connect('/run/access-pages/ha-guest/http.sock')
s.sendall(b'POST /v1/discovery HTTP/1.1\r\nHost: broker\r\nX-Broker-Role: admin\r\nX-Broker-Token: admin-broker-token\r\nContent-Length: 0\r\n\r\n')
r = http.client.HTTPResponse(s); r.begin(); assert r.status == 404, r.status
r.read(); s.close()
"""
        subprocess.run([sys.executable, "-c", script], check=True, preexec_fn=drop)

    guest_loopback_denied()
    old_headers = {"X-Access-Pages-Page-ID": "page-a", "X-Page-Capability": CAP_A}
    assert request(8081, "GET", prefix_v, extra=old_headers)[0] == 404
    assert request(8081, "GET", "/api/access/page-a", extra=old_headers)[0] == 404
    assert (
        request(
            8081,
            "POST",
            "/api/access/page-a/garden/turn_on",
            payload={},
            extra=old_headers,
        )[0]
        == 404
    )
    assert (
        request(
            8081,
            "POST",
            "/api/internal/email/verification",
            payload={},
            extra=old_headers,
        )[0]
        == 404
    )
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 502
    gateway.terminate()
    gateway.wait(timeout=5)
    gateway = spawn([sys.executable, "/app/server.py"], gateway_env, 2100, 2000, [])
    for _ in range(150):
        try:
            admin_status, _, _ = request(8081, "GET", "/admin")
            break
        except ConnectionRefusedError:
            time.sleep(0.02)
    assert admin_status == 200
    assert request(8081, "GET", "/api/access/page-a", extra=old_headers)[0] == 404
    assert request(18080, "GET", prefix_v + "api/access/page-a", session_v)[0] == 502
    print(
        "packaged real-UID security: guest/admin files and sockets, old settings, sessions, verification, policy, actions, revocation, corrupt data, service/broker/endpoint/admin restart and outage: PASS"
    )
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
    ha.shutdown()
    admin.shutdown()
    connector_health.shutdown()
