"""Disposable browser fixture: real app, ingress proxy, Guest Service and broker.

HA responses, LayerV cleanup, Supervisor forwarding and policy transport are
synthetic. The local Unix connection runs as the test user; packaged tests own
UID/socket confinement. No external accounts, devices or production data.
"""

from contextlib import ExitStack
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
PREFIX = "/api/hassio_ingress/browser-test"
calls = []
states = [{"entity_id": f"switch.{name}", "state": "off",
           "attributes": {"friendly_name": label}}
          for name, label in (("garden", "Garden light"), ("other", "Other light"))]


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, body, content_type="application/json", status=200):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class SyntheticHA(QuietHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer synthetic-ha-token":
            self.send_error(401)
        elif self.path == "/api/states":
            self.respond(states)
        elif self.path == "/api/services":
            self.respond([{"domain": "switch", "services": {
                name: {"target": {}, "fields": {}} for name in ("turn_on", "turn_off")}}])
        else:
            self.send_error(404)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer synthetic-ha-token":
            self.send_error(401)
            return
        payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if self.path == "/api/template":
            self.respond([{"entity_id": item["entity_id"], "area_id": "", "area_name": ""}
                          for item in states] if "area_id" in payload["template"] else [])
        elif self.path in ("/api/services/switch/turn_on", "/api/services/switch/turn_off"):
            entity = next((item for item in states if item["entity_id"] == payload.get("entity_id")), None)
            if entity is None or set(payload) != {"entity_id"}:
                self.send_error(400)
                return
            calls.append({"path": self.path, **payload})
            entity["state"] = "on" if self.path.endswith("turn_on") else "off"
            self.respond([])
        else:
            self.send_error(404)


def serve(stack, http_server):
    thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    thread.start()

    def close():
        http_server.shutdown()
        thread.join(timeout=5)
        http_server.server_close()

    stack.callback(close)
    return http_server.server_address[1]


def main():
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="access-pages-browser-")))
        # Never inherit installed application endpoints, tokens or data paths.
        for key in list(os.environ):
            if key.startswith(("HA_", "GATEWAY_", "ACCESS_PAGES_", "LAYERV_", "SMTP_",
                               "POLICY_", "INGRESS_", "CONNECTOR_", "ACTIVITY_",
                               "ALERT_", "VERIFICATION_", "ADMIN_")):
                del os.environ[key]
        ha_port = serve(stack, ThreadingHTTPServer(("127.0.0.1", 0), SyntheticHA))
        os.environ.update(GATEWAY_DATA_DIR=str(directory),
                          HA_BASE_URL=f"http://127.0.0.1:{ha_port}",
                          HA_TOKEN="synthetic-ha-token", ADMIN_TOKEN="synthetic-owner-token",
                          HA_BROKER_TOKEN="synthetic-broker-token",
                          HA_BROKER_ADMIN_TOKEN="synthetic-admin-broker-token",
                          INGRESS_ADMIN_TOKEN="synthetic-owner-token",
                          TRUSTED_INGRESS_PROXIES="127.0.0.1")

        import server
        import ha_broker
        import guest_service
        from tests import test_broker_guest_sessions, test_guest_cutover

        broker = test_broker_guest_sessions.BrokerGuestSessionTests()
        broker.setUp()
        stack.callback(broker.tearDown)
        guest = test_guest_cutover.GuestCutoverTests()
        guest.setUp()
        stack.callback(guest.tearDown)
        page = broker.pages.load("page-a")
        page["resources"] = [item for item in page["resources"] if item["id"] == "garden"]
        page["resources"][0]["actions"] = [
            {"id": "turn_on", "name": "Turn on", "service": "turn_on"}]
        page["access_grants"] = [dict(page["access_grants"][0], label="Browser guest",
                                      qurl_id="synthetic-qurl", resource_id="synthetic-resource")]
        broker.pages.replace("page-a", page)
        broker.policy.replace("page-a", {**page, "access_grants": []})
        stack.enter_context(patch.object(server, "PAGE_STORE", broker.pages))
        stack.enter_context(patch.object(ha_broker, "HA_CLIENT", server.HA_CLIENT))
        admin_broker_port = serve(stack, ThreadingHTTPServer(("127.0.0.1", 0), ha_broker.Handler))
        stack.enter_context(patch.object(server, "HA_CLIENT", server.BrokerHomeAssistantClient(
            f"http://127.0.0.1:{admin_broker_port}", "synthetic-admin-broker-token", broker_role="admin")))
        stack.enter_context(patch.object(server, "LAYERV_CLIENT", Mock(configured=False,
                                                                      delete_qurl=Mock(return_value=False))))

        def publish(page):
            policy = {**page, "access_grants": []}
            if broker.policy._path(page["id"]).exists():
                broker.policy.replace(page["id"], policy)
            else:
                broker.policy.create(policy)

        stack.enter_context(patch.object(server.POLICY_PUBLISHER, "publish", side_effect=publish))

        def connect_broker():
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(5)
            connection.connect(str(broker.socket_path))
            return connection

        stack.enter_context(patch.object(guest_service, "_connect_broker", side_effect=connect_broker))
        admin_port = serve(stack, server.GatewayHTTPServer(("127.0.0.1", 0), server.Handler))
        os.environ["INGRESS_UPSTREAM"] = f"http://127.0.0.1:{admin_port}"
        spec = importlib.util.spec_from_file_location("browser_ingress", ROOT / "homeassistant-app/ingress_proxy.py")
        ingress = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ingress)
        ingress_port = serve(stack, ThreadingHTTPServer(("127.0.0.1", 0), ingress.Handler))

        class Frontend(QuietHandler):
            def proxy(self):
                path = urlsplit(self.path).path
                if self.command == "GET" and path == "/__ready":
                    self.respond({"ready": True})
                    return
                if self.command == "GET" and path == "/__calls":
                    self.respond(calls)
                    return
                if self.command == "GET" and path == "/ha":
                    self.respond(f'<html><body><iframe title="Access Pages" src="{PREFIX}/" '
                                 'style="width:100%;height:900px;border:0"></iframe></body></html>'.encode(),
                                 "text/html")
                    return
                headers = {key: value for key, value in self.headers.items()
                           if key.lower() in {"content-type", "cookie", "x-guest-request"}}
                target = self.path
                if path.startswith(PREFIX + "/"):
                    connection = http.client.HTTPConnection("127.0.0.1", ingress_port, timeout=10)
                    target = self.path[len(PREFIX):]
                    headers["X-Ingress-Path"] = PREFIX
                elif path.startswith(("/g/", "/static/")):
                    connection = test_guest_cutover.UnixHTTPConnection(guest.socket_path)
                    headers.update({"X-Access-Pages-Page-ID": "page-a", "X-Page-Capability": broker.cap_a,
                                    "X-Access-Pages-Request-ID": "a" * 32})
                    import guest_request
                    headers[guest_request.STARTED_NS] = str(guest_request.clock_ns())
                else:
                    # Direct requests receive no owner token.
                    connection = http.client.HTTPConnection("127.0.0.1", admin_port, timeout=10)
                body = self.rfile.read(int(self.headers.get("Content-Length", "0"))) or None
                try:
                    connection.request(self.command, target, body=body, headers=headers)
                    response = connection.getresponse()
                    payload = response.read()
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in {"connection", "transfer-encoding", "content-length"}:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                finally:
                    connection.close()

            do_GET = do_POST = do_DELETE = proxy

        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", str(directory / "key.pem"),
                        "-out", str(directory / "cert.pem")], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(directory / "cert.pem", directory / "key.pem")
        frontend = ThreadingHTTPServer(("127.0.0.1", 18765), Frontend)
        frontend.socket = tls.wrap_socket(frontend.socket, server_side=True)
        serve(stack, frontend)
        stopped = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stopped.set())
        signal.signal(signal.SIGINT, lambda *_: stopped.set())
        stopped.wait()


if __name__ == "__main__":
    main()
