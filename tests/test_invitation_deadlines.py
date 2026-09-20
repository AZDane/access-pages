"""Real HTTP regression for a cold invitation outlasting both proxy deadlines."""

from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Event, Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from layerv import BrokerLayerVClient, LayerVError
from tests.test_ingress_proxy import ingress_proxy


class InvitationDeadlineTests(unittest.TestCase):
    def test_slow_creation_returns_upstream_error_through_both_proxies(self):
        class QuietHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, status, payload, retry_after):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Retry-After", str(retry_after))
                self.end_headers()
                self.wfile.write(body)

        class SlowBroker(QuietHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                # Real socket wait exceeds the previous 20s broker and 30s
                # ingress deadlines. No upstream account or qURL is involved.
                Event().wait(35)
                self.reply(502, {"error": "LayerV qURL creation rate limit reached (429); wait 120 seconds before retrying", "layerv_status": 429}, 120)

        def start(handler, stack):
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server.daemon_threads = True
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(server.server_close)
            stack.callback(server.shutdown)
            return "http://127.0.0.1:" + str(server.server_port)

        with ExitStack() as stack:
            broker = BrokerLayerVClient(start(SlowBroker, stack), "synthetic-token")

            class Gateway(QuietHandler):
                def do_POST(self):
                    self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    try:
                        broker._request("POST", "/v1/grants", {})
                    except LayerVError as error:
                        self.reply(502, {"error": str(error), "layerv_status": error.status}, error.retry_after)

            gateway_url = start(Gateway, stack)
            stack.enter_context(patch.object(ingress_proxy, "UPSTREAM", gateway_url))
            stack.enter_context(patch.object(ingress_proxy, "_trusted_ingress_request", return_value=True))
            proxy_url = start(ingress_proxy.Handler, stack)
            request = Request(proxy_url + "/api/admin/pages/guest/qurls", data=b"{}", method="POST")
            with self.assertRaises(HTTPError) as raised:
                urlopen(request, timeout=45)
            response = raised.exception
            self.assertEqual(response.code, 502)
            self.assertEqual(response.headers["Retry-After"], "120")
            payload = json.load(response)
            self.assertEqual(payload["layerv_status"], 429)
            self.assertIn("rate limit reached", payload["error"])
            self.assertNotIn("timed out", payload["error"])
