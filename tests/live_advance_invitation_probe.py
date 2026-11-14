"""Opt-in disposable production probe of the actual broker create/retire path.

Uses a fresh anonymous CLI identity and a loopback adapter for the device-auth
request bridge (no account key, SMTP, or Home Assistant). Browser assertions run
separately while this process owns the resource. Only the private output file
contains invitation credentials. Run with PYTHONPATH set to this repository.
"""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time

os.environ.setdefault('ACCESS_PAGES_BROKER_TOKEN', 'disposable-probe')
os.environ.setdefault('LAYERV_API_BASE_URL', 'https://api.layerv.ai')
os.environ.setdefault('LAYERV_API_TOKEN', 'device-bridge-only')
os.environ.setdefault('LAYERV_RESOURCE_ID', 'disposable-probe')
import layerv_broker as broker
from guest_resources import ConnectorPublisher, GuestResources
from layerv import LayerVClient, LayerVError
from pages import PageStore


def probe(directory, binary):
    root = Path(directory)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    publisher = ConnectorPublisher(root / 'state', api_base_url='https://api.layerv.ai', enrollment_key='unused-anonymous-probe', binary=binary)
    publisher.wrapping_key.write_bytes(secrets.token_bytes(32))
    publisher.wrapping_key.chmod(0o600)
    def invoke(args, body=None):
        with publisher._key_pipe() as (fd, env):
            response = subprocess.run([*publisher.command, *args], input=json.dumps(body) if body is not None else '', capture_output=True, text=True, env=env, pass_fds=(fd,), timeout=90)
        if response.returncode:
            raise RuntimeError('Native command failed; credentials and diagnostics withheld')
        return json.loads(response.stdout)

    class Bridge(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            self.forward(body)
        def do_GET(self):
            self.forward(None)
        def do_DELETE(self):
            self.forward(None)
        def forward(self, body):
            try:
                envelope = invoke(['request', self.command, self.path], body)
                encoded = json.dumps(envelope.get('body', {})).encode()
                if envelope['status'] >= 400:
                    error_file = root / 'upstream-error.private.json'
                    error_file.write_bytes(encoded)
                    error_file.chmod(0o600)
                self.send_response(envelope['status'])
                self.send_header('Content-Length', str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except Exception:
                self.send_error(502, 'Disposable bridge failed')
        def log_message(self, *args):
            pass

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            encoded = b'<html><body><h1 id="marker">scheduled-qurl-smoke</h1></body></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        def log_message(self, *args):
            pass

    servers = [ThreadingHTTPServer(('127.0.0.1', 0), Bridge), ThreadingHTTPServer(('127.0.0.2', 8080), Origin)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    grants = []
    try:
        invoke(['login', '--anonymous'])
        publisher._mark_bootstrapped()
        publisher._start()
        broker.PAGE_STORE = PageStore(root / 'pages')
        broker.PAGE_STORE.create({'id': 'probe', 'title': 'Disposable probe', 'resources': []})
        broker.DATA_DIR = root / 'broker'
        broker.PAGE_CONNECTOR_REGISTRY = root / 'registry.json'
        broker.PAGE_CONNECTOR_REGISTRY.write_text(json.dumps({'pages': {'probe': {'target_ip': '127.0.0.2'}}}))
        broker.CLIENT = LayerVClient(f'http://127.0.0.1:{servers[0].server_port}', 'synthetic-bridge-token', 'unused')
        broker.GUEST_RESOURCES = GuestResources(root / 'resources.sqlite3', installation_id=secrets.token_hex(12), publisher=publisher, management_client=broker.CLIENT)
        # Measure the actual creation-to-expiration cap for both invitation types.
        windows = ((86400, 3600, True), (86400, 3600, False)) if os.getenv('PROBE_LIMITS', '1') == '1' else ()
        for lead, length, single in (*windows, (0, 600, False), (45, 90, True)):
            grant_id = 'grant_' + secrets.token_urlsafe(12)
            grants.append(grant_id)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            start, end = now + timedelta(seconds=lead), now + timedelta(seconds=lead + length)
            target = f'/g/probe/{grant_id}/?bootstrap=' + secrets.token_urlsafe(32)
            try:
                result = broker.create_grant('probe', grant_id, 'Disposable probe', f'{(lead + length)//60}m', target, single, f'{length}s', start.isoformat() if lead else None, end.isoformat())
            except LayerVError as error:
                if lead == 86400 and error.status == 400:
                    print('25-hour creation rejected; single-use:', single, flush=True)
                    broker.delete_grant('probe', grant_id)
                    grants.remove(grant_id)
                    continue
                raise
            if lead == 0:
                path = root / 'control.private.json'
                path.write_text(json.dumps(result))
                path.chmod(0o600)
                continue
            if lead == 86400:
                broker.delete_grant('probe', grant_id)
                grants.remove(grant_id)
                print('25-hour creation accepted and retired; single-use:', single, flush=True)
            else:
                path = root / 'invitation.private.json'
                path.write_text(json.dumps({'payload': {'not_before': start.isoformat(), 'expires_at': end.isoformat()}, 'response': result}))
                path.chmod(0o600)
                print('Browser invitation ready; private output written', flush=True)
                while time.time() < end.timestamp() + 90 and not (root / 'browser.done').exists():
                    time.sleep(1)
    finally:
        failures = 0
        for grant in grants:
            try:
                broker.delete_grant('probe', grant)
            except Exception:
                failures += 1
        publisher.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        print('Disposable cleanup failures:', failures, flush=True)
        if failures:
            raise RuntimeError('Retain private directory and reconcile disposable resources')


if __name__ == '__main__':
    probe(sys.argv[1], sys.argv[2])
