"""Real Unix peer disconnects during redirect, state and error responses."""
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import guest_service


class DisconnectRegressionTests(unittest.TestCase):
    def exercise(self, *, bootstrap, error=False):
        flushed = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        responses = []
        errors = []
        prefix = '/g/page-a/grant_aaaaaaaaaaaaaaaa/'

        class Handler(guest_service.GuestHandler):
            def _send(self, status, *args, **kwargs):
                responses.append(status)
                return super()._send(status, *args, **kwargs)

            def end_headers(self):
                super().end_headers()
                flushed.set()
                if not release.wait(3):
                    raise RuntimeError('Test client did not close')

            def _guest(self, method):
                try:
                    super()._guest(method)
                finally:
                    finished.set()

        class Server(guest_service.GuestSocketServer):
            def handle_error(self, request, client_address):
                errors.append(type(sys.exc_info()[1]).__name__)

        def broker(route, payload):
            if error:
                raise OSError('synthetic unavailable broker')
            if route == '/broker-bootstrap':
                return 200, {'session': 'synthetic-session-1234567890',
                             'expires_at': int(time.time()) + 3600}
            self.assertEqual(payload['session'], 'synthetic-session-1234567890')
            return 200, {'id': 'page-a', 'resources': []}

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(guest_service, '_connector_healthy', return_value=True),
            patch.object(guest_service, '_broker_guest_auth', side_effect=broker),
        ):
            path = str(Path(temporary) / 'guest.sock')
            with Server(path, Handler) as server:
                thread = threading.Thread(target=server.serve_forever,
                                          kwargs={'poll_interval': .01})
                thread.start()
                try:
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(3)
                        client.connect(path)
                        route = prefix + ('?bootstrap=synthetic-secret-1234567890'
                                          if bootstrap else 'api/access/page-a')
                        cookie = '' if bootstrap else 'Cookie: access_pages_guest=synthetic-session-1234567890\r\n'
                        client.sendall((f'GET {route} HTTP/1.1\r\n'
                                        'Host: guest\r\n'
                                        'X-Access-Pages-Page-ID: page-a\r\n'
                                        'X-Page-Capability: synthetic-capability-123456\r\n'
                                        f'{cookie}'
                                        'Connection: close\r\n\r\n').encode())
                        headers = b''
                        while b'\r\n\r\n' not in headers:
                            chunk = client.recv(4096)
                            self.assertTrue(chunk)
                            headers += chunk
                        self.assertTrue(flushed.wait(3))
                    # A real peer close, after all headers but before _send
                    # writes its body. No synthetic BrokenPipe exception.
                    release.set()
                    self.assertTrue(finished.wait(3))
                    expected = 503 if error else 303 if bootstrap else 200
                    self.assertIn(f' {expected} '.encode(), headers)
                    if bootstrap and not error:
                        self.assertIn(b'Content-Length: 0\r\n', headers)
                        self.assertIn(('Location: ' + prefix).encode(), headers)
                        self.assertIn(b'Set-Cookie: access_pages_guest=', headers)
                        self.assertIn(b'Secure; HttpOnly; SameSite=Lax;', headers)
                    self.assertEqual(responses, [expected],
                                     'Disconnected response must not become a second 503')
                    self.assertEqual(errors, [])
                finally:
                    release.set()
                    server.shutdown()
                    thread.join(3)

    def test_empty_redirect_does_not_write_after_complete_headers(self):
        self.exercise(bootstrap=True)

    def test_disconnect_during_state_body_does_not_attempt_second_response(self):
        self.exercise(bootstrap=False)

    def test_disconnect_while_sending_error_is_terminal(self):
        self.exercise(bootstrap=False, error=True)


if __name__ == '__main__':
    unittest.main()
