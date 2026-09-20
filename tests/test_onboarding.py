import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from threading import Event, Lock
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "homeassistant-app"
    / "onboarding.py"
)
with patch.dict("os.environ", {}, clear=True):
    SPEC = importlib.util.spec_from_file_location("onboarding", MODULE_PATH)
    onboarding = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(onboarding)


class OnboardingTests(unittest.TestCase):
    def test_gateway_error_has_the_reported_json_parse_signature(self):
        script = (
            "try { JSON.parse('502: Bad Gateway') } "
            "catch (error) { process.stdout.write(error.message) }"
        )
        result = subprocess.run(
            ["node", "-e", script],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            result.stdout,
            "Unexpected non-whitespace character after JSON at "
            "position 3 (line 1 column 4)",
        )

    def test_real_onboarding_process_waits_for_persistence_and_sends_json(self):
        key = "lv_test_processSyntheticCredential"
        for _ in range(5):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            read_fd, write_fd = os.pipe()
            ack_read_fd, ack_write_fd = os.pipe()
            process = subprocess.Popen(
                [sys.executable, str(MODULE_PATH)],
                env={
                    **os.environ,
                    "ONBOARDING_HOST": "127.0.0.1",
                    "ONBOARDING_PORT": str(port),
                    "ONBOARDING_SUBMISSION_FD": str(write_fd),
                    "ONBOARDING_ACK_FD": str(ack_read_fd),
                },
                pass_fds=(write_fd, ack_read_fd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            os.close(write_fd)
            os.close(ack_read_fd)
            try:
                for _ in range(100):
                    try:
                        with urlopen(
                            f"http://127.0.0.1:{port}/health", timeout=0.3
                        ):
                            break
                    except OSError:
                        time.sleep(0.01)
                request = Request(
                    f"http://127.0.0.1:{port}/api/onboarding/key",
                    data=json.dumps({"api_key": key}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                result = {}

                def submit():
                    try:
                        with urlopen(request, timeout=3) as response:
                            result["status"] = response.status
                            result["type"] = response.headers["Content-Type"]
                            result["body"] = response.read()
                    except Exception as error:
                        result["error"] = error

                thread = threading.Thread(target=submit)
                thread.start()
                self.assertEqual(os.read(read_fd, 4098), (key + "\n").encode())
                self.assertTrue(thread.is_alive())
                os.write(ack_write_fd, b"1")
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive())
                self.assertNotIn("error", result)
                self.assertEqual(result["status"], 201)
                self.assertEqual(result["type"], "application/json; charset=utf-8")
                self.assertEqual(json.loads(result["body"]), {"success": True})
                self.assertNotIn(key.encode(), result["body"])
                self.assertEqual(process.wait(timeout=3), 0)
            finally:
                os.close(read_fd)
                os.close(ack_write_fd)
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)

    def test_waits_for_gateway_before_reloading_after_setup(self):
        self.assertIn('result.status === "ok"', onboarding.JAVASCRIPT)
        self.assertIn('result.success !== true', onboarding.JAVASCRIPT)
        self.assertIn('response.headers.get("Content-Type")', onboarding.JAVASCRIPT)
        self.assertIn('Setup response was interrupted', onboarding.JAVASCRIPT)
        self.assertNotIn(
            "setTimeout(() => window.location.reload(), 4500)",
            onboarding.JAVASCRIPT,
        )

    def test_accepts_api_keys_without_logging_or_embedding_them(self):
        key = "lv_test_syntheticCredential"

        self.assertEqual(onboarding._valid_key(key), key)
        self.assertNotIn(key, onboarding.HTML)
        self.assertNotIn("console.", onboarding.JAVASCRIPT)

    def test_rejects_empty_oversized_or_whitespace_keys(self):
        for value in ("", "short", "contains space", "x" * 4097):
            with self.subTest(value=value[:20]), self.assertRaises(
                ValueError
            ):
                onboarding._valid_key(value)

    def test_secret_is_submitted_over_inherited_pipe(self):
        read_fd, write_fd = os.pipe()
        ack_read_fd, ack_write_fd = os.pipe()
        try:
            os.write(ack_write_fd, b"1")
            with patch.object(onboarding, "SUBMISSION_FD", write_fd), patch.object(
                onboarding, "ACK_FD", ack_read_fd
            ):
                onboarding._submit_secret("synthetic-key")
            self.assertEqual(
                os.read(read_fd, 4096),
                b"synthetic-key\n",
            )
        finally:
            os.close(read_fd)
            os.close(write_fd)
            os.close(ack_read_fd)
            os.close(ack_write_fd)

    def test_rejected_persistence_ack_does_not_report_success(self):
        read_fd, write_fd = os.pipe()
        ack_read_fd, ack_write_fd = os.pipe()
        try:
            os.write(ack_write_fd, b"0")
            with patch.object(onboarding, "SUBMISSION_FD", write_fd), patch.object(
                onboarding, "ACK_FD", ack_read_fd
            ):
                with self.assertRaises(RuntimeError):
                    onboarding._submit_secret("synthetic-key")
            self.assertEqual(os.read(read_fd, 4096), b"synthetic-key\n")
        finally:
            os.close(read_fd)
            os.close(write_fd)
            os.close(ack_read_fd)
            os.close(ack_write_fd)

    def test_http_setup_never_returns_the_submitted_key(self):
        read_fd, write_fd = os.pipe()
        ack_read_fd, ack_write_fd = os.pipe()
        try:
            server = onboarding.ThreadingHTTPServer(
                ("127.0.0.1", 0),
                onboarding.Handler,
            )
            server.completed = Event()
            server.submission_lock = Lock()
            thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
            )
            key = "lv_test_httpSyntheticCredential"
            os.write(ack_write_fd, b"1")
            with patch.object(onboarding, "SUBMISSION_FD", write_fd), patch.object(
                onboarding, "ACK_FD", ack_read_fd
            ):
                thread.start()
                request = Request(
                    (
                        f"http://127.0.0.1:{server.server_port}"
                        "/api/onboarding/key"
                    ),
                    data=json.dumps({"api_key": key}).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urlopen(request, timeout=2) as response:
                    body = response.read().decode("utf-8")
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

            self.assertEqual(response.status, 201)
            self.assertNotIn(key, body)
            self.assertEqual(
                os.read(read_fd, 4096),
                (key + "\n").encode("utf-8"),
            )
        finally:
            os.close(read_fd)
            os.close(write_fd)
            os.close(ack_read_fd)
            os.close(ack_write_fd)

    def test_http_persistence_failure_is_explicit_json_without_key(self):
        read_fd, write_fd = os.pipe()
        ack_read_fd, ack_write_fd = os.pipe()
        server = onboarding.ThreadingHTTPServer(
            ("127.0.0.1", 0), onboarding.Handler
        )
        server.completed = Event()
        server.submission_lock = Lock()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        key = "lv_test_failedSyntheticCredential"
        try:
            os.write(ack_write_fd, b"0")
            with patch.object(onboarding, "SUBMISSION_FD", write_fd), patch.object(
                onboarding, "ACK_FD", ack_read_fd
            ):
                thread.start()
                request = Request(
                    f"http://127.0.0.1:{server.server_port}/api/onboarding/key",
                    data=json.dumps({"api_key": key}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with self.assertRaises(HTTPError) as rejected:
                    urlopen(request, timeout=2)
                self.assertEqual(rejected.exception.code, 500)
                self.assertEqual(
                    rejected.exception.headers["Content-Type"],
                    "application/json; charset=utf-8",
                )
                body = rejected.exception.read()
                self.assertEqual(
                    json.loads(body),
                    {"error": "Could not store the LayerV API key"},
                )
                self.assertNotIn(key.encode(), body)
                self.assertTrue(server.completed.is_set())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
            os.close(read_fd)
            os.close(write_fd)
            os.close(ack_read_fd)
            os.close(ack_write_fd)

    def test_only_one_credential_submission_is_accepted(self):
        read_fd, write_fd = os.pipe()
        ack_read_fd, ack_write_fd = os.pipe()
        try:
            server = onboarding.ThreadingHTTPServer(
                ("127.0.0.1", 0),
                onboarding.Handler,
            )
            server.completed = Event()
            server.submission_lock = Lock()
            thread = threading.Thread(
                target=server.serve_forever,
                daemon=True,
            )
            first_key = "lv_test_firstSyntheticCredential"
            second_key = "lv_test_secondSyntheticCredential"
            os.write(ack_write_fd, b"1")
            with patch.object(onboarding, "SUBMISSION_FD", write_fd), patch.object(
                onboarding, "ACK_FD", ack_read_fd
            ):
                thread.start()
                endpoint = (
                    f"http://127.0.0.1:{server.server_port}"
                    "/api/onboarding/key"
                )
                first = Request(
                    endpoint,
                    data=json.dumps({"api_key": first_key}).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urlopen(first, timeout=2) as response:
                    self.assertEqual(response.status, 201)
                second = Request(
                    endpoint,
                    data=json.dumps({"api_key": second_key}).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with self.assertRaises(HTTPError) as rejected:
                    urlopen(second, timeout=2)
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

            self.assertEqual(rejected.exception.code, 409)
            self.assertEqual(
                os.read(read_fd, 4096),
                (first_key + "\n").encode("utf-8"),
            )
        finally:
            os.close(read_fd)
            os.close(write_fd)
            os.close(ack_read_fd)
            os.close(ack_write_fd)


if __name__ == "__main__":
    unittest.main()
