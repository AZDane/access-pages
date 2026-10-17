"""Manual live LayerV probe; creates/deletes only anonymous synthetic resources.

Not discovered by unittest. Run in the packaged App as UID 2103 with network
access. Never supply an account API key or point this server at Home Assistant.
"""

import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading

from guest_resources import ConnectorPublisher


CONTENT = b"Access Pages disposable connectivity probe\n"


class Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(CONTENT)))
        self.end_headers()
        self.wfile.write(CONTENT)

    def log_message(self, *args):
        pass


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def probe():
    check(os.getuid() == 2103, "Run as the packaged broker UID")
    with tempfile.TemporaryDirectory(prefix="ap-live-publish-") as temp:
        publisher = ConnectorPublisher(
            Path(temp) / "shared-state", api_base_url="https://api.layerv.ai",
            enrollment_key="unused-anonymous-probe",
        )
        publisher.wrapping_key.write_bytes(secrets.token_bytes(32))
        publisher.wrapping_key.chmod(0o600)
        server = http.server.ThreadingHTTPServer(("127.0.0.2", 8080), Probe)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def run(args):
            with publisher._key_pipe() as (fd, env):
                result = subprocess.run(
                    [*publisher.command, *args], env=env, pass_fds=(fd,),
                    capture_output=True, text=True, timeout=100,
                )
            # stdout contains guest links/credentials; do not print it or raw errors.
            print(args[0], "exit", result.returncode, flush=True)
            check(result.returncode == 0, f"{args[0]} failed; secret output withheld")
            return json.loads(result.stdout) if result.stdout.strip() else {}

        resources = {}
        try:
            run(["login", "--anonymous"])
            publisher._mark_bootstrapped()
            publisher._start()
            for isolation in ("page", "guest"):
                identifier = "ha-" + isolation + "-" + secrets.token_hex(20)
                resources[identifier] = None
                published = run(["publish", "http://127.0.0.2:8080", "--id", identifier, "--public"])
                crid = resources[identifier] = published["crid"]
                run(["share", crid, "--ttl", "5m"])
                output = Path(temp) / f"{isolation}.txt"
                run(["get", crid, "--file", str(output), "--yes"])
                check(output.read_bytes() == CONTENT, "Tunneled content differs")
                print(isolation, "fresh publication, link minting, tunneled content: passed", flush=True)
            publisher._stop_daemon()
            publisher._start()
            for identifier, crid in resources.items():
                repeated = run(["publish", "http://127.0.0.2:8080", "--id", identifier, "--public"])
                check(repeated["crid"] == crid, "Restart changed the resource identity")
            print("Warm restart and stable resource reuse: passed", flush=True)
        finally:
            cleanup_failed = False
            try:
                for identifier, crid in resources.items():
                    try:
                        if not crid:
                            # A native create may have succeeded before read-back failed.
                            envelope = run(["request", "GET", "/v1/resources?slug=" + identifier])
                            check(envelope.get("status") == 200, "Could not reconcile partial publication")
                            rows = (envelope.get("body") or {}).get("data", [])
                            matches = [row for row in rows if row.get("slug") == identifier]
                            check(len(matches) <= 1, "Ambiguous probe resource cleanup")
                            crid = matches[0]["crid"] if matches else None
                        if crid:
                            run(["delete", crid, "--yes"])
                            print("Synthetic resource deleted", flush=True)
                    except Exception:
                        cleanup_failed = True
                        print("WARNING: synthetic resource cleanup failed", flush=True)
            finally:
                publisher.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            check(not cleanup_failed, "Live probe cleanup incomplete")


if __name__ == "__main__":
    probe()
