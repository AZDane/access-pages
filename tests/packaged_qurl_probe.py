"""Offline qURL lifecycle/lock probe in a disposable App container.

Run as the packaged broker UID with --network none. The empty owner-bound
registry is synthetic; this does not claim live enrollment or tunnel access.
"""

import fcntl
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time

from guest_resources import ConnectorPublisher
from layerv import LayerVError

assert os.getuid() == 2103, "Run as the packaged access-pages-broker identity"
assert ssl.create_default_context().cert_store_stats()["x509_ca"] > 0
assert subprocess.check_output(["/usr/local/bin/qurl", "--version"], text=True).strip() == "qurl version 3.0.0"


def publisher_at(directory):
    publisher = ConnectorPublisher(
        Path(directory) / "state", api_base_url="http://127.0.0.1:9",
        enrollment_key="unused-offline-fixture",
    )
    return publisher


with tempfile.TemporaryDirectory(prefix="qurl-probe-") as directory:
    publisher = publisher_at(directory)
    # No routes => qURL defers opening the sealed envelope/session factory.
    # Only the App-side required-file checks use this sentinel. All daemon
    # processes, Unix IPC, locks, signals and process identities below are real.
    publisher.agent_state.write_text("offline-envelope-sentinel")
    publisher.agent_state.chmod(0o600)
    publisher.runtime_mode.write_text('{"schema_version":1,"supervision":"external"}')
    publisher.runtime_mode.chmod(0o600)
    publisher.wrapping_key.write_bytes(b"k" * 32)
    publisher.wrapping_key.chmod(0o600)
    publisher.bootstrap_complete.touch(mode=0o600)
    registry = publisher.state / "local_shares.json"
    registry.write_text(json.dumps({"version": 2, "owner_id": "offline-owner", "shares": {}}))
    registry.chmod(0o600)
    original = {p: p.read_bytes() for p in (
        publisher.agent_state, publisher.runtime_mode, publisher.wrapping_key, registry,
    )}
    try:
        started = time.monotonic()
        publisher.restore()
        assert publisher.healthy()
        first_pid = publisher._ipc()["pid"]
        print(f"daemon startup/health: {time.monotonic() - started:.2f}s", flush=True)

        contender = publisher_at(directory)
        started = time.monotonic()
        try:
            contender.restore()
        except LayerVError:
            assert contender.daemon.poll() is not None
        else:
            raise AssertionError("Accepted predecessor health while own child waited on its lock")
        finally:
            contender.close()
        elapsed = time.monotonic() - started
        assert 9 <= elapsed < 17, elapsed
        assert publisher._ipc()["pid"] == first_pid and publisher.healthy()
        print(f"contended ownership fails closed; predecessor remains healthy: {elapsed:.2f}s", flush=True)

        started = time.monotonic()
        publisher.close()
        assert publisher.daemon.returncode == 130
        assert time.monotonic() - started < 6
        publisher = publisher_at(directory)
        publisher.restore()
        assert publisher._ipc()["pid"] != first_pid and publisher.healthy()
        publisher.close()
        assert publisher.daemon.returncode == 130
        print("SIGINT shutdown, released lock and warm restart: passed", flush=True)

        # An overlap that ends inside our budget must allow the waiting child
        # to acquire the same inode; never delete a lock file to force startup.
        lock_path = publisher.state / "daemon.lock"
        with lock_path.open("r+b") as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            timer = threading.Timer(0.5, lambda: fcntl.flock(lease, fcntl.LOCK_UN))
            timer.start()
            try:
                publisher = publisher_at(directory)
                publisher.restore()
                assert publisher.healthy()
            finally:
                timer.join()
        publisher.daemon.kill()
        publisher.daemon.wait(timeout=5)
        assert not publisher.healthy()
        publisher.restore()
        assert publisher.healthy()
        publisher.close()
        print("short lock overlap and recovery after killed daemon: passed", flush=True)
        assert all(p.read_bytes() == data for p, data in original.items())
        print("owner registry, supervision marker and identity files unchanged: passed", flush=True)
    finally:
        publisher.close()
