"""Exercise the packaged Gateway with full, closed, and available stderr.

Run as root in a disposable, network-none container; no host data mounts.
"""
import fcntl
import http.client
import os
import socket
import subprocess
import time


BINARY = "/usr/local/bin/access-pages-guest-endpoint"
BASE = {
    "HOST": "127.0.0.1", "GATEWAY_BOUND_PAGE_ID": "startup-probe",
    "PAGE_CAPABILITY_TOKEN": "synthetic-startup-capability",
    "GUEST_ENDPOINT_GUEST_SERVICE_SOCKET": "/run/access-pages/guest/http.sock",
}


def run_case(mode, changes, expected):
    reader, writer = os.pipe()
    if mode == "full":
        os.set_blocking(writer, False)
        try:
            while True:
                os.write(writer, b"x" * 4096)
        except BlockingIOError:
            pass
        os.set_blocking(writer, True)
    elif mode == "closed":
        os.close(reader)
        reader = None
    flags = fcntl.fcntl(writer, fcntl.F_GETFL)
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    if expected == "address already in use":
        reservation.listen()
    else:
        reservation.close()
    env = {**BASE, "PORT": str(port), **changes}
    env = {key: value for key, value in env.items() if value is not None}
    started = time.monotonic()
    child = subprocess.Popen([BINARY], env=env, stderr=writer, stdout=subprocess.DEVNULL,
                             user=23000, group=23000, extra_groups=[2004])
    try:
        if expected is None:
            deadline = started + 5
            while True:
                assert child.poll() is None, "Gateway exited before readiness"
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request("GET", "/health")
                    response = connection.getresponse()
                    assert response.status == 200
                    response.read()
                    break
                except OSError:
                    assert time.monotonic() < deadline, "Gateway blocked before readiness"
                    time.sleep(.02)
                finally:
                    connection.close()
            for _ in range(20):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request("GET", "/not-a-guest-route")
                    response = connection.getresponse()
                    assert response.status == 404
                    assert len(response.getheader("X-Access-Pages-Request-ID")) == 32
                    response.read()
                finally:
                    connection.close()
        else:
            assert child.wait(timeout=3) == 1, "Fatal startup must exit with status 1"
        assert fcntl.fcntl(writer, fcntl.F_GETFL) == flags, "Inherited pipe flags changed"
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        reservation.close()
        os.close(writer)
        if reader is not None:
            output = os.read(reader, 65536)
            os.close(reader)
    if mode == "available":
        if expected:
            assert expected.encode() in output, output
        else:
            assert output == b"", output
    print(f"PASS stderr={mode} case={changes or expected or 'valid'} seconds={time.monotonic()-started:.3f}")


for output_mode in ("full", "closed", "available"):
    run_case(output_mode, {}, None)
    for variable in (*BASE, "PORT"):
        run_case(output_mode, {variable: None}, f"missing required environment variable: {variable}")
    for value in ("bad", "0", "65536"):
        run_case(output_mode, {"PORT": value}, "invalid PORT")
    run_case(output_mode, {"GUEST_ENDPOINT_GUEST_SERVICE_SOCKET": "/invalid"}, "invalid guest service socket")
    run_case(output_mode, {}, "address already in use")
