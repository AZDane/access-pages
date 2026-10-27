"""Exercise real TLS handshakes with the packaged Python/OpenSSL runtime.

Generate disposable fixtures outside AppArmor with --generate-fixture DIR,
then mount DIR at /tmp/tls read-only. No external endpoint or production credential is used.
"""

from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading


if len(sys.argv) == 3 and sys.argv[1] == "--generate-fixture":
    directory = Path(sys.argv[2])
    directory.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem"),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    raise SystemExit(0)

server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
server_context.load_cert_chain("/tmp/tls/cert.pem", "/tmp/tls/key.pem")
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen()
listener.settimeout(0.2)
port = listener.getsockname()[1]
finished = threading.Event()
errors = []


def serve():
    while not finished.is_set():
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        try:
            with server_context.wrap_socket(connection, server_side=True) as tls:
                assert tls.recv(4) == b"ping"
                tls.sendall(b"pong")
        except ssl.SSLError:
            # Certificate rejection deliberately aborts two client handshakes.
            pass
        except Exception as error:
            errors.append(error)
        finally:
            connection.close()


thread = threading.Thread(target=serve, daemon=True)
thread.start()


def exchange(context, hostname):
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as tls:
            tls.sendall(b"ping")
            assert tls.recv(4) == b"pong"
            return tls.version()


try:
    trusted = ssl.create_default_context(cafile="/tmp/tls/cert.pem")
    for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        trusted.minimum_version = trusted.maximum_version = version
        print(f"Verified local TLS handshake: {exchange(trusted, 'localhost')}")
    for context, hostname in (
        (ssl.create_default_context(), "localhost"),
        (trusted, "wrong-hostname.invalid"),
    ):
        try:
            exchange(context, hostname)
        except ssl.SSLCertVerificationError:
            print(f"Untrusted certificate or wrong hostname rejected: {hostname}")
        else:
            raise AssertionError("TLS verification accepted an invalid peer")
finally:
    finished.set()
    thread.join(timeout=5)
    listener.close()
assert not thread.is_alive() and not errors, errors
print("Packaged TLS 1.2/1.3 handshakes and certificate verification: PASS")
