"""Unprivileged Access Pages guest HTTP boundary."""

from __future__ import annotations

import json
import http.client
import mimetypes
import os
import re
import socket
import socketserver
import stat
import struct
import time
from http.server import BaseHTTPRequestHandler
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from threading import BoundedSemaphore
from urllib.parse import parse_qs, urlsplit

import guest_diagnostics as diagnostics


SOCKET_PATH = Path(os.environ.get(
    "GUEST_SERVICE_SOCKET", "/run/access-pages/guest/http.sock"
))
GUEST_UID = 2101
GUEST_GID = 2101
TRANSPORT_GID = 2004
BROKER_SOCKET = Path(os.environ.get(
    "HA_BROKER_GUEST_SOCKET", "/run/access-pages/ha-guest/http.sock"
))
STATIC_DIR = Path("/app/static")
GUEST_ROUTE = re.compile(r"/g/([a-z0-9][a-z0-9_-]{0,63})/(grant_[A-Za-z0-9_-]{16})/(.*)")
ASSETS = frozenset({
    "access.css", "access.js", "access-api.js", "home-assistant.png",
    "access-pages-mark.png", "access-pages-wordmark.png",
    "guest-access-lockup.png", "guest-access-mark-transparent.png",
    "layerv.png", "layerv-wordmark.png",
})
PUBLIC_GUEST_ERRORS = {
    "verification_required": "Email verification is required",
    "verification_invalid": "The verification code is invalid or expired",
    "access_ended": "This access link has expired or been revoked",
    "access_denied": "Guest access is unavailable",
    "resource_unavailable": "This resource is not available on this page",
    "camera_unavailable": "This camera is not available on this page",
    "camera_refresh_wait": "Camera image is not ready to refresh",
    "camera_refresh_limit": "Camera image refresh limit reached",
    "action_unavailable": "This action is not permitted",
    "action_rate_limit": "Too many action requests; try again shortly",
    "request_limit": "Too many requests; try again shortly",
    "proximity_required": "A location reading is required",
    "proximity_inaccurate": "Location is not accurate enough",
    "proximity_expired": "Location reading expired; try again",
    "proximity_out_of_range": "Location is outside the allowed area",
    "proximity_invalid": "Invalid location reading",
    "invalid_parameters": "Invalid action parameters",
    "control_unavailable": "This control is not available for that value",
    "ha_unavailable": "Home Assistant could not complete the request",
    "temporarily_unavailable": "Guest access temporarily unavailable",
    "action_deadline": "This command timed out before dispatch. Refresh state before trying again.",
}
GUEST_REQUEST_SLOTS = BoundedSemaphore(64)


@diagnostics.timed_work("guest_service", "connector_health")
def _connector_healthy() -> bool:
    broker = http.client.HTTPConnection("127.0.0.1", 8083, timeout=2)
    try:
        broker.request("GET", "/health")
        response = broker.getresponse()
        response.read(1024)
        return response.status == 200
    finally:
        broker.close()


def _unique_object_pairs(pairs):
    entries = {}
    for key, value in pairs:
        if key in entries:
            raise ValueError("Duplicate guest request field")
        entries[key] = value
    return entries


def _check_directory(path: Path, uid: int, gid: int, mode: int) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise RuntimeError(f"Unsafe guest service directory: {path}")


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/broker-health":
            try:
                _broker_health()
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
                self.send_error(503)
                return
            body = b'{"status":"ready","broker":"guest"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/health":
            self.send_error(404)
            return
        body = json.dumps({
            "status": "ready", "uid": os.getuid(), "gid": os.getgid(),
        }).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        fields = {
            "/broker-page": {"capability", "page_id"},
            "/broker-bootstrap": {
                "capability", "page_id", "grant_id", "bootstrap",
            },
            "/broker-session-status": {
                "capability", "page_id", "grant_id", "session",
            },
            "/broker-verification-challenge": {
                "capability", "page_id", "grant_id", "session", "replace",
            },
            "/broker-verification-verify": {
                "capability", "page_id", "grant_id", "session", "code",
            },
            "/broker-resource-state": {
                "capability", "page_id", "grant_id", "session", "resource_id",
            },
            "/broker-action": {
                "capability", "page_id", "grant_id", "session",
                "resource_id", "action_id", "parameters", "proximity",
            },
        }
        if self.path not in fields:
            self.send_error(404)
            return
        # These private test paths translate credentials; the broker decides.
        try:
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Body framing is not supported")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                raise ValueError("Invalid request framing")
            length = int(lengths[0])
            if not 0 < length <= 1024:
                raise ValueError("Invalid request size")
            payload = json.loads(
                self.rfile.read(length), object_pairs_hook=_unique_object_pairs,
            )
            if not isinstance(payload, dict) or set(payload) != fields[self.path]:
                raise ValueError("Invalid page identity request")
            if self.path == "/broker-page":
                status, page_id = _broker_page_identity(
                    payload["capability"], payload["page_id"]
                )
                result = {"page_id": page_id}
            else:
                status, result = _broker_guest_auth(self.path, payload)
        except (ValueError, TypeError, json.JSONDecodeError):
            self.send_error(400)
            return
        except (OSError, RuntimeError):
            self.send_error(503)
            return
        if status != 200:
            self.send_error(status)
            return
        body = json.dumps(result).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class GuestHandler(HealthHandler):
    def send_response(self, code, message=None) -> None:
        # The public Go endpoint owns fixed guest response headers. Avoid
        # BaseHTTPRequestHandler's version-bearing Server header upstream.
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def send_error(self, code, message=None, explain=None) -> None:
        self._json(code, {"error": "Guest request denied"})

    def _send(self, status: int, body: bytes, content_type: str,
              headers: dict[str, str] | None = None) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The peer has gone away; a second response cannot reach it.
            self.close_connection = True
            diagnostics.emit("guest_response_written", "guest_service", status=status,
                             outcome="disconnected")
        else:
            diagnostics.emit("guest_response_written", "guest_service", status=status,
                             outcome=getattr(self, "_failure_outcome", None) or (
                                 "success" if status < 400 else
                                 "unavailable" if status >= 500 else "denied"))

    def _json(self, status: int, payload: dict,
              headers: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json", headers)

    def _cookie(self) -> str:
        values = self.headers.get_all("Cookie", [])
        if len(values) != 1:
            return ""
        cookies = SimpleCookie()
        try:
            cookies.load(values[0])
        except (CookieError, ValueError):
            return ""
        token = cookies.get("access_pages_guest")
        return token.value if token and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", token.value) else ""

    def _asset(self, filename: str) -> None:
        if filename not in ASSETS:
            self._json(404, {"error": "not found"})
            return
        body = (STATIC_DIR / filename).read_bytes()
        self._send(200, body, mimetypes.guess_type(filename)[0] or "application/octet-stream")

    def _payload(self) -> dict:
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            raise ValueError("Invalid request body")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 4096:
            raise ValueError("Invalid request body")
        payload = json.loads(
            self.rfile.read(int(lengths[0])), object_pairs_hook=_unique_object_pairs,
        )
        if not isinstance(payload, dict):
            raise ValueError("Invalid request body")
        return payload

    def do_GET(self) -> None:
        if self.path in {"/health", "/broker-health"}:
            super().do_GET()
            return
        self._guest("GET")

    def do_POST(self) -> None:
        if self.path.startswith("/broker-"):
            super().do_POST()
            return
        self._guest("POST")

    def _guest(self, method: str) -> None:
        self._failure_outcome = None
        parsed = urlsplit(self.path)
        operation = diagnostics.guest_operation(method, parsed.path, "bootstrap" in parse_qs(parsed.query))
        try:
            timing = diagnostics.timing_from_headers(self.headers, operation, required=operation == "action")
        except ValueError:
            self._json(400, {"error": "Invalid request timing"})
            return
        token = diagnostics.CURRENT.set(timing)
        try:
            diagnostics.emit("guest_service_received", "guest_service")
            self._guest_scoped(method)
        finally:
            diagnostics.CURRENT.reset(token)

    def _guest_scoped(self, method: str) -> None:
        if not GUEST_REQUEST_SLOTS.acquire(blocking=False):
            self._json(503, {"error": "Guest access temporarily unavailable"})
            return
        try:
            diagnostics.action_remaining(20)
            self._serve_guest(method)
        except diagnostics.ActionDeadlineExceeded:
            self._failure_outcome = "deadline_exceeded"
            diagnostics.emit("action_not_dispatched", "guest_service", outcome="deadline_exceeded")
            self._json(503, {"error": PUBLIC_GUEST_ERRORS["action_deadline"]})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
            diagnostics.emit("guest_request_failed", "guest_service", outcome="disconnected")
        except TimeoutError:
            diagnostics.emit("guest_request_failed", "guest_service", outcome="timeout")
            self._failure_outcome = "timeout"
            self._json(503, {"error": "Guest access temporarily unavailable"})
        except (ValueError, TypeError, json.JSONDecodeError):
            self._json(400, {"error": "Invalid guest request"})
        except (OSError, RuntimeError):
            self._json(503, {"error": "Guest access temporarily unavailable"})
        finally:
            GUEST_REQUEST_SLOTS.release()

    def _serve_guest(self, method: str) -> None:
        parsed = urlsplit(self.path)
        if method == "GET" and parsed.path.startswith("/static/") and not parsed.query:
            self._asset(parsed.path.removeprefix("/static/"))
            return
        # The LayerV broker remains listening in administrative recovery, but
        # no existing guest session may be used while its Agent is invalid.
        if not _connector_healthy():
            self._json(503, {"error": "Guest access temporarily unavailable"})
            return
        match = GUEST_ROUTE.fullmatch(parsed.path)
        if (not match or not parsed.path.isascii() or "%" in parsed.path or
                "\\" in parsed.path or any(part in {".", "..", ""}
                for part in parsed.path.split("/")[1:-1])):
            self._json(404, {"error": "not found"})
            return
        page_id, grant_id, suffix = match.groups()
        claims = self.headers.get_all("X-Access-Pages-Page-ID", [])
        capabilities = self.headers.get_all("X-Page-Capability", [])
        if len(claims) != 1 or claims[0] != page_id or len(capabilities) != 1:
            self._json(401, {"error": "Invalid page identity"})
            return
        capability = capabilities[0]
        prefix = f"/g/{page_id}/{grant_id}/"
        query = parse_qs(parsed.query, keep_blank_values=True)
        if "bootstrap" in query:
            if method != "GET" or suffix or set(query) != {"bootstrap"} or len(query["bootstrap"]) != 1:
                raise ValueError("Invalid bootstrap request")
            session = self._cookie()
            if session:
                status, _ = _broker_guest_auth("/broker-bootstrap-resume", {
                    "capability": capability, "page_id": page_id,
                    "grant_id": grant_id, "session": session,
                    "bootstrap": query["bootstrap"][0],
                })
                if status == 200:
                    self._send(303, b"", "text/plain", {"Location": prefix})
                    return
                if status >= 500:
                    self._json(status, {"error": "Guest access temporarily unavailable"})
                    return
                if status != 401:
                    self._json(status, {"error": "Invitation unavailable"})
                    return
                # A stale browser cookie must not block a reusable invitation.
                # The broker validates the secret and enforces single-use grants.
            status, result = _broker_guest_auth("/broker-bootstrap", {
                "capability": capability, "page_id": page_id,
                "grant_id": grant_id, "bootstrap": query["bootstrap"][0],
            })
            if status != 200:
                self._json(status, {"error": "Invitation unavailable"})
                return
            max_age = max(0, result["expires_at"] - int(time.time()))
            self._send(303, b"", "text/plain", {
                "Location": prefix,
                "Set-Cookie": f"access_pages_guest={result['session']}; Path={prefix}; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}",
            })
            return
        if query and not (method == "GET" and suffix.startswith("api/access/") and set(query) == {"frame"}):
            raise ValueError("Unsupported guest query")
        session = self._cookie()
        if not session:
            self._json(401, {"error": "A valid guest session is required"})
            return
        request = {"capability": capability, "page_id": page_id,
                   "grant_id": grant_id, "session": session}
        if method == "GET" and (not suffix or suffix.startswith("static/")):
            status, result = _broker_guest_auth("/broker-session-status", request)
            if status != 200:
                code = result.get("code") if isinstance(result, dict) else None
                code = code if isinstance(code, str) else None
                self._json(status, {"error": PUBLIC_GUEST_ERRORS.get(
                    code, "Guest session unavailable",
                )})
                return
            if not suffix:
                body = (STATIC_DIR / "access.html").read_text(encoding="utf-8").replace(
                    '<html lang="en">', f'<html lang="en" data-page-id="{page_id}">', 1)
                body = body.replace('src="/static/', f'src="{prefix}static/')
                body = body.replace('href="/static/', f'href="{prefix}static/')
                body = body.replace('<head>', f'<head><base href="{prefix}">', 1)
                self._send(200, body.encode("utf-8"), "text/html; charset=utf-8")
            else:
                self._asset(suffix.removeprefix("static/"))
            return
        api = f"api/access/{page_id}"
        if suffix != api and not suffix.startswith(api + "/"):
            self._json(404, {"error": "not found"})
            return
        tail = suffix[len(api):].strip("/").split("/") if suffix != api else []
        if method == "GET":
            if not tail:
                route = "/broker-page-view"
            elif len(tail) == 2 and tail[0] == "camera" and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", tail[1]):
                route = "/broker-camera"
                request["resource_id"] = tail[1]
            else:
                self._json(404, {"error": "not found"})
                return
        else:
            if self.headers.get("X-Guest-Request") != "1":
                self._json(403, {"error": "Invalid guest request"})
                return
            payload = self._payload()
            if tail == ["verification", "send"] and set(payload) == {"replace"} and type(payload["replace"]) is bool:
                route = "/broker-verification-challenge"
                request["replace"] = payload["replace"]
            elif tail == ["verification", "verify"] and set(payload) == {"code"}:
                route = "/broker-verification-verify"
                request["code"] = payload["code"]
            elif len(tail) == 2 and all(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", part) for part in tail):
                route = "/broker-action"
                request.update({"resource_id": tail[0], "action_id": tail[1],
                                "parameters": {key: value for key, value in payload.items() if key != "proximity"},
                                "proximity": payload.get("proximity")})
            else:
                self._json(404, {"error": "not found"})
                return
        status, result = _broker_guest_auth(route, request)
        if status != 200:
            code = result.get("code") if isinstance(result, dict) else None
            code = code if isinstance(code, str) else None
            if route == "/broker-page-view" and status == 403:
                self._json(403, {"error": "Email verification is required", "verification_required": True})
            else:
                headers = ({"Retry-After": str(result["retry_after"])}
                           if result.get("retry_after") else None)
                self._json(status, {"error": PUBLIC_GUEST_ERRORS.get(code, "Guest request denied")}, headers)
            return
        if route == "/broker-camera":
            self._send(200, result["body"], result["content_type"])
        else:
            self._json(200, result)


class GuestSocketServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def _connect_broker() -> socket.socket:
    _check_directory(BROKER_SOCKET.parent.parent, 0, 0, 0o755)
    _check_directory(BROKER_SOCKET.parent, 2102, 2101, 0o2750)
    metadata = BROKER_SOCKET.lstat()
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        != (2102, 2101, 0o660)
    ):
        raise RuntimeError("Unsafe guest broker socket")
    if not hasattr(socket, "SO_PEERCRED"):
        raise RuntimeError("Unix peer credentials unavailable")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(diagnostics.action_remaining(2))
        connection.connect(str(BROKER_SOCKET))
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _pid, uid, gid = struct.unpack("3i", credentials)
        if (uid, gid) != (2102, 2001):
            raise RuntimeError("Guest broker peer has unexpected identity")
        return connection
    except Exception:
        connection.close()
        raise


def _broker_health() -> None:
    with _connect_broker() as connection:
        connection.sendall(b"GET /guest/v1/health HTTP/1.1\r\nHost: guest-broker\r\n\r\n")
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read(1024)
        if response.status != 200 or json.loads(body) != {
            "status": "ok", "authority": "guest",
        }:
            raise RuntimeError("Guest broker readiness failed")


def _broker_page_identity(capability: str, claimed_page: str) -> tuple[int, str]:
    if not isinstance(capability, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{16,128}", capability
    ):
        raise ValueError("Invalid page capability")
    if not isinstance(claimed_page, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,63}", claimed_page
    ):
        raise ValueError("Invalid claimed page")
    with _connect_broker() as connection:
        # The capability is sent only after SO_PEERCRED verifies the broker.
        connection.sendall((
            "POST /guest/v1/page-identity HTTP/1.1\r\n"
            "Host: guest-broker\r\n"
            f"X-Page-Capability: {capability}\r\n"
            f"X-Access-Pages-Page-ID: {claimed_page}\r\n"
            "Content-Length: 0\r\n\r\n"
        ).encode("ascii"))
        response = http.client.HTTPResponse(connection)
        response.begin()
        if response.status in (401, 403):
            response.read(1024)
            return response.status, ""
        if response.status != 200:
            raise RuntimeError("Guest broker rejected identity request")
        payload = json.loads(response.read(1024))
        if payload != {"page_id": claimed_page}:
            raise RuntimeError("Guest broker returned unexpected page identity")
        return 200, claimed_page


def _broker_guest_auth(path: str, payload: dict) -> tuple[int, dict]:
    try:
        return _broker_guest_auth_scoped(path, payload)
    except (OSError, http.client.HTTPException) as error:
        diagnostics.emit("broker_rpc_failed", "guest_service",
                         outcome=diagnostics.error_outcome(error))
        raise


def _broker_guest_auth_scoped(path: str, payload: dict) -> tuple[int, dict]:
    routes = {
        "/broker-bootstrap": ("/guest/v1/bootstrap", "bootstrap"),
        "/broker-bootstrap-resume": ("/guest/v1/bootstrap-resume", "session"),
        "/broker-session-status": ("/guest/v1/session-status", "session"),
        "/broker-verification-challenge": (
            "/guest/v1/verification-challenge", "session",
        ),
        "/broker-verification-verify": (
            "/guest/v1/verification-verify", "session",
        ),
        "/broker-resource-state": ("/guest/v1/resource-state", "session"),
        "/broker-page-view": ("/guest/v1/page-view", "session"),
        "/broker-camera": ("/guest/v1/camera", "session"),
        "/broker-action": ("/guest/v1/action", "session"),
    }
    route, field_name = routes[path]
    capability = payload["capability"]
    page_id = payload["page_id"]
    grant_id = payload["grant_id"]
    secret = payload[field_name]
    if (
        not isinstance(capability, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", capability)
        or not isinstance(page_id, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", page_id)
        or not isinstance(grant_id, str)
        or not re.fullmatch(r"grant_[A-Za-z0-9_-]{16}", grant_id)
        or not isinstance(secret, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", secret)
    ):
        raise ValueError("Invalid scoped credentials")
    scoped = {"grant_id": grant_id, field_name: secret}
    if path == "/broker-verification-challenge":
        if type(payload["replace"]) is not bool:
            raise ValueError("Invalid replacement request")
        scoped["replace"] = payload["replace"]
    elif path == "/broker-verification-verify":
        if not isinstance(payload["code"], str) or len(payload["code"]) > 32:
            raise ValueError("Invalid verification code")
        scoped["code"] = payload["code"]
    elif path == "/broker-bootstrap-resume":
        if not isinstance(payload["bootstrap"], str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", payload["bootstrap"]
        ):
            raise ValueError("Invalid bootstrap request")
        scoped["bootstrap"] = payload["bootstrap"]
    elif path in {"/broker-resource-state", "/broker-camera"}:
        if not isinstance(payload["resource_id"], str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,63}", payload["resource_id"]
        ):
            raise ValueError("Invalid resource ID")
        scoped["resource_id"] = payload["resource_id"]
    elif path == "/broker-action":
        if (
            not isinstance(payload["resource_id"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", payload["resource_id"])
            or not isinstance(payload["action_id"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", payload["action_id"])
            or not isinstance(payload["parameters"], dict)
            or (payload["proximity"] is not None and (
                not isinstance(payload["proximity"], dict)
                or set(payload["proximity"]) != {
                    "latitude", "longitude", "accuracy_meters", "measured_at",
                }
            ))
        ):
            raise ValueError("Invalid action request")
        scoped.update({key: payload[key] for key in (
            "resource_id", "action_id", "parameters", "proximity",
        )})
    body = json.dumps(scoped).encode("ascii")
    timing = diagnostics.CURRENT.get()
    rpc_started = diagnostics.clock_ns()
    timing_headers = timing.headers(rpc_started) if timing else ""
    with _connect_broker() as connection:
        connection.settimeout(diagnostics.action_remaining(20))
        # The broker peer is verified before any capability or session is sent.
        connection.sendall((
            f"POST {route} HTTP/1.1\r\n"
            "Host: guest-broker\r\n"
            f"X-Page-Capability: {capability}\r\n"
            f"X-Access-Pages-Page-ID: {page_id}\r\n"
            f"{timing_headers}"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body)
        diagnostics.emit("broker_rpc_sent", "guest_service",
                         duration_ns=diagnostics.clock_ns() - rpc_started)
        response = http.client.HTTPResponse(connection)
        response.begin()
        if response.status in (400, 401, 403, 404, 429, 502, 503):
            raw = response.read(1025)
            if len(raw) > 1024:
                return response.status, {}
            try:
                denial = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                denial = {}
            code = denial.get("code") if isinstance(denial, dict) else None
            result = {"code": code} if isinstance(code, str) and code in PUBLIC_GUEST_ERRORS else {}
            retry_after = response.getheader("Retry-After")
            if (response.status == 429 and retry_after and retry_after.isdecimal()
                    and 0 < int(retry_after) <= 3600):
                result["retry_after"] = int(retry_after)
            return response.status, result
        if response.status != 200:
            raise RuntimeError("Guest broker rejected scoped request")
        limit = (5 * 1024 * 1024 if path == "/broker-camera" else
                 256 * 1024 if path == "/broker-page-view" else
                 128 * 1024 if path == "/broker-resource-state" else 1024)
        body = response.read(limit + 1)
        if len(body) > limit:
            raise RuntimeError("Guest broker response is too large")
        if path == "/broker-camera":
            content_type = response.getheader("Content-Type")
            if not body or content_type not in {"image/jpeg", "image/jpg", "image/png", "image/webp"}:
                raise RuntimeError("Guest broker returned invalid camera image")
            return 200, {"body": body, "content_type": content_type}
        result = json.loads(body)
        if path == "/broker-page-view":
            if (not isinstance(result, dict) or result.get("id") != page_id or
                    not isinstance(result.get("resources"), list)):
                raise RuntimeError("Guest broker returned invalid page view")
            return 200, result
        if path == "/broker-action":
            if (
                not isinstance(result, dict)
                or set(result) != {"success", "page", "resource", "action"}
                or result != {
                    "success": True, "page": page_id,
                    "resource": payload["resource_id"],
                    "action": payload["action_id"],
                }
            ):
                raise RuntimeError("Guest broker returned invalid action status")
            return 200, result
        if path == "/broker-resource-state":
            if (
                not isinstance(result, dict)
                or set(result) != {"resource_id", "state", "state_attributes"}
                or result["resource_id"] != payload["resource_id"]
                or not isinstance(result["state_attributes"], dict)
            ):
                raise RuntimeError("Guest broker returned invalid resource state")
            return 200, result
        if path == "/broker-verification-challenge":
            if (
                not isinstance(result, dict)
                or set(result) != {"sent", "pending"}
                or type(result["sent"]) is not bool
                or result["pending"] is not True
            ):
                raise RuntimeError("Guest broker returned invalid challenge status")
            return 200, result
        expected = {"page_id", "grant_id", "expires_at", "status"}
        if field_name == "bootstrap":
            expected.add("session")
        if (
            not isinstance(result, dict)
            or set(result) != expected
            or result["page_id"] != page_id
            or result["grant_id"] != grant_id
            or type(result["expires_at"]) is not int
            or result["status"] not in {"session_ready", "verification_required"}
            or (field_name == "bootstrap" and not re.fullmatch(
                r"[A-Za-z0-9_-]{16,128}", result["session"]
            ))
        ):
            raise RuntimeError("Guest broker returned invalid scoped status")
        return 200, result


def main() -> None:
    if (os.getuid(), os.getgid(), os.getgroups()) != (GUEST_UID, GUEST_GID, []):
        raise RuntimeError("Guest service requires its dedicated identity")
    _check_directory(SOCKET_PATH.parent.parent, 0, 0, 0o755)
    _check_directory(SOCKET_PATH.parent, GUEST_UID, TRANSPORT_GID, 0o2710)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        raise RuntimeError("Guest service socket already exists")
    os.umask(0o077)
    with GuestSocketServer(str(SOCKET_PATH), GuestHandler) as server:
        metadata = SOCKET_PATH.lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (GUEST_UID, TRANSPORT_GID)
        ):
            raise RuntimeError("Guest service socket has unsafe ownership")
        SOCKET_PATH.chmod(0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()
