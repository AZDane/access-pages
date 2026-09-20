from http import HTTPStatus
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
import hmac
from hashlib import sha256
import json
import math
import os
import re
import socket
import socketserver
import sqlite3
import stat
import struct
import threading
import time
from pathlib import Path

from ha import (
    CAMERA_IMAGE_TYPES,
    CAMERA_IMAGE_MAX_BYTES,
    CURATED_ACTIONS,
    HomeAssistantClient,
    HomeAssistantError,
    normalize_capabilities,
    public_state_fields,
    public_resource_state,
    validate_dispatch_deadline,
)
from pages import PAGE_ID_RE, PageConfigError, PageNotFoundError, PageStore
from rate_limit import MinimumIntervalRateLimiter, SlidingWindowRateLimiter
from verification import VerificationStore


HOST = os.getenv("HA_BROKER_HOST", "0.0.0.0")
PORT = int(os.getenv("HA_BROKER_PORT", "8082"))
GUEST_SOCKET = Path(os.getenv(
    "HA_BROKER_GUEST_SOCKET", "/run/access-pages/ha-guest/http.sock"
))
GUEST_PEER_UID = 2101
TOKEN = os.environ["HA_BROKER_TOKEN"]
ADMIN_TOKEN = os.environ["HA_BROKER_ADMIN_TOKEN"]
if hmac.compare_digest(TOKEN, ADMIN_TOKEN):
    raise RuntimeError("HA broker guest and admin tokens must be distinct")
PAGE_STORE = PageStore(Path(os.getenv("HA_BROKER_POLICY_DIR", "/policy")))
PAGE_CAPABILITY_REGISTRY = Path(os.getenv(
    "HA_PAGE_CAPABILITY_REGISTRY", "/policy-capabilities/page-capabilities.json"
))
GUEST_CAPABILITY_REGISTRY = Path(os.getenv(
    "HA_GUEST_CAPABILITY_REGISTRY", "/policy-capabilities/guest-page-capabilities.json"
))
GUEST_GRANT_STORE = PageStore(Path(os.getenv(
    "HA_GUEST_GRANTS_DIR", "/data/pages"
)))
GUEST_SESSION_STORE = VerificationStore(Path(os.getenv(
    "HA_GUEST_SESSION_DB", "/data/ha-broker-runtime/guest-auth/sessions.sqlite3"
)))
GUEST_ACTION_RATE_LIMITER = SlidingWindowRateLimiter(12, 60)
GUEST_CAMERA_RATE_LIMITER = SlidingWindowRateLimiter(10, 60)
GUEST_CAMERA_REFRESH_LIMITER = MinimumIntervalRateLimiter()
HA_CLIENT = HomeAssistantClient(
    os.environ["HA_BASE_URL"],
    os.environ["HA_TOKEN"],
)


class BrokerPolicyError(ValueError):
    def __init__(self, message, status=HTTPStatus.BAD_REQUEST, retry_after=None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


# Only these broker outcomes may become guest-visible text. Unknown failures
# remain generic even when a lower layer includes an exception message.
PUBLIC_DENIALS = {
    "Verification required": "verification_required",
    "Resource not assigned": "resource_unavailable",
    "Camera not assigned": "camera_unavailable",
    "Camera image is not ready to refresh": "camera_refresh_wait",
    "Camera image refresh limit reached": "camera_refresh_limit",
    "Too many action requests": "action_rate_limit",
    "Resource not found": "action_unavailable",
    "Action not permitted": "action_unavailable",
    "Resource is read-only": "action_unavailable",
    "Proximity reading required": "proximity_required",
    "Location is not accurate enough": "proximity_inaccurate",
    "Location reading expired": "proximity_expired",
    "Location is out of range": "proximity_out_of_range",
    "Invalid location reading": "proximity_invalid",
    "Location reading is invalid": "proximity_invalid",
    "Assigned entity not found": "resource_unavailable",
    "Parameters must be an object": "invalid_parameters",
    "Unknown action parameters": "invalid_parameters",
    "Invalid temperature": "invalid_parameters",
    "Temperature is outside live capability": "control_unavailable",
    "Invalid numeric value": "invalid_parameters",
    "Value is outside live capability": "control_unavailable",
    "Unsupported option": "control_unavailable",
    "Unsupported HVAC mode": "control_unavailable",
    "Invalid fan percentage": "invalid_parameters",
    "Unsupported fan percentage": "control_unavailable",
    "Invalid brightness": "invalid_parameters",
    "Brightness is outside capability": "control_unavailable",
    "Invalid volume": "invalid_parameters",
    "Volume is outside capability": "control_unavailable",
}


def _emit_guest_event(page_id, grant_id, event, **validated):
    """Best-effort report from the policy broker to the admin authority."""
    body = json.dumps({"page_id": page_id, "grant_id": grant_id,
                       "event": event, **validated}, separators=(",", ":")).encode()
    connection = HTTPConnection("127.0.0.1", 8081, timeout=3)
    try:
        connection.request(
            "POST", "/api/internal/guest-event", body=body,
            headers={"Content-Type": "application/json",
                     "X-HA-Broker-Token": ADMIN_TOKEN},
        )
        response = connection.getresponse()
        response.read(1024)
        if response.status != HTTPStatus.OK:
            print(f"guest event rejected: {event} ({response.status})", flush=True)
    except (HTTPException, OSError) as error:
        print(f"guest event delivery failed: {event}: {type(error).__name__}", flush=True)
    finally:
        connection.close()


def _page(page_id):
    try:
        return PAGE_STORE.load(page_id)
    except PageNotFoundError as error:
        raise BrokerPolicyError("Page not found", HTTPStatus.NOT_FOUND) from error
    except PageConfigError as error:
        raise BrokerPolicyError("Page policy is invalid") from error


def _resource_action(page, resource_id, action_id):
    resource = next(
        (item for item in page["resources"] if item["id"] == resource_id),
        None,
    )
    if resource is None:
        raise BrokerPolicyError("Resource not found", HTTPStatus.NOT_FOUND)
    action = next(
        (item for item in resource["actions"] if item["id"] == action_id),
        None,
    )
    if action is None:
        raise BrokerPolicyError("Action not permitted", HTTPStatus.NOT_FOUND)
    if action["service"] not in CURATED_ACTIONS.get(resource["domain"], {}):
        raise BrokerPolicyError("Action not permitted", HTTPStatus.FORBIDDEN)
    if resource["domain"] == "sensor" or action["service"] == "view":
        raise BrokerPolicyError("Resource is read-only", HTTPStatus.FORBIDDEN)
    return resource, action


def camera_image(page_id, resource_id):
    page = _page(page_id)
    resource = next(
        (item for item in page["resources"] if item["id"] == resource_id),
        None,
    )
    if resource is None or resource["domain"] != "camera":
        raise BrokerPolicyError("Camera not found", HTTPStatus.NOT_FOUND)
    return HA_CLIENT.get_camera_image(resource["entity_id"])


def _finite(value, message):
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise BrokerPolicyError(message) from error
    if not math.isfinite(result):
        raise BrokerPolicyError(message)
    return result


def _matches_step(value, minimum, maximum, step):
    if value == maximum:
        return True
    quotient = (value - minimum) / step
    return math.isclose(quotient, round(quotient), abs_tol=1e-7)


def _service_data(resource, action, supplied):
    if not isinstance(supplied, dict):
        raise BrokerPolicyError("Parameters must be an object")
    domain = resource["domain"]
    needs_state = (
        domain in {"climate", "number", "input_number", "select", "input_select"}
        or (domain == "fan" and action["service"] == "set_percentage")
    )
    state = {}
    if needs_state:
        states = HA_CLIENT.get_states({resource["entity_id"]})
        state = next(
            (item for item in states if item.get("entity_id") == resource["entity_id"]),
            None,
        )
        if state is None:
            raise BrokerPolicyError("Assigned entity not found", HTTPStatus.NOT_FOUND)
    capabilities = normalize_capabilities(
        resource["domain"],
        state.get("state"),
        state.get("attributes") or {},
        {item["service"] for item in resource["actions"]},
    )
    service = action["service"]
    allowed_keys = set()
    result = {}

    if domain == "climate" and service == "set_temperature":
        allowed_keys = {"temperature"}
        value = _finite(supplied.get("temperature"), "Invalid temperature")
        cap = capabilities.get("climate", {}).get("temperature")
        if (
            not cap
            or value < cap["min"]
            or value > cap["max"]
            or not _matches_step(value, cap["min"], cap["max"], cap["step"])
        ):
            raise BrokerPolicyError("Temperature is outside live capability")
        result["temperature"] = value
    elif domain == "climate" and service == "set_hvac_mode":
        allowed_keys = {"hvac_mode"}
        value = str(supplied.get("hvac_mode", "")).strip()
        if value not in capabilities.get("climate", {}).get("hvac_modes", []):
            raise BrokerPolicyError("Unsupported HVAC mode")
        result["hvac_mode"] = value
    elif domain in {"number", "input_number"}:
        allowed_keys = {"value"}
        value = _finite(supplied.get("value"), "Invalid numeric value")
        cap = capabilities.get("number")
        if (
            not cap
            or value < cap["min"]
            or value > cap["max"]
            or not _matches_step(value, cap["min"], cap["max"], cap["step"])
        ):
            raise BrokerPolicyError("Value is outside live capability")
        result["value"] = value
    elif domain in {"select", "input_select"}:
        allowed_keys = {"option"}
        value = str(supplied.get("option", "")).strip()
        if value not in capabilities.get("select", {}).get("options", []):
            raise BrokerPolicyError("Unsupported option")
        result["option"] = value
    elif domain == "fan" and service == "set_percentage":
        allowed_keys = {"percentage"}
        try:
            value = int(supplied.get("percentage"))
        except (TypeError, ValueError, OverflowError) as error:
            raise BrokerPolicyError("Invalid fan percentage") from error
        if value not in capabilities.get("fan_percentage", {}).get("values", []):
            raise BrokerPolicyError("Unsupported fan percentage")
        result["percentage"] = value
    elif (
        domain == "light"
        and service == "turn_on"
        and "brightness_pct" in supplied
    ):
        allowed_keys = {"brightness_pct"}
        try:
            value = int(supplied.get("brightness_pct"))
        except (TypeError, ValueError, OverflowError) as error:
            raise BrokerPolicyError("Invalid brightness") from error
        if value < 1 or value > 100:
            raise BrokerPolicyError("Brightness is outside capability")
        result["brightness_pct"] = value
    elif domain == "media_player" and service == "volume_set":
        allowed_keys = {"volume_level"}
        value = _finite(supplied.get("volume_level"), "Invalid volume")
        if value < 0 or value > 1:
            raise BrokerPolicyError("Volume is outside capability")
        result["volume_level"] = value

    if set(supplied) - allowed_keys:
        raise BrokerPolicyError("Unknown action parameters")
    return result


def execute_page_action(page_id, resource_id, action_id, parameters, grant_deadline=None):
    page = _page(page_id)
    resource, action = _resource_action(page, resource_id, action_id)
    service_data = _service_data(resource, action, parameters)
    if grant_deadline is not None:
        validate_dispatch_deadline(grant_deadline)
    HA_CLIENT.call_service(
        resource["domain"],
        action["service"],
        resource["entity_id"],
        service_data,
        **({"grant_deadline": grant_deadline} if grant_deadline is not None else {}),
    )
    return {"success": True}


def verify_page_proximity(page_id, reading):
    page = _page(page_id)
    policy = page.get("proximity", {})
    if not policy.get("enabled", False):
        raise BrokerPolicyError("Proximity is not enabled for this page")
    if not isinstance(reading, dict):
        raise BrokerPolicyError("Location reading is invalid")
    try:
        within_range = HA_CLIENT.verify_proximity(
            page_id,
            reading,
            int(policy["radius_meters"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise BrokerPolicyError("Location reading is invalid") from error
    return {"within_range": within_range}


def notification_targets():
    services = HA_CLIENT._request("GET", "/api/services")
    notify = next(
        (item for item in services if item.get("domain") == "notify"), {}
    )
    service_catalog = notify.get("services") or {}
    if isinstance(service_catalog, dict):
        service_names = service_catalog
    elif isinstance(service_catalog, list):
        service_names = [
            str(item.get("service") or item.get("name") or "")
            for item in service_catalog if isinstance(item, dict)
        ]
    else:
        service_names = []
    legacy = {
        f"notify.{name}" for name in service_names
        if str(name).startswith("mobile_app_")
    }
    states = HA_CLIENT._request("GET", "/api/states")
    entities = {
        str(item.get("entity_id", "")) for item in states
        if isinstance(item, dict)
        and str(item.get("entity_id", "")).startswith("notify.mobile_app_")
    }
    return sorted(legacy | entities)


def send_notification(target, title, message):
    if target not in notification_targets():
        raise BrokerPolicyError("Notification target is not registered")
    states = HA_CLIENT._request("GET", "/api/states")
    entity_ids = {
        str(item.get("entity_id", "")) for item in states
        if isinstance(item, dict)
    }
    payload = {"title": str(title)[:120], "message": str(message)[:500]}
    if target in entity_ids:
        payload["target"] = {"entity_id": target}
        path = "/api/services/notify/send_message"
    else:
        path = f"/api/services/notify/{target.removeprefix('notify.')}"
    HA_CLIENT._request("POST", path, payload)
    return {"success": True}


class Handler(BaseHTTPRequestHandler):
    def _authorized(self, *, admin=False):
        supplied = self.headers.get("X-Broker-Token", "")
        if admin:
            return hmac.compare_digest(supplied, ADMIN_TOKEN)
        return hmac.compare_digest(supplied, TOKEN)

    def _admin_request(self):
        role = self.headers.get("X-Broker-Role", "guest")
        if role not in {"guest", "admin"}:
            return None
        return self.path == "/v1/discovery" or role == "admin"

    def _authorized_page(self):
        supplied = self.headers.get("X-Broker-Token", "")
        if not supplied:
            return ""
        try:
            registry = json.loads(
                PAGE_CAPABILITY_REGISTRY.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return ""
        supplied_hash = sha256(supplied.encode()).hexdigest()
        for page_id, expected_hash in registry.items():
            if hmac.compare_digest(supplied_hash, str(expected_hash)):
                return str(page_id)
        return ""

    def log_message(self, *_args):
        return

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_image(self, body, content_type):
        if content_type not in CAMERA_IMAGE_TYPES:
            raise BrokerPolicyError("Unsupported camera image")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 64 * 1024:
            raise BrokerPolicyError("Invalid request size")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise BrokerPolicyError("Request must be an object")
        return value

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        role = self.headers.get("X-Broker-Role", "guest")
        admin_request = role == "admin"
        bound_page_id = "" if admin_request else self._authorized_page()
        if role not in {"guest", "admin"} or not (
            self._authorized(admin=True) if admin_request else bound_page_id
        ):
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            payload = self._payload()
            if self.path == "/v1/states":
                requested = payload.get("entity_ids")
                if not isinstance(requested, list) or not requested:
                    raise BrokerPolicyError("Entity IDs are required")
                assigned = {
                    resource["entity_id"]
                    for page in (
                        [_page(bound_page_id)] if bound_page_id else
                        [_page(item["id"]) for item in PAGE_STORE.list_pages()]
                    )
                    for resource in page["resources"]
                }
                if any(item not in assigned for item in requested):
                    raise BrokerPolicyError("Entity is not assigned", HTTPStatus.FORBIDDEN)
                states = HA_CLIENT.get_states(set(requested))
                self._send(200, states)
            elif self.path == "/v1/camera-image":
                body, content_type = camera_image(
                    bound_page_id or str(payload.get("page_id", "")),
                    str(payload.get("resource_id", "")),
                )
                self._send_image(body, content_type)
            elif self.path == "/v1/page-action":
                self._send(
                    200,
                    execute_page_action(
                        bound_page_id or str(payload.get("page_id", "")),
                        str(payload.get("resource_id", "")),
                        str(payload.get("action_id", "")),
                        payload.get("parameters", {}),
                        payload.get("grant_deadline"),
                    ),
                )
            elif self.path == "/v1/proximity":
                self._send(
                    200,
                    verify_page_proximity(
                        bound_page_id or str(payload.get("page_id", "")),
                        payload.get("reading"),
                    ),
                )
            elif self.path == "/v1/notification-targets":
                if not admin_request:
                    raise BrokerPolicyError("Admin authority required", HTTPStatus.FORBIDDEN)
                self._send(
                    200,
                    {"targets": notification_targets()},
                )
            elif self.path == "/v1/send-notification":
                if not admin_request:
                    raise BrokerPolicyError("Admin authority required", HTTPStatus.FORBIDDEN)
                self._send(
                    200,
                    send_notification(
                        str(payload.get("target", "")),
                        str(payload.get("title", "")),
                        str(payload.get("message", "")),
                    ),
                )
            elif self.path == "/v1/revoke-guest-sessions":
                if not admin_request:
                    raise BrokerPolicyError("Admin authority required", HTTPStatus.FORBIDDEN)
                page_id = payload.get("page_id")
                grant_id = payload.get("grant_id")
                if (set(payload) != {"page_id", "grant_id"}
                        or not isinstance(page_id, str)
                        or not PAGE_ID_RE.fullmatch(page_id)
                        or not isinstance(grant_id, str)
                        or not re.fullmatch(r"grant_[A-Za-z0-9_-]{16}", grant_id)):
                    raise BrokerPolicyError("Invalid guest session cleanup")
                # Current grant removal is already the authoritative denial.
                # Never delete a session for a grant that is still live.
                if _current_guest_grant(page_id, grant_id):
                    raise BrokerPolicyError("Guest grant remains active", HTTPStatus.CONFLICT)
                GUEST_SESSION_STORE.revoke(page_id, grant_id)
                self._send(200, {"success": True})
            elif self.path == "/v1/discovery":
                if not admin_request:
                    raise BrokerPolicyError("Admin authority required", HTTPStatus.FORBIDDEN)
                self._send(
                    200,
                    HA_CLIENT.discover_entities(
                        force=bool(payload.get("force", False))
                    ),
                )
            else:
                self._send(404, {"error": "not found"})
        except (BrokerPolicyError, json.JSONDecodeError) as error:
            self._send(
                getattr(error, "status", HTTPStatus.BAD_REQUEST),
                {"error": str(error) or "Invalid request"},
            )
        except HomeAssistantError:
            self._send(HTTPStatus.BAD_GATEWAY, {"error": "Home Assistant failed"})


class GuestHandler(BaseHTTPRequestHandler):
    """Separate guest authority; never dispatch to the TCP broker handler."""

    def _send_page(self, page_id):
        body = json.dumps({"page_id": page_id}).encode("ascii")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_result(self, payload):
        body = json.dumps(payload).encode("ascii")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_denial(self, status, code, retry_after=None):
        body = json.dumps({"code": code}).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        self.end_headers()
        self.wfile.write(body)

    def _send_image(self, body, content_type):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _bound_page(self):
        capabilities = self.headers.get_all("X-Page-Capability", [])
        claims = self.headers.get_all("X-Access-Pages-Page-ID", [])
        if len(capabilities) != 1 or len(claims) > 1:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return ""
        claimed_page = claims[0] if claims else ""
        if claimed_page and not PAGE_ID_RE.fullmatch(claimed_page):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return ""
        page_id = _guest_page_identity(capabilities[0])
        if not page_id:
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return ""
        if claimed_page and claimed_page != page_id:
            self.send_error(HTTPStatus.FORBIDDEN)
            return ""
        return page_id

    def do_GET(self):
        if self.path != "/guest/v1/health":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = b'{"status":"ok","authority":"guest"}'
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path not in {
            "/guest/v1/page-identity",
            "/guest/v1/bootstrap",
            "/guest/v1/bootstrap-resume",
            "/guest/v1/session-status",
            "/guest/v1/verification-challenge",
            "/guest/v1/verification-verify",
            "/guest/v1/resource-state",
            "/guest/v1/page-view",
            "/guest/v1/camera",
            "/guest/v1/action",
        }:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if self.headers.get("Transfer-Encoding"):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        try:
            length = int(lengths[0]) if lengths else 0
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if self.path == "/guest/v1/page-identity":
            if length != 0:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            page_id = self._bound_page()
            if not page_id:
                return
            # A page capability is identity, never guest authorization.
            self._send_page(page_id)
            return
        if not 0 < length <= 1024:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        page_id = self._bound_page()
        if not page_id:
            return
        try:
            payload = json.loads(
                self.rfile.read(length), object_pairs_hook=_unique_object_pairs,
            )
            fields = {
                "/guest/v1/bootstrap": {"grant_id", "bootstrap"},
                "/guest/v1/bootstrap-resume": {"grant_id", "session", "bootstrap"},
                "/guest/v1/session-status": {"grant_id", "session"},
                "/guest/v1/verification-challenge": {
                    "grant_id", "session", "replace",
                },
                "/guest/v1/verification-verify": {
                    "grant_id", "session", "code",
                },
                "/guest/v1/resource-state": {
                    "grant_id", "session", "resource_id",
                },
                "/guest/v1/page-view": {"grant_id", "session"},
                "/guest/v1/camera": {"grant_id", "session", "resource_id"},
                "/guest/v1/action": {
                    "grant_id", "session", "resource_id", "action_id",
                    "parameters", "proximity",
                },
            }
            if not isinstance(payload, dict) or set(payload) != fields[self.path]:
                raise ValueError("Invalid scoped request")
            grant_id = payload["grant_id"]
            field_name = "bootstrap" if self.path == "/guest/v1/bootstrap" else "session"
            secret = payload[field_name]
            if (
                not isinstance(grant_id, str)
                or not re.fullmatch(r"grant_[A-Za-z0-9_-]{16}", grant_id)
                or not isinstance(secret, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", secret)
            ):
                raise ValueError("Invalid scoped credentials")
            if self.path == "/guest/v1/verification-challenge" and type(payload["replace"]) is not bool:
                raise ValueError("Invalid replacement request")
            if self.path == "/guest/v1/verification-verify" and (
                not isinstance(payload["code"], str)
                or len(payload["code"]) > 32
            ):
                raise ValueError("Invalid verification code")
            if self.path in {"/guest/v1/resource-state", "/guest/v1/camera", "/guest/v1/action"} and (
                not isinstance(payload["resource_id"], str)
                or not PAGE_ID_RE.fullmatch(payload["resource_id"])
            ):
                raise ValueError("Invalid resource ID")
            if self.path == "/guest/v1/action" and (
                not isinstance(payload["action_id"], str)
                or not PAGE_ID_RE.fullmatch(payload["action_id"])
                or not isinstance(payload["parameters"], dict)
                or (payload["proximity"] is not None and (
                    not isinstance(payload["proximity"], dict)
                    or set(payload["proximity"]) != {
                        "latitude", "longitude", "accuracy_meters", "measured_at",
                    }
                ))
            ):
                raise ValueError("Invalid action request")
        except (ValueError, UnicodeDecodeError):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        try:
            if self.path == "/guest/v1/bootstrap":
                result = _exchange_guest_bootstrap(page_id, grant_id, secret)
            elif self.path == "/guest/v1/bootstrap-resume":
                result = _resume_guest_bootstrap(
                    page_id, grant_id, secret, payload["bootstrap"]
                )
            elif self.path == "/guest/v1/verification-challenge":
                result = _request_guest_verification(
                    page_id, grant_id, secret, payload["replace"]
                )
            elif self.path == "/guest/v1/verification-verify":
                result = _verify_guest_code(
                    page_id, grant_id, secret, payload["code"]
                )
            elif self.path == "/guest/v1/resource-state":
                result = _guest_resource_state(
                    page_id, grant_id, secret, payload["resource_id"]
                )
            elif self.path == "/guest/v1/page-view":
                result = _guest_page_view(page_id, grant_id, secret)
            elif self.path == "/guest/v1/camera":
                result = _guest_camera(page_id, grant_id, secret, payload["resource_id"])
            elif self.path == "/guest/v1/action":
                result = _guest_action(
                    page_id, grant_id, secret, payload["resource_id"],
                    payload["action_id"], payload["parameters"],
                    payload["proximity"],
                )
            else:
                result = _guest_session_status(page_id, grant_id, secret)
        except BrokerPolicyError as error:
            self._send_denial(error.status, PUBLIC_DENIALS.get(str(error), "access_denied"),
                              error.retry_after)
            return
        except ValueError:
            self._send_denial(
                HTTPStatus.UNAUTHORIZED
                if self.path == "/guest/v1/verification-verify"
                else HTTPStatus.TOO_MANY_REQUESTS,
                "verification_invalid" if self.path == "/guest/v1/verification-verify"
                else "request_limit",
            )
            return
        except HomeAssistantError:
            self._send_denial(HTTPStatus.BAD_GATEWAY, "ha_unavailable")
            return
        except (OSError, sqlite3.Error):
            self._send_denial(HTTPStatus.SERVICE_UNAVAILABLE, "temporarily_unavailable")
            return
        if result is None:
            self._send_denial(HTTPStatus.UNAUTHORIZED, "access_ended")
            return
        if self.path == "/guest/v1/camera":
            self._send_image(*result)
        else:
            self._send_result(result)

    def log_message(self, *_args):
        return


def _unique_object_pairs(pairs):
    entries = {}
    for key, value in pairs:
        if key in entries:
            raise ValueError("Duplicate JSON key")
        entries[key] = value
    return entries


def _guest_page_identity(capability):
    """Resolve only a current page; a capability is not guest authorization."""
    if not isinstance(capability, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{16,128}", capability
    ):
        return ""
    try:
        registry = json.loads(
            GUEST_CAPABILITY_REGISTRY.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object_pairs,
        )
    except (OSError, ValueError):
        return ""
    if not isinstance(registry, dict):
        return ""
    digest = sha256(capability.encode("ascii")).hexdigest()
    matches = []
    for page_id, expected in registry.items():
        if (
            not isinstance(page_id, str)
            or not PAGE_ID_RE.fullmatch(page_id)
            or not isinstance(expected, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected)
        ):
            return ""
        if hmac.compare_digest(digest, expected):
            matches.append(page_id)
    if len(matches) != 1:
        return ""
    try:
        PAGE_STORE.load(matches[0])
    except (PageNotFoundError, PageConfigError, OSError):
        return ""
    return matches[0]


def _current_guest_grant(page_id, grant_id):
    """Read current admin-owned grant definitions; never copy their authority."""
    try:
        page = GUEST_GRANT_STORE.load(page_id)
    except (PageNotFoundError, PageConfigError, OSError):
        return None
    for grant in page["access_grants"]:
        if grant["id"] != grant_id or grant.get("credential_flow") != "bootstrap-v1":
            continue
        expiry = int(datetime.fromisoformat(
            grant["expires_at"].replace("Z", "+00:00")
        ).timestamp())
        if expiry <= time.time():
            return None
        return grant, expiry
    return None


def _guest_session_result(page_id, grant_id, expiry, grant, session):
    verified = (
        GUEST_SESSION_STORE.guest_verified_until(session, page_id, grant_id)
        if grant["verification_required"] else None
    )
    if verified:
        expiry = min(expiry, verified)
    pending = bool(grant["verification_required"] and not verified)
    return {
        "page_id": page_id,
        "grant_id": grant_id,
        "expires_at": expiry,
        "status": "verification_required" if pending else "session_ready",
    }


def _exchange_guest_bootstrap(page_id, grant_id, bootstrap):
    current = _current_guest_grant(page_id, grant_id)
    if not current:
        return None
    grant, expiry = current
    try:
        session, stored_expiry = GUEST_SESSION_STORE.consume_bootstrap(
            page_id, grant_id, bootstrap, grant["token_hash"],
            datetime.fromtimestamp(expiry, tz=timezone.utc),
        )
    except ValueError:
        return None
    current = _current_guest_grant(page_id, grant_id)
    if not current or current[0]["token_hash"] != grant["token_hash"]:
        GUEST_SESSION_STORE.revoke(page_id, grant_id)
        return None
    grant, current_expiry = current
    result = _guest_session_result(
        page_id, grant_id, min(stored_expiry, current_expiry), grant, session
    )
    result["session"] = session
    return result


def _guest_session_status(page_id, grant_id, session):
    info = GUEST_SESSION_STORE.guest_session_info(session, page_id)
    if not info or info[0] != grant_id:
        return None
    current = _current_guest_grant(page_id, grant_id)
    if not current or not hmac.compare_digest(info[2], current[0]["token_hash"]):
        return None
    grant, current_expiry = current
    expiry = min(info[1], current_expiry)
    if expiry <= time.time():
        return None
    return _guest_session_result(page_id, grant_id, expiry, grant, session)


def _resume_guest_bootstrap(page_id, grant_id, session, bootstrap):
    """Validate the invitation as well as the existing bound session."""
    status = _guest_session_status(page_id, grant_id, session)
    current = _current_guest_grant(page_id, grant_id)
    if not status or not current or not re.fullmatch(r"[A-Za-z0-9_-]{43}", bootstrap):
        return None
    if not hmac.compare_digest(sha256(bootstrap.encode("ascii")).hexdigest(),
                               current[0]["token_hash"]):
        return None
    return status


def _send_guest_verification_email(page_id, grant_id, code):
    # The admin Gateway resolves the current recipient from its private store.
    body = json.dumps({
        "page_id": page_id, "grant_id": grant_id, "code": code,
    }).encode("ascii")
    connection = HTTPConnection("127.0.0.1", 8081, timeout=15)
    try:
        connection.request(
            "POST", "/api/internal/email/guest-verification", body=body,
            headers={"Content-Type": "application/json",
                     "X-HA-Broker-Token": ADMIN_TOKEN},
        )
        response = connection.getresponse()
        response.read()
        if response.status != HTTPStatus.OK:
            raise OSError("Guest verification email delivery failed")
    except (HTTPException, OSError) as error:
        raise OSError("Guest verification email delivery failed") from error
    finally:
        connection.close()


def _verified_guest_context(page_id, grant_id, session):
    status = _guest_session_status(page_id, grant_id, session)
    current = _current_guest_grant(page_id, grant_id)
    if not status or not current or not current[0]["verification_required"]:
        return None
    return current[1]


def _request_guest_verification(page_id, grant_id, session, replace):
    if _verified_guest_context(page_id, grant_id, session) is None:
        return None
    challenge = GUEST_SESSION_STORE.issue_guest_challenge(
        session, page_id, grant_id, replace=replace,
    )
    if challenge is None:
        return {"sent": False, "pending": True}
    code, challenge_id = challenge
    try:
        _send_guest_verification_email(page_id, grant_id, code)
        if _verified_guest_context(page_id, grant_id, session) is None:
            raise OSError("Guest grant changed during delivery")
    except OSError:
        GUEST_SESSION_STORE.cancel_guest_challenge(session, challenge_id)
        raise
    _emit_guest_event(page_id, grant_id, "verification_code_sent")
    return {"sent": True, "pending": True}


def _verify_guest_code(page_id, grant_id, session, code):
    grant_expiry = _verified_guest_context(page_id, grant_id, session)
    if grant_expiry is None:
        return None
    if not re.fullmatch(r"\d{6}", code):
        _emit_guest_event(page_id, grant_id, "verification_failed")
        raise ValueError("Invalid verification code")
    try:
        GUEST_SESSION_STORE.verify_guest_challenge(
            session, page_id, grant_id, code, grant_expiry,
        )
    except ValueError:
        _emit_guest_event(page_id, grant_id, "verification_failed")
        raise
    _emit_guest_event(page_id, grant_id, "guest_email_verified")
    return _guest_session_status(page_id, grant_id, session)


def _published_guest_resource(page_id, resource_id):
    """Resolve an Access Pages ID from current published broker policy."""
    try:
        page = PAGE_STORE.load(page_id)
    except (PageNotFoundError, PageConfigError, OSError):
        return None
    return next((item for item in page["resources"]
                 if item["id"] == resource_id and item["domain"] != "camera"), None)


def _guest_resource_state(page_id, grant_id, session, resource_id):
    status = _guest_session_status(page_id, grant_id, session)
    if not status:
        return None
    if status["status"] != "session_ready":
        raise BrokerPolicyError("Verification required", HTTPStatus.FORBIDDEN)
    _emit_guest_event(page_id, grant_id, "initial_access")
    resource = _published_guest_resource(page_id, resource_id)
    if resource is None:
        raise BrokerPolicyError("Resource not assigned", HTTPStatus.NOT_FOUND)
    entity_id = resource["entity_id"]
    states = HA_CLIENT.get_states({entity_id})
    # Revocation and policy changes committed while HA was queried fail closed.
    status = _guest_session_status(page_id, grant_id, session)
    current = _published_guest_resource(page_id, resource_id)
    if (not status or status["status"] != "session_ready" or not current
            or current["entity_id"] != entity_id):
        return None
    record = next((item for item in states
                   if isinstance(item, dict) and item.get("entity_id") == entity_id), {})
    return {"resource_id": current["id"], **public_state_fields(record)}


def _guest_page_view(page_id, grant_id, session):
    status = _guest_session_status(page_id, grant_id, session)
    if not status:
        return None
    if status["status"] != "session_ready":
        raise BrokerPolicyError("Verification required", HTTPStatus.FORBIDDEN)
    page = _page(page_id)
    # The old Gateway recorded this authenticated visit before fetching HA
    # state, so a temporary HA read failure does not erase a real visit.
    checked = _guest_session_status(page_id, grant_id, session)
    if not checked or checked["status"] != "session_ready":
        return None
    _emit_guest_event(page_id, grant_id, "initial_access")
    resources = page["resources"]
    entity_ids = {item["entity_id"] for item in resources}
    states = HA_CLIENT.get_states(entity_ids) if entity_ids else []
    current = _page(page_id)
    checked = _guest_session_status(page_id, grant_id, session)
    if not checked or checked["status"] != "session_ready" or current != page:
        return None
    by_entity = {item.get("entity_id"): item for item in states
                 if isinstance(item, dict) and item.get("entity_id") in entity_ids}
    return {
        "id": page_id,
        "title": page["title"],
        "description": page["description"],
        "proximity": {
            "required": bool(page.get("proximity", {}).get("enabled", False)),
            "radius_meters": int(page.get("proximity", {}).get("radius_meters", 500)),
            "verification_ttl_seconds": 300,
        },
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "resources": [public_resource_state(item, by_entity.get(item["entity_id"], {}))
                      for item in resources],
    }


def _guest_camera(page_id, grant_id, session, resource_id):
    status = _guest_session_status(page_id, grant_id, session)
    if not status:
        return None
    if status["status"] != "session_ready":
        raise BrokerPolicyError("Verification required", HTTPStatus.FORBIDDEN)
    _emit_guest_event(page_id, grant_id, "initial_access")
    page = _page(page_id)
    resource = next((item for item in page["resources"]
                     if item["id"] == resource_id and item["domain"] == "camera"), None)
    if resource is None:
        raise BrokerPolicyError("Camera not assigned", HTTPStatus.NOT_FOUND)
    rate_key = f"{page_id}:{grant_id}:{resource_id}"
    interval = resource.get("camera_refresh_interval", 30) or 2
    allowed, retry_after = GUEST_CAMERA_REFRESH_LIMITER.check(rate_key, interval)
    if not allowed:
        raise BrokerPolicyError("Camera image is not ready to refresh",
                                HTTPStatus.TOO_MANY_REQUESTS, retry_after)
    if not GUEST_CAMERA_RATE_LIMITER.allow(rate_key):
        raise BrokerPolicyError("Camera image refresh limit reached",
                                HTTPStatus.TOO_MANY_REQUESTS, 6)
    body, content_type = HA_CLIENT.get_camera_image(resource["entity_id"])
    current = _page(page_id)
    checked = _guest_session_status(page_id, grant_id, session)
    if (not checked or checked["status"] != "session_ready" or
            current != page or len(body) > CAMERA_IMAGE_MAX_BYTES or
            content_type not in CAMERA_IMAGE_TYPES):
        return None
    return body, content_type


def _guest_action_proximity(page, reading):
    policy = page.get("proximity", {})
    if not policy.get("enabled", False):
        return
    if reading is None:
        raise BrokerPolicyError("Proximity reading required", HTTPStatus.FORBIDDEN)
    latitude = _finite(reading["latitude"], "Invalid location reading")
    longitude = _finite(reading["longitude"], "Invalid location reading")
    accuracy = _finite(reading["accuracy_meters"], "Invalid location reading")
    measured_at = _finite(reading["measured_at"], "Invalid location reading")
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        raise BrokerPolicyError("Invalid location reading")
    radius = int(policy["radius_meters"])
    if accuracy < 0 or accuracy > min(1000, radius):
        raise BrokerPolicyError("Location is not accurate enough", HTTPStatus.FORBIDDEN)
    age = time.time() - measured_at
    if age < -30 or age > 300:
        raise BrokerPolicyError("Location reading expired", HTTPStatus.FORBIDDEN)
    if not HA_CLIENT.verify_proximity(page["id"], {
        "latitude": latitude, "longitude": longitude,
        "accuracy_meters": accuracy, "measured_at": measured_at,
    }, radius):
        raise BrokerPolicyError("Location is out of range", HTTPStatus.FORBIDDEN)


def _guest_action(page_id, grant_id, session, resource_id, action_id,
                  parameters, proximity):
    status = _guest_session_status(page_id, grant_id, session)
    if not status:
        return None
    if status["status"] != "session_ready":
        raise BrokerPolicyError("Verification required", HTTPStatus.FORBIDDEN)
    _emit_guest_event(page_id, grant_id, "initial_access")
    if not GUEST_ACTION_RATE_LIMITER.allow(f"{page_id}:{grant_id}"):
        _emit_guest_event(page_id, grant_id, "action_rate_limited")
        raise BrokerPolicyError("Too many action requests", HTTPStatus.TOO_MANY_REQUESTS)
    page = _page(page_id)
    try:
        resource, action = _resource_action(page, resource_id, action_id)
    except BrokerPolicyError as error:
        _emit_guest_event(page_id, grant_id, "unapproved_action_attempt",
                          reason="action_not_permitted" if str(error) != "Resource not found"
                          else "resource_not_assigned")
        raise
    _guest_action_proximity(page, proximity)
    service_data = _service_data(resource, action, parameters)
    # All potentially blocking policy/capability/proximity work is complete.
    # Recheck grant and published policy immediately before HA dispatch.
    current_page = _page(page_id)
    current_resource, current_action = _resource_action(
        current_page, resource_id, action_id,
    )
    if (current_resource != resource or current_action != action
            or current_page["proximity"] != page["proximity"]):
        return None
    status = _guest_session_status(page_id, grant_id, session)
    if not status or status["status"] != "session_ready":
        return None
    deadline = datetime.fromtimestamp(status["expires_at"], timezone.utc).isoformat()
    event_details = {
        "resource_id": resource["id"], "action_id": action["id"],
        "entity_id": resource["entity_id"], "entity_name": resource["name"],
        "parameters": service_data,
    }
    try:
        HA_CLIENT.call_service(
            resource["domain"], action["service"], resource["entity_id"],
            service_data, grant_deadline=deadline,
        )
    except HomeAssistantError:
        _emit_guest_event(page_id, grant_id, "action_failed", **event_details)
        raise
    _emit_guest_event(page_id, grant_id, "action_success", **event_details)
    # Once sent to HA, an action cannot be recalled by later grant revocation.
    return {"success": True, "page": page_id,
            "resource": resource_id, "action": action_id}


class GuestSocketServer(socketserver.UnixStreamServer):
    def get_request(self):
        connection, address = super().get_request()
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise PermissionError("Unix peer credentials unavailable")
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            _pid, uid, _gid = struct.unpack("3i", credentials)
            if uid != GUEST_PEER_UID:
                raise PermissionError("Guest broker peer is not Guest Service")
            return connection, address
        except (OSError, struct.error) as error:
            connection.close()
            raise PermissionError("Guest broker peer could not be verified") from error


def _guest_socket_server():
    if (os.getuid(), os.getgid(), os.getgroups()) != (2102, 2001, [2000, 2102]):
        raise RuntimeError("HA broker requires its dedicated identity")
    parent = GUEST_SOCKET.parent.parent.lstat()
    directory = GUEST_SOCKET.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode))
        != (0, 0, 0o755)
        or not stat.S_ISDIR(directory.st_mode)
        or (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode))
        != (2102, 2101, 0o2750)
    ):
        raise RuntimeError("Unsafe guest broker socket directory")
    try:
        GUEST_SOCKET.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError("Guest broker socket already exists")
    os.umask(0o077)
    server = GuestSocketServer(str(GUEST_SOCKET), GuestHandler)
    metadata = GUEST_SOCKET.lstat()
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (2102, 2101)
    ):
        server.server_close()
        raise RuntimeError("Unsafe guest broker socket ownership")
    GUEST_SOCKET.chmod(0o660)
    return server


def run():
    guest_server = _guest_socket_server()
    threading.Thread(target=guest_server.serve_forever, daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    run()
