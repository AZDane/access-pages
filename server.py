from datetime import datetime, timedelta, timezone
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import BoundedSemaphore, Lock, RLock, Thread
from urllib.parse import parse_qs, quote as quote, urlencode as urlencode, urlparse
import base64
import hmac
import json
import math
import re
import mimetypes
import os
import secrets
import sqlite3
import sys
import time

import access as access_routes
import admin as admin_routes
import internal as internal_routes
from activity import GuestActivityStore
from actions import execute_public_action
from audit import audit
from rate_limit import MinimumIntervalRateLimiter, SlidingWindowRateLimiter
from config import (
    ADMIN_TOKEN,
    ACTIVITY_DB_FILE,
    CONNECTOR_STATUS_FILE,
    GATEWAY_VERSION,
    HA_BASE_URL,
    HA_BROKER_TOKEN,
    HA_BROKER_URL,
    HA_ENTITY_EXCLUDE_AREAS,
    HA_ENTITY_EXCLUDE_DEVICE_CLASSES,
    HA_ENTITY_EXCLUDE_DOMAINS,
    HA_ENTITY_EXCLUDE_ENTITIES,
    HA_ENTITY_INCLUDE_DEVICE_CLASSES,
    HA_ENTITY_INCLUDE_AREAS,
    HA_ENTITY_INCLUDE_DOMAINS,
    HA_ENTITY_INCLUDE_ENTITIES,
    HA_TOKEN,
    HOST,
    LAYERV_API_BASE_URL,
    LAYERV_API_TOKEN,
    ACCESS_PAGES_BROKER_TOKEN,
    ACCESS_PAGES_BROKER_URL,
    LAYERV_RESOURCE_ID,
    QURL_MAX_LIFETIME_DAYS,
    PAGES_DIR,
    PORT,
    POLICY_PUBLISH_TOKEN,
    POLICY_PUBLISH_URL,
    RESET_REQUEST_FILE,
    SMTP_CONFIG_FILE,
    ALERT_CONFIG_FILE,
    VERIFICATION_RECIPIENT_FILE,
)
from email_delivery import (
    EmailConfigError,
    SMTPConfigStore,
    NotificationTargetStore,
    VerificationRecipientStore,
    guest_invitation_email_content,
    send_email,
    verification_email_content,  # noqa: F401 - exported to internal route runtime
    validate_email,
)
from ha import (
    BrokerHomeAssistantClient,
    HomeAssistantClient,
    HomeAssistantError,
    normalize_capabilities,
    public_resource_state,
)
from layerv import BrokerLayerVClient, LayerVClient, LayerVError
from pages import (
    PageConfigError,
    PageNotFoundError,
    PageStore,
    page_admin_view,  # noqa: F401 - exported through the shared route runtime
    validate_notifications,
)
from policy import (
    PolicyPublisher,
    PolicyPublishError,  # noqa: F401 - exported through the shared route runtime
)


PROXIMITY_READING_MAX_AGE_SECONDS = 300
PROXIMITY_MAX_ACCURACY_METERS = 1000

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
# Local pilot only. Packaged migration stays disabled until LayerV acceptance.

QURL_LIFETIME_RE = re.compile(r"^([1-9][0-9]{0,4})([mhdw])$")
QURL_MAX_LIFETIME = timedelta(days=QURL_MAX_LIFETIME_DAYS)


def parse_qurl_lifetime(value):
    lifetime = str(value).strip().lower()
    match = QURL_LIFETIME_RE.fullmatch(lifetime)
    if not match:
        raise ValueError(
            "Use a whole-number duration such as 30m, 12h, 3d, or 1w"
        )

    amount = int(match.group(1))
    unit = match.group(2)
    multipliers = {
        "m": timedelta(minutes=1),
        "h": timedelta(hours=1),
        "d": timedelta(days=1),
        "w": timedelta(weeks=1),
    }
    duration = amount * multipliers[unit]
    if duration > QURL_MAX_LIFETIME:
        raise ValueError(
            "qURL lifetime exceeds the configured maximum of "
            f"{QURL_MAX_LIFETIME_DAYS} days"
        )
    return lifetime, duration

HA_CLIENT_CLASS = (
    BrokerHomeAssistantClient
    if HA_BROKER_URL
    else HomeAssistantClient
)
HA_CLIENT = HA_CLIENT_CLASS(
    **(
        {
            "broker_url": HA_BROKER_URL,
            "broker_token": HA_BROKER_TOKEN,
            "broker_role": (
                "admin"
            ),
        }
        if HA_BROKER_URL
        else {"base_url": HA_BASE_URL, "token": HA_TOKEN}
    ),
    include_areas=HA_ENTITY_INCLUDE_AREAS,
    include_domains=HA_ENTITY_INCLUDE_DOMAINS,
    include_device_classes=HA_ENTITY_INCLUDE_DEVICE_CLASSES,
    include_entities=HA_ENTITY_INCLUDE_ENTITIES,
    exclude_areas=HA_ENTITY_EXCLUDE_AREAS,
    exclude_domains=HA_ENTITY_EXCLUDE_DOMAINS,
    exclude_device_classes=HA_ENTITY_EXCLUDE_DEVICE_CLASSES,
    exclude_entities=HA_ENTITY_EXCLUDE_ENTITIES,
)
PAGE_STORE = PageStore(
    PAGES_DIR,
    file_mode=int(os.getenv("PAGE_FILE_MODE", "600"), 8),
)
POLICY_PUBLISHER = PolicyPublisher(
    POLICY_PUBLISH_URL,
    POLICY_PUBLISH_TOKEN,
    pending_directory=PAGES_DIR,
)
ACTIVITY_STORE = GuestActivityStore(ACTIVITY_DB_FILE)
SMTP_CONFIG_STORE = SMTPConfigStore(SMTP_CONFIG_FILE)
NOTIFICATION_TARGET_STORE = NotificationTargetStore(ALERT_CONFIG_FILE)
VERIFICATION_RECIPIENTS = VerificationRecipientStore(
    VERIFICATION_RECIPIENT_FILE,
)
PREVIEW_ACTION_RATE_LIMITER = SlidingWindowRateLimiter(limit=12, window_seconds=60)
CAMERA_IMAGE_RATE_LIMITER = SlidingWindowRateLimiter(
    limit=10,
    window_seconds=60,
)
CAMERA_REFRESH_RATE_LIMITER = MinimumIntervalRateLimiter(max_entries=10000)
MANUAL_CAMERA_MIN_INTERVAL_SECONDS = 2
_PAGE_ACTION_LOCKS = {}
_PAGE_ACTION_LOCKS_GUARD = Lock()
RUNTIME = sys.modules[__name__]


@contextmanager
def page_action_lock(page_id):
    """Return the lock that linearizes actions and local revocation per page."""
    with _PAGE_ACTION_LOCKS_GUARD:
        entry = _PAGE_ACTION_LOCKS.setdefault(
            page_id,
            {"lock": RLock(), "users": 0},
        )
        entry["users"] += 1
    entry["lock"].acquire()
    try:
        yield
    finally:
        entry["lock"].release()
        with _PAGE_ACTION_LOCKS_GUARD:
            entry["users"] -= 1
            if entry["users"] == 0 and _PAGE_ACTION_LOCKS.get(page_id) is entry:
                del _PAGE_ACTION_LOCKS[page_id]


def layerv_error_diagnostics(error):
    """Return non-sensitive fields suitable for operational audit logs."""
    status = error.status if isinstance(error.status, int) else None
    if status in (401, 403):
        category = "authentication"
    elif status == 429:
        category = "rate_limit"
    elif status is not None and status >= 500:
        category = "upstream"
    elif status is not None:
        category = "api_rejection"
    else:
        category = "network_or_protocol"
    diagnostics = {"error_category": category}
    if status is not None:
        diagnostics["http_status"] = status
    return diagnostics


def cleanup_guest_sessions(page_id, grant_id):
    """Ask the broker to delete stale state after local grant removal."""
    if not isinstance(HA_CLIENT, BrokerHomeAssistantClient):
        return
    try:
        HA_CLIENT.revoke_guest_sessions(page_id, grant_id)
    except HomeAssistantError:
        audit("guest_session_cleanup_failed", page_id=page_id, grant_id=grant_id)


class GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    connection_timeout = 15
    max_active_requests = 64

    def __init__(self, *args, **kwargs):
        self._request_slots = BoundedSemaphore(self.max_active_requests)
        super().__init__(*args, **kwargs)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.connection_timeout)
        return connection, address

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


if ACCESS_PAGES_BROKER_URL:
    LAYERV_CLIENT = BrokerLayerVClient(
        broker_url=ACCESS_PAGES_BROKER_URL,
        broker_token=ACCESS_PAGES_BROKER_TOKEN,
        resource_id=LAYERV_RESOURCE_ID,
    )
else:
    LAYERV_CLIENT = LayerVClient(
        api_base_url=LAYERV_API_BASE_URL,
        api_token=LAYERV_API_TOKEN,
        resource_id=LAYERV_RESOURCE_ID,
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


class Handler(BaseHTTPRequestHandler):
    max_header_count = 64
    max_header_bytes = 32 * 1024

    server_version = "AccessPagesGateway/0.5"

    def _validate_entity_policy(self, payload):
        resources = payload.get("resources", [])
        if not resources:
            return
        discovered = {
            item["entity_id"]: item
            for item in HA_CLIENT.discover_entities()["entities"]
        }
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            entity_id = str(resource.get("entity_id", "")).strip()
            domain = str(resource.get("domain", "")).strip()
            entity = discovered.get(entity_id)
            if (
                entity is None
                or domain != entity.get("domain")
                or not HA_CLIENT.entity_allowed(
                    entity_id,
                    domain,
                    entity.get("device_class", ""),
                    entity.get("area_id", ""),
                )
            ):
                raise PageConfigError(
                    f"Entity is unavailable under the gateway policy: "
                    f"{entity_id}"
                )

            allowed_actions = {
                str(action.get("service", "")): str(action.get("name", ""))
                for action in entity.get("actions", [])
                if isinstance(action, dict) and action.get("service")
            }
            for action in resource.get("actions", []):
                if not isinstance(action, dict):
                    raise PageConfigError(f"Invalid action for {entity_id}")
                action_id = str(action.get("id", "")).strip()
                service = str(action.get("service", "")).strip()
                name = str(action.get("name", "")).strip()
                if (
                    service not in allowed_actions
                    or action_id != service
                    or name != allowed_actions[service]
                ):
                    raise PageConfigError(
                        f"Action is unavailable under the gateway policy: "
                        f"{domain}.{service or action_id}"
                    )

    def log_message(self, format, *args):
        # Avoid writing query-string bearer tokens into normal request logs.
        safe_path = urlparse(self.path).path
        message = "%s - - [%s] %s\n" % (
            self.address_string(),
            self.log_date_time_string(),
            format % ((safe_path,) + args[1:])
            if args and isinstance(args[0], str) and "?" in args[0]
            else format % args,
        )
        self.stderr_write(message)

    def stderr_write(self, message):
        import sys
        sys.stderr.write(message)

    def _send_bytes(self, status, body, content_type, extra_headers=None):
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data: blob:; "
                "style-src 'self'; script-src 'self'; "
                "connect-src 'self'; frame-ancestors 'none';",
            )
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            # Disconnected and deliberately slow clients are expected under
            # the network-abuse controls and should not create traceback noise.
            self.close_connection = True

    def _send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            extra_headers,
        )

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler otherwise emits an HTML error without the
        # Gateway's no-store, no-referrer, nosniff, and CSP protections.
        self._send_json(code, {"error": HTTPStatus(code).phrase})

    def _valid_request_envelope(self):
        header_count = len(self.headers)
        header_bytes = sum(
            len(name.encode("utf-8"))
            + len(value.encode("utf-8"))
            + 4
            for name, value in self.headers.items()
        )
        if (
            header_count > self.max_header_count
            or header_bytes > self.max_header_bytes
        ):
            self.close_connection = True
            self._send_json(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                {"error": "Request headers are too large"},
            )
            return False
        return True

    def _send_static_file(self, filename):
        target = (STATIC_DIR / filename).resolve()

        if STATIC_DIR.resolve() not in target.parents or not target.is_file():
            self._send_json(404, {"error": "not found"})
            return

        content_type = (
            mimetypes.guess_type(target.name)[0]
            or "application/octet-stream"
        )
        self._send_bytes(200, target.read_bytes(), content_type)

    def _send_access_shell(self, page_id):
        target = STATIC_DIR / "access.html"
        body = target.read_text(encoding="utf-8").replace(
            '<html lang="en">',
            f'<html lang="en" data-page-id="{page_id}">',
            1,
        )
        self._send_bytes(200, body.encode("utf-8"), "text/html; charset=utf-8")

    def _read_json(self, max_bytes=512_000):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("Invalid Content-Length") from error

        if content_length <= 0:
            return {}
        if content_length > max_bytes:
            raise ValueError("Request body is too large")

        body = self.rfile.read(content_length)

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(
                "Request body must be valid JSON"
            ) from error
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object")
        return payload

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def _admin_token(self):
        return self.headers.get("X-Admin-Token", "")

    def _is_admin(self):
        supplied = self._admin_token().encode("utf-8")
        expected = ADMIN_TOKEN.encode("utf-8")
        return bool(supplied) and hmac.compare_digest(
            supplied,
            expected,
        )

    def _require_admin(self):
        if self._is_admin():
            return True

        self._send_json(
            HTTPStatus.UNAUTHORIZED,
            {"error": "Valid admin token required"},
        )
        return False

    def _send_guest_invitation(self, page_id, grant, recipient):
        try:
            text, html = guest_invitation_email_content(
                grant["qurl_link"],
                verification_required=bool(grant.get("verification_required")),
            )
            send_email(
                SMTP_CONFIG_STORE.load(),
                recipient,
                "Your Access Pages invitation",
                text,
                html_body=html,
            )
            audit(
                "guest_invitation_email_sent",
                page_id=page_id,
                grant_id=grant["id"],
            )
            return True
        except EmailConfigError:
            audit(
                "guest_invitation_email_failed",
                page_id=page_id,
                grant_id=grant["id"],
            )
            return False

    def _load_page(self, page_id):
        try:
            return PAGE_STORE.load(page_id)
        except (PageConfigError, PageNotFoundError) as error:
            self._send_page_error(error)
            return None

    def _preview_token(self, page_id, expires_at):
        message = f"{page_id}:{expires_at}".encode("utf-8")
        signature = hmac.new(
            ADMIN_TOKEN.encode("utf-8"),
            message,
            "sha256",
        ).digest()
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return f"{expires_at}.{encoded}"

    def _valid_preview_token(self, page_id, supplied_token):
        if not supplied_token or "." not in supplied_token:
            return False

        expires_text, supplied_signature = supplied_token.split(".", 1)
        try:
            expires_at = int(expires_text)
        except ValueError:
            return False

        if expires_at <= int(utc_now().timestamp()):
            return False

        expected = self._preview_token(page_id, expires_at)
        return hmac.compare_digest(supplied_token, expected)

    def _require_preview_access(self, page):
        if POLICY_PUBLISHER.pending(page["id"]):
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Page policy is awaiting reconciliation"})
            return False
        token = self._query().get("preview_token", [""])[0]
        if not self._valid_preview_token(page["id"], token):
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Valid admin preview required"})
            return False
        self.action_deadline = isoformat(datetime.fromtimestamp(int(token.split(".", 1)[0]), timezone.utc))
        self.camera_access_scope = "preview:" + sha256(token.encode()).hexdigest()[:24]
        return True

    def _cleanup_expired_grants(self, page_id):
        try:
            page, expired = PAGE_STORE.expire_access_grants(page_id)
        except (PageConfigError, PageNotFoundError, ValueError):
            return None

        for grant in expired:
            cleanup_guest_sessions(page_id, grant["id"])
            try:
                expired_at = parse_time(grant["expires_at"])
                ACTIVITY_STORE.mark_revoked(
                    page_id,
                    grant,
                    revoked_at=expired_at,
                )
                ACTIVITY_STORE.record_security_event(
                    page_id=page_id,
                    grant_id=grant["id"],
                    event_type="guest_access_expired",
                    details={"reason": "lifetime_ended"},
                )
            except (OSError, sqlite3.Error, ValueError):
                audit(
                    "guest_activity_storage_failed",
                    operation="expire",
                    page_id=page_id,
                    grant_id=grant["id"],
                )

            qurl_id = grant.get("qurl_id", "")
            if qurl_id:
                try:
                    LAYERV_CLIENT.delete_qurl(
                        resource_id=grant.get("resource_id", ""),
                        qurl_id=qurl_id,
                        page_id=page_id,
                        grant_id=grant["id"],
                    )
                except LayerVError as error:
                    audit(
                        "expired_qurl_cleanup_failed",
                        page_id=page_id,
                        grant_id=grant["id"],
                        qurl_id=qurl_id,
                        **layerv_error_diagnostics(error),
                    )
        return page

    def _send_ha_error(self, error):
        payload = {"error": str(error)}
        if error.status is not None:
            payload["ha_status"] = error.status
        self._send_json(HTTPStatus.BAD_GATEWAY, payload)

    def _send_layerv_error(self, error):
        payload = {"error": str(error)}
        if error.status is not None:
            payload["layerv_status"] = error.status
        headers = {"Retry-After": str(error.retry_after)} if error.retry_after is not None else None
        self._send_json(HTTPStatus.SERVICE_UNAVAILABLE if error.status == 503 else HTTPStatus.BAD_GATEWAY, payload, headers)

    def _send_page_error(self, error):
        if isinstance(error, PageNotFoundError):
            self._send_json(404, {"error": "Page not found"})
        else:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": str(error)},
            )

    def _public_page(self, page):
        entity_ids = {
            resource["entity_id"]
            for resource in page["resources"]
        }

        states_by_entity = {}

        if entity_ids:
            states = HA_CLIENT.get_states(entity_ids)
            states_by_entity = {
                state.get("entity_id"): state
                for state in states
                if state.get("entity_id") in entity_ids
            }

        resources = [
            public_resource_state(
                resource, states_by_entity.get(resource["entity_id"], {}),
            )
            for resource in page["resources"]
        ]

        return {
            "id": page["id"],
            "title": page["title"],
            "description": page["description"],
            "proximity": {
                "required": bool(
                    page.get("proximity", {}).get("enabled", False)
                ),
                "radius_meters": int(
                    page.get("proximity", {}).get("radius_meters", 500)
                ),
                "verification_ttl_seconds": (
                    PROXIMITY_READING_MAX_AGE_SECONDS
                ),
            },
            "refreshed_at": isoformat(utc_now()),
            "resources": resources,
        }

    def _send_camera_image(self, page, resource_id):
        resource = next(
            (
                item for item in page["resources"]
                if item["id"] == resource_id and item["domain"] == "camera"
            ),
            None,
        )
        if resource is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Camera not found"})
            return
        access_scope = getattr(self, "camera_access_scope", None)
        if not access_scope:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Valid admin preview required"})
            return
        rate_key = f"{page['id']}:{access_scope}:{resource_id}"
        configured_interval = resource.get("camera_refresh_interval", 30)
        minimum_interval = (
            MANUAL_CAMERA_MIN_INTERVAL_SECONDS
            if configured_interval == 0
            else configured_interval
        )
        allowed, retry_after = CAMERA_REFRESH_RATE_LIMITER.check(
            rate_key, minimum_interval
        )
        if not allowed:
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Camera image is not ready to refresh"},
                {"Retry-After": str(retry_after)},
            )
            return
        if not CAMERA_IMAGE_RATE_LIMITER.allow(rate_key):
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"error": "Camera image refresh limit reached"},
                {"Retry-After": "6"},
            )
            return
        try:
            body, content_type = HA_CLIENT.get_camera_image(
                resource["entity_id"],
                page_id=page["id"],
                resource_id=resource_id,
            )
        except HomeAssistantError as error:
            self._send_ha_error(error)
            return
        deadline = getattr(self, "action_deadline", None)
        if deadline:
            from ha import validate_dispatch_deadline
            try:
                validate_dispatch_deadline(deadline)
            except HomeAssistantError:
                self._send_json(HTTPStatus.GONE, {"error": "Guest access expired while fetching the camera image"})
                return
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            {"Content-Disposition": "inline"},
        )

    def _require_proximity(self, page, payload):
        policy = page.get("proximity", {})
        if not policy.get("enabled", False):
            return True
        reading = payload.get("proximity")
        if not isinstance(reading, dict):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "You must be near the home to use controls"},
            )
            return False
        try:
            latitude = float(reading["latitude"])
            longitude = float(reading["longitude"])
            accuracy = float(reading["accuracy_meters"])
            measured_at = float(reading["measured_at"])
        except (KeyError, TypeError, ValueError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "The location reading is invalid"},
            )
            return False
        if not all(math.isfinite(value) for value in (
            latitude, longitude, accuracy, measured_at
        )) or not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "The location reading is invalid"},
            )
            return False
        radius = int(policy.get("radius_meters", 500))
        if accuracy < 0 or accuracy > min(
            PROXIMITY_MAX_ACCURACY_METERS,
            radius,
        ):
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Your location is not accurate enough to use controls"},
            )
            return False
        age = utc_now().timestamp() - measured_at
        if age < -30 or age > PROXIMITY_READING_MAX_AGE_SECONDS:
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Your location check has expired; try again"},
            )
            return False
        try:
            within_range = HA_CLIENT.verify_proximity(
                page["id"],
                {
                    "latitude": latitude,
                    "longitude": longitude,
                    "accuracy_meters": accuracy,
                    "measured_at": measured_at,
                },
                radius,
            )
        except (HomeAssistantError, KeyError, TypeError, ValueError):
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "Could not verify the Home location"},
            )
            return False
        if not within_range:
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "You are too far from the home to use controls"},
            )
            return False
        return True

    def _create_qurl(self, page_id, payload):
        page = self._load_page(page_id)
        if page is None:
            return

        try:
            lifetime, lifetime_delta = parse_qurl_lifetime(
                payload.get("lifetime", "24h")
            )
        except ValueError as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": str(error)},
            )
            return

        label = str(payload.get("label", "")).strip()[:120]
        one_time_use = bool(payload.get("one_time_use", False))
        verification_required = bool(
            payload.get("verification_required", False)
        )
        notifications = payload.get("notifications")
        if notifications is not None:
            try:
                notifications = validate_notifications(notifications)
                available = set(NOTIFICATION_TARGET_STORE.load())
                if SMTP_CONFIG_STORE.configured():
                    available.add("email")
                if any(item not in available for item in notifications["targets"]):
                    raise PageConfigError("A notification target is not configured")
            except HomeAssistantError as error:
                self._send_ha_error(error)
                return
        verification_email = ""
        send_invitation = verification_required or payload.get("send_invitation") is True
        invitation_email = ""
        if verification_required:
            try:
                verification_email = validate_email(payload.get("verification_email"), "Guest email")
                if not SMTP_CONFIG_STORE.configured():
                    raise EmailConfigError("Configure email delivery before requiring verification")
            except EmailConfigError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
        if send_invitation:
            try:
                invitation_email = validate_email(
                    verification_email if verification_required else payload.get("invitation_email"), "Guest email",
                )
                if not SMTP_CONFIG_STORE.configured():
                    raise EmailConfigError("Configure email delivery before sending invitations")
            except EmailConfigError as error:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
        if one_time_use and lifetime_delta > timedelta(hours=24):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Single-use access supports at most 24 hours; use renewable access for a longer guest grant"})
            return

        raw_token = secrets.token_urlsafe(32)
        grant_id = f"grant_{secrets.token_urlsafe(12)}"
        target_path = f"/g/{page_id}/{grant_id}/?bootstrap={raw_token}"
        created_at = utc_now()
        local_expires_at = created_at + lifetime_delta

        try:
            qurl = LAYERV_CLIENT.create_qurl(
                label=label,
                expires_in=lifetime,
                one_time_use=one_time_use,
                page_id=page_id,
                grant_id=grant_id,
                target_path=target_path,
                target_path_supported=True,
                session_duration=f"{min(int(lifetime_delta.total_seconds()), 86400)}s",
            )
        except LayerVError as error:
            self._send_layerv_error(error)
            return

        expires_at = qurl.get("expires_at") or isoformat(local_expires_at)

        grant = {
            "id": grant_id,
            "token_hash": token_hash(raw_token),
            "created_at": isoformat(created_at),
            "expires_at": expires_at,
            "label": label,
            "lifetime": lifetime,
            "one_time_use": one_time_use,
            "qurl_link": qurl["qurl_link"],
            "qurl_site": qurl.get("qurl_site", ""),
            "resource_id": qurl.get("resource_id", "") or LAYERV_CLIENT.resource_id,
            "qurl_id": qurl.get("qurl_id", ""),
            "type": qurl.get("type", ""),
            "verification_required": verification_required,
            "notifications": notifications or {"targets": [], "events": []},
            "target_path_applied": bool(qurl.get("target_path_applied", False)),
            "credential_flow": "bootstrap-v1",
            "resource_crid": qurl.get("resource_crid", ""),
            "upstream_scope": qurl.get("upstream_scope", "page"),
        }

        if verification_required:
            try:
                VERIFICATION_RECIPIENTS.set(page_id, grant_id, verification_email)
            except (EmailConfigError, OSError):
                try:
                    LAYERV_CLIENT.delete_qurl(
                        resource_id=grant.get("resource_id", ""),
                        qurl_id=grant.get("qurl_id", ""),
                        page_id=page_id,
                        grant_id=grant_id,
                    )
                except LayerVError:
                    pass
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "Could not store verification recipient"},
                )
                return
        # The remote qURL request may take long enough for an administrator to
        # update or revoke this page. Reload before committing so a stale page
        # snapshot can never restore revoked grants or overwrite newer policy.
        page = PAGE_STORE.load(page_id)
        page["access_grants"].insert(0, grant)
        PAGE_STORE.replace(page_id, page)
        try:
            ACTIVITY_STORE.register_guest(page_id, grant)
        except (OSError, sqlite3.Error):
            audit(
                "guest_activity_storage_failed",
                operation="register",
                page_id=page_id,
                grant_id=grant["id"],
            )
        audit(
            "qurl_created",
            page_id=page_id,
            grant_id=grant["id"],
            qurl_id=grant.get("qurl_id"),
        )

        public_grant = {
            key: value
            for key, value in grant.items()
            if key != "token_hash"
        }

        public_grant["access_url"] = qurl["qurl_link"]
        public_grant["single_link"] = True

        email_delivery = {"required": verification_required, "requested": send_invitation, "sent": False}
        if send_invitation:
            email_delivery["sent"] = self._send_guest_invitation(
                page_id,
                grant,
                invitation_email,
            )

        self._send_json(
            HTTPStatus.CREATED,
            {
                "success": True,
                "grant": public_grant,
                "email_delivery": email_delivery,
            },
        )

    def _revoke_grant(self, page_id, grant_id):
        with page_action_lock(page_id):
            try:
                page = PAGE_STORE.load(page_id)
            except (PageConfigError, PageNotFoundError) as error:
                self._send_page_error(error)
                return

            grant = next(
                (
                    item
                    for item in page["access_grants"]
                    if item["id"] == grant_id
                ),
                None,
            )
            if grant is None:
                self._send_json(404, {"error": "Access link not found"})
                return

            try:
                PAGE_STORE.remove_access_grant(page_id, grant_id)
                try:
                    VERIFICATION_RECIPIENTS.delete(page_id, grant_id)
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit(
                        "verification_recipient_cleanup_failed",
                        page_id=page_id,
                        grant_id=grant_id,
                    )
            except (PageConfigError, PageNotFoundError) as error:
                self._send_page_error(error)
                return
            try:
                ACTIVITY_STORE.mark_revoked(page_id, grant)
            except (OSError, sqlite3.Error):
                audit(
                    "guest_activity_storage_failed",
                    operation="revoke",
                    page_id=page_id,
                    grant_id=grant_id,
                )

        # Disable local access first so revocation is immediate even if LayerV
        # is temporarily unavailable. The LayerV DELETE endpoint revokes the
        # remote qURL while retaining any history LayerV keeps for it.
        cleanup_guest_sessions(page_id, grant_id)
        qurl_id = grant.get("qurl_id", "")
        remote_error = None
        remote_pending = False
        if not qurl_id:
            remote_error = "Missing qURL ID; local access was revoked"
        else:
            try:
                if isinstance(LAYERV_CLIENT, BrokerLayerVClient):
                    queued = LAYERV_CLIENT.queue_revocation(page_id=page_id, grant_id=grant_id)
                    remote_pending = bool(queued.get("pending", False))
                    remote_already_missing = bool(queued.get("already_missing", False))
                else:
                    remote_already_missing = bool(LAYERV_CLIENT.delete_qurl(
                        resource_id=grant.get("resource_id", ""),
                        qurl_id=qurl_id,
                        page_id=page_id,
                        grant_id=grant_id,
                    ))
            except LayerVError as error:
                remote_error = str(error)
                remote_already_missing = False
        if not qurl_id:
            remote_already_missing = False

        audit(
            "access_grant_revoked",
            page_id=page_id,
            grant_id=grant_id,
            qurl_id=qurl_id,
            remote_revoked=not remote_error and not remote_pending,
            remote_revocation_pending=remote_pending,
            remote_already_missing=remote_already_missing,
        )

        if remote_error:
            self._send_json(
                HTTPStatus.BAD_GATEWAY,
                {
                    "success": False,
                    "local_access_revoked": True,
                    "remote_access_revoked": False,
                    "grant_id": grant_id,
                    "remote_error": remote_error,
                },
            )
            return

        self._send_json(
            200,
            {
                "success": True,
                "local_access_revoked": True,
                "remote_access_revoked": not remote_pending,
                "remote_revocation_pending": remote_pending,
                "remote_already_missing": remote_already_missing,
                "grant_id": grant_id,
            },
        )

    def _revoke_all_grants(self, page_id):
        with page_action_lock(page_id):
            page = self._load_page(page_id)
            if page is None:
                return

            grants = list(page["access_grants"])
            revoked_count = len(grants)

            # The page store writes a durable local revocation marker before
            # queuing cleanup; reads deny grants while either step is pending.
            PAGE_STORE.revoke_page_access_grants(page_id)
            for grant in grants:
                try:
                    VERIFICATION_RECIPIENTS.delete(page_id, grant["id"])
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit("verification_recipient_cleanup_failed", page_id=page_id, grant_id=grant["id"])
                try:
                    ACTIVITY_STORE.mark_revoked(page_id, grant)
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit(
                        "guest_activity_storage_failed",
                        operation="revoke",
                        page_id=page_id,
                        grant_id=grant["id"],
                    )

        remote_failures = []
        remote_pending_count = 0
        for grant in grants:
            cleanup_guest_sessions(page_id, grant["id"])
            qurl_id = grant.get("qurl_id", "")
            if not qurl_id:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "error": "Missing qURL ID; local access was revoked",
                })
                continue
            try:
                if isinstance(LAYERV_CLIENT, BrokerLayerVClient):
                    LAYERV_CLIENT.queue_revocation(page_id=page_id, grant_id=grant["id"])
                    remote_pending_count += 1
                else:
                    LAYERV_CLIENT.delete_qurl(
                        resource_id=grant.get("resource_id", ""),
                        qurl_id=qurl_id,
                        page_id=page_id,
                        grant_id=grant["id"],
                    )
            except LayerVError as error:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "qurl_id": qurl_id,
                    "error": str(error),
                })

        audit(
            "qurls_revoked",
            page_id=page_id,
            revoked_count=revoked_count,
            remote_failure_count=len(remote_failures),
        )
        self._send_json(
            HTTPStatus.BAD_GATEWAY if remote_failures else 200,
            {
                "success": not remote_failures,
                "local_access_revoked": True,
                "revoked_count": revoked_count,
                "remote_revocation_pending_count": remote_pending_count,
                "remote_failures": remote_failures,
            },
        )

    def _reset_layer_v_connection(self, payload):
        if payload.get("confirmation") != "RESET":
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Type RESET to confirm the LayerV connection reset"},
            )
            return

        page_ids = sorted(item["id"] for item in PAGE_STORE.list_pages())
        with ExitStack() as locks:
            for page_id in page_ids:
                locks.enter_context(page_action_lock(page_id))
            pages_updated, grants = PAGE_STORE.revoke_all_access_grants()
            for grant in grants:
                try:
                    VERIFICATION_RECIPIENTS.delete(grant.get("_page_id", ""), grant["id"])
                except (OSError, sqlite3.Error, EmailConfigError):
                    audit("verification_recipient_cleanup_failed", page_id=grant.get("_page_id", ""), grant_id=grant["id"])
                try:
                    ACTIVITY_STORE.mark_revoked(
                        grant.get("_page_id", ""),
                        grant,
                    )
                except (OSError, sqlite3.Error):
                    audit(
                        "guest_activity_storage_failed",
                        operation="revoke",
                        grant_id=grant["id"],
                    )
        remote_failures = []
        for grant in grants:
            cleanup_guest_sessions(grant.get("_page_id", ""), grant["id"])
            qurl_id = grant.get("qurl_id", "")
            if not qurl_id:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "error": "Missing qURL ID; local access was revoked",
                })
                continue
            try:
                LAYERV_CLIENT.delete_qurl(
                    resource_id=grant.get("resource_id", ""),
                    qurl_id=qurl_id,
                    page_id=grant.get("_page_id", ""),
                    grant_id=grant["id"],
                )
            except LayerVError as error:
                remote_failures.append({
                    "grant_id": grant["id"],
                    "qurl_id": qurl_id,
                    "error": str(error),
                })

        RESET_REQUEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = RESET_REQUEST_FILE.with_name(
            f".{RESET_REQUEST_FILE.name}.tmp"
        )
        temporary.write_text("reset\n", encoding="utf-8")
        temporary.chmod(0o600)
        audit(
            "layerv_connection_reset_requested",
            pages_updated=pages_updated,
            grants_revoked=len(grants),
            remote_failure_count=len(remote_failures),
        )
        try:
            self._send_json(
                HTTPStatus.ACCEPTED,
                {
                    "success": True,
                    "pages_preserved": True,
                    "pages_updated": pages_updated,
                    "grants_revoked": len(grants),
                    "remote_failures": remote_failures,
                    "reset_scheduled": True,
                },
            )
        finally:
            # Arm the supervisor only after the response is written, so it
            # cannot stop this gateway mid-response.
            temporary.replace(RESET_REQUEST_FILE)

    def _execute_public_action(
        self,
        page,
        resource_id,
        action_id,
        payload,
    ):
        execute_public_action(
            self,
            HA_CLIENT,
            page,
            resource_id,
            action_id,
            payload,
            normalize_capabilities,
            audit,
        )



    def do_GET(self):
        self.action_deadline = None
        if not self._valid_request_envelope():
            return
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/admin":
            # The shell contains no admin data. API requests remain protected
            # by X-Admin-Token, allowing a scrubbed URL to survive reloads.
            self._send_static_file("admin.html")
            return

        if path.startswith("/access/"):
            # Administrative preview only. Compiled page endpoints do not
            # forward this route.
            page_id = path.removeprefix("/access/").strip("/")
            if not page_id or "/" in page_id or not self._valid_preview_token(
                page_id, self._query().get("preview_token", [""])[0],
            ):
                self._send_json(404, {"error": "not found"})
                return
            if self._load_page(page_id) is None:
                return
            self._send_access_shell(page_id)
            return

        if path == "/health":
            layerv_recovery_required = (
                isinstance(LAYERV_CLIENT, BrokerLayerVClient)
                and LAYERV_CLIENT.recovery_required()
            )
            connector_status = {"total": 0, "active": 0}
            mobile_notification_count = 0
            try:
                stored_status = json.loads(
                    CONNECTOR_STATUS_FILE.read_text(encoding="utf-8")
                )
                connector_status = {
                    "total": max(0, int(stored_status.get("total", 0))),
                    "active": max(0, int(stored_status.get("active", 0))),
                }
                connector_status["active"] = min(
                    connector_status["active"], connector_status["total"]
                )
                if stored_status.get("mode") == "shared":
                    connector_status["mode"] = "shared"
                    connector_status["page_endpoints"] = min(
                        connector_status["total"],
                        max(0, int(stored_status.get("page_endpoints", 0))),
                    )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
            try:
                mobile_notification_count = len(HA_CLIENT.notification_targets())
            except (HomeAssistantError, TypeError):
                pass
            self._send_json(
                200,
                {
                    "status": "ok",
                    "version": GATEWAY_VERSION,
                    "page_count": len(PAGE_STORE.list_pages()),
                    "connectors": connector_status,
                    "layerv_api_configured": LAYERV_CLIENT.configured,
                    "layerv_recovery_required": layerv_recovery_required,
                    "role": "admin",
                    "guest_features": {
                        "scoped_invitations": True,
                    },
                    "email_configured": (
                        SMTP_CONFIG_STORE.configured()
                    ),
                    "notification_email_configured": (
                        SMTP_CONFIG_STORE.configured()
                    ),
                    "mobile_notification_count": (
                        mobile_notification_count
                    ),
                },
            )
            return

        if path.startswith("/api/admin/preview/"):
            access_routes.handle_get(self, path, RUNTIME)
            return
        if path.startswith("/api/admin/"):
            admin_routes.handle_get(self, parsed, path, RUNTIME)
            return
        if path.startswith("/static/"):
            filename = path.removeprefix("/static/")
            if not filename:
                self._send_json(404, {"error": "not found"})
                return
            self._send_static_file(filename)
            return
        self._send_json(404, {"error": "not found"})




    def do_POST(self):
        self.action_deadline = None
        if not self._valid_request_envelope():
            return
        path = urlparse(self.path).path
        try:
            payload = self._read_json()
        except ValueError as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": str(error)},
            )
            return

        if path.startswith("/api/internal/"):
            internal_routes.handle_post(self, path, payload, RUNTIME)
            return
        if path.startswith("/api/admin/preview/"):
            access_routes.handle_post(self, path, payload, RUNTIME)
            return
        if path.startswith("/api/admin/"):
            admin_routes.handle_post(self, path, payload, RUNTIME)
            return
        self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        if not self._valid_request_envelope():
            return
        path = urlparse(self.path).path
        admin_routes.handle_put(self, path, RUNTIME)

    def do_DELETE(self):
        if not self._valid_request_envelope():
            return
        path = urlparse(self.path).path
        admin_routes.handle_delete(self, path, RUNTIME)



def run():
    PAGES_DIR.mkdir(parents=True, exist_ok=True)
    PAGE_STORE.recover_pending_revocations()
    if LAYERV_CLIENT.configured or POLICY_PUBLISHER.configured:
        def retry_cleanup():
            while True:
                try:
                    PAGE_STORE.recover_pending_revocations()
                    if LAYERV_CLIENT.configured:
                        # Expiry cleanup must not depend on another visitor or
                        # the owner opening the admin page after the deadline.
                        for page in PAGE_STORE.list_pages():
                            with page_action_lock(page["id"]):
                                _, expired = PAGE_STORE.expire_access_grants(page["id"])
                                for grant in expired:
                                    cleanup_guest_sessions(page["id"], grant["id"])
                                    VERIFICATION_RECIPIENTS.delete(page["id"], grant["id"])
                                    ACTIVITY_STORE.mark_revoked(page["id"], grant, revoked_at=parse_time(grant["expires_at"]))
                        PAGE_STORE.cleanup.drain(LAYERV_CLIENT)
                    for page_id in POLICY_PUBLISHER.pending_pages():
                        with page_action_lock(page_id):
                            try:
                                page = PAGE_STORE.load(page_id)
                            except PageNotFoundError:
                                POLICY_PUBLISHER.delete(page_id)
                            else:
                                # Admin rollback may have restored the prior
                                # policy after an ambiguous network failure.
                                POLICY_PUBLISHER.publish(page)
                except (OSError, sqlite3.Error, PolicyPublishError, PageConfigError):
                    audit("upstream_cleanup_storage_failed")
                time.sleep(5)
        Thread(target=retry_cleanup, daemon=True).start()
    server = GatewayHTTPServer((HOST, PORT), Handler)
    print(f"Access Pages gateway listening on http://{HOST}:{PORT}")
    print(f"Pages directory: {PAGES_DIR}")
    print(f"LayerV API configured: {LAYERV_CLIENT.configured}")
    server.serve_forever()


if __name__ == "__main__":
    run()
