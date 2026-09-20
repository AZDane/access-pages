from datetime import timedelta
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import time
from urllib.parse import urlparse, parse_qs
from threading import Event, RLock, Thread
import sqlite3

from layerv import LayerVClient, LayerVError
from guest_resources import AgentRecoveryRequired, ConnectorPublisher, GuestResources, PendingInvitations
from pages import PageConfigError, PageNotFoundError, PageStore


HOST = os.getenv("ACCESS_PAGES_BROKER_HOST", "0.0.0.0")
PORT = int(os.getenv("ACCESS_PAGES_BROKER_PORT", "8083"))
TOKEN = os.environ["ACCESS_PAGES_BROKER_TOKEN"]
MAX_DAYS = int(os.getenv("QURL_MAX_LIFETIME_DAYS", "3"))
PAGE_STORE = PageStore(Path(os.getenv("ACCESS_PAGES_BROKER_POLICY_DIR", "/policy")))
DATA_DIR = Path(os.getenv("ACCESS_PAGES_BROKER_DATA_DIR", "/data"))
CLIENT = LayerVClient(
    os.environ["LAYERV_API_BASE_URL"],
    os.environ["LAYERV_API_TOKEN"],
    os.environ["LAYERV_RESOURCE_ID"],
)
PAGE_CONNECTOR_REGISTRY = Path(
    os.getenv("ACCESS_PAGES_PAGE_CONNECTOR_REGISTRY", "/data/page-connectors.json")
)
LIFETIME = re.compile(r"^([1-9][0-9]{0,4})([mhdw])$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,160}$")
STORE_LOCK = RLock()
GUEST_RESOURCES = None
RECOVERY_REQUIRED = False
RESOURCE_ISOLATION = os.getenv("ACCESS_PAGES_RESOURCE_ISOLATION", "guest")
GATEWAY_GRANTS_DIR = os.getenv("ACCESS_PAGES_GATEWAY_GRANTS_DIR", "")
if RESOURCE_ISOLATION not in {"guest", "page"}:
    raise RuntimeError("ACCESS_PAGES_RESOURCE_ISOLATION must be guest or page")


class PolicyError(ValueError):
    def __init__(self, message, status=HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


def _page(page_id):
    try:
        return PAGE_STORE.load(page_id)
    except PageNotFoundError as error:
        raise PolicyError("Page not found", HTTPStatus.NOT_FOUND) from error
    except PageConfigError as error:
        raise PolicyError("Page policy is invalid") from error


def _lifetime(value):
    match = LIFETIME.fullmatch(str(value).strip().lower())
    if not match:
        raise PolicyError("Invalid qURL lifetime")
    amount = int(match.group(1))
    unit = match.group(2)
    duration = amount * {
        "m": timedelta(minutes=1),
        "h": timedelta(hours=1),
        "d": timedelta(days=1),
        "w": timedelta(weeks=1),
    }[unit]
    if duration > timedelta(days=MAX_DAYS):
        raise PolicyError("qURL lifetime exceeds configured maximum")
    return f"{amount}{unit}"


def _grant_file(page_id, grant_id):
    if not SAFE_ID.fullmatch(page_id) or not SAFE_ID.fullmatch(grant_id):
        raise PolicyError("Invalid page or grant ID")
    return DATA_DIR / f"{page_id}--{grant_id}.json"


def _target_path(page_id, value):
    # This is the Gateway's generated route grammar, not a general URL.
    # Matching the wire value prevents parser normalization from accepting
    # fragments, path params, controls, or encoded alternate representations.
    path = str(value)
    if re.fullmatch(
        re.escape(f"/g/{page_id}/") + r"grant_[A-Za-z0-9_-]{16}/\?bootstrap=[A-Za-z0-9_-]{43}", path,
    ):
        return path
    raise PolicyError("Invalid user-bound target path")


def _save_mapping(page_id, grant_id, result, default_resource_id=""):
    path = _grant_file(page_id, grant_id)
    mapping = {
        "page_id": page_id,
        "grant_id": grant_id,
        "qurl_id": str(result.get("qurl_id", "")),
        "resource_id": str(
            result.get("resource_id") or default_resource_id
        ),
        "resource_crid": str(result.get("resource_crid", "")),
        "upstream_scope": result.get("upstream_scope", "page"),
    }
    if not mapping["qurl_id"] or not mapping["resource_id"]:
        raise PolicyError("LayerV response lacks durable identifiers")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=DATA_DIR,
        prefix=".grant-",
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(mapping, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
        directory = os.open(DATA_DIR, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _load_mapping(page_id, grant_id):
    try:
        value = json.loads(
            _grant_file(page_id, grant_id).read_text(encoding="utf-8")
        )
    except FileNotFoundError as error:
        raise PolicyError("Grant not found", HTTPStatus.NOT_FOUND) from error
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(
            "Stored grant mapping is unavailable",
            HTTPStatus.INTERNAL_SERVER_ERROR,
        ) from error
    if (
        not isinstance(value, dict)
        or value.get("page_id") != page_id
        or value.get("grant_id") != grant_id
    ):
        raise PolicyError(
            "Stored grant mapping is invalid",
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )
    return value


def create_grant(page_id, grant_id, label, expires_in, target_path="", one_time_use=False, session_duration="1h"):
    _page(page_id)
    lifetime = _lifetime(expires_in)
    validated_target_path = _target_path(page_id, target_path)
    if not validated_target_path.startswith(f"/g/{page_id}/{grant_id}/"):
        raise PolicyError("Target path does not match the invitation")
    match = re.fullmatch(r"([1-9][0-9]{0,5})([smh])", session_duration)
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600}[match[2]] if match else 0
    lifetime_match = LIFETIME.fullmatch(lifetime)
    lifetime_seconds = int(lifetime_match[1]) * {"m": 60, "h": 3600, "d": 86400, "w": 604800}[lifetime_match[2]]
    if not 1 <= seconds <= min(86400, lifetime_seconds) or (one_time_use and lifetime_seconds > 86400):
        raise PolicyError("Invalid admission duration for the guest lifetime")
    path = _grant_file(page_id, grant_id)
    with STORE_LOCK:
        if path.exists():
            raise PolicyError("Grant already exists", HTTPStatus.CONFLICT)
        if GUEST_RESOURCES is None:
            raise PolicyError("Shared guest Connector is not ready", HTTPStatus.SERVICE_UNAVAILABLE)
        try:
            registry = json.loads(PAGE_CONNECTOR_REGISTRY.read_text(encoding="utf-8"))
            target_ip = registry["pages"][page_id]["target_ip"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise PolicyError("Page endpoint is not ready", HTTPStatus.CONFLICT) from error
        import ipaddress
        try:
            if not ipaddress.ip_address(target_ip).is_loopback:
                raise ValueError("Not loopback")
        except ValueError as error:
            raise PolicyError("Page endpoint target is invalid") from error
        client = GUEST_RESOURCES.ensure(page_id, grant_id, f"http://{target_ip}:8080", isolation=RESOURCE_ISOLATION)
        journal = PendingInvitations(DATA_DIR / "pending-invitations.sqlite3") if RESOURCE_ISOLATION == "page" else None
        upstream_label = journal.prepare(page_id, grant_id, client.resource_id) if journal else str(label)[:120]
        try:
            result = client.create_qurl(
                label=upstream_label,
                expires_in=lifetime,
                page_id=page_id,
                grant_id=grant_id,
                target_path=validated_target_path,
                target_path_supported=True,
                one_time_use=one_time_use,
                session_duration=session_duration,
            )
        except LayerVError:
            # The response may be lost after the invitation was committed.
            # Retire the exclusively owned resource rather than guessing its
            # qURL ID. Page pools cannot be compensated this way.
            if RESOURCE_ISOLATION == "guest":
                try:
                    GUEST_RESOURCES.revoke(page_id, grant_id, client.resource_id)
                except LayerVError:
                    pass  # Its independent durable retirement queue remains.
            raise
        returned_resource = str(result.get("resource_id") or client.resource_id)
        expected_resource = getattr(client, "resource_public_key", "")
        if not isinstance(expected_resource, str) or not expected_resource:
            expected_resource = client.resource_id
        if returned_resource != expected_resource:
            # Do not persist, or attempt deletion against, a foreign resource
            # named by an inconsistent upstream response.
            raise PolicyError("LayerV response resource does not match the page")
        try:
            _save_mapping(page_id, grant_id, result, client.resource_id)
        except (OSError, PolicyError):
            qurl_id = str(result.get("qurl_id", ""))
            if qurl_id:
                try:
                    client.delete_qurl(
                        resource_id=str(
                            result.get("resource_crid")
                            or client.resource_id
                        ),
                        qurl_id=qurl_id,
                    )
                except LayerVError:
                    pass
            if result.get("upstream_scope") == "guest":
                try:
                    GUEST_RESOURCES.revoke(page_id, grant_id, client.resource_id)
                except LayerVError:
                    pass
            raise
        # The page journal remains until the Gateway's local grant commit is
        # observed, covering a lost broker reply after its private mapping save.
        return result


def delete_grant(page_id, grant_id):
    with STORE_LOCK:
        try:
            grant = _load_mapping(page_id, grant_id)
        except PolicyError as error:
            if error.status == HTTPStatus.NOT_FOUND:
                already_missing = GUEST_RESOURCES.revoke_owned(page_id, grant_id) if GUEST_RESOURCES is not None else True
                return {"success": True, "already_missing": bool(already_missing)}
            raise
        if grant.get("upstream_scope") == "guest":
            if GUEST_RESOURCES is None:
                raise PolicyError("Shared guest Connector is not ready", HTTPStatus.SERVICE_UNAVAILABLE)
            already_missing = GUEST_RESOURCES.revoke(page_id, grant_id, grant["resource_crid"], qurl_id=grant["qurl_id"])
        else:
            already_missing = CLIENT.delete_qurl(
                resource_id=grant.get("resource_crid") or grant["resource_id"],
                qurl_id=grant["qurl_id"],
            )
        _grant_file(page_id, grant_id).unlink(missing_ok=True)
        directory = os.open(DATA_DIR, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return {"success": True, "already_missing": bool(already_missing)}


def _gateway_grant_live(page_id, grant_id):
    if not _grant_file(page_id, grant_id).exists():
        return False
    if not GATEWAY_GRANTS_DIR:
        return True
    mapping = _load_mapping(page_id, grant_id)
    try:
        page = PageStore(Path(GATEWAY_GRANTS_DIR)).load(page_id)
    except PageNotFoundError:
        return False
    return any(
        grant["id"] == grant_id
        and grant.get("qurl_id") == mapping["qurl_id"]
        and grant.get("resource_crid") == mapping.get("resource_crid")
        for grant in page["access_grants"]
    )


@contextmanager
def _revocation_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATA_DIR / "deferred-revocations.sqlite3")
    (DATA_DIR / "deferred-revocations.sqlite3").chmod(0o600)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS revocations (page TEXT, grant_id TEXT, due REAL, attempts INTEGER DEFAULT 0, PRIMARY KEY(page,grant_id))")
    db.commit()
    try:
        with db:
            yield db
    finally:
        db.close()


def queue_revocation(page_id, grant_id):
    # Validate ownership before accepting a durable retirement request.
    try:
        _load_mapping(page_id, grant_id)
    except PolicyError as error:
        if error.status != HTTPStatus.NOT_FOUND:
            raise
        return delete_grant(page_id, grant_id)
    with _revocation_db() as db:
        db.execute("INSERT OR IGNORE INTO revocations(page,grant_id,due) VALUES(?,?,?)",
                   (page_id, grant_id, time.time() + 15))
        due = db.execute("SELECT due FROM revocations WHERE page=? AND grant_id=?", (page_id, grant_id)).fetchone()[0]
    return {"success": True, "pending": True, "not_before": due}


def _live_mapping(page_id, grant_id):
    if _gateway_grant_live(page_id, grant_id):
        return True
    if GATEWAY_GRANTS_DIR and _grant_file(page_id, grant_id).exists():
        # Also protects the interval between the local grant removal and the
        # administrator's queue request, and survives a lost broker request.
        queue_revocation(page_id, grant_id)
        return True  # The durable queue owns retirement, including retries.
    return False


def drain_revocations():
    with _revocation_db() as db:
        rows = db.execute("SELECT page,grant_id,attempts FROM revocations WHERE due<=? LIMIT 50", (time.time(),)).fetchall()
    for page, grant, attempts in rows:
        if GATEWAY_GRANTS_DIR and _gateway_grant_live(page, grant):
            continue  # Never retire an invitation that is still authorized.
        try:
            delete_grant(page, grant)
        except (LayerVError, OSError, PolicyError) as error:
            retry = getattr(error, "retry_after", None) or min(3600, 5 * 2 ** min(attempts, 10))
            with _revocation_db() as db:
                db.execute("UPDATE revocations SET due=?,attempts=attempts+1 WHERE page=? AND grant_id=?", (time.time() + max(5, retry), page, grant))
        else:
            with _revocation_db() as db:
                db.execute("DELETE FROM revocations WHERE page=? AND grant_id=?", (page, grant))


def _page_exists(page_id):
    try:
        PAGE_STORE.load(page_id)
    except PageNotFoundError:
        return False
    return True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def _send(self, status, payload, retry_after=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Ownership and compensation have already been recorded. A lost
            # caller must not turn the upstream outcome into a traceback.
            print(json.dumps({"event": "broker_response_client_disconnected", "http_status": int(status),
                              "error": payload.get("error", "") if status >= 400 else "",
                              "layerv_status": payload.get("layerv_status")}), flush=True)

    def _authorized(self):
        return hmac.compare_digest(
            self.headers.get("X-Broker-Token", ""),
            TOKEN,
        )

    def _payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 32 * 1024:
            raise PolicyError("Invalid request size")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise PolicyError("Request must be an object")
        return value

    def do_GET(self):
        if self.path == "/health" and (RECOVERY_REQUIRED or (
            GUEST_RESOURCES is not None and GUEST_RESOURCES.publisher.recovery_required
        )):
            self._send(503, {"status": "recovery required", "recovery_required": True})
            return
        if self.path == "/health" and (
            GUEST_RESOURCES is None or not GUEST_RESOURCES.publisher.healthy()
        ):
            self._send(503, {"status": "connector unavailable"})
            return
        self._send(
            200 if self.path == "/health" else 404,
            {"status": "ok"} if self.path == "/health" else {"error": "not found"},
        )

    def do_POST(self):
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if RECOVERY_REQUIRED or (
            GUEST_RESOURCES is not None and GUEST_RESOURCES.publisher.recovery_required
        ):
            self._send(503, {"error": "LayerV Agent recovery required; reset the LayerV connection"})
            return
        try:
            payload = self._payload()
            if self.path != "/v1/grants":
                self._send(404, {"error": "not found"})
                return
            self._send(
                200,
                create_grant(
                    str(payload.get("page_id", "")),
                    str(payload.get("grant_id", "")),
                    str(payload.get("label", "")),
                    str(payload.get("expires_in", "")),
                    str(payload.get("target_path", "")),
                    payload.get("one_time_use") is True,
                    str(payload.get("session_duration", "1h")),
                ),
            )
        except (PolicyError, json.JSONDecodeError) as error:
            self._send(
                getattr(error, "status", HTTPStatus.BAD_REQUEST),
                {"error": str(error) or "Invalid request"},
            )
        except (OSError, sqlite3.Error):
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Broker storage failed"},
            )
        except LayerVError as error:
            self._send(HTTPStatus.SERVICE_UNAVAILABLE if error.status == 503 else HTTPStatus.BAD_GATEWAY, {"error": str(error), "layerv_status": error.status}, error.retry_after)

    def do_DELETE(self):
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        try:
            parsed = urlparse(self.path)
            parts = parsed.path.removeprefix("/v1/grants/").split("/")
            if len(parts) != 2 or not all(parts):
                raise PolicyError("Invalid grant path", HTTPStatus.NOT_FOUND)
            deferred = parse_qs(parsed.query).get("defer") == ["15"]
            self._send(200, queue_revocation(parts[0], parts[1]) if deferred else delete_grant(parts[0], parts[1]))
        except PolicyError as error:
            self._send(error.status, {"error": str(error)})
        except (OSError, sqlite3.Error):
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Broker storage failed"},
            )
        except LayerVError as error:
            self._send(HTTPStatus.SERVICE_UNAVAILABLE if error.status == 503 else HTTPStatus.BAD_GATEWAY, {"error": str(error), "layerv_status": error.status}, error.retry_after)


def reconcile_once(publisher):
    if RECOVERY_REQUIRED or publisher.recovery_required or publisher._fresh():
        # The reset keeps old retirement work. It needs an enrolled Agent, so
        # leave it queued until the first new publication has bootstrapped.
        return
    with STORE_LOCK:
        drain_revocations()
        GUEST_RESOURCES.retire_orphans(_live_mapping)
        GUEST_RESOURCES.retire_deleted_page_pools(_page_exists)
        GUEST_RESOURCES.drain_retirements()
        PendingInvitations(DATA_DIR / "pending-invitations.sqlite3").drain(CLIENT, _live_mapping)
    publisher.restore()


def run():
    global GUEST_RESOURCES, RECOVERY_REQUIRED
    publisher = ConnectorPublisher(
        DATA_DIR / "shared-state", api_base_url=CLIENT.api_base_url,
        enrollment_key=CLIENT.api_token, mode="per-share",
    )
    GUEST_RESOURCES = GuestResources(
        DATA_DIR / "guest-resources.sqlite3",
        installation_id=os.environ["ACCESS_PAGES_INSTALLATION_ID"],
        publisher=publisher, management_client=CLIENT,
    )
    try:
        publisher.restore()
    except AgentRecoveryRequired:
        RECOVERY_REQUIRED = True
        print("LayerV Agent recovery required; Admin reset remains available", flush=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    stopped = Event()
    def reconcile_resources():
        while not stopped.wait(5):
            try:
                reconcile_once(publisher)
            except (LayerVError, OSError, sqlite3.Error, ValueError):
                # No credentials or native logs are included in diagnostics.
                print("Guest Connector reconciliation pending", flush=True)
    Thread(target=reconcile_resources, daemon=True).start()
    def stop(_signum, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever()
    finally:
        stopped.set()
        server.server_close()
        publisher.close()


if __name__ == "__main__":
    run()
