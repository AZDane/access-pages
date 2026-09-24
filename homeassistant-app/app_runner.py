"""Home Assistant App supervisor for the gateway and qURL Connector."""

from __future__ import annotations

import json
import os
import re
import select
import secrets
import shutil
import signal
import stat
# This module intentionally supervises fixed executables and argument lists.
import subprocess  # nosec B404
import sys
import time
import uuid
from pathlib import Path
from hashlib import sha256
from contextlib import contextmanager

from pages import PageNotFoundError, PageStore
from guest_resources import GuestResources
from guest_request import clock_ns


DATA_DIR = Path(os.getenv("APP_DATA_DIR", "/data"))
OPTIONS_FILE = Path(os.getenv("APP_OPTIONS_FILE", "/data/options.json"))
APP_CONFIG_FILE = DATA_DIR / "app-config.json"
INSTALLATION_ID_FILE = DATA_DIR / "installation-id"
SECRET_DIR = DATA_DIR / "secrets"
LAYERV_TOKEN_FILE = SECRET_DIR / "layerv-api-key"
CONNECTOR_STATE_DIR = DATA_DIR / "connector-state"
CONNECTOR_CONFIG_FILE = DATA_DIR / "connector-config" / "qurl-proxy.yaml"
CONNECTOR_LOG_DIR = DATA_DIR / "logs" / "layer-v-connector"
PAGE_CONNECTOR_DIR = DATA_DIR / "page-connectors"
PAGE_CONNECTOR_HISTORY = PAGE_CONNECTOR_DIR / "history.json"
PAGE_CONNECTOR_REGISTRY = DATA_DIR / "access-pages-broker" / "page-connectors.json"
ADMIN_RUNTIME_DIR = DATA_DIR / "admin-runtime"
CONNECTOR_STATUS_FILE = ADMIN_RUNTIME_DIR / "page-connector-status.json"
RESET_REQUEST_FILE = ADMIN_RUNTIME_DIR / "reset-connection.request"
POLICY_DIR = DATA_DIR / "policy-pages"
ACTIVITY_DIR = DATA_DIR / "guest-runtime"
ACTIVITY_DB_FILE = ACTIVITY_DIR / "guest-activity.sqlite3"
GUEST_PAGE_DIR = DATA_DIR / "guest-pages"
PAGE_CAPABILITY_SECRETS = DATA_DIR / "page-capabilities.json"
HA_CAPABILITY_DIR = DATA_DIR / "ha-broker-runtime"
HA_GUEST_SESSION_DIR = HA_CAPABILITY_DIR / "guest-auth"
HA_GUEST_SESSION_DB = HA_GUEST_SESSION_DIR / "sessions.sqlite3"
GUEST_SERVICE_PARENT = Path("/run/access-pages")
GUEST_SERVICE_DIR = GUEST_SERVICE_PARENT / "guest"
GUEST_SERVICE_SOCKET = GUEST_SERVICE_DIR / "http.sock"
GUEST_TRANSPORT_GID = 2004
HA_GUEST_DIR = GUEST_SERVICE_PARENT / "ha-guest"
HA_GUEST_SOCKET = HA_GUEST_DIR / "http.sock"
HA_CAPABILITY_REGISTRY = HA_CAPABILITY_DIR / "page-capabilities.json"
HA_GUEST_CAPABILITY_REGISTRY = HA_CAPABILITY_DIR / "guest-page-capabilities.json"
ACCESS_PAGES_BROKER_DATA_DIR = DATA_DIR / "access-pages-broker"
LAYERV_API_BASE_URL = os.getenv(
    "LAYERV_API_BASE_URL", "https://api.layerv.ai"
).rstrip("/")
RUNTIME_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    # The App supplies an isolated container-local temporary filesystem.
    "TMPDIR": "/tmp",  # nosec B108
}
DIAGNOSTIC_ENVIRONMENT = {}


def _diagnostic_environment(options):
    """Consume a native duration selection once; Off + restart rearms it."""
    selection = options.get("diagnostic_logging", "off")
    durations = {"off": 0, "30 minutes": 1800, "1 hour": 3600, "4 hours": 14400}
    if selection not in durations:
        raise SetupError("Invalid diagnostic logging duration")
    marker = DATA_DIR / "diagnostics-consumed"
    try:
        consumed = False
        if marker.exists():
            with marker.open("rb") as source:
                consumed = source.read(2) != b"0"
        if selection == "off" or not consumed:
            # Durably consume before enabling. Failure leaves diagnostics OFF.
            fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(b"0" if selection == "off" else b"1")
                output.flush()
                os.fsync(output.fileno())
            directory = os.open(DATA_DIR, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        if selection != "off" and not consumed:
            return {"ACCESS_PAGES_DIAGNOSTICS_UNTIL_NS": str(clock_ns() + durations[selection] * 1_000_000_000)}
    except OSError:
        pass
    return {}


PROCESS_IDENTITIES = {
    "admin": (2100, 2000, [], 0o007),
    "guest_service": (2101, 2101, [], 0o077),
    "ha_broker": (2102, 2001, [2000, 2102], 0o027),
    "access_pages_broker": (2103, 2001, [2000], 0o077),
    "policy_store": (2104, 2001, [], 0o027),
    "ingress": (2106, 2106, [], 0o077),
    "onboarding": (2107, 2107, [], 0o077),
}
PAGE_CONNECTOR_UID_MIN = 22000
PAGE_CONNECTOR_UID_MAX = 22999
PAGE_ENDPOINT_UID_OFFSET = 1000


class SetupError(RuntimeError):
    """A safe-to-display onboarding failure."""


@contextmanager
def _broker_identity():
    """Perform broker-owned state writes without root filesystem authority."""
    uid, gid, groups = os.geteuid(), os.getegid(), os.getgroups()
    if uid == 0:
        os.setgroups([])
        os.setegid(2103)
        os.seteuid(2103)
    try:
        yield
    finally:
        if uid == 0:
            os.seteuid(uid)
            os.setegid(gid)
            os.setgroups(groups)


def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(mode)
    temporary.replace(path)


def _store_onboarding_key(value: str) -> None:
    key = str(value).strip()
    if (
        len(key) < 10
        or len(key) > 4096
        or any(character.isspace() for character in key)
    ):
        raise SetupError("The onboarding process returned an invalid API key")
    _atomic_write(LAYERV_TOKEN_FILE, key + "\n", mode=0o600)
    os.chown(LAYERV_TOKEN_FILE, 0, 2003)
    LAYERV_TOKEN_FILE.chmod(0o640)


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SetupError(f"Could not read {path.name}") from error
    if not isinstance(value, dict):
        raise SetupError(f"{path.name} must contain a JSON object")
    return value


def _installation_id() -> str:
    if INSTALLATION_ID_FILE.exists():
        value = INSTALLATION_ID_FILE.read_text(encoding="utf-8").strip()
        try:
            return str(uuid.UUID(value))
        except ValueError as error:
            raise SetupError("The saved installation ID is invalid") from error
    value = str(uuid.uuid4())
    _atomic_write(INSTALLATION_ID_FILE, value + "\n")
    return value


def _connector_id(options: dict, installation_id: str) -> str:
    configured = str(options.get("connector_id", "")).strip()
    value = configured or f"ha-{installation_id.replace('-', '')[:16]}"
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,62}[a-z0-9]", value):
        raise SetupError(
            "Connector ID must be 3-64 lowercase letters, numbers, or hyphens; "
            "it must start with a letter and end with a letter or number"
        )
    return value


def _layer_v_token() -> str:
    if LAYERV_TOKEN_FILE.exists():
        return LAYERV_TOKEN_FILE.read_text(encoding="utf-8").strip()
    raise SetupError("Open the App Web UI to connect LayerV")










def _page_connector_id(
    base_connector_id: str,
    page_id: str,
    generation: int = 0,
) -> str:
    """Return a stable LayerV-safe connector ID for one capability page."""
    digest = sha256(
        f"{page_id}:{generation}".encode("utf-8")
    ).hexdigest()[:10]
    prefix_budget = 64 - len(digest) - 2
    base = base_connector_id[:prefix_budget].rstrip("-")
    if not base:
        base = "ha"
    return f"{base}-p-{digest}"


def _page_connector_target_ip(runtime_uid: int) -> str:
    """Return a stable loopback destination which identifies one page."""
    offset = runtime_uid - PAGE_CONNECTOR_UID_MIN
    if not 0 <= offset <= PAGE_CONNECTOR_UID_MAX - PAGE_CONNECTOR_UID_MIN:
        raise SetupError("Invalid page connector runtime identity")
    return f"127.77.{offset // 250}.{offset % 250 + 1}"






def _write_page_connector_registry(entries: dict[str, dict]) -> None:
    payload = {
        "version": 1,
        "pages": entries,
    }
    _atomic_write(
        PAGE_CONNECTOR_REGISTRY,
        json.dumps(payload, separators=(",", ":")) + "\n",
        mode=0o600,
    )
    os.chown(PAGE_CONNECTOR_REGISTRY, 2103, 2103)




def _write_connector_status(
    entries: dict[str, dict],
) -> None:
    status = {"total": len(entries), "active": 0}
    status["mode"] = "shared"
    status["page_endpoints"] = len(entries)
    _atomic_write(
        CONNECTOR_STATUS_FILE,
        json.dumps(status) + "\n",
        mode=0o600,
    )
    os.chown(CONNECTOR_STATUS_FILE, 2100, 2100)


def _read_page_connector_registry() -> dict[str, dict]:
    if not PAGE_CONNECTOR_REGISTRY.exists():
        return {}
    try:
        payload = _read_json(PAGE_CONNECTOR_REGISTRY)
        pages = payload.get("pages", {})
        if not isinstance(pages, dict):
            raise SetupError("Page connector registry has invalid pages")
        return pages
    except SetupError as error:
        raise SetupError("Could not read page connector registry") from error


def _read_page_connector_history() -> dict[str, dict]:
    if not PAGE_CONNECTOR_HISTORY.exists():
        return {}
    try:
        payload = _read_json(PAGE_CONNECTOR_HISTORY)
    except SetupError as error:
        raise SetupError("Could not read page connector history") from error
    history = {}
    for page_id, value in payload.items():
        if isinstance(value, int) and value >= 0:
            history[str(page_id)] = {"generation": value}
        elif isinstance(value, dict):
            history[str(page_id)] = value
    return history


def _write_page_connector_history(history: dict[str, dict]) -> None:
    _atomic_write(
        PAGE_CONNECTOR_HISTORY,
        json.dumps(history, separators=(",", ":")) + "\n",
        mode=0o600,
    )


def _page_connector_identity(
    page_id: str,
    previous: dict[str, dict],
    history: dict[str, dict],
) -> tuple[int, int]:
    """Allocate a stable UID/GID which is never shared between pages."""
    owner_by_uid = {}
    for source in (history, previous):
        for owner, entry in source.items():
            if not isinstance(entry, dict) or "runtime_uid" not in entry:
                continue
            uid = entry["runtime_uid"]
            gid = entry.get("runtime_gid", uid)
            if (
                not isinstance(uid, int)
                or not isinstance(gid, int)
                or uid < PAGE_CONNECTOR_UID_MIN
                or uid > PAGE_CONNECTOR_UID_MAX
                or gid != uid
            ):
                raise SetupError("Invalid page connector runtime identity")
            prior_owner = owner_by_uid.setdefault(uid, owner)
            if prior_owner != owner:
                raise SetupError("Duplicate page connector runtime identity")
    existing = previous.get(page_id) or history.get(page_id) or {}
    if "runtime_uid" in existing:
        uid = existing["runtime_uid"]
        return uid, uid
    for uid in range(PAGE_CONNECTOR_UID_MIN, PAGE_CONNECTOR_UID_MAX + 1):
        if uid not in owner_by_uid:
            return uid, uid
    raise SetupError("No page connector runtime identities remain")




def _load_or_register(
    options: dict,
    # Empty means generate a fresh token; it is not a default credential.
    retained_admin_token: str = "",  # nosec B107
) -> dict:
    installation_id = _installation_id()
    connector_id = _connector_id(options, installation_id)
    api_token = _layer_v_token()

    if APP_CONFIG_FILE.exists():
        saved = _read_json(APP_CONFIG_FILE)
        if saved.get("version") != 2:
            raise SetupError("Unsupported App configuration version")
        if saved.get("connector_id") != connector_id:
            raise SetupError(
                "Connector ID differs from saved state; restore the original value "
                "or explicitly reset the App"
            )
        changed = False
        for name in (
            "ha_broker_token",
            "ha_broker_admin_token",
            "access_pages_broker_token",
            "policy_store_token",
        ):
            if not str(saved.get(name, "")).strip():
                saved[name] = secrets.token_urlsafe(48)
                changed = True
        if "verification_broker_token" in saved:
            saved.pop("verification_broker_token")
            changed = True
        if changed:
            _atomic_write(
                APP_CONFIG_FILE,
                json.dumps(saved, indent=2) + "\n",
            )
        return {**saved, "api_token": api_token}

    saved = {
        "version": 2,
        "installation_id": installation_id,
        "connector_id": connector_id,
        "resource_id": "",
        # The token authenticates the internal Ingress proxy, not LayerV.
        # Retaining it during an intentional connection reset lets the same
        # proxy remain available while the gateway changes to onboarding.
        "admin_token": retained_admin_token or secrets.token_urlsafe(32),
        "ha_broker_token": secrets.token_urlsafe(48),
        "ha_broker_admin_token": secrets.token_urlsafe(48),
        "access_pages_broker_token": secrets.token_urlsafe(48),
        "policy_store_token": secrets.token_urlsafe(48),
    }
    _atomic_write(APP_CONFIG_FILE, json.dumps(saved, indent=2) + "\n")
    return {**saved, "api_token": api_token}






def _policy_options(options: dict) -> dict:
    return {
        "HA_ENTITY_INCLUDE_DOMAINS": str(
            options.get("include_domains", "")
        ),
        "HA_ENTITY_INCLUDE_AREAS": str(options.get("include_areas", "")),
        "HA_ENTITY_EXCLUDE_DOMAINS": str(
            options.get("exclude_domains", "")
        ),
        "HA_ENTITY_EXCLUDE_ENTITIES": str(
            options.get("exclude_entities", "")
        ),
        "QURL_MAX_LIFETIME_DAYS": str(
            options.get("qurl_max_lifetime_days", 3)
        ),
    }


def _resource_isolation_environment(options: dict) -> dict:
    mode = options.get("resource_isolation", "guest")
    if mode not in {"guest", "page"}:
        raise SetupError("resource_isolation must be guest or page")
    return {
        "ACCESS_PAGES_RESOURCE_ISOLATION": mode,
    }


def _admin_gateway_environment(options: dict, config: dict) -> dict:
    return {
        **RUNTIME_ENVIRONMENT,
        **_policy_options(options),
        **_resource_isolation_environment(options),
        "HOST": "127.0.0.1",
        "PORT": "8081",
        "HA_BASE_URL": "",
        "HA_BROKER_URL": "http://127.0.0.1:8082",
        "HA_BROKER_TOKEN": config["ha_broker_admin_token"],
        "ADMIN_TOKEN": config["admin_token"],
        "GATEWAY_DATA_DIR": str(DATA_DIR),
        "ACTIVITY_DB_FILE": str(ACTIVITY_DB_FILE),
        "PAGE_FILE_MODE": "640",
        "GATEWAY_VERSION": os.getenv("GATEWAY_VERSION", "development"),
        "LAYERV_API_BASE_URL": LAYERV_API_BASE_URL,
        "LAYERV_RESOURCE_ID": config["resource_id"],
        "ACCESS_PAGES_BROKER_URL": "http://127.0.0.1:8083",
        "ACCESS_PAGES_BROKER_TOKEN": config["access_pages_broker_token"],
        "POLICY_PUBLISH_URL": "http://127.0.0.1:8084",
        "POLICY_PUBLISH_TOKEN": config["policy_store_token"],
        "ACCESS_PAGES_RESET_REQUEST_FILE": str(RESET_REQUEST_FILE),
        "SMTP_CONFIG_FILE": str(ADMIN_RUNTIME_DIR / "smtp.json"),
        "ALERT_CONFIG_FILE": str(ADMIN_RUNTIME_DIR / "alerts.json"),
        "CONNECTOR_STATUS_FILE": str(CONNECTOR_STATUS_FILE),
        "VERIFICATION_RECIPIENT_FILE": str(
            ADMIN_RUNTIME_DIR / "verification-recipients.json"
        ),
    }


def _page_endpoint_environment(
    *,
    page_id: str,
    capability_token: str,
    host: str,
) -> dict:
    return {
        **DIAGNOSTIC_ENVIRONMENT,
        **RUNTIME_ENVIRONMENT,
        "HOST": host,
        "PORT": "8080",
        "GATEWAY_BOUND_PAGE_ID": page_id,
        "PAGE_CAPABILITY_TOKEN": capability_token,
        "GUEST_ENDPOINT_GUEST_SERVICE_SOCKET": str(GUEST_SERVICE_SOCKET),
    }


def _guest_service_environment() -> dict[str, str]:
    return {
        **DIAGNOSTIC_ENVIRONMENT,
        "PATH": RUNTIME_ENVIRONMENT["PATH"],
        "LANG": RUNTIME_ENVIRONMENT["LANG"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "GUEST_SERVICE_SOCKET": str(GUEST_SERVICE_SOCKET),
        "HA_BROKER_GUEST_SOCKET": str(HA_GUEST_SOCKET),
    }


def _prepare_guest_service_socket() -> None:
    GUEST_SERVICE_PARENT.mkdir(mode=0o755, exist_ok=True)
    parent = GUEST_SERVICE_PARENT.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or (parent.st_uid, parent.st_gid) != (0, 0)
        or stat.S_IMODE(parent.st_mode) != 0o755
    ):
        raise SetupError("Unsafe guest service runtime directory")
    if not GUEST_SERVICE_DIR.exists():
        GUEST_SERVICE_DIR.mkdir(mode=0o700)
        os.chown(GUEST_SERVICE_DIR, 2101, GUEST_TRANSPORT_GID)
        GUEST_SERVICE_DIR.chmod(0o2710)
    directory = GUEST_SERVICE_DIR.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or (directory.st_uid, directory.st_gid) != (2101, GUEST_TRANSPORT_GID)
        or stat.S_IMODE(directory.st_mode) != 0o2710
    ):
        raise SetupError("Unsafe guest service socket directory")
    try:
        socket_file = GUEST_SERVICE_SOCKET.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISSOCK(socket_file.st_mode)
        or (socket_file.st_uid, socket_file.st_gid) != (2101, GUEST_TRANSPORT_GID)
        or stat.S_IMODE(socket_file.st_mode) != 0o660
    ):
        raise SetupError("Unsafe existing guest service socket")
    GUEST_SERVICE_SOCKET.unlink()


def _prepare_ha_guest_socket() -> None:
    if not HA_GUEST_DIR.exists():
        HA_GUEST_DIR.mkdir(mode=0o700)
        os.chown(HA_GUEST_DIR, 2102, 2101)
        HA_GUEST_DIR.chmod(0o2750)
    directory = HA_GUEST_DIR.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode))
        != (2102, 2101, 0o2750)
    ):
        raise SetupError("Unsafe HA guest broker directory")
    try:
        socket_file = HA_GUEST_SOCKET.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISSOCK(socket_file.st_mode)
        or (socket_file.st_uid, socket_file.st_gid,
            stat.S_IMODE(socket_file.st_mode)) != (2102, 2101, 0o660)
    ):
        raise SetupError("Unsafe existing HA guest broker socket")
    HA_GUEST_SOCKET.unlink()


def _ha_broker_environment(config: dict) -> dict:
    supervisor_token = os.getenv("SUPERVISOR_TOKEN", "").strip()
    if not supervisor_token:
        raise SetupError("Home Assistant did not provide SUPERVISOR_TOKEN")
    return {
        **DIAGNOSTIC_ENVIRONMENT,
        **RUNTIME_ENVIRONMENT,
        "HA_BROKER_HOST": "127.0.0.1",
        "HA_BROKER_PORT": "8082",
        "HA_BROKER_GUEST_SOCKET": str(HA_GUEST_SOCKET),
        "HA_BROKER_TOKEN": config["ha_broker_token"],
        "HA_BROKER_ADMIN_TOKEN": config["ha_broker_admin_token"],
        "HA_BROKER_POLICY_DIR": str(POLICY_DIR),
        "HA_PAGE_CAPABILITY_REGISTRY": str(HA_CAPABILITY_REGISTRY),
        "HA_GUEST_CAPABILITY_REGISTRY": str(HA_GUEST_CAPABILITY_REGISTRY),
        "HA_GUEST_GRANTS_DIR": str(DATA_DIR / "pages"),
        "HA_GUEST_SESSION_DB": str(HA_GUEST_SESSION_DB),
        "HA_BASE_URL": "http://supervisor/core",
        "HA_TOKEN": supervisor_token,
    }


def _layerv_broker_environment(options: dict, config: dict) -> dict:
    return {
        **RUNTIME_ENVIRONMENT,
        **_resource_isolation_environment(options),
        "ACCESS_PAGES_BROKER_HOST": "127.0.0.1",
        "ACCESS_PAGES_BROKER_PORT": "8083",
        "ACCESS_PAGES_BROKER_TOKEN": config["access_pages_broker_token"],
        "ACCESS_PAGES_BROKER_POLICY_DIR": str(POLICY_DIR),
        "ACCESS_PAGES_GATEWAY_GRANTS_DIR": str(DATA_DIR / "pages"),
        "ACCESS_PAGES_BROKER_DATA_DIR": str(ACCESS_PAGES_BROKER_DATA_DIR),
        "LAYERV_API_TOKEN": config["api_token"],
        "LAYERV_API_BASE_URL": LAYERV_API_BASE_URL,
        "LAYERV_RESOURCE_ID": config["resource_id"],
        "ACCESS_PAGES_INSTALLATION_ID": config["installation_id"],
        "ACCESS_PAGES_PAGE_CONNECTOR_REGISTRY": str(PAGE_CONNECTOR_REGISTRY),
        "QURL_MAX_LIFETIME_DAYS": str(
            options.get("qurl_max_lifetime_days", 3)
        ),
    }


def _policy_store_environment(config: dict) -> dict:
    return {
        **RUNTIME_ENVIRONMENT,
        "POLICY_STORE_HOST": "127.0.0.1",
        "POLICY_STORE_PORT": "8084",
        "POLICY_STORE_TOKEN": config["policy_store_token"],
        "POLICY_STORE_DIR": str(POLICY_DIR),
        "POLICY_FILE_MODE": "640",
    }


# Backward-compatible test/helper alias for the privileged admin plane.
def _gateway_environment(options: dict, config: dict) -> dict:
    return _admin_gateway_environment(options, config)


def _demote(identity):
    uid, gid, groups, umask = (
        PROCESS_IDENTITIES[identity]
        if isinstance(identity, str)
        else identity
    )

    def apply_identity():
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
        os.umask(umask)

    return apply_identity


def _spawn(command, environment, identity):
    return subprocess.Popen(  # nosec B603
        command,
        env=environment,
        preexec_fn=_demote(identity),
    )


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_ENTRY_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _open_data_directory(path: Path, *, create: bool = False) -> int:
    """Open every component beneath the HA-owned data mount without links."""
    parts = path.relative_to(DATA_DIR).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise SetupError("Unsafe runtime directory")
    try:
        descriptor = os.open(DATA_DIR, _DIRECTORY_FLAGS)
        for part in parts:
            try:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except FileNotFoundError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise SetupError("Unsafe runtime directory") from error


def _repair_tree_fd(
    descriptor: int, uid: int, gid: int, directory_mode: int,
    file_mode: int, *, skip: frozenset[str] = frozenset(),
    allow_native_socket: bool = False, relative: tuple[str, ...] = (),
) -> None:
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        raise SetupError("Unsafe runtime tree object")
    os.fchown(descriptor, uid, gid)
    os.fchmod(descriptor, directory_mode)
    with os.scandir(descriptor) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        if name in skip:
            continue
        if allow_native_socket and relative == ("shared-state",) and name == "daemon.sock":
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISSOCK(info.st_mode):
                if info.st_uid != uid or info.st_gid != gid or info.st_mode & 0o077:
                    raise SetupError("Unsafe Connector socket")
                # A UNIX socket cannot be opened as a regular file. It is
                # broker-owned and never mutated by this privileged walk.
                continue
        try:
            child = os.open(name, _ENTRY_FLAGS, dir_fd=descriptor)
        except OSError as error:
            raise SetupError("Unsafe runtime tree object") from error
        try:
            kind = os.fstat(child).st_mode
            if stat.S_ISDIR(kind):
                _repair_tree_fd(
                    child, uid, gid, directory_mode, file_mode,
                    allow_native_socket=allow_native_socket,
                    relative=(*relative, name),
                )
            elif stat.S_ISREG(kind):
                os.fchown(child, uid, gid)
                os.fchmod(child, file_mode)
            else:
                raise SetupError("Unsafe runtime tree object")
        finally:
            os.close(child)


def _repair_file(path: Path, uid: int, gid: int, mode: int) -> None:
    try:
        parent = _open_data_directory(path.parent)
    except FileNotFoundError:
        return
    try:
        try:
            descriptor = os.open(path.name, _ENTRY_FLAGS, dir_fd=parent)
        except FileNotFoundError:
            return
        except OSError as error:
            raise SetupError("Unsafe runtime file") from error
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SetupError("Unsafe runtime file")
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _prepare_runtime_permissions() -> None:
    paths = (
        (DATA_DIR / "pages", 2100, 2000, 0o2750, 0o640),
        (POLICY_DIR, 2104, 2001, 0o2750, 0o640),
        (ACTIVITY_DIR, 2100, 2100, 0o700, 0o600),
        (ADMIN_RUNTIME_DIR, 2100, 2100, 0o700, 0o600),
        (ACCESS_PAGES_BROKER_DATA_DIR, 2103, 2103, 0o700, 0o600),
        # Only root may replace broker capability mappings; the broker reads
        # their hashes via its dedicated supplemental group.
        (HA_CAPABILITY_DIR, 0, 2102, 0o750, 0o640),
    )
    for directory, uid, gid, directory_mode, file_mode in paths:
        descriptor = _open_data_directory(directory, create=True)
        try:
            _repair_tree_fd(
                descriptor, uid, gid, directory_mode, file_mode,
                skip=frozenset({HA_GUEST_SESSION_DIR.name})
                if directory == HA_CAPABILITY_DIR else frozenset(),
                allow_native_socket=directory == ACCESS_PAGES_BROKER_DATA_DIR,
            )
        finally:
            os.close(descriptor)
    _prepare_ha_guest_session_dir()
    descriptor = _open_data_directory(CONNECTOR_LOG_DIR, create=True)
    try:
        _repair_tree_fd(descriptor, 2103, 2103, 0o700, 0o600)
    finally:
        os.close(descriptor)
    _repair_file(PAGE_CAPABILITY_SECRETS, 0, 0, 0o600)
    _repair_file(PAGE_CONNECTOR_HISTORY, 0, 0, 0o600)
    descriptor = _open_data_directory(SECRET_DIR, create=True)
    try:
        os.fchown(descriptor, 0, 2003)
        # The dedicated secret-reader group needs directory traversal only.
        os.fchmod(descriptor, 0o750)  # nosec B103
    finally:
        os.close(descriptor)
    _repair_file(LAYERV_TOKEN_FILE, 0, 2003, 0o640)


def _prepare_ha_guest_session_dir() -> None:
    if not HA_GUEST_SESSION_DIR.exists():
        HA_GUEST_SESSION_DIR.mkdir(mode=0o700)
        os.chown(HA_GUEST_SESSION_DIR, 2102, 2102)
    session_dir = HA_GUEST_SESSION_DIR.lstat()
    if (
        not stat.S_ISDIR(session_dir.st_mode)
        or (session_dir.st_uid, session_dir.st_gid,
            stat.S_IMODE(session_dir.st_mode)) != (2102, 2102, 0o700)
    ):
        raise SetupError("Unsafe HA guest session directory")


def _seed_authoritative_policy() -> int:
    source = PageStore(DATA_DIR / "pages")
    target = PageStore(POLICY_DIR, file_mode=0o640)
    source_ids = set()
    for summary in source.list_pages():
        page = source.load(summary["id"])
        for grant in page["access_grants"]:
            qurl_id = str(grant.get("qurl_id", "")).strip()
            resource_id = str(grant.get("resource_id", "")).strip()
            if not qurl_id or not resource_id:
                continue
            mapping_path = (
                ACCESS_PAGES_BROKER_DATA_DIR
                / f"{page['id']}--{grant['id']}.json"
            )
            if not mapping_path.exists():
                with _broker_identity():
                    _atomic_write(
                        mapping_path,
                        json.dumps({
                            "page_id": page["id"],
                            "grant_id": grant["id"],
                            "qurl_id": qurl_id,
                            "resource_id": resource_id,
                        }, separators=(",", ":")),
                    )
        page["access_grants"] = []
        source_ids.add(page["id"])
        try:
            target.replace(page["id"], page)
        except PageNotFoundError:
            target.create(page)
    for summary in target.list_pages():
        if summary["id"] not in source_ids:
            target.delete(summary["id"])
    return len(source_ids)


def _page_capabilities(page_ids: set[str]) -> dict[str, str]:
    try:
        saved = _read_json(PAGE_CAPABILITY_SECRETS)
    except SetupError:
        saved = {}
    capabilities = {
        page_id: str(saved.get(page_id) or secrets.token_urlsafe(32))
        for page_id in sorted(page_ids)
    }
    _atomic_write(
        PAGE_CAPABILITY_SECRETS,
        json.dumps(capabilities, separators=(",", ":")) + "\n",
        mode=0o600,
    )
    os.chown(PAGE_CAPABILITY_SECRETS, 0, 0)
    hashes = {
        page_id: sha256(token.encode()).hexdigest()
        for page_id, token in capabilities.items()
    }
    for directory, path, uid, gid, mode, registry in (
        # Page capabilities identify endpoints; broker sessions authorize guests.
        # Overwrite the old registry as well, removing legacy ambient access.
        (HA_CAPABILITY_DIR, HA_CAPABILITY_REGISTRY, 0, 2102, 0o640, {}),
        (HA_CAPABILITY_DIR, HA_GUEST_CAPABILITY_REGISTRY,
         0, 2102, 0o640, hashes),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        _atomic_write(
            path, json.dumps(registry, separators=(",", ":")) + "\n", mode=mode,
        )
        os.chown(path, uid, gid)
    return capabilities


def _reconcile_page_endpoints(
    options: dict,
    config: dict,
    connector_entries: dict[str, dict],
    processes: dict[str, subprocess.Popen],
) -> None:
    page_store = PageStore(DATA_DIR / "pages")
    pages = {
        item["id"]: page_store.load(item["id"])
        for item in page_store.list_pages()
    }
    active_pages = pages
    capabilities = _page_capabilities(set(active_pages))
    for page_id, page in active_pages.items():
        entry = connector_entries.get(page_id)
        if not entry:
            continue
        endpoint_uid = int(entry["runtime_uid"]) + PAGE_ENDPOINT_UID_OFFSET
        current = processes.get(page_id)
        if current is None or current.poll() is not None:
            processes[page_id] = _spawn(
                ["/usr/local/bin/access-pages-guest-endpoint"],
                _page_endpoint_environment(
                    page_id=page_id,
                    capability_token=capabilities[page_id],
                    host=str(entry["target_ip"]),
                ),
                (endpoint_uid, endpoint_uid, [GUEST_TRANSPORT_GID], 0o077),
            )
    for page_id in set(processes) - set(active_pages):
        _stop([processes.pop(page_id)])


def _reconcile_page_connectors(
    config: dict,
) -> dict[str, dict]:
    """Publish local page endpoints for the shared native Connector."""
    previous = _read_page_connector_registry()
    history = _read_page_connector_history()
    page_store = PageStore(DATA_DIR / "pages")
    entries = {}
    for item in page_store.list_pages():
        page_id = item["id"]
        runtime_uid, runtime_gid = _page_connector_identity(
            page_id, {**previous, **entries}, history
        )
        entries[page_id] = {
            "connector_id": _page_connector_id(config["connector_id"], page_id),
            "resource_id": "",
            "generation": 0,
            "runtime_uid": runtime_uid,
            "runtime_gid": runtime_gid,
            "target_ip": _page_connector_target_ip(runtime_uid),
        }
    for page_id in set(previous) - set(entries):
        entry = previous[page_id]
        history[page_id] = {
            "runtime_uid": entry["runtime_uid"],
            "runtime_gid": entry["runtime_gid"],
        }
    _write_page_connector_history(history)
    if PAGE_CONNECTOR_HISTORY.exists():
        os.chown(PAGE_CONNECTOR_HISTORY, 0, 0)
        PAGE_CONNECTOR_HISTORY.chmod(0o600)
    _write_page_connector_registry(entries)
    _write_connector_status(entries)
    return entries


def _configured_key_available() -> bool:
    return LAYERV_TOKEN_FILE.is_file()


def _reset_connection_files() -> None:
    """Remove connector identity and credentials while preserving pages."""
    resources = ACCESS_PAGES_BROKER_DATA_DIR / "guest-resources.sqlite3"
    try:
        info = resources.lstat()
    except FileNotFoundError:
        info = None
    if info is not None:
        if not stat.S_ISREG(info.st_mode) or (os.geteuid() == 0 and info.st_uid != 2103):
            raise SetupError("Unsafe guest resource state")
        # The SQLite path belongs to the broker. Drop root while opening and
        # modifying it so an attacker-controlled replacement cannot redirect
        # privileged SQLite file operations outside that ownership domain.
        with _broker_identity():
            GuestResources(
                resources, installation_id="", publisher=None,
                management_client=None,
            ).invalidate_for_reset()
    for path in (
        LAYERV_TOKEN_FILE,
        APP_CONFIG_FILE,
        CONNECTOR_CONFIG_FILE,
        INSTALLATION_ID_FILE,
    ):
        path.unlink(missing_ok=True)
    if CONNECTOR_STATE_DIR.exists():
        shutil.rmtree(CONNECTOR_STATE_DIR)
    # The broker owns the qURL 2.6.0 external namespace and its local wrapping
    # key. Only the administrator's explicit reset may discard this identity.
    for broker_state in (
        ACCESS_PAGES_BROKER_DATA_DIR / "shared-state",
        ACCESS_PAGES_BROKER_DATA_DIR / "connector-home",
    ):
        if broker_state.exists():
            shutil.rmtree(broker_state)
    for name in ("agent-bootstrap-complete", "agent-wrapping-key"):
        (ACCESS_PAGES_BROKER_DATA_DIR / name).unlink(missing_ok=True)
    if PAGE_CONNECTOR_DIR.exists():
        shutil.rmtree(PAGE_CONNECTOR_DIR)
    if CONNECTOR_LOG_DIR.exists():
        shutil.rmtree(CONNECTOR_LOG_DIR)
    if GUEST_PAGE_DIR.exists():
        shutil.rmtree(GUEST_PAGE_DIR)
    PAGE_CAPABILITY_SECRETS.unlink(missing_ok=True)
    HA_CAPABILITY_REGISTRY.unlink(missing_ok=True)
    HA_GUEST_CAPABILITY_REGISTRY.unlink(missing_ok=True)
    PAGE_CONNECTOR_REGISTRY.unlink(missing_ok=True)
    RESET_REQUEST_FILE.unlink(missing_ok=True)




def _start_ingress(admin_token: str) -> subprocess.Popen:
    environment = {
        **RUNTIME_ENVIRONMENT,
        "INGRESS_ADMIN_TOKEN": admin_token,
        "INGRESS_UPSTREAM": "http://127.0.0.1:8081",
        "INGRESS_PORT": "8099",
    }
    # The Python executable and script path are fixed.
    return _spawn(
        [sys.executable, "/usr/local/bin/ingress_proxy.py"],
        environment,
        "ingress",
    )


def _run_onboarding(
    setup_error: str = "",
    ingress: subprocess.Popen | None = None,
    shutdown_requested=None,
) -> int:
    """Expose one-time credential setup through authenticated HA Ingress."""
    owned_processes: list[subprocess.Popen] = []
    read_fd = -1
    write_fd = -1
    ack_read_fd = -1
    ack_write_fd = -1
    try:
        print(
            "LayerV setup required — open the App Web UI to connect",
            flush=True,
        )
        if ingress is None:
            ingress = _start_ingress(secrets.token_urlsafe(32))
            owned_processes.append(ingress)
        read_fd, write_fd = os.pipe()
        ack_read_fd, ack_write_fd = os.pipe()
        environment = {
            **RUNTIME_ENVIRONMENT,
            "ONBOARDING_HOST": "127.0.0.1",
            "ONBOARDING_PORT": "8081",
            "ONBOARDING_SUBMISSION_FD": str(write_fd),
            "ONBOARDING_ACK_FD": str(ack_read_fd),
            "ONBOARDING_ERROR": setup_error,
        }
        # The Python executable and script path are fixed.
        onboarding = subprocess.Popen(  # nosec B603
            [sys.executable, "/usr/local/bin/onboarding.py"],
            env=environment,
            pass_fds=(write_fd, ack_read_fd),
            preexec_fn=_demote("onboarding"),
        )
        os.close(write_fd)
        write_fd = -1
        os.close(ack_read_fd)
        ack_read_fd = -1
        owned_processes.append(onboarding)
        submission_error = None
        while onboarding.poll() is None:
            if shutdown_requested is not None and shutdown_requested():
                return 0
            if ingress.poll() is not None:
                return ingress.returncode or 1
            if read_fd >= 0 and select.select([read_fd], [], [], 0.25)[0]:
                with os.fdopen(read_fd, "rb") as submission:
                    read_fd = -1
                    payload = submission.readline(4098)
                try:
                    key = payload.decode("utf-8").rstrip("\n")
                    _store_onboarding_key(key)
                except (UnicodeDecodeError, OSError, SetupError) as error:
                    submission_error = SetupError(
                        "Could not store the LayerV API key"
                    )
                    submission_error.__cause__ = error
                    os.write(ack_write_fd, b"0")
                else:
                    os.write(ack_write_fd, b"1")
                os.close(ack_write_fd)
                ack_write_fd = -1
        if onboarding.returncode:
            return onboarding.returncode
        if submission_error is not None:
            raise submission_error
        if read_fd >= 0:
            raise SetupError("The onboarding credential handoff was invalid")
        return 0
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        if read_fd >= 0:
            os.close(read_fd)
        if ack_read_fd >= 0:
            os.close(ack_read_fd)
        if ack_write_fd >= 0:
            os.close(ack_write_fd)
        _stop(owned_processes)


def _stop(processes: list[subprocess.Popen]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + 10
    for process in processes:
        remaining = max(0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> int:
    global DIAGNOSTIC_ENVIRONMENT
    processes: list[subprocess.Popen] = []
    ingress: subprocess.Popen | None = None
    shutdown_requested = False

    def handle_signal(_signum, _frame):
        nonlocal shutdown_requested
        shutdown_requested = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # This is an empty state sentinel, not a credential.
    retained_admin_token = ""  # nosec B105
    try:
        options = _read_json(OPTIONS_FILE)
        # /data is a Home Assistant-managed mount, so image-build ownership is
        # hidden on a fresh installation. Prepare it before the unprivileged
        # onboarding registration process attempts its first write.
        _prepare_runtime_permissions()
        DIAGNOSTIC_ENVIRONMENT = _diagnostic_environment(options)
        print("Access Pages diagnostic logging: " + (
            "temporary capture enabled" if DIAGNOSTIC_ENVIRONMENT else "off"
        ), flush=True)
        while True:
            setup_error = ""
            while True:
                if not _configured_key_available():
                    if _run_onboarding(
                        setup_error,
                        ingress,
                        shutdown_requested=lambda: shutdown_requested,
                    ) != 0:
                        return 2
                    if shutdown_requested:
                        return 0
                    setup_error = ""
                try:
                    config = _load_or_register(
                        options,
                        retained_admin_token,
                    )
                    _prepare_runtime_permissions()
                    _seed_authoritative_policy()
                    page_store = PageStore(DATA_DIR / "pages")
                    _page_capabilities({
                        item["id"] for item in page_store.list_pages()
                    })
                    break
                except SetupError as error:
                    if APP_CONFIG_FILE.exists():
                        raise
                    print(str(error), file=sys.stderr, flush=True)
                    LAYERV_TOKEN_FILE.unlink(missing_ok=True)
                    CONNECTOR_CONFIG_FILE.unlink(missing_ok=True)
                    setup_error = str(error)

            _prepare_guest_service_socket()
            _prepare_ha_guest_socket()
            policy_store = _spawn(
                [sys.executable, "/app/policy_store.py"],
                _policy_store_environment(config),
                "policy_store",
            )
            ha_broker = _spawn(
                [sys.executable, "/app/ha_broker.py"],
                _ha_broker_environment(config),
                "ha_broker",
            )
            layerv_broker = _spawn(
                [sys.executable, "/app/layerv_broker.py"],
                _layerv_broker_environment(options, config),
                "access_pages_broker",
            )
            admin_gateway = _spawn(
                [sys.executable, "/app/server.py"],
                _admin_gateway_environment(options, config),
                "admin",
            )
            guest_service = _spawn(
                [sys.executable, "/app/guest_service.py"],
                _guest_service_environment(),
                "guest_service",
            )
            if ingress is None:
                ingress = _start_ingress(config["admin_token"])
            page_endpoints: dict[str, subprocess.Popen] = {}
            processes = [
                policy_store,
                ha_broker,
                layerv_broker,
                admin_gateway,
                guest_service,
                ingress,
            ]
            try:
                connector_entries = _reconcile_page_connectors(config)
                _reconcile_page_endpoints(
                    options, config, connector_entries, page_endpoints,
                )
            except Exception:
                _stop(list(page_endpoints.values()))
                raise
            processes.extend(page_endpoints.values())

            next_page_reconcile = 0.0
            while True:
                if shutdown_requested:
                    return 0
                if RESET_REQUEST_FILE.is_file():
                    break
                if time.monotonic() >= next_page_reconcile:
                    try:
                        connector_entries = _reconcile_page_connectors(config)
                        _reconcile_page_endpoints(
                            options, config, connector_entries, page_endpoints,
                        )
                    except Exception:
                        _stop(list(page_endpoints.values()))
                        raise
                    processes = [
                        policy_store,
                        ha_broker,
                        layerv_broker,
                        admin_gateway,
                        guest_service,
                        ingress,
                        *page_endpoints.values(),
                    ]
                    next_page_reconcile = time.monotonic() + 1.0
                for process in processes:
                    exit_code = process.poll()
                    if exit_code is not None:
                        _stop(processes)
                        return exit_code or 1
                time.sleep(0.5)

            # Keep Home Assistant Ingress listening while the gateway swaps
            # from its admin UI to onboarding. Stopping the proxy here makes
            # Home Assistant's /app wrapper surface a transient 404.
            _stop([
                policy_store,
                ha_broker,
                layerv_broker,
                admin_gateway,
                guest_service,
                *page_endpoints.values(),
            ])
            processes = [ingress]
            retained_admin_token = config["admin_token"]
            _reset_connection_files()
            print(
                "LayerV connection reset — open the App Web UI to reconnect",
                flush=True,
            )
    except SetupError as error:
        print(f"Setup required: {error}", file=sys.stderr)
        return 2
    finally:
        _stop(processes)


if __name__ == "__main__":
    raise SystemExit(main())
