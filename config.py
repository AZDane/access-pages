import os
from pathlib import Path


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def csv_env(name: str) -> frozenset[str]:
    return frozenset(
        item.strip()
        for item in os.getenv(name, "").split(",")
        if item.strip()
    )


def optional_secret(name: str, file_name: str) -> str:
    path = os.getenv(file_name, "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise RuntimeError(
                f"Could not read secret file configured by {file_name}"
            ) from error
    return os.getenv(name, "").strip()


HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8080"))

HA_BROKER_URL = os.getenv("HA_BROKER_URL", "").strip().rstrip("/")
HA_BROKER_TOKEN = os.getenv("HA_BROKER_TOKEN", "").strip()
HA_BASE_URL = os.getenv("HA_BASE_URL", "").strip().rstrip("/")
HA_TOKEN = os.getenv("HA_TOKEN", "").strip()
if HA_BROKER_URL:
    if not HA_BROKER_TOKEN:
        raise RuntimeError("HA_BROKER_TOKEN is required with HA_BROKER_URL")
elif not HA_BASE_URL or not HA_TOKEN:
    raise RuntimeError(
        "HA_BASE_URL and HA_TOKEN are required without an HA broker"
    )

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
if not ADMIN_TOKEN:
    raise RuntimeError("ADMIN_TOKEN is required for the admin role")

POLICY_PUBLISH_URL = os.getenv(
    "POLICY_PUBLISH_URL",
    "",
).strip().rstrip("/")
POLICY_PUBLISH_TOKEN = os.getenv("POLICY_PUBLISH_TOKEN", "").strip()
if POLICY_PUBLISH_URL and not POLICY_PUBLISH_TOKEN:
    raise RuntimeError(
        "POLICY_PUBLISH_TOKEN is required with POLICY_PUBLISH_URL"
    )

QURL_MAX_LIFETIME_DAYS = int(
    os.getenv("QURL_MAX_LIFETIME_DAYS", "3")
)
if not 1 <= QURL_MAX_LIFETIME_DAYS <= 30:
    raise RuntimeError(
        "QURL_MAX_LIFETIME_DAYS must be between 1 and 30"
    )

# Optional discovery policy. An empty include policy exposes every entity the
# gateway supports. When any include set is populated, an entity must match at
# least one include. Exclusions always win.
HA_ENTITY_INCLUDE_DOMAINS = csv_env("HA_ENTITY_INCLUDE_DOMAINS")
HA_ENTITY_INCLUDE_AREAS = csv_env("HA_ENTITY_INCLUDE_AREAS")
HA_ENTITY_INCLUDE_DEVICE_CLASSES = csv_env(
    "HA_ENTITY_INCLUDE_DEVICE_CLASSES"
)
HA_ENTITY_INCLUDE_ENTITIES = csv_env("HA_ENTITY_INCLUDE_ENTITIES")
HA_ENTITY_EXCLUDE_DOMAINS = csv_env("HA_ENTITY_EXCLUDE_DOMAINS")
HA_ENTITY_EXCLUDE_AREAS = csv_env("HA_ENTITY_EXCLUDE_AREAS")
HA_ENTITY_EXCLUDE_DEVICE_CLASSES = csv_env(
    "HA_ENTITY_EXCLUDE_DEVICE_CLASSES"
)
HA_ENTITY_EXCLUDE_ENTITIES = csv_env("HA_ENTITY_EXCLUDE_ENTITIES")

DATA_DIR = Path(os.getenv("GATEWAY_DATA_DIR", "/data"))
PAGES_DIR = DATA_DIR / "pages"
ACTIVITY_DB_FILE = Path(
    os.getenv(
        "ACTIVITY_DB_FILE",
        str(DATA_DIR / "guest-activity.sqlite3"),
    )
)
RESET_REQUEST_FILE = Path(
    os.getenv(
        "ACCESS_PAGES_RESET_REQUEST_FILE",
        str(DATA_DIR / "reset-connection.request"),
    )
)
SMTP_CONFIG_FILE = Path(
    os.getenv(
        "SMTP_CONFIG_FILE",
        str(DATA_DIR / "admin-runtime" / "smtp.json"),
    )
)
ALERT_CONFIG_FILE = Path(os.getenv(
    "ALERT_CONFIG_FILE", str(DATA_DIR / "admin-runtime" / "alerts.json")
))
VERIFICATION_RECIPIENT_FILE = Path(os.getenv(
    "VERIFICATION_RECIPIENT_FILE",
    str(DATA_DIR / "admin-runtime" / "verification-recipients.json"),
))
CONNECTOR_STATUS_FILE = Path(os.getenv(
    "CONNECTOR_STATUS_FILE",
    str(DATA_DIR / "admin-runtime" / "page-connector-status.json"),
))

# Optional until qURL generation is enabled. Public access pages are still
# token-protected even when these are not configured.
LAYERV_API_TOKEN = optional_secret(
    "LAYERV_API_TOKEN",
    "LAYERV_API_TOKEN_FILE",
)
ACCESS_PAGES_BROKER_URL = os.getenv(
    "ACCESS_PAGES_BROKER_URL",
    "",
).strip().rstrip("/")
ACCESS_PAGES_BROKER_TOKEN = os.getenv("ACCESS_PAGES_BROKER_TOKEN", "").strip()
if ACCESS_PAGES_BROKER_URL and not ACCESS_PAGES_BROKER_TOKEN:
    raise RuntimeError(
        "ACCESS_PAGES_BROKER_TOKEN is required with ACCESS_PAGES_BROKER_URL"
    )
LAYERV_API_BASE_URL = os.getenv(
    "LAYERV_API_BASE_URL",
    "https://api.layerv.ai",
).strip().rstrip("/")
LAYERV_RESOURCE_ID = os.getenv(
    "LAYERV_RESOURCE_ID",
    "",
).strip()
GATEWAY_VERSION = os.getenv("GATEWAY_VERSION", "development").strip()
