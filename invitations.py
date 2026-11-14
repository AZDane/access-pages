"""Shared grant construction; callers own persistence and delivery recovery."""

from datetime import datetime, timezone
from hashlib import sha256


def invitation_grant(qurl, *, grant_id, secret, created_at, expires_at,
                     label, lifetime, one_time_use, verification_required,
                     notifications, resource_id=""):
    upstream = qurl.get("expires_at")
    if upstream:
        expires_at = min(expires_at, datetime.fromisoformat(upstream.replace("Z", "+00:00")))
    return {
        "id": grant_id, "token_hash": sha256(secret.encode()).hexdigest(),
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
        "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
        "label": label, "lifetime": lifetime, "one_time_use": one_time_use,
        "qurl_link": qurl["qurl_link"], "qurl_site": qurl.get("qurl_site", ""),
        "resource_id": qurl.get("resource_id", "") or resource_id,
        "qurl_id": qurl.get("qurl_id", ""), "type": qurl.get("type", ""),
        "verification_required": verification_required,
        "notifications": notifications or {"targets": [], "events": []},
        "target_path_applied": bool(qurl.get("target_path_applied", False)),
        "credential_flow": "bootstrap-v1",
        "resource_crid": qurl.get("resource_crid", ""),
        "upstream_scope": qurl.get("upstream_scope", "page"),
    }
