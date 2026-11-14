"""Shared grant construction; callers own persistence and delivery recovery."""

from datetime import datetime, timezone
from hashlib import sha256
import re


def scheduled_timestamp(value):
    """Strict whole-second RFC 3339, normalized to UTC; never guess a zone."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value):
        raise ValueError("Scheduling timestamps require whole-second RFC 3339 values")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("Scheduling timestamp is outside the supported range") from error


def scheduled_window(not_before, expires_at, now, max_days=30):
    start = scheduled_timestamp(not_before) if not_before is not None else now
    end = scheduled_timestamp(expires_at)
    if not 0 < (end - start).total_seconds() <= 86400:
        raise ValueError("Scheduled access must last at most 24 hours")
    if not 0 < (end - now).total_seconds() <= min(30, max_days) * 86400:
        raise ValueError(f"Invitation expiration must be within {min(30, max_days)} days of creation")
    return start, end


def grant_window_open(grant, now):
    """Shared local admission check; old grants have no lower boundary."""
    try:
        end = datetime.fromisoformat(grant["expires_at"].replace("Z", "+00:00"))
        if end.tzinfo is None or now >= end:
            return False
        if "not_before" in grant:
            start = scheduled_timestamp(grant["not_before"])
            return start <= now < end and start < end
        return True
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def invitation_grant(qurl, *, grant_id, secret, created_at, expires_at,
                     label, lifetime, one_time_use, verification_required,
                     notifications, resource_id="", not_before=None):
    upstream = qurl.get("expires_at")
    if upstream:
        expires_at = min(expires_at, datetime.fromisoformat(upstream.replace("Z", "+00:00")))
    return {
        **({"not_before": scheduled_timestamp(not_before).isoformat(timespec="seconds")} if not_before is not None else {}),
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
