"""Authenticated schedule administration, separate from guest-facing routes."""

import time
from zoneinfo import ZoneInfo, available_timezones

from email_delivery import EmailConfigError
from layerv import BrokerLayerVClient
from schedules import Scheduler, validate_schedule


def handle(handler, path, runtime, payload=None):
    parts = path.removeprefix("/api/admin/pages/").split("/")
    if not path.startswith("/api/admin/pages/") or len(parts) not in (2, 3) or parts[1] != "schedules":
        return False
    if not handler._require_admin():
        return True
    page_id = parts[0]
    try:
        page = runtime.PAGE_STORE.load(page_id)
        store = runtime.SCHEDULE_STORE
        now = time.time()
        supported = isinstance(runtime.LAYERV_CLIENT, BrokerLayerVClient)
        if payload is None:
            rows = store.schedules(page_id)
            for row in rows:
                row["upcoming"] = store.upcoming(row["definition"], now, row["id"]) if row["status"] == "enabled" else []
            default_zone = runtime.SCHEDULE_TIMEZONE
            try:
                ZoneInfo(default_zone)
            except (ValueError, KeyError):
                default_zone = "UTC"
            store.link_activity(runtime.ACTIVITY_STORE, page_id)
            guests = store.guests(page_id)
            for guest in guests:
                delivery = store.delivery_timeline(page_id, guest["id"], None, (1e12, ""), limit=1)
                guest["latest_delivery"] = delivery[0] if delivery else None
                guest["needs_attention"] = store.needs_attention(page_id, guest["id"])
            associations = {row["grant_id"]: row["scheduled_guest_id"] for row in runtime.ACTIVITY_STORE.page_guests(page_id) if row.get("scheduled_guest_id")}
            handler._send_json(200, {"schedules": rows, "guests": guests, "scheduled_grants": associations,
                                     "active_invitations": [{key: grant[key] for key in ("id", "label", "expires_at")}
                                                            for grant in page["access_grants"] if grant["id"] in associations],
                                     "smtp_configured": runtime.SMTP_CONFIG_STORE.configured(),
                                     "supported": supported, "timezone": default_zone,
                                     "timezones": sorted(available_timezones())})
            return True
        if not isinstance(payload, dict):
            raise ValueError("Request must be an object")
        action = payload.get("action", "save")
        schedule_id = parts[2] if len(parts) == 3 else None
        if action == "timeline":
            guest_id = payload.get("guest_id")
            if not isinstance(guest_id, str):
                raise ValueError("Choose a guest")
            handler._send_json(200, store.timeline(runtime.ACTIVITY_STORE, page_id, guest_id,
                                                   occurrence_id=payload.get("occurrence_id"),
                                                   kind=payload.get("kind", "all"), cursor=payload.get("cursor")))
            return True
        with runtime.page_action_lock(page_id):
            if schedule_id:
                current = store.get(schedule_id)
                if current["page"] != page_id or current["status"] == "deleted":
                    raise ValueError("Schedule not found")
            if action == "revoke_guest":
                guest_id = payload.get("guest_id")
                if schedule_id or not isinstance(guest_id, str):
                    raise ValueError("Choose a guest")
                rows = store.revoke_guest(page_id, guest_id, now)
                worker = Scheduler(runtime, store)
                for row in rows:
                    worker.deny(row)
            elif action in {"pause", "resume", "delete"}:
                if not schedule_id:
                    raise ValueError("Choose a schedule")
                if action == "resume" and (not supported or not runtime.SMTP_CONFIG_STORE.configured()):
                    raise ValueError("Configure SMTP and the App Connector before resuming")
                status = {"pause": "paused", "resume": "enabled", "delete": "deleted"}[action]
                if action == "pause" and current["status"] == "revoked":
                    status = "revoked"
                store.status(schedule_id, status, now,
                             revoke=payload.get("revoke_active") is True)
            elif action == "pause_all":
                store.pause_page(page_id, now, revoke=payload.get("revoke_active") is True)
            elif action == "preview":
                definition = validate_schedule(payload.get("definition"))
                overlaps = [s for s in store.schedules(page_id)
                            if s["id"] != schedule_id and s["status"] == "enabled"
                            and s["definition"]["email"].casefold() == definition["email"].casefold()]
                handler._send_json(200, {"upcoming": store.upcoming(definition, now, schedule_id),
                                         "warning": "Other schedules exist for this guest on this page; check for overlapping access." if overlaps else ""})
                return True
            elif action == "save":
                if not supported:
                    raise ValueError("Scheduling requires the Home Assistant App Connector")
                if not schedule_id and not runtime.SMTP_CONFIG_STORE.configured():
                    raise ValueError("Configure SMTP before scheduling invitations")
                definition = validate_schedule(payload.get("definition"))
                if definition["kind"] == "once" and not store.upcoming(definition, now, schedule_id):
                    raise ValueError("Choose a future unprocessed date, or duplicate the schedule for another invitation")
                available = set(runtime.NOTIFICATION_TARGET_STORE.load())
                if runtime.SMTP_CONFIG_STORE.configured():
                    available.add("email")
                if any(target not in available for target in definition["notifications"]["targets"]):
                    raise ValueError("A guest activity notification target is not configured")
                guest_id = payload.get("guest_id")
                if guest_id is not None and not isinstance(guest_id, str):
                    raise ValueError("Choose a guest")
                schedule_id = store.save(page_id, definition, now, schedule_id, guest_id)
            else:
                raise ValueError("Unknown schedule action")
            if payload.get("revoke_active") is True:
                worker = Scheduler(runtime, store)
                for row in store.work():
                    if row["page"] == page_id and row["state"] == "cancelling" and (not schedule_id or row["schedule"] == schedule_id):
                        worker.deny(row)
        runtime.audit("schedule_changed", page_id=page_id, schedule_id=schedule_id, operation=action)
        handler._send_json(200, {"success": True, "id": schedule_id})
    except (ValueError, EmailConfigError, runtime.PageConfigError, runtime.PageNotFoundError) as error:
        handler._send_json(400, {"error": str(error)})
    except (OSError, runtime.sqlite3.Error):
        handler._send_json(503, {"error": "Schedule storage unavailable; reload before retrying"})
    return True
