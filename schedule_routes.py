"""Authenticated schedule administration, separate from guest-facing routes."""

import time
from zoneinfo import ZoneInfo

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
        runtime.PAGE_STORE.load(page_id)
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
            handler._send_json(200, {"schedules": rows, "occurrences": store.history(page_id),
                                     "smtp_configured": runtime.SMTP_CONFIG_STORE.configured(),
                                     "supported": supported, "timezone": default_zone})
            return True
        if not isinstance(payload, dict):
            raise ValueError("Request must be an object")
        action = payload.get("action", "save")
        schedule_id = parts[2] if len(parts) == 3 else None
        with runtime.page_action_lock(page_id):
            if schedule_id:
                current = store.get(schedule_id)
                if current["page"] != page_id or current["status"] == "deleted":
                    raise ValueError("Schedule not found")
            if action in {"pause", "resume", "delete"}:
                if not schedule_id:
                    raise ValueError("Choose a schedule")
                if action == "resume" and (not supported or not runtime.SMTP_CONFIG_STORE.configured()):
                    raise ValueError("Configure SMTP and the App Connector before resuming")
                store.status(schedule_id, {"pause": "paused", "resume": "enabled", "delete": "deleted"}[action], now,
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
                schedule_id = store.save(page_id, definition, now, schedule_id)
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
