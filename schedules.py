"""Admin-only, durable scheduled invitations. No guest authorization lives here.

One process owns the worker lock. Page locks serialize owner cancellation with
grant commitment and sending. Interrupted mints are retired before a new attempt;
interrupted SMTP sends retry the SAME link (SMTP is not exactly-once).
"""

from contextlib import contextmanager
from datetime import date, datetime, time as wall_time, timedelta, timezone
import fcntl
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
from threading import Event, Thread
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from email_delivery import EmailConfigError, guest_invitation_email_content, send_email, validate_email
from invitations import invitation_grant
from layerv import BrokerLayerVClient, LayerVError
from pages import PageConfigError, PageNotFoundError, validate_notifications, validate_page_id

UTC = timezone.utc
GRACE = 15 * 60
MAX_SCHEDULES = 200
TERMINAL = {"accepted", "ended", "skipped", "failed", "cancelled"}


def stamp(value):
    return datetime.fromtimestamp(value, UTC).isoformat()


def validate_schedule(payload):
    if not isinstance(payload, dict):
        raise ValueError("Schedule must be an object")
    label = str(payload.get("label", "")).strip()
    if not label or len(label) > 120:
        raise ValueError("Enter a guest name of at most 120 characters")
    zone = str(payload.get("timezone", ""))
    try:
        ZoneInfo(zone)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("Choose a valid IANA timezone, such as America/Phoenix") from None
    kind = payload.get("kind")
    if kind not in {"once", "weekly"}:
        raise ValueError("Choose a one-time or weekly schedule")
    result = {"label": label, "email": validate_email(payload.get("email")),
              "timezone": zone, "kind": kind}
    for key, default in (("next_day", False), ("verification_required", True), ("one_time_use", False)):
        value = payload.get(key, default)
        if type(value) is not bool:
            raise ValueError(f"Invalid {key}")
        result[key] = value
    for key in ("start_time", "end_time"):
        value = payload.get(key, "")
        if not isinstance(value, str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value):
            raise ValueError("Select start and end times")
        result[key] = value
    start = wall_time.fromisoformat(result["start_time"])
    end = wall_time.fromisoformat(result["end_time"])
    minutes = (end.hour - start.hour) * 60 + end.minute - start.minute + 1440 * result["next_day"]
    if not 2 <= minutes <= 1440:
        raise ValueError("Access must last 2 minutes to 24 hours; use Ends next day for overnight access")
    for key in ("date", "first_date", "last_date"):
        value = payload.get(key) or ""
        if not isinstance(value, str) or (value and date.fromisoformat(value).isoformat() != value):
            raise ValueError("Invalid schedule date")
        result[key] = value
    if kind == "once" and not result["date"]:
        raise ValueError("Select the access date")
    if result["first_date"] and result["last_date"] and result["last_date"] < result["first_date"]:
        raise ValueError("The last date must be on or after the first date")
    weekdays = payload.get("weekdays", [])
    if not isinstance(weekdays, list) or any(type(x) is not int or not 0 <= x <= 6 for x in weekdays):
        raise ValueError("Invalid weekdays")
    if kind == "weekly" and not weekdays:
        raise ValueError("Select at least one weekday")
    result["weekdays"] = sorted(set(weekdays))
    result["notifications"] = validate_notifications(payload.get("notifications"))
    return result


def local_instant(day, clock, zone):
    naive = datetime.combine(day, wall_time.fromisoformat(clock))
    candidates = set()
    for fold in (0, 1):
        instant = naive.replace(tzinfo=zone, fold=fold).astimezone(UTC)
        if instant.astimezone(zone).replace(tzinfo=None) == naive:
            candidates.add(instant.timestamp())
    return next(iter(candidates)) if len(candidates) == 1 else None


def occurrence_window(definition, day):
    """None means not selected. Invalid DST boundaries are visible skipped rows."""
    d = definition
    key = day.isoformat()
    if d["kind"] == "once":
        if key != d["date"]:
            return None
    elif (day.weekday() not in d["weekdays"] or
          (d["first_date"] and key < d["first_date"]) or
          (d["last_date"] and key > d["last_date"])):
        return None
    zone = ZoneInfo(d["timezone"])
    start = local_instant(day, d["start_time"], zone)
    end = local_instant(day + timedelta(days=int(d["next_day"])), d["end_time"], zone)
    reason = ""
    if start is None or end is None:
        reason = "Skipped: ambiguous or nonexistent daylight-saving time"
    elif end <= start or end - start > 86400:
        reason = "Skipped: elapsed duration exceeds the invitation limit"
    return {"local_date": key, "start": start, "end": end, "reason": reason}


def upcoming(definition, now, limit=5):
    day = datetime.fromtimestamp(now, ZoneInfo(definition["timezone"])).date()
    if definition["kind"] == "once":
        day = max(day, date.fromisoformat(definition["date"]))
    elif definition["first_date"]:
        day = max(day, date.fromisoformat(definition["first_date"]))
    rows = []
    for offset in range(370):
        candidate = occurrence_window(definition, day + timedelta(days=offset))
        if candidate and (candidate["start"] is None or candidate["start"] > now):
            rows.append(candidate)
            if len(rows) >= limit:
                break
    return rows


class ScheduleStore:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10)
        self.path.chmod(0o600)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("Unsupported schedule database version")
            db.execute("CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, page TEXT NOT NULL, definition TEXT NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL, cursor REAL NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS occurrences (id TEXT PRIMARY KEY, schedule TEXT NOT NULL, page TEXT NOT NULL, local_date TEXT NOT NULL, start REAL NOT NULL, end REAL NOT NULL, state TEXT NOT NULL, due REAL NOT NULL, record TEXT NOT NULL, UNIQUE(schedule,local_date))")
            db.execute("CREATE INDEX IF NOT EXISTS schedule_work ON occurrences(state,due)")
            db.execute("CREATE TABLE IF NOT EXISTS schedule_meta (key TEXT PRIMARY KEY, value REAL NOT NULL)")
            db.execute("PRAGMA user_version=1")
            with db:
                yield db
        finally:
            db.close()

    def schedules(self, page=None):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM schedules WHERE (? IS NULL OR page=?) AND status!='deleted' ORDER BY id", (page, page)).fetchall()
        return [{**dict(row), "definition": json.loads(row["definition"])} for row in rows]

    def check_recovery(self, pages):
        """HA cold backups exclude the permit. Restored jobs require owner resume.

        Called by the supervisor before guest processes start. Copies made outside
        HA must omit the permit too. A missing/mismatched permit fails closed.
        """
        permit = self.path.with_name("schedule-authorization")
        with self.connect() as db:
            saved = db.execute("SELECT value FROM schedule_meta WHERE key='authorization'").fetchone()
            try:
                current = permit.read_text(encoding="ascii")
            except FileNotFoundError:
                current = ""
            recovering = bool(saved and current != saved[0])
            if recovering:
                db.execute("UPDATE schedules SET status='blocked' WHERE status='enabled'")
                db.execute("UPDATE occurrences SET state='cancelling',due=0 WHERE state NOT IN ('ended','skipped','failed','cancelled')")
        if recovering:
            for row in self.work():
                row["record"].update(reason="Backup recovery: review and resume future invitations", final_state="cancelled")
                self.put(row, "cancelling")
                grant_id = row["record"].get("grant_id")
                if grant_id:
                    try:
                        pages.remove_access_grant(row["page"], grant_id)
                    except PageNotFoundError:
                        pass
        token = "permit_" + secrets.token_hex(32)
        # A crash between the file and database writes causes safe recovery.
        temporary = permit.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            output.write(token)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(permit)
        directory = os.open(permit.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        with self.connect() as db:
            db.execute("INSERT INTO schedule_meta VALUES('authorization',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (token,))
        return recovering

    def get(self, schedule_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM schedules WHERE id=?", (schedule_id,)).fetchone()
        if row is None:
            raise ValueError("Schedule not found")
        return {**dict(row), "definition": json.loads(row["definition"])}

    def upcoming(self, definition, now, schedule_id=None):
        """An edit never reissues a date already processed by this schedule."""
        with self.connect() as db:
            used = {row[0] for row in db.execute("SELECT local_date FROM occurrences WHERE schedule=?", (schedule_id,))}
        return [row for row in upcoming(definition, now, limit=6) if row["local_date"] not in used][:5]

    def save(self, page, definition, now, schedule_id=None):
        validate_page_id(page)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if schedule_id:
                row = db.execute("SELECT * FROM schedules WHERE id=? AND page=? AND status!='deleted'", (schedule_id, page)).fetchone()
                if row is None:
                    raise ValueError("Schedule not found")
                db.execute("UPDATE schedules SET definition=?,revision=revision+1,cursor=? WHERE id=?", (json.dumps(definition), now, schedule_id))
                db.execute("UPDATE occurrences SET state='cancelling',due=0 WHERE schedule=? AND state NOT IN ('accepted','ended','skipped','failed','cancelled')", (schedule_id,))
            else:
                if db.execute("SELECT count(*) FROM schedules WHERE status!='deleted'").fetchone()[0] >= MAX_SCHEDULES:
                    raise ValueError("Maximum of 200 schedules reached")
                schedule_id = "schedule_" + secrets.token_hex(12)
                db.execute("INSERT INTO schedules VALUES(?,?,?,'enabled',1,?)", (schedule_id, page, json.dumps(definition), now))
        return schedule_id

    def status(self, schedule_id, status, now, revoke=False):
        if status not in {"enabled", "paused", "blocked", "deleted"}:
            raise ValueError("Invalid schedule status")
        with self.connect() as db:
            db.execute("UPDATE schedules SET status=?,cursor=?,revision=revision+1 WHERE id=?", (status, now, schedule_id))
            db.execute("UPDATE occurrences SET state='cancelling',due=0 WHERE schedule=? AND (state NOT IN ('accepted','ended','skipped','failed','cancelled') OR (? AND state='accepted'))", (schedule_id, revoke))

    def pause_page(self, page, now, revoke=False):
        # Page locks are held by owner routes and workers, including reset.
        if not self.path.exists():
            return
        for schedule in self.schedules(page):
            self.status(schedule["id"], "paused", now, revoke)

    def work(self):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM occurrences WHERE state NOT IN ('ended','skipped','failed','cancelled') ORDER BY due,start LIMIT 1000").fetchall()
        return [{**dict(row), "record": json.loads(row["record"])} for row in rows]

    def put(self, row, state, due=0):
        with self.connect() as db:
            db.execute("UPDATE occurrences SET state=?,due=?,record=? WHERE id=?", (state, due, json.dumps(row["record"]), row["id"]))
        row.update(state=state, due=due)

    def history(self, page):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM occurrences WHERE page=? ORDER BY start DESC LIMIT 100", (page,)).fetchall()
        # Never return stored grants, links, bootstrap hashes, or raw failures.
        result = []
        for row in rows:
            record = json.loads(row["record"])
            result.append({key: row[key] for key in ("id", "schedule", "local_date", "start", "end", "state", "due")} |
                          {key: record.get(key) for key in ("label", "reason", "attempts", "email_attempts", "accepted_at", "timezone")})
        return result

    def plan(self, schedule, now):
        d = schedule["definition"]
        zone = ZoneInfo(d["timezone"])
        today = datetime.fromtimestamp(now, zone).date()
        cursor = schedule["cursor"]
        # Record at most 30 days of missed occurrences; older ones are never replayed.
        first = max(datetime.fromtimestamp(cursor, zone).date() - timedelta(days=1), today - timedelta(days=30))
        with self.connect() as db:
            for offset in range((today - first).days + 1):
                window = occurrence_window(d, first + timedelta(days=offset))
                if not window:
                    continue
                start, end = window["start"], window["end"]
                if start is None or end is None:
                    # Use a nominal boundary only to timestamp the skipped event;
                    # never mint access for an ambiguous/nonexistent wall time.
                    start = datetime.combine(first + timedelta(days=offset), wall_time.fromisoformat(d["start_time"]), zone).timestamp()
                    end = start
                if not cursor < start <= now:
                    continue
                reason = window["reason"]
                if not reason and (now >= start + GRACE or end - now < 60):
                    reason = "Skipped: start grace period passed while unavailable"
                record = {**d, "revision": schedule["revision"], "attempts": 0, "email_attempts": 0, "reason": reason}
                occurrence_id = "occ_" + sha256(f'{schedule["id"]}:{window["local_date"]}'.encode()).hexdigest()[:32]
                db.execute("INSERT OR IGNORE INTO occurrences VALUES(?,?,?,?,?,?,?,?,?)", (occurrence_id, schedule["id"], schedule["page"], window["local_date"], start, end, "skipped" if reason else "pending", now, json.dumps(record)))
            db.execute("UPDATE schedules SET cursor=? WHERE id=?", (now, schedule["id"]))

    def housekeeping(self, now):
        with self.connect() as db:
            previous = db.execute("SELECT value FROM schedule_meta WHERE key='last_tick'").fetchone()
            if previous and now < previous[0] - 60:
                db.execute("UPDATE schedules SET status='blocked' WHERE status='enabled'")
                db.execute("UPDATE occurrences SET state='cancelling',due=0 WHERE state NOT IN ('ended','skipped','failed','cancelled')")
            db.execute("INSERT INTO schedule_meta VALUES('last_tick',?) ON CONFLICT(key) DO UPDATE SET value=MAX(value,excluded.value)", (now,))
            db.execute("DELETE FROM occurrences WHERE end<? AND state IN ('ended','skipped','failed','cancelled')", (now - 30 * 86400,))


class Scheduler:
    def __init__(self, runtime, store, clock=time.time):
        self.r = runtime
        self.store = store
        self.clock = clock
        self.stop = Event()
        self.lock_file = None
        self.creation_after = 0
        self.email_after = 0

    def deny(self, row):
        """Synchronous local denial, also used by the owner's revoke action."""
        grant_id = row["record"].get("grant_id")
        if not grant_id:
            return
        try:
            page = self.r.PAGE_STORE.load(row["page"])
            grant = next((g for g in page["access_grants"] if g["id"] == grant_id), None)
            if grant:
                self.r.PAGE_STORE.remove_access_grant(row["page"], grant_id)
                self.r.ACTIVITY_STORE.mark_revoked(row["page"], grant)
        except PageNotFoundError:
            pass
        self.r.cleanup_guest_sessions(row["page"], grant_id)
        self.r.VERIFICATION_RECIPIENTS.delete(row["page"], grant_id)

    def retire(self, row):
        """Local denial first; keep durable work until upstream owns cleanup."""
        grant_id = row["record"].get("grant_id")
        if not grant_id:
            return
        self.deny(row)
        self.r.LAYERV_CLIENT.queue_revocation(page_id=row["page"], grant_id=grant_id)
        row["record"].pop("grant", None)
        row["record"].pop("grant_id", None)

    def abandon(self, row, state, reason):
        row["record"].update(final_state=state, reason=reason)
        self.store.put(row, "cancelling")
        self.retire(row)
        self.store.put(row, state)

    def tick(self, delivery=False):
        now = self.clock()
        if not delivery:
            self.store.housekeeping(now)
            for schedule in self.store.schedules():
                with self.r.page_action_lock(schedule["page"]):
                    schedule = self.store.get(schedule["id"])
                    if schedule["status"] != "enabled":
                        continue
                    if not self.r.SMTP_CONFIG_STORE.configured():
                        self.store.status(schedule["id"], "blocked", now)
                        continue
                    try:
                        self.r.PAGE_STORE.load(schedule["page"])
                    except PageNotFoundError:
                        self.store.status(schedule["id"], "deleted", now, True)
                        continue
                    self.store.plan(schedule, now)
        for old in self.store.work():
            if (old["state"] in {"ready", "sending"}) != delivery:
                continue
            with self.r.page_action_lock(old["page"]):
                # Owner edits may have cancelled the row while this worker waited.
                row = next((item for item in self.store.work() if item["id"] == old["id"]), None)
                if row is None or (row["state"] in {"ready", "sending"}) != delivery:
                    continue
                now = self.clock()
                try:
                    self.process(row, now, delivery)
                except (OSError, sqlite3.Error, LayerVError, EmailConfigError, PageConfigError, ValueError):
                    # Keep the pre-call journal state; retry/reconcile on the next tick.
                    self.r.audit("scheduled_invitation_worker_failed", occurrence_id=row["id"])

    def process(self, row, now, delivery):
        record = row["record"]
        if row["state"] == "cancelling":
            self.retire(row)
            self.store.put(row, record.get("final_state", "cancelled"))
            return
        if row["state"] == "accepted":
            if "grant" in record:
                try:
                    self.r.PAGE_STORE.remove_saved_guest_link(row["page"], record["grant_id"])
                except PageNotFoundError:
                    pass
                record.pop("grant", None)
                self.store.put(row, "accepted")
            if now >= row["end"]:
                self.abandon(row, "ended", "Access window ended")
            return
        schedule = self.store.get(row["schedule"])
        if schedule["status"] != "enabled" or schedule["revision"] != record["revision"]:
            self.abandon(row, "cancelled", "Schedule changed or paused before delivery")
            return
        deadline = min(row["start"] + GRACE, row["end"] - 60)
        if now >= deadline:
            self.abandon(row, "failed", "Delivery deadline passed; original access end preserved")
            return
        if not self.r.SMTP_CONFIG_STORE.configured():
            self.store.status(schedule["id"], "blocked", now)
            self.abandon(row, "failed", "Email configuration unavailable; resume after configuring SMTP")
            return
        if row["due"] > now:
            return
        if delivery:
            if now >= self.email_after:
                self.deliver(row, now)
            return
        if row["state"] == "creating":
            # A previous call/process failed before persisting a definitive result.
            # No local grant was committed; resource ownership is already journaled.
            self.retire(row)
            self.store.put(row, "pending", now + 5)
            return
        if row["state"] == "created":
            self.commit(row, now)
            return
        if row["state"] == "committing":
            page = self.r.PAGE_STORE.load(row["page"])
            if any(g["id"] == record["grant_id"] for g in page["access_grants"]):
                self.store.put(row, "ready")
            else:
                self.abandon(row, "cancelled", "Interrupted commit or owner revocation; access was not restored")
            return
        if now < self.creation_after:
            return
        record["attempts"] += 1
        record["grant_id"] = "grant_" + secrets.token_urlsafe(12)
        secret = secrets.token_urlsafe(32)
        self.store.put(row, "creating")
        duration = min(86400, row["end"] - now)
        lifetime = f"{math.ceil(duration / 60)}m"
        try:
            qurl = self.r.LAYERV_CLIENT.create_qurl(
                label=record["label"], expires_in=lifetime,
                one_time_use=record["one_time_use"], page_id=row["page"],
                grant_id=record["grant_id"],
                target_path=f'/g/{row["page"]}/{record["grant_id"]}/?bootstrap={secret}',
                target_path_supported=True, session_duration=f"{int(duration)}s",
            )
        except LayerVError as error:
            delay = error.retry_after or min(300, 5 * 2 ** min(record["attempts"], 6))
            self.creation_after = self.clock() + max(5, delay) + secrets.randbelow(5)
            record["reason"] = "LayerV creation failed; reconciling before retry"
            self.store.put(row, "creating", self.creation_after)
            if error.status in {401, 403}:
                self.store.status(schedule["id"], "blocked", self.clock())
            return
        grant = invitation_grant(qurl, grant_id=record["grant_id"], secret=secret,
                                 created_at=datetime.fromtimestamp(now, UTC),
                                 expires_at=datetime.fromtimestamp(row["end"], UTC),
                                 label=record["label"], lifetime=lifetime,
                                 one_time_use=record["one_time_use"],
                                 verification_required=record["verification_required"],
                                 notifications=record["notifications"])
        record["grant"] = grant
        self.store.put(row, "created")
        self.commit(row, self.clock())

    def commit(self, row, now):
        record = row["record"]
        grant = record["grant"]
        if now >= min(row["start"] + GRACE, row["end"] - 60) or datetime.fromisoformat(grant["expires_at"]).timestamp() <= now + 60:
            self.abandon(row, "failed", "Creation finished too late for delivery")
            return
        page = self.r.PAGE_STORE.load(row["page"])
        self.store.put(row, "committing")
        if record["verification_required"]:
            self.r.VERIFICATION_RECIPIENTS.set(row["page"], grant["id"], record["email"])
        if not any(g["id"] == grant["id"] for g in page["access_grants"]):
            page["access_grants"].insert(0, grant)
            self.r.PAGE_STORE.replace(row["page"], page)
        self.r.ACTIVITY_STORE.register_guest(row["page"], grant)
        self.store.put(row, "ready")

    def deliver(self, row, now):
        record = row["record"]
        page = self.r.PAGE_STORE.load(row["page"])
        grant = next((g for g in page["access_grants"] if g["id"] == record["grant_id"]), None)
        if grant is None or datetime.fromisoformat(grant["expires_at"]).timestamp() <= now + 60:
            self.abandon(row, "cancelled", "Invitation revoked or expired before delivery")
            return
        record["email_attempts"] += 1
        self.store.put(row, "sending")
        zone = ZoneInfo(record["timezone"])
        window = " to ".join(datetime.fromtimestamp(row[key], zone).strftime("%Y-%m-%d %H:%M %Z (%z)") for key in ("start", "end"))
        text, html = guest_invitation_email_content(record["grant"]["qurl_link"], verification_required=record["verification_required"])
        text += f"\nScheduled access: {window}\nTimezone: {record['timezone']}\nAccess still ends at the original time if this email arrives late.\n"
        # Plain text and HTML show the same original absolute window.
        from html import escape
        html += f"<p>Scheduled access: {escape(window)}. Timezone: {escape(record['timezone'])}. Access ends at the original time even if delivery is late.</p>"
        try:
            send_email(self.r.SMTP_CONFIG_STORE.load(), record["email"], "Your scheduled Access Pages invitation", text, html_body=html,
                       message_id=f'<{row["id"]}@access-pages.invalid>')
        except EmailConfigError as error:
            if getattr(error, "permanent", False):
                self.abandon(row, "failed", "Email server rejected the invitation")
            else:
                delay = min(300, 10 * 2 ** min(record["email_attempts"], 5)) + secrets.randbelow(5)
                self.email_after = self.clock() + delay
                record["reason"] = "Email delivery uncertain or unavailable; retrying the same link"
                self.store.put(row, "ready", self.email_after)
            return
        record.update(accepted_at=self.clock(), reason="Accepted by email server; inbox delivery is not confirmed")
        self.store.put(row, "accepted")
        # Retain only the authority hash and cleanup IDs after SMTP acceptance.
        self.r.PAGE_STORE.remove_saved_guest_link(row["page"], grant["id"])
        record.pop("grant", None)
        self.store.put(row, "accepted")
        self.r.audit("scheduled_invitation_accepted", occurrence_id=row["id"])

    def start(self):
        if not isinstance(self.r.LAYERV_CLIENT, BrokerLayerVClient):
            return  # Recovery requires broker-owned resource retirement.
        self.store.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_file = open(self.store.path.with_suffix(".lock"), "a", encoding="utf-8")
        os.fchmod(self.lock_file.fileno(), 0o600)
        fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for delivery in (False, True):
            Thread(target=self.loop, args=(delivery,), daemon=True, name="schedule-email" if delivery else "schedule-create").start()

    def loop(self, delivery):
        while not self.stop.is_set():
            try:
                self.tick(delivery)
            except (OSError, sqlite3.Error, ValueError, PageConfigError):
                self.r.audit("schedule_storage_unavailable")
            self.stop.wait(5)
