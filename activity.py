import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock


RETENTION_DAYS = 30
MAX_ACTIONS_PER_GUEST = 1000
MAX_SECURITY_EVENTS_PER_PAGE = 1000
SAFE_SECURITY_DETAIL_KEYS = {
    "action_id",
    "reason",
    "resource_id",
}
SAFE_PARAMETER_KEYS = {
    "brightness_pct",
    "hvac_mode",
    "option",
    "percentage",
    "position",
    "source",
    "temperature",
    "target_temp_high",
    "target_temp_low",
    "value",
    "volume_level",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class GuestActivityStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = RLock()

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        self._initialize(connection)
        try:
            # Activity storage is owned by the trusted admin plane. Guest
            # endpoints submit page-bound events through the internal broker.
            os.chmod(self.path, 0o600)  # nosec B103
        except OSError:
            pass
        return connection

    @staticmethod
    def _initialize(connection):
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS guests (
                grant_id TEXT PRIMARY KEY,
                page_id TEXT NOT NULL,
                label TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                purge_after TEXT,
                first_access_at TEXT,
                initial_access_recorded INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                grant_id TEXT NOT NULL REFERENCES guests(grant_id)
                    ON DELETE CASCADE,
                occurred_at TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                entity_name TEXT NOT NULL,
                action_id TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                outcome TEXT NOT NULL,
                error TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_id TEXT NOT NULL,
                grant_id TEXT REFERENCES guests(grant_id)
                    ON DELETE CASCADE,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS activity_guest_time
                ON actions(grant_id, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS security_page_time
                ON security_events(page_id, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS security_guest_time
                ON security_events(grant_id, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS guest_page_state
                ON guests(page_id, revoked_at);
            CREATE TABLE IF NOT EXISTS scheduled_activity_links (
                grant_id TEXT PRIMARY KEY REFERENCES guests(grant_id) ON DELETE CASCADE,
                page_id TEXT NOT NULL,
                guest_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                starts REAL NOT NULL,
                ends REAL NOT NULL,
                timezone TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS scheduled_activity_guest
                ON scheduled_activity_links(page_id, guest_id);
            """
        )
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(guests)")
        }
        if "first_access_at" not in columns:
            connection.execute(
                "ALTER TABLE guests ADD COLUMN first_access_at TEXT"
            )
        if "initial_access_recorded" not in columns:
            connection.execute("ALTER TABLE guests ADD COLUMN initial_access_recorded INTEGER NOT NULL DEFAULT 0")
            connection.execute("UPDATE guests SET initial_access_recorded=1 WHERE first_access_at IS NOT NULL")

    def register_guest(self, page_id: str, grant: dict) -> None:
        with self._lock, self._connect() as connection:
            self._upsert_guest(connection, page_id, grant)
            self._purge(connection)

    def mark_revoked(
        self,
        page_id: str,
        grant: dict,
        *,
        revoked_at: datetime | None = None,
    ) -> None:
        revoked = revoked_at or _now()
        purge_after = revoked + timedelta(days=RETENTION_DAYS)
        with self._lock, self._connect() as connection:
            self._upsert_guest(connection, page_id, grant)
            connection.execute(
                """
                UPDATE guests
                SET revoked_at = ?, purge_after = ?
                WHERE grant_id = ?
                """,
                (_iso(revoked), _iso(purge_after), grant["id"]),
            )
            self._purge(connection)

    @staticmethod
    def _upsert_guest(connection, page_id: str, grant: dict) -> None:
        connection.execute(
            """
            INSERT INTO guests (
                grant_id, page_id, label, created_at, expires_at,
                revoked_at, purge_after
            ) VALUES (?, ?, ?, ?, ?, NULL, NULL)
            ON CONFLICT(grant_id) DO UPDATE SET
                page_id = excluded.page_id,
                label = excluded.label,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at
            """,
            (
                grant["id"],
                page_id,
                str(grant.get("label", ""))[:120],
                grant["created_at"],
                grant["expires_at"],
            ),
        )

    def record_action(
        self,
        *,
        grant_id: str,
        entity_id: str,
        entity_name: str,
        action_id: str,
        parameters: dict,
        outcome: str,
        error: str = "",
    ) -> None:
        safe_parameters = {
            key: value
            for key, value in parameters.items()
            if key in SAFE_PARAMETER_KEYS
            and isinstance(value, (str, int, float, bool))
        }
        safe_error = str(error).strip()[:240]
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO actions (
                    grant_id, occurred_at, entity_id, entity_name,
                    action_id, parameters_json, outcome, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    grant_id,
                    _iso(_now()),
                    entity_id[:255],
                    entity_name[:120],
                    action_id[:80],
                    json.dumps(safe_parameters, separators=(",", ":")),
                    outcome,
                    safe_error,
                ),
            )
            connection.execute(
                """
                DELETE FROM actions
                WHERE grant_id = ? AND id NOT IN (
                    SELECT id FROM actions
                    WHERE grant_id = ?
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT ?
                )
                """,
                (grant_id, grant_id, MAX_ACTIONS_PER_GUEST),
            )
            self._purge(connection)

    def record_registered_initial_access(self, page_id: str, grant_id: str) -> bool:
        """Record a broker-confirmed visit without recreating a removed grant."""
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """UPDATE guests SET first_access_at = ?, initial_access_recorded=1
                   WHERE page_id = ? AND grant_id = ? AND initial_access_recorded=0""",
                (_iso(_now()), page_id, grant_id),
            )
            self._purge(connection)
            return cursor.rowcount == 1

    def record_security_event(
        self,
        *,
        page_id: str,
        event_type: str,
        grant_id: str | None = None,
        details: dict | None = None,
    ) -> None:
        safe_details = {
            key: value
            for key, value in (details or {}).items()
            if key in SAFE_SECURITY_DETAIL_KEYS
            and isinstance(value, (str, int, float, bool))
        }
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO security_events (
                    page_id, grant_id, occurred_at, event_type, details_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    page_id[:64],
                    grant_id or None,
                    _iso(_now()),
                    event_type[:80],
                    json.dumps(safe_details, separators=(",", ":")),
                ),
            )
            connection.execute(
                """
                DELETE FROM security_events
                WHERE page_id = ? AND id NOT IN (
                    SELECT id FROM security_events
                    WHERE page_id = ?
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT ?
                )
                """,
                (
                    page_id,
                    page_id,
                    MAX_SECURITY_EVENTS_PER_PAGE,
                ),
            )
            self._purge(connection)

    def page_guests(self, page_id: str) -> list[dict]:
        with self._lock, self._connect() as connection:
            self._purge(connection)
            rows = connection.execute(
                """
                SELECT guests.*, scheduled_activity_links.guest_id AS scheduled_guest_id,
                       COUNT(actions.id) AS action_count,
                       MAX(actions.occurred_at) AS last_activity
                FROM guests
                LEFT JOIN actions ON actions.grant_id = guests.grant_id
                LEFT JOIN scheduled_activity_links ON scheduled_activity_links.grant_id = guests.grant_id
                WHERE guests.page_id = ?
                GROUP BY guests.grant_id
                ORDER BY guests.revoked_at IS NULL DESC,
                         COALESCE(last_activity, guests.created_at) DESC
                """,
                (page_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def guest_activity(self, page_id: str, grant_id: str) -> dict | None:
        with self._lock, self._connect() as connection:
            self._purge(connection)
            guest = connection.execute(
                "SELECT * FROM guests WHERE page_id = ? AND grant_id = ?",
                (page_id, grant_id),
            ).fetchone()
            if guest is None:
                return None
            rows = connection.execute(
                """
                SELECT occurred_at, entity_id, entity_name, action_id,
                       parameters_json, outcome, error
                FROM actions
                WHERE grant_id = ?
                ORDER BY occurred_at DESC
                LIMIT 500
                """,
                (grant_id,),
            ).fetchall()
            event_rows = connection.execute(
                """
                SELECT occurred_at, event_type, details_json
                FROM security_events
                WHERE grant_id = ?
                ORDER BY occurred_at DESC
                LIMIT 500
                """,
                (grant_id,),
            ).fetchall()
        actions = []
        for row in rows:
            item = dict(row)
            item["parameters"] = json.loads(item.pop("parameters_json"))
            actions.append(item)
        security_events = []
        for row in event_rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            security_events.append(item)
        return {
            "guest": dict(guest),
            "actions": actions,
            "security_events": security_events,
        }

    def page_security_events(self, page_id: str) -> list[dict]:
        with self._lock, self._connect() as connection:
            self._purge(connection)
            rows = connection.execute(
                """
                SELECT security_events.occurred_at,
                       security_events.event_type,
                       security_events.details_json,
                       security_events.grant_id,
                       guests.label AS guest_label
                FROM security_events
                LEFT JOIN guests
                    ON guests.grant_id = security_events.grant_id
                WHERE security_events.page_id = ?
                ORDER BY security_events.occurred_at DESC
                LIMIT 100
                """,
                (page_id,),
            ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            events.append(item)
        return events

    def delete_revoked_guest(self, page_id: str, grant_id: str) -> bool:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM guests
                WHERE page_id = ? AND grant_id = ? AND revoked_at IS NOT NULL
                """,
                (page_id, grant_id),
            )
            return cursor.rowcount == 1

    def delete_page(self, page_id: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM security_events WHERE page_id = ?",
                (page_id,),
            )
            connection.execute(
                "DELETE FROM guests WHERE page_id = ?",
                (page_id,),
            )

    @staticmethod
    def _purge(connection) -> None:
        event_cutoff = _now() - timedelta(days=RETENTION_DAYS)
        connection.execute(
            "DELETE FROM guests WHERE purge_after IS NOT NULL AND purge_after <= ?",
            (_iso(_now()),),
        )
        connection.execute(
            "DELETE FROM security_events WHERE occurred_at <= ?",
            (_iso(event_cutoff),),
        )
        connection.execute("DELETE FROM actions WHERE occurred_at <= ?", (_iso(event_cutoff),))
        connection.execute("UPDATE guests SET first_access_at=NULL WHERE first_access_at <= ?", (_iso(event_cutoff),))

    def purge(self):
        """Run rolling retention even when nobody opens the activity screen."""
        with self._lock, self._connect() as connection:
            self._purge(connection)

    def link_scheduled_guest(self, page, grant_id, guest_id, occurrence):
        """Metadata only: this association never grants or extends access."""
        with self._lock, self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO scheduled_activity_links
                   SELECT grant_id, page_id, ?, ?, ?, ?, ? FROM guests
                   WHERE grant_id=? AND page_id=?""",
                (guest_id, occurrence["id"], occurrence["start"], occurrence["end"],
                 occurrence["record"]["timezone"], grant_id, page),
            )

    def scheduled_timeline(self, page, guest_id, occurrence_id, before, limit=51):
        with self._lock, self._connect() as connection:
            self._purge(connection)
            rows = connection.execute(
                """WITH events AS (
                    SELECT grant_id, unixepoch(occurred_at) AS at, 'action:' || id AS key,
                           'action' AS type, entity_name AS title, outcome,
                           parameters_json AS details, action_id, error FROM actions
                    UNION ALL
                    SELECT grant_id, unixepoch(occurred_at), 'security:' || id,
                           'security', event_type, '', details_json, '', '' FROM security_events
                    UNION ALL
                    SELECT grant_id, unixepoch(first_access_at), 'visit:' || grant_id,
                           'visit', 'First successful access', '', '{}', '', '' FROM guests
                           WHERE first_access_at IS NOT NULL
                ) SELECT events.*, links.occurrence_id, links.starts AS start, links.ends AS end,
                         links.timezone FROM events JOIN scheduled_activity_links links
                         ON links.grant_id=events.grant_id
                  WHERE links.page_id=? AND links.guest_id=?
                    AND (? IS NULL OR links.occurrence_id=?)
                    AND (at<? OR (at=? AND key<?))
                  ORDER BY at DESC, key DESC LIMIT ?""",
                (page, guest_id, occurrence_id, occurrence_id, before[0], before[0], before[1], limit),
            ).fetchall()
        return [{key: row[key] for key in ("at", "key", "type", "title", "outcome", "action_id", "error",
                                          "occurrence_id", "start", "end", "timezone")} |
                {"details": json.loads(row["details"])} for row in rows]
