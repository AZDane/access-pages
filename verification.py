"""Short-lived email verification challenges and guest sessions."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import hmac
import secrets
import sqlite3
from threading import Lock
from contextlib import contextmanager
from time import monotonic, sleep


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> int:
    return int(value.timestamp())


class VerificationStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._initialized = False
        self._initialize_lock = Lock()

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        self.path.chmod(0o600)
        try:
            deadline = monotonic() + 10
            while True:
                try:
                    connection.execute("PRAGMA journal_mode=WAL")
                    break
                except sqlite3.OperationalError as error:
                    if "locked" not in str(error) or monotonic() >= deadline:
                        raise
                    sleep(0.01)
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self):
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            with self._connect() as db:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS challenges (
                    page_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                    code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    sent_at INTEGER NOT NULL,
                    PRIMARY KEY (page_id, grant_id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, page_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sessions_grant
                    ON sessions(page_id, grant_id);
                CREATE TABLE IF NOT EXISTS consumed_bootstraps (
                    token_hash TEXT PRIMARY KEY,
                    page_id TEXT NOT NULL, grant_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS guest_sessions (
                    token_hash TEXT PRIMARY KEY, page_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL, expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS guest_session_grants (
                    token_hash TEXT PRIMARY KEY, grant_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS guest_challenges (
                    token_hash TEXT PRIMARY KEY, page_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL, challenge_id TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL,
                    sent_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS guest_verifications (
                    token_hash TEXT PRIMARY KEY, page_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL, expires_at INTEGER NOT NULL
                );
                """)
            self._initialized = True

    def consume_bootstrap(self, page_id, grant_id, secret, expected_hash, grant_expires):
        """Exchange an invitation once; verification remains a separate gate.

        The caller must load the current active grant, and must recheck that
        grant on every request. Neither a route nor this cookie is a grant.
        """
        actual = sha256(secret.encode()).hexdigest()
        if not secret or not hmac.compare_digest(actual, expected_hash):
            raise ValueError("The invitation is invalid or already consumed")
        self._initialize()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = _timestamp(_now())
            # Admission can be renewed with the same qURL. This cookie identifies
            # its original browser until grant expiry; OTP authorization retains
            # its separate twelve-hour limit below.
            expires = _timestamp(grant_expires)
            if expires <= now:
                raise ValueError("The invitation is invalid or already consumed")
            try:
                db.execute(
                    "INSERT INTO consumed_bootstraps VALUES(?,?,?)",
                    (actual, page_id, grant_id),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("The invitation is invalid or already consumed") from error
            token = secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO guest_sessions VALUES(?,?,?,?)",
                (sha256(token.encode()).hexdigest(), page_id, grant_id, expires),
            )
            db.execute(
                "INSERT INTO guest_session_grants VALUES(?,?)",
                (sha256(token.encode()).hexdigest(), expected_hash),
            )
        return token, expires

    def guest_session_grant(self, token, page_id):
        info = self.guest_session_info(token, page_id)
        return info[0] if info else None

    def guest_session_info(self, token, page_id):
        """Return the bound grant and stored expiry for one live guest cookie."""
        if not token:
            return None
        self._initialize()
        with self._connect() as db:
            row = db.execute(
                "SELECT s.grant_id, s.expires_at, g.grant_hash "
                "FROM guest_sessions s JOIN guest_session_grants g "
                "ON s.token_hash=g.token_hash WHERE s.token_hash=? "
                "AND s.page_id=? AND s.expires_at>?",
                (sha256(token.encode()).hexdigest(), page_id, _timestamp(_now())),
            ).fetchone()
        return tuple(row) if row else None

    def issue_guest_challenge(self, token, page_id, grant_id, *, replace=False):
        """Persist a session-bound OTP; return a hash for conditional cancellation."""
        self._initialize()
        key = sha256(token.encode()).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = _timestamp(_now())
            session = db.execute(
                "SELECT 1 FROM guest_sessions WHERE token_hash=? AND page_id=? "
                "AND grant_id=? AND expires_at>?", (key, page_id, grant_id, now),
            ).fetchone()
            if not session:
                raise ValueError("Guest session is invalid")
            current = db.execute(
                "SELECT expires_at, attempts, sent_at FROM guest_challenges "
                "WHERE token_hash=?", (key,),
            ).fetchone()
            if current and current[0] > now and current[1] < 5 and not replace:
                return None
            if current and now - current[2] < 60:
                raise ValueError("Wait 60 seconds before requesting another code")
            code = f"{secrets.randbelow(1_000_000):06d}"
            challenge_id = secrets.token_urlsafe(16)
            db.execute(
                "INSERT OR REPLACE INTO guest_challenges VALUES(?,?,?,?,?,?,?,?)",
                (key, page_id, grant_id, challenge_id,
                 sha256(code.encode()).hexdigest(), now + 600, 0, now),
            )
        return code, challenge_id

    def cancel_guest_challenge(self, token, challenge_id):
        self._initialize()
        with self._connect() as db:
            db.execute(
                "DELETE FROM guest_challenges WHERE token_hash=? AND challenge_id=?",
                (sha256(token.encode()).hexdigest(), challenge_id),
            )

    def verify_guest_challenge(self, token, page_id, grant_id, code, grant_expiry):
        self._initialize()
        key = sha256(token.encode()).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now = _timestamp(_now())
            session = db.execute(
                "SELECT expires_at FROM guest_sessions WHERE token_hash=? "
                "AND page_id=? AND grant_id=? AND expires_at>?",
                (key, page_id, grant_id, now),
            ).fetchone()
            row = db.execute(
                "SELECT code_hash, expires_at, attempts FROM guest_challenges "
                "WHERE token_hash=? AND page_id=? AND grant_id=?",
                (key, page_id, grant_id),
            ).fetchone()
            if (not session or not row or row[1] <= now or row[2] >= 5
                    or grant_expiry <= now):
                raise ValueError("The verification code is invalid or expired")
            db.execute(
                "UPDATE guest_challenges SET attempts=attempts+1 WHERE token_hash=?",
                (key,),
            )
            if not hmac.compare_digest(row[0], sha256(code.encode()).hexdigest()):
                db.commit()
                raise ValueError("The verification code is invalid or expired")
            expires = min(now + 12 * 3600, session[0], grant_expiry)
            db.execute("DELETE FROM guest_challenges WHERE token_hash=?", (key,))
            db.execute(
                "INSERT OR REPLACE INTO guest_verifications VALUES(?,?,?,?)",
                (key, page_id, grant_id, expires),
            )
        return expires

    def guest_verified_until(self, token, page_id, grant_id):
        self._initialize()
        with self._connect() as db:
            row = db.execute(
                "SELECT expires_at FROM guest_verifications WHERE token_hash=? "
                "AND page_id=? AND grant_id=? AND expires_at>?",
                (sha256(token.encode()).hexdigest(), page_id, grant_id,
                 _timestamp(_now())),
            ).fetchone()
        return row[0] if row else None

    def issue_challenge(
        self, page_id: str, grant_id: str, *, replace: bool = False,
    ) -> str | None:
        self._initialize()
        now = _timestamp(_now())
        with self._connect() as db:
            # Serialize the complete read/check/write, including across store
            # instances. SQLite's implicit transaction starts only at UPDATE.
            db.execute("BEGIN IMMEDIATE")
            now = _timestamp(_now())
            current = db.execute(
                "SELECT expires_at, attempts, sent_at FROM challenges "
                "WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            ).fetchone()
            if current and current[0] > now and current[1] < 5 and not replace:
                return None
            if current and now - current[2] < 60:
                raise ValueError("Wait 60 seconds before requesting another code")
            code = f"{secrets.randbelow(1_000_000):06d}"
            db.execute(
                "INSERT OR REPLACE INTO challenges "
                "(page_id, grant_id, code_hash, expires_at, attempts, sent_at) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                (page_id, grant_id, sha256(code.encode()).hexdigest(), now + 600, now),
            )
        return code

    def cancel_challenge(self, page_id: str, grant_id: str) -> None:
        self._initialize()
        with self._connect() as db:
            db.execute(
                "DELETE FROM challenges WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            )

    def verify(self, page_id: str, grant_id: str, code: str, grant_expires: datetime):
        self._initialize()
        now = _timestamp(_now())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Time may have advanced while waiting for another writer.
            now = _timestamp(_now())
            if _timestamp(grant_expires) <= now:
                raise ValueError("The verification code is invalid or expired")
            row = db.execute(
                "SELECT code_hash, expires_at, attempts FROM challenges "
                "WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            ).fetchone()
            if not row or row[1] <= now or row[2] >= 5:
                raise ValueError("The verification code is invalid or expired")
            db.execute(
                "UPDATE challenges SET attempts=attempts+1 WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            )
            matched = hmac.compare_digest(
                row[0], sha256(code.encode()).hexdigest(),
            )
            if not matched:
                db.commit()
                raise ValueError("The verification code is invalid or expired")
            token = secrets.token_urlsafe(32)
            session_expires = min(now + 12 * 3600, _timestamp(grant_expires))
            db.execute(
                "DELETE FROM challenges WHERE page_id=? AND grant_id=?",
                (page_id, grant_id),
            )
            db.execute(
                "INSERT INTO sessions(token_hash,page_id,grant_id,expires_at) "
                "VALUES(?,?,?,?)",
                (sha256(token.encode()).hexdigest(), page_id, grant_id, session_expires),
            )
        return token, session_expires

    def valid_session(self, token: str, page_id: str, grant_id: str) -> bool:
        if not token:
            return False
        self._initialize()
        now = _timestamp(_now())
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            row = db.execute(
                "SELECT 1 FROM sessions WHERE token_hash=? AND page_id=? "
                "AND grant_id=? AND expires_at>?",
                (sha256(token.encode()).hexdigest(), page_id, grant_id, now),
            ).fetchone()
        return row is not None

    def revoke(self, page_id: str, grant_id: str) -> None:
        self._initialize()
        with self._connect() as db:
            db.execute("DELETE FROM challenges WHERE page_id=? AND grant_id=?", (page_id, grant_id))
            db.execute("DELETE FROM guest_sessions WHERE page_id=? AND grant_id=?", (page_id, grant_id))
            db.execute("DELETE FROM guest_session_grants WHERE token_hash NOT IN "
                       "(SELECT token_hash FROM guest_sessions)")
            db.execute("DELETE FROM guest_challenges WHERE page_id=? AND grant_id=?", (page_id, grant_id))
            db.execute("DELETE FROM guest_verifications WHERE page_id=? AND grant_id=?", (page_id, grant_id))
            db.execute("DELETE FROM sessions WHERE page_id=? AND grant_id=?", (page_id, grant_id))
