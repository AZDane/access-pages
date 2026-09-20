"""Private durable ownership of one LayerV resource per page/guest grant.

Resource allocation uses a supplied supported Connector publisher. Resource
ownership is recorded before publication. Each guest grant has one resource
and one invitation. Revocation uses this private binding, never browser identifiers.
"""

from contextlib import contextmanager
from hashlib import sha256
import http.client
import json
import os
import re
import secrets
import signal
import socket
import sqlite3
import stat
import subprocess  # nosec B404
import tempfile
import time
from pathlib import Path
from threading import RLock

from layerv import LayerVClient, LayerVError


class AgentRecoveryRequired(LayerVError):
    """Established Agent identity needs an explicit owner reset."""

    def __init__(self, message):
        super().__init__(message, status=503)


def _present(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


PAGE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
GRANT = re.compile(r"grant_[A-Za-z0-9_-]{16}")


class ConnectorPublisher:
    """Run all guest routes in one pinned CLI daemon owned by the broker.

    qURL 2.6.0 reloads this externally supervised daemon. The broker owns its
    lifecycle; CLI commands must never install a native background job.
    """

    native_retirement = True

    def __init__(
        self,
        state_directory,
        *,
        api_base_url,
        enrollment_key,
        binary="/usr/local/bin/qurl",
        mode="per-share",
    ):
        if mode not in {"single", "per-share"}:
            raise ValueError("Invalid Connector session mode")
        self.state = Path(state_directory)
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state.chmod(0o700)
        home = self.state.parent / "connector-home"
        home.mkdir(exist_ok=True, mode=0o700)
        self.env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "QURL_CONNECTOR_STATE_DIR": str(self.state),
            "QURL_SHARE_GROUP_MODE": mode,
        }
        self.command = [binary, "--endpoint", api_base_url, "--supervision", "external", "-o", "json"]
        self.management = LayerVClient(api_base_url, enrollment_key, "enrollment")
        self.wrapping_key = self.state.parent / "agent-wrapping-key"
        self.agent_state = self.state / "agent_state.sealed.json"
        self.runtime_mode = self.state / "runtime_mode.json"
        # Outside the state directory so its loss cannot appear fresh.
        self.bootstrap_complete = self.state.parent / "agent-bootstrap-complete"
        self.mode = mode
        self.daemon = None
        self.closed = False
        self.recovery_required = False
        self.lock = RLock()

    def _fresh(self):
        if _present(self.bootstrap_complete) or _present(self.wrapping_key) or any(self.state.iterdir()):
            return False
        resources = self.state.parent / "guest-resources.sqlite3"
        if resources.exists():
            with sqlite3.connect(f"file:{resources}?mode=ro", uri=True) as db:
                state_table = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrollment_state'"
                ).fetchone()
                if not state_table:
                    # Older databases with any allocation are established.
                    return not db.execute(
                        "SELECT EXISTS(SELECT 1 FROM resources) OR "
                        "EXISTS(SELECT 1 FROM retirements) OR "
                        "EXISTS(SELECT 1 FROM page_generations)"
                    ).fetchone()[0]
                status = db.execute(
                    "SELECT status FROM enrollment_state WHERE name='agent'"
                ).fetchone()
                if not status or status[0] not in {"fresh", "reset-authorized"}:
                    return False
                if db.execute("SELECT 1 FROM resources WHERE phase='ready' LIMIT 1").fetchone():
                    return False
        return True

    def _advance_enrollment(self, previous, current):
        resources = self.state.parent / "guest-resources.sqlite3"
        if not resources.exists():
            return  # Standalone publisher use; production allocates before login.
        with sqlite3.connect(f"file:{resources}?mode=rw", uri=True) as db:
            updated = db.execute(
                "UPDATE enrollment_state SET status=? "
                "WHERE name='agent' AND status IN (?,?)",
                (current, *previous),
            )
            if updated.rowcount != 1:
                self.recovery_required = True
                raise AgentRecoveryRequired(
                    "LayerV Agent enrollment state changed; explicit administrator recovery is required"
                )

    def _require_enrolled(self):
        for path in (self.bootstrap_complete, self.wrapping_key, self.agent_state, self.runtime_mode):
            try:
                info = path.lstat()
            except FileNotFoundError as error:
                self.recovery_required = True
                raise AgentRecoveryRequired(
                    "Persisted LayerV Agent state is missing or incompatible; explicit administrator recovery is required"
                ) from error
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise LayerVError("Unsafe privileged Agent state", status=503)

    def _read_wrapping_key(self):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.wrapping_key, flags)
            with os.fdopen(fd, "rb") as file:
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise LayerVError("Unsafe privileged Agent wrapping key", status=503)
                key = file.read(33)
                if len(key) != 32:
                    raise LayerVError("Invalid privileged Agent wrapping key", status=503)
                return key
        except OSError as error:
            self.recovery_required = True
            raise AgentRecoveryRequired("LayerV Agent wrapping key is unavailable; explicit administrator recovery is required") from error

    @contextmanager
    def _key_pipe(self):
        key = self._read_wrapping_key()
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, key)
            os.close(write_fd)
            write_fd = -1
            yield read_fd, {**self.env, "LAYERV_KEY_PROVIDER": "local-key", "LAYERV_LOCAL_KEY_FD": str(read_fd)}
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)

    def _run(self, args):
        if args and args[0] == "login":
            if _present(self.bootstrap_complete) or _present(self.agent_state):
                raise AgentRecoveryRequired("LayerV Agent enrollment already exists; explicit administrator recovery is required")
        else:
            self._require_enrolled()
        try:
            with self._key_pipe() as (key_fd, environment):
                result = subprocess.run(  # nosec B603
                    [*self.command, *args], env=environment, pass_fds=(key_fd,),
                    capture_output=True, text=True, timeout=90,
                )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LayerVError(
                "Connector operation is unavailable", status=503, retry_after=2
            ) from error
        if result.returncode:
            operation = args[0] if args and args[0] in {"login", "publish", "delete", "status"} else "operation"
            reason = {
                4: (
                    "LayerV rejected the initial enrollment credential"
                    if operation == "login" else
                    "LayerV rejected the persisted Agent/device credential; explicit administrator recovery is required"
                ),
                6: "LayerV denied permission; check the API key's agent, read, and write scopes",
                9: "LayerV rate limit reached; wait before retrying",
                11: "LayerV or the Connector is unavailable",
            }.get(result.returncode, "Connector operation failed")
            # Only recognize fixed vendor headlines; never return raw stderr,
            # which can contain private credentials or resource information.
            stderr = result.stderr if isinstance(result.stderr, str) else ""
            if any(headline in stderr for headline in (
                "Your qURL account has reached a plan limit.",
                "This qURL account has reached its limit on active device credentials",
                "Your qURL account has reached its limit on enrolled Connectors",
            )):
                reason = "LayerV account plan limit reached"
            error_type = AgentRecoveryRequired if result.returncode == 4 and operation != "login" else LayerVError
            if error_type is AgentRecoveryRequired:
                self.recovery_required = True
            raise error_type(
                f"{reason} during {operation} (Connector exit {result.returncode})",
                **({} if error_type is AgentRecoveryRequired else {
                    "status": 429 if result.returncode == 9 else 503,
                    "retry_after": 60 if result.returncode == 9 else 2,
                }),
            )
        if args and args[0] == "delete" and "local sharing cleanup did not finish:" in result.stderr:
            # qURL may report cloud deletion before local route retirement.
            raise LayerVError("Native route retirement is pending", status=503, retry_after=2)
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            raise LayerVError("Connector returned invalid operation data") from error

    def _mark_bootstrapped(self):
        if _present(self.bootstrap_complete):
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.bootstrap_complete, flags, 0o600)
        except FileExistsError:
            return
        with os.fdopen(descriptor, "wb") as marker:
            marker.flush()
            os.fsync(marker.fileno())
        directory = os.open(self.state.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _bootstrap(self):
        if not self._fresh():
            self.recovery_required = True
            raise AgentRecoveryRequired("LayerV Agent enrollment is incomplete; explicit administrator recovery is required")
        token = self.management.mint_agent_enrollment_token()
        self._advance_enrollment(("fresh", "reset-authorized"), "enrolling")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self.wrapping_key, flags, 0o600)
            with os.fdopen(descriptor, "wb") as file:
                file.write(secrets.token_bytes(32))
                file.flush()
                os.fsync(file.fileno())
            token_fd, token_path = tempfile.mkstemp(prefix="agent-enrollment-", dir=self.state.parent)
            try:
                with os.fdopen(token_fd, "w", encoding="utf-8") as file:
                    file.write(token + "\n")
                    file.flush()
                    os.fsync(file.fileno())
                self._run(["login", "--enrollment-token-file", token_path])
            finally:
                os.unlink(token_path)
        except OSError as error:
            raise LayerVError("LayerV Agent enrollment state is unavailable", status=503) from error
        if not self.agent_state.is_file() or not self.runtime_mode.is_file():
            raise LayerVError("LayerV Agent enrollment did not establish durable state", status=503)
        self._advance_enrollment(("enrolling", "enrolling"), "enrolled")
        self._mark_bootstrapped()

    def _ipc(self):
        path = self.state / "daemon.sock"
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise OSError("Connector socket is not owner-only")
        connection = http.client.HTTPConnection("localhost", timeout=3)
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.settimeout(3)
            sock.connect(str(path))
            connection.sock = sock
            connection.request("GET", "/status")
            response = connection.getresponse()
            if response.status != 200:
                raise OSError("Connector status unavailable")
            data = json.load(response)
            expected = "5/2.6.0" + ("/per-share" if self.mode == "per-share" else "")
            if data.get("job_version") != expected:
                raise OSError("Connector version or session mode mismatch")
            return data
        finally:
            connection.close()
            sock.close()

    def _start(self):
        if self.closed:
            raise LayerVError("Shared Connector is shutting down", status=503)
        self._require_enrolled()
        if self.daemon is not None and self.daemon.poll() is None:
            self._ipc()
            return
        log_path = self.state.parent / "connector.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as log, self._key_pipe() as (key_fd, environment):
            self.daemon = subprocess.Popen(  # nosec B603
                [*self.command, "daemon", "run", "--state-dir", str(self.state),
                 "--share-group-mode", self.mode],
                env=environment, pass_fds=(key_fd,), stdout=log, stderr=log,
            )
        for _ in range(100):
            if self.daemon.poll() is not None:
                break
            try:
                self._ipc()
                return
            except (OSError, ValueError):
                time.sleep(0.1)
        self._stop_daemon()
        raise LayerVError("Shared Connector is not ready", status=503, retry_after=2)

    def __call__(self, connector_id, target_url):
        with self.lock:
            if self.closed:
                raise LayerVError("Shared Connector is shutting down", status=503)
            if self._fresh():
                self._bootstrap()
            self._require_enrolled()
            self._start()
            self._ipc()
            return self._run(["publish", target_url, "--id", connector_id])

    def close(self):
        with self.lock:
            self.closed = True
            self._stop_daemon()

    def _stop_daemon(self):
        if self.daemon is not None and self.daemon.poll() is None:
            self.daemon.send_signal(signal.SIGINT)
            try:
                self.daemon.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait()

    def cleanup(self, resource_crid):
        with self.lock:
            # This supported operation retires the native resource binding and
            # reloads IPC even when management already revoked the resource.
            self._run(["delete", resource_crid, "--yes"])

    def revoke_resource(self, resource_crid):
        # The pinned CLI's typed registered-device operation is authorized for
        # resource deletion (verified against an active isolated resource).
        self.cleanup(resource_crid)
        return False

    def restore(self):
        with self.lock:
            if self._fresh():
                return
            self._require_enrolled()
            if (self.state / "local_shares.json").exists():
                self._start()

    def ensure_ready(self, public_key):
        with self.lock:
            self._start()
            diagnostics = self._ipc().get("resources", {}).get(public_key, {})
            if diagnostics.get("state") != "serving":
                raise LayerVError(
                    "Guest resource route is not serving", status=503, retry_after=2
                )

    def healthy(self):
        with self.lock:
            if self.recovery_required:
                return False
            if self._fresh():
                return True
            try:
                self._require_enrolled()
            except LayerVError:
                return False
            if not (self.state / "local_shares.json").exists():
                return True
            if self.daemon is None or self.daemon.poll() is not None:
                return False
            try:
                self._ipc()
            except (OSError, ValueError):
                return False
            return True


class GuestResources:
    def __init__(self, path, *, installation_id, publisher, management_client):
        self.path = Path(path)
        self.installation_id = installation_id
        self.publisher = publisher
        self.management_client = management_client
        self.lock = RLock()

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10)
        self.path.chmod(0o600)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS resources ("
                "page TEXT, grant_id TEXT, connector_id TEXT UNIQUE, target TEXT, "
                "crid TEXT UNIQUE, public_key TEXT, phase TEXT, "
                "PRIMARY KEY(page,grant_id))"
            )
            db.execute("CREATE TABLE IF NOT EXISTS page_generations(page TEXT PRIMARY KEY,generation INTEGER)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS retirements (page TEXT, grant_id TEXT, "
                "crid TEXT, due REAL, attempts INTEGER, PRIMARY KEY(page,grant_id))"
            )
            retirement_columns = {row[1] for row in db.execute("PRAGMA table_info(retirements)")}
            if "qurl_id" not in retirement_columns:
                db.execute("ALTER TABLE retirements ADD COLUMN qurl_id TEXT NOT NULL DEFAULT ''")
            if "management_only" not in retirement_columns:
                db.execute(
                    "ALTER TABLE retirements ADD COLUMN management_only INTEGER NOT NULL DEFAULT 0"
                )
            columns = {row[1] for row in db.execute("PRAGMA table_info(resources)")}
            if "created_at" not in columns:
                db.execute("ALTER TABLE resources ADD COLUMN created_at REAL NOT NULL DEFAULT 0")
            if "recovery_due" not in columns:
                db.execute("ALTER TABLE resources ADD COLUMN recovery_due REAL NOT NULL DEFAULT 0")
            if "recovery_attempts" not in columns:
                db.execute("ALTER TABLE resources ADD COLUMN recovery_attempts INTEGER NOT NULL DEFAULT 0")
            db.execute("CREATE TABLE IF NOT EXISTS recovery_gates(name TEXT PRIMARY KEY,due REAL NOT NULL)")
            db.execute(
                "CREATE TABLE IF NOT EXISTS enrollment_state "
                "(name TEXT PRIMARY KEY, status TEXT NOT NULL)"
            )
            if not db.execute("SELECT 1 FROM enrollment_state WHERE name='agent'").fetchone():
                # Existing allocations predate this marker and must never look fresh.
                previously_allocated = db.execute(
                    "SELECT EXISTS(SELECT 1 FROM resources) OR "
                    "EXISTS(SELECT 1 FROM retirements) OR "
                    "EXISTS(SELECT 1 FROM page_generations)"
                ).fetchone()[0]
                db.execute(
                    "INSERT INTO enrollment_state(name,status) VALUES('agent',?)",
                    ("enrolled" if previously_allocated else "fresh",),
                )
            with db:
                yield db
        finally:
            db.close()

    def _binding(self, page_id, grant_id):
        with self._connect() as db:
            return db.execute(
                "SELECT connector_id,target,crid,public_key,phase FROM resources "
                "WHERE page=? AND grant_id=?",
                (page_id, grant_id),
            ).fetchone()

    def invalidate_for_reset(self):
        """Retire old identity bindings before its credentials are removed."""
        with self.lock, self._connect() as db:
            rows = db.execute(
                "SELECT page,grant_id,crid,phase FROM resources WHERE phase!='revoked'"
            ).fetchall()
            for page, grant, crid, phase in rows:
                retirement_id = grant
                if grant == "__page__":
                    row = db.execute(
                        "SELECT generation FROM page_generations WHERE page=?", (page,)
                    ).fetchone()
                    generation = row[0] if row else 0
                    retirement_id = f"__retired_page_{generation}__"
                    db.execute(
                        "INSERT OR REPLACE INTO page_generations VALUES(?,?)",
                        (page, generation + 1),
                    )
                    db.execute(
                        "UPDATE resources SET grant_id=? WHERE page=? AND grant_id=?",
                        (retirement_id, page, grant),
                    )
                    db.execute(
                        "UPDATE retirements SET grant_id=? WHERE page=? AND grant_id=?",
                        (retirement_id, page, grant),
                    )
                db.execute(
                    "UPDATE resources SET phase=? WHERE page=? AND grant_id=?",
                    ("retiring" if crid else "revoked", page, retirement_id),
                )
                if crid:
                    db.execute(
                        "INSERT OR IGNORE INTO retirements(page,grant_id,crid,due,attempts) "
                        "VALUES(?,?,?,?,0)",
                        (page, retirement_id, crid, time.time()),
                    )
            db.execute(
                "UPDATE enrollment_state SET status='reset-authorized' WHERE name='agent'"
            )
            # The old native namespace is about to be removed. Its queued
            # resources can be deleted by management authority without asking
            # the new Agent to operate on another Agent's local routes.
            db.execute("UPDATE retirements SET management_only=1")

    def ensure(self, page_id, grant_id, target_url, *, isolation="guest"):
        if not PAGE.fullmatch(page_id) or not GRANT.fullmatch(grant_id):
            raise LayerVError("Invalid guest resource binding")
        if isolation not in {"guest", "page"}:
            raise LayerVError("Invalid resource isolation mode")
        # Page pools have their own durable key. Switching modes cannot move an
        # existing grant or make guest resource revocation affect a page pool.
        owner_id = grant_id if isolation == "guest" else "__page__"
        with self.lock:
            binding = self._binding(page_id, owner_id)
            generation = 0
            if isolation == "page":
                with self._connect() as db:
                    row = db.execute("SELECT generation FROM page_generations WHERE page=?", (page_id,)).fetchone()
                    generation = row[0] if row else 0
                    if binding is not None and binding[4] == "revoked":
                        db.execute("UPDATE resources SET grant_id=? WHERE page=? AND grant_id='__page__'", (f"__retired_page_{generation}__", page_id))
                        generation += 1
                        db.execute("INSERT OR REPLACE INTO page_generations VALUES(?,?)", (page_id, generation))
                        binding = None
            if binding is None:
                digest = sha256(
                    (f"{self.installation_id}\0{page_id}\0{owner_id}" + (f"\0{generation}" if isolation == "page" and generation else "")).encode()
                ).hexdigest()[:40]
                with self._connect() as db:
                    db.execute(
                        "INSERT INTO resources(page,grant_id,connector_id,target,phase,created_at) VALUES(?,?,?,?,'creating',?)",
                        (
                            page_id,
                            owner_id,
                            "ha-" + isolation + "-" + digest,
                            target_url,
                            time.time(),
                        ),
                    )
                binding = self._binding(page_id, owner_id)
            connector_id, target, crid, public_key, phase = binding
            if target != target_url:
                raise LayerVError(
                    "Guest resource target changed; reconciliation is required"
                )
            if phase in {"retiring", "revoked"}:
                raise LayerVError("Guest resource is revoked")
            if phase == "creating":
                # The stable Connector ID permits recovery after an interrupted
                # publication without creating another resource for this grant.
                result = self.publisher(connector_id, target_url)
                crid = result.get("crid", "")
                public_key = result.get("resource_id", "")
                if (
                    not isinstance(crid, str)
                    or not re.fullmatch(r"[a-z2-7]{40,128}", crid)
                    or not isinstance(public_key, str)
                    or not public_key
                    or public_key == crid
                    or result.get("target_url") != target_url
                    or result.get("status") != "serving"
                ):
                    raise LayerVError(
                        "Connector did not confirm the guest resource identity and readiness"
                    )
                try:
                    with self._connect() as db:
                        db.execute(
                            "UPDATE resources SET crid=?,public_key=?,phase='ready' "
                            "WHERE page=? AND grant_id=?",
                            (crid, public_key, page_id, owner_id),
                        )
                except sqlite3.IntegrityError as error:
                    raise LayerVError(
                        "Connector resource is already bound to another guest"
                    ) from error
            ready = getattr(self.publisher, "ensure_ready", None)
            if callable(ready):
                ready(public_key)
            return LayerVClient(
                self.management_client.api_base_url,
                self.management_client.api_token,
                crid,
                resource_public_key=public_key,
                resource_scope=isolation,
            )

    def revoke_owned(self, page_id, grant_id):
        """Recover cleanup from native ownership when an invitation file is lost."""
        with self.lock:
            binding = self._binding(page_id, grant_id)
            if binding is None:
                return True
            if not binding[2]:
                raise LayerVError("Resource allocation recovery is pending", status=503, retry_after=5)
            return self.revoke(page_id, grant_id, binding[2])

    def revoke(self, page_id, grant_id, expected_crid, *, qurl_id=""):
        with self.lock:
            binding = self._binding(page_id, grant_id)
            if not binding or binding[2] != expected_crid:
                raise LayerVError("Guest resource does not match its private binding")
            if binding[4] == "revoked":
                return True
            with self._connect() as db:
                db.execute(
                    "UPDATE resources SET phase='retiring' WHERE page=? AND grant_id=?",
                    (page_id, grant_id),
                )
                db.execute(
                    "INSERT OR IGNORE INTO retirements(page,grant_id,crid,due,attempts) VALUES(?,?,?,?,0)",
                    (page_id, grant_id, expected_crid, time.time()),
                )
                if qurl_id:
                    db.execute("UPDATE retirements SET qurl_id=? WHERE page=? AND grant_id=?", (qurl_id, page_id, grant_id))
            # Resource DELETE also revokes its qURL. Avoid a redundant link
            # DELETE before resource retirement, including on cleanup retries.
            # A 503 leaves the durable retiring binding intact. The existing
            # grant-cleanup queue retries, including after either process restarts.
            with self._connect() as db:
                old_identity = db.execute(
                    "SELECT management_only FROM retirements WHERE page=? AND grant_id=?",
                    (page_id, grant_id),
                ).fetchone()
            if old_identity and old_identity[0]:
                already_missing = self.management_client.delete_resource(resource_crid=expected_crid)
            elif getattr(self.publisher, "native_retirement", False) is True:
                try:
                    already_missing = self.publisher.revoke_resource(expected_crid)
                except LayerVError:
                    # Retained management authority provides a supported
                    # fallback; native cache cleanup must still be confirmed.
                    already_missing = self.management_client.delete_resource(resource_crid=expected_crid)
                    self.publisher.cleanup(expected_crid)
            else:
                already_missing = self.management_client.delete_resource(resource_crid=expected_crid)
                cleanup = getattr(self.publisher, "cleanup", None)
                if callable(cleanup):
                    cleanup(expected_crid)
            with self._connect() as db:
                db.execute(
                    "UPDATE resources SET phase='revoked' WHERE page=? AND grant_id=?",
                    (page_id, grant_id),
                )
                db.execute("DELETE FROM retirements WHERE page=? AND grant_id=?", (page_id, grant_id))
            return already_missing

    def drain_retirements(self):
        """Retry independently of invitation files, including failed compensation."""
        with self.lock:
            with self._connect() as db:
                # Recover retiring rows written by older candidate versions.
                db.execute(
                    "INSERT OR IGNORE INTO retirements(page,grant_id,crid,due,attempts) "
                    "SELECT page,grant_id,crid,?,0 FROM resources "
                    "WHERE phase='retiring' AND crid IS NOT NULL",
                    (time.time(),),
                )
                rows = db.execute(
                    "SELECT page,grant_id,crid,attempts FROM retirements "
                    "WHERE due<=? LIMIT 50", (time.time(),)
                ).fetchall()
            for page, grant, crid, attempts in rows:
                try:
                    self.revoke(page, grant, crid)
                except LayerVError as error:
                    delay = error.retry_after if error.retry_after is not None else min(3600, 2 ** min(attempts + 1, 12))
                    with self._connect() as db:
                        db.execute(
                            "UPDATE retirements SET due=?,attempts=attempts+1 "
                            "WHERE page=? AND grant_id=?",
                            (time.time() + max(1, delay), page, grant),
                        )

    def retire_orphans(self, mapping_exists, *, grace_seconds=300):
        """Recover allocations interrupted before their invitation was recorded.

        The caller holds the broker store lock so an in-flight mint cannot race
        this scan. Page pools are persistent infrastructure and are excluded.
        """
        with self.lock:
            with self._connect() as db:
                now = time.time()
                gate = db.execute("SELECT due FROM recovery_gates WHERE name='orphan_publication'").fetchone()
                if gate and gate[0] > now:
                    return
                rows = db.execute(
                    "SELECT page,grant_id,target,crid,phase,recovery_attempts FROM resources "
                    "WHERE grant_id!='__page__' AND phase IN ('creating','ready') "
                    "AND created_at<=? AND recovery_due<=? LIMIT 50", (now - grace_seconds, now)
                ).fetchall()
            for page, grant, target, crid, phase, attempts in rows:
                if mapping_exists(page, grant):
                    continue

                try:
                    if phase == "creating":
                        # Resume the stable native ID to recover an allocation
                        # whose publication reply or local commit was lost.
                        crid = self.ensure(page, grant, target).resource_id
                    self.revoke(page, grant, crid)
                except LayerVError as error:
                    # Retiring failures have their own durable retry schedule;
                    # publication recovery must also back off durably. A rate
                    # rejection pauses this whole scan, including other rows.
                    rate_limited = error.status == 429
                    floor = 60 if rate_limited else 5
                    delay = max(error.retry_after or 0, min(3600, floor * 2 ** min(attempts, 10)))
                    due = time.time() + delay
                    with self._connect() as db:
                        db.execute("UPDATE resources SET recovery_due=?,recovery_attempts=recovery_attempts+1 "
                                   "WHERE page=? AND grant_id=? AND phase IN ('creating','ready')", (due, page, grant))
                        if rate_limited:
                            db.execute("INSERT OR REPLACE INTO recovery_gates VALUES('orphan_publication',?)", (due,))
                    if rate_limited:
                        break

    def retire_deleted_page_pools(self, page_exists):
        """An explicitly deleted page no longer owns shared infrastructure."""
        with self.lock:
            with self._connect() as db:
                rows = db.execute("SELECT page,crid FROM resources WHERE grant_id='__page__' AND phase='ready'").fetchall()
            for page, crid in rows:
                if not page_exists(page):
                    try:
                        self.revoke(page, "__page__", crid)
                    except LayerVError:
                        continue


class PendingInvitations:
    """Recover page-pool mints whose response or mapping commit was interrupted.

    The unique upstream label is private broker ownership metadata. The Gateway
    stores the owner's human label separately. No bootstrap or access link is
    persisted in this journal.
    """

    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10)
        self.path.chmod(0o600)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS mints(page TEXT,grant_id TEXT,resource TEXT,label TEXT,created REAL,due REAL,attempts INTEGER,PRIMARY KEY(page,grant_id))")
            with db:
                yield db
        finally:
            db.close()

    def prepare(self, page, grant, resource):
        label = "ha-invite-" + sha256(f"{resource}\0{page}\0{grant}".encode()).hexdigest()
        with self._connect() as db:
            db.execute("INSERT OR IGNORE INTO mints VALUES(?,?,?,?,?,?,0)", (page, grant, resource, label, time.time(), time.time() + 300))
        return label

    def complete(self, page, grant):
        with self._connect() as db:
            db.execute("DELETE FROM mints WHERE page=? AND grant_id=?", (page, grant))

    def drain(self, client, mapping_exists):
        # Caller holds the broker store lock across the scan and minting.
        with self._connect() as db:
            rows = db.execute("SELECT page,grant_id,resource,label,attempts FROM mints WHERE due<=? LIMIT 50", (time.time(),)).fetchall()
        for page, grant, resource, label, attempts in rows:
            if mapping_exists(page, grant):
                self.complete(page, grant)
                continue
            try:
                for invitation in client.list_qurls(resource_crid=resource):
                    if not isinstance(invitation, dict) or invitation.get("label") != label:
                        continue
                    qurl = invitation.get("qurl_id")
                    if not isinstance(qurl, str) or not re.fullmatch(r"q_[0-9a-f]{11}", qurl):
                        raise LayerVError("LayerV returned an invalid orphan invitation identifier")
                    client.delete_qurl(resource_id=resource, qurl_id=qurl)
            except LayerVError as error:
                delay = error.retry_after if error.retry_after is not None else min(3600, 2 ** min(attempts + 1, 12))
                with self._connect() as db:
                    db.execute("UPDATE mints SET due=?,attempts=attempts+1 WHERE page=? AND grant_id=?", (time.time() + max(1, delay), page, grant))
            else:
                self.complete(page, grant)
