"""Run in a disposable App image as root to test real service-UID races."""

import importlib.util
import os
import socket
import sqlite3
import stat
from pathlib import Path
from guest_resources import GuestResources

spec = importlib.util.spec_from_file_location("app_runner", "/usr/local/bin/app_runner.py")
app_runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_runner)

pages = Path("/data/pages")
privileged = Path("/data/app-config.json")
privileged.write_text("root-owned")
os.chown(privileged, 0, 0)
os.chmod(privileged, 0o600)
initial = privileged.stat()


def as_service(operation, uid=2100, gid=2100, groups=()):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups(list(groups))
            os.setgid(gid)
            os.setuid(uid)
            operation()
        except BaseException:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def same_privileged():
    current = privileged.stat()
    assert (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)) == (
        initial.st_uid, initial.st_gid, stat.S_IMODE(initial.st_mode)
    )
    assert privileged.read_text() == "root-owned"


valid = pages / "valid"
as_service(lambda: (valid.mkdir(), (valid / "state.json").write_text("valid")))
os.chmod(valid, 0o777)
os.chmod(valid / "state.json", 0o666)
app_runner._prepare_runtime_permissions()

# Model a backup restored with root ownership and broader permissions. The
# broker must retain the saved data and be able to write after startup repair.
session_dir = app_runner.HA_GUEST_SESSION_DIR
session_db = app_runner.HA_GUEST_SESSION_DB
with sqlite3.connect(session_db) as db:
    db.execute("CREATE TABLE restored_session (token TEXT)")
    db.execute("INSERT INTO restored_session VALUES ('saved-session')")
before_restore_repair = session_db.read_bytes()
for path, mode in ((session_dir, 0o755), (session_db, 0o644)):
    os.chown(path, 0, 0)
    os.chmod(path, mode)
app_runner._prepare_runtime_permissions()
app_runner._prepare_runtime_permissions()
for path, mode in ((session_dir, 0o700), (session_db, 0o600)):
    info = path.stat()
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (2102, 2102, mode)
assert session_db.read_bytes() == before_restore_repair


def use_restored_sessions():
    with sqlite3.connect(session_db) as db:
        assert db.execute("SELECT token FROM restored_session").fetchall() == [("saved-session",)]
        db.execute("INSERT INTO restored_session VALUES ('new-session')")


as_service(use_restored_sessions, uid=2102, gid=2001, groups=(2000, 2102))
with sqlite3.connect(session_db) as db:
    assert db.execute("SELECT COUNT(*) FROM restored_session").fetchone()[0] == 2


def guest_cannot_read_sessions():
    try:
        session_db.read_bytes()
    except PermissionError:
        return
    raise AssertionError("guest could read broker session database")


as_service(guest_cannot_read_sessions, uid=2101, gid=2101)

native_state = Path("/data/access-pages-broker/shared-state")
def create_native_socket():
    native_state.mkdir(mode=0o700)
    transport = socket.socket(socket.AF_UNIX)
    try:
        transport.bind(str(native_state / "daemon.sock"))
        os.chmod(native_state / "daemon.sock", 0o600)
    finally:
        transport.close()


broker_uid, broker_gid, _, _ = app_runner.PROCESS_IDENTITIES["access_pages_broker"]
as_service(create_native_socket, uid=broker_uid, gid=broker_gid)
native_socket = native_state / "daemon.sock"
socket_before = native_socket.stat()
assert (socket_before.st_uid, socket_before.st_gid) == (broker_uid, broker_gid)
app_runner._prepare_runtime_permissions()
socket_after = native_socket.stat()
assert (socket_after.st_ino, socket_after.st_uid, socket_after.st_gid, socket_after.st_mode) == (
    socket_before.st_ino, socket_before.st_uid, socket_before.st_gid, socket_before.st_mode
)
assert (valid.stat().st_uid, valid.stat().st_gid, stat.S_IMODE(valid.stat().st_mode)) == (2100, 2000, 0o2750)
assert ((valid / "state.json").stat().st_uid, (valid / "state.json").stat().st_gid, stat.S_IMODE((valid / "state.json").stat().st_mode)) == (2100, 2000, 0o640)
app_runner._prepare_runtime_permissions()

for socket_uid, socket_gid, socket_mode in (
    (2100, broker_gid, 0o600),
    (broker_uid, 2000, 0o600),
    (broker_uid, broker_gid, 0o660),
    (broker_uid, broker_gid, 0o606),
):
    os.chown(native_socket, socket_uid, socket_gid)
    os.chmod(native_socket, socket_mode)
    try:
        app_runner._prepare_runtime_permissions()
    except app_runner.SetupError as error:
        assert str(error) == "Unsafe Connector socket"
    else:
        raise AssertionError("Unsafe Connector socket was accepted")
    current = native_socket.stat()
    assert (current.st_uid, current.st_gid, stat.S_IMODE(current.st_mode)) == (
        socket_uid, socket_gid, socket_mode
    ), "Permission repair mutated an unsafe socket"

# The private-tree group remains valid for existing installations.
os.chown(native_socket, broker_uid, 2103)
os.chmod(native_socket, 0o600)
app_runner._prepare_runtime_permissions()

link = pages / "attack"
as_service(lambda: link.symlink_to(privileged))
try:
    app_runner._prepare_runtime_permissions()
except app_runner.SetupError:
    pass
else:
    raise AssertionError("top-level service symlink was accepted")
same_privileged()
link.unlink()

nested = valid / "nested"
as_service(lambda: nested.symlink_to(privileged))
try:
    app_runner._prepare_runtime_permissions()
except app_runner.SetupError:
    pass
else:
    raise AssertionError("nested service symlink was accepted")
same_privileged()
nested.unlink()

race = pages / "race"
stop = pages / "race-stop"
child = os.fork()
if child == 0:
    try:
        os.setgroups([])
        os.setgid(2100)
        os.setuid(2100)
        while not stop.exists():
            candidate = pages / ".race-candidate"
            candidate.symlink_to(privileged)
            os.replace(candidate, race)
            candidate.write_text("ordinary")
            os.replace(candidate, race)
    except BaseException:
        os._exit(1)
    os._exit(0)
for _ in range(100):
    try:
        app_runner._prepare_runtime_permissions()
    except app_runner.SetupError:
        pass
    same_privileged()
stop.touch()
_, status = os.waitpid(child, 0)
assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
if race.is_symlink():
    race.unlink()
(pages / ".race-candidate").unlink(missing_ok=True)
app_runner._prepare_runtime_permissions()
same_privileged()

resource_db = Path("/data/access-pages-broker/guest-resources.sqlite3")
manager = GuestResources(resource_db, installation_id="old", publisher=None,
                         management_client=None)
with manager._connect() as db:
    db.execute("INSERT INTO resources(page,grant_id,connector_id,target,crid,public_key,phase) "
               "VALUES(?,?,?,?,?,?,?)", ("cat", "__page__", "ha-page-old",
               "http://127.0.0.2:8080", "a" * 59, "old-public", "ready"))
os.chown(resource_db, 2103, 2103)
app_runner._reset_connection_files()
with manager._connect() as db:
    assert db.execute("SELECT COUNT(*) FROM retirements").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM resources WHERE phase='ready'").fetchone()[0] == 0
print("real-UID permission repair and reset: valid restart, symlink, nested symlink, race, old binding retirement: PASS")
