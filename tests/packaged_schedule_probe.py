"""Offline packaged schedule lifecycle, restore and service-identity checks."""
from datetime import datetime, timezone
from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from activity import GuestActivityStore
from email_delivery import VerificationRecipientStore
from layerv import BrokerLayerVClient
from pages import PageStore
from schedules import ScheduleStore, Scheduler, validate_schedule
from zoneinfo import ZoneInfo

spec = importlib.util.spec_from_file_location("app_runner", "/usr/local/bin/app_runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
runner._prepare_runtime_permissions()
assert ZoneInfo("America/Phoenix").key == "America/Phoenix"
root = Path("/data/admin-runtime")
store = ScheduleStore(root / "schedules.sqlite3")
pages = PageStore(Path("/data/pages"), file_mode=0o640)
pages.create({"id": "scheduled-test", "title": "Scheduled test", "resources": []})
store.check_recovery(pages)
now = datetime(2099, 1, 1, 8, 59, tzinfo=timezone.utc).timestamp()
schedule = validate_schedule({"label": "Synthetic guest", "email": "guest@example.invalid", "timezone": "UTC",
                              "kind": "once", "date": "2099-01-01", "start_time": "09:00", "end_time": "12:00"})
id_ = store.save("scheduled-test", schedule, now)
client = Mock(spec=BrokerLayerVClient)
client.create_qurl.return_value = {"qurl_link": "https://qurl.invalid/#synthetic", "qurl_id": "q_fixture",
                                   "resource_id": "fixture", "resource_crid": "fixture", "upstream_scope": "guest",
                                   "expires_at": "2099-01-01T12:00:30+00:00", "target_path_applied": True}
runtime = SimpleNamespace(PAGE_STORE=pages, LAYERV_CLIENT=client, SMTP_CONFIG_STORE=Mock(),
                          VERIFICATION_RECIPIENTS=VerificationRecipientStore(root / "verification-recipients.json"),
                          ACTIVITY_STORE=GuestActivityStore(root / "schedule-probe-activity.sqlite3"),
                          page_action_lock=lambda _: nullcontext(), cleanup_guest_sessions=Mock(), audit=Mock())
runtime.SMTP_CONFIG_STORE.configured.return_value = True
worker = Scheduler(runtime, store, clock=lambda: now)
worker.tick()
client.create_qurl.assert_not_called()
now += 60
worker.tick()
with patch("schedules.send_email") as sender:
    worker.tick(delivery=True)
    worker.tick(delivery=True)
    sender.assert_called_once()
grant = pages.load("scheduled-test")["access_grants"][0]
assert grant["expires_at"] == "2099-01-01T12:00:00+00:00"
assert not grant["qurl_link"]
assert "qurl.invalid" not in json.dumps(store.history("scheduled-test"))
assert not store.check_recovery(pages)
store.path.with_name("schedule-authorization").unlink()
assert store.check_recovery(pages)
assert store.get(id_)["status"] == "blocked"
assert not pages.load("scheduled-test")["access_grants"]
runner._prepare_runtime_permissions()


def as_identity(uid, gid, operation):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            operation()
        except BaseException:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def guest_denied():
    for path in (store.path, store.path.with_name("schedule-authorization")):
        try:
            path.read_bytes()
        except PermissionError:
            continue
        raise AssertionError("Guest can read the Admin schedule store")


as_identity(2101, 2101, guest_denied)
as_identity(2100, 2100, lambda: store.status(id_, "enabled", now))
print("Packaged scheduling: original deadline, one email, restore revocation, Admin/guest isolation passed")
