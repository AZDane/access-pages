"""Durable cleanup; the native broker can accept durable retirement ownership.

Broker success may mean a queued retirement, rather than confirmed upstream
enforcement. Its durable queue retains the mapping until deletion succeeds.
"""

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from layerv import LayerVError


class CleanupQueue:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=10)
        self.path.chmod(0o600)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS cleanup (page TEXT, grant_id TEXT, resource TEXT, qurl TEXT, due REAL, attempts INTEGER, PRIMARY KEY(resource,qurl))"
            )
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, page_id, grant):
        resource = grant.get("resource_crid") or grant.get("resource_id")
        if not grant.get("qurl_id") or not resource:
            return
        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO cleanup VALUES(?,?,?,?,?,0)",
                (
                    page_id,
                    grant["id"],
                    resource,
                    grant["qurl_id"],
                    time.time(),
                ),
            )

    def complete(self, resource_id, qurl_id):
        with self._connect() as db:
            db.execute(
                "DELETE FROM cleanup WHERE resource=? AND qurl=?",
                (resource_id, qurl_id),
            )

    def drain(self, client):
        with self._connect() as db:
            rows = db.execute(
                "SELECT page,grant_id,resource,qurl,attempts FROM cleanup WHERE due<=? LIMIT 50",
                (time.time(),),
            ).fetchall()
        for page, grant, resource, qurl, attempts in rows:
            try:
                client.delete_qurl(
                    page_id=page, grant_id=grant, resource_id=resource, qurl_id=qurl
                )
            except LayerVError as error:
                delay = (
                    error.retry_after
                    if error.retry_after is not None
                    else min(3600, 2 ** min(attempts + 1, 12))
                )
                with self._connect() as db:
                    db.execute(
                        "UPDATE cleanup SET due=?,attempts=attempts+1 WHERE resource=? AND qurl=?",
                        (time.time() + max(1, delay), resource, qurl),
                    )
            else:
                self.complete(resource, qurl)
