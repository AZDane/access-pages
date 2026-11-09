"""Review alerts must arrive early, remain quiet unchanged, and never renew evidence."""

from copy import deepcopy
from datetime import date
import unittest
from unittest.mock import Mock, patch

from security.review_alerts import alerts, GitHub, synchronize


class ReviewAlertTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {"dispositions": [{
            "id": "CVE-2026-119374", "type": "debian", "review_due": "2026-11-26",
            "reviewed_on": "2026-11-09", "owner": "AZDane",
            "packages": [{"name": "libsqlite3-0", "version": "3.46.1-7+deb13u2"}],
        }]}

    def test_seven_day_boundary_and_overdue_catchup(self):
        original = deepcopy(self.baseline)
        self.assertEqual(alerts(self.baseline, date(2026, 11, 18)), {})
        for day in (19, 25, 26, 30):
            planned = alerts(self.baseline, date(2026, 11, day))
            self.assertEqual(len(planned), 1)
            self.assertIn("expired" if day >= 26 else "due within seven days", next(iter(planned.values()))["body"])
        self.assertEqual(self.baseline, original)

    def test_groups_dates_and_includes_all_due_findings(self):
        second = deepcopy(self.baseline["dispositions"][0])
        second["id"] = "CVE-2026-119379"
        self.baseline["dispositions"].append(second)
        third = deepcopy(second)
        third["review_due"] = "2026-12-20"
        self.baseline["dispositions"].append(third)
        planned = alerts(self.baseline, date(2026, 11, 19))
        self.assertEqual(len(planned), 1)
        body = next(iter(planned.values()))["body"]
        self.assertIn("CVE-2026-119374", body)
        self.assertIn("CVE-2026-119379", body)
        self.assertNotIn("2026-12-20", body)

    def test_no_due_reviews_does_not_query_or_write(self):
        api = Mock()
        synchronize({}, api)
        self.assertEqual(api.mock_calls, [])

    def test_create_deduplicate_and_reopen(self):
        planned = alerts(self.baseline, date(2026, 11, 19))
        content = next(iter(planned.values()))
        api = Mock(base="repos/AZDane/access-pages/issues")
        api.issues.return_value = []
        synchronize(planned, api)
        api.request.assert_called_once_with("POST", api.base, {**content, "assignees": ["AZDane"]})
        api.reset_mock()
        api.issues.return_value = [{**content, "number": 100, "state": "open"}]
        synchronize(planned, api)
        api.request.assert_not_called()
        api.issues.return_value[0]["state"] = "closed"
        synchronize(planned, api)
        api.request.assert_called_once_with("PATCH", api.base + "/100", {**content, "state": "open"})

    def test_changed_assessment_updates_same_issue(self):
        old = next(iter(alerts(self.baseline, date(2026, 11, 19)).values()))
        self.baseline["dispositions"][0]["packages"][0]["version"] = "reviewed-new-version"
        planned = alerts(self.baseline, date(2026, 11, 19))
        api = Mock(base="repos/AZDane/access-pages/issues")
        api.issues.return_value = [{**old, "number": 100, "state": "open"}]
        synchronize(planned, api)
        api.request.assert_called_once_with("PATCH", api.base + "/100", {**next(iter(planned.values())), "state": "open"})

    def test_invalid_date_fails_instead_of_suppressing_alert(self):
        self.baseline["dispositions"][0]["review_due"] = "bad-date"
        with self.assertRaises(ValueError):
            alerts(self.baseline, date(2026, 11, 19))

    def test_duplicate_managed_issues_fail_without_writes(self):
        planned = alerts(self.baseline, date(2026, 11, 19))
        issue = {**next(iter(planned.values())), "number": 100, "state": "open"}
        api = Mock()
        api.issues.return_value = [issue, {**issue, "number": 101}]
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            synchronize(planned, api)
        api.request.assert_not_called()

    def test_repository_cannot_inject_api_arguments(self):
        for repository in ("--hostname=example.org", "owner/repo/issues", "owner/repo?state=all"):
            with self.assertRaises(ValueError):
                GitHub(repository)

    def test_paginated_lookup_ignores_human_issues_and_pull_requests(self):
        with patch("security.review_alerts.shutil.which", return_value="/usr/bin/gh"):
            api = GitHub("AZDane/access-pages")
        human = {"number": 1, "user": {"login": "AZDane"}}
        bot = {"number": 2, "user": {"login": "github-actions[bot]"}}
        api.request = Mock(side_effect=[[human] * 100, [bot, {**bot, "pull_request": {}}]])
        self.assertEqual(api.issues(), [bot])
        self.assertEqual(api.request.call_count, 2)
        self.assertIn("page=2", api.request.call_args.args[1])
