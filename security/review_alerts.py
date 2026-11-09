"""Warn about bounded vulnerability reviews without changing policy or evidence."""

import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - fixed gh executable, argument arrays, no shell.


MARKER = "<!-- access-pages-security-review:"


def alerts(baseline, today):
    groups = {}
    for entry in baseline["dispositions"]:
        due = date.fromisoformat(entry["review_due"])
        if due <= today + timedelta(days=7):
            groups.setdefault(due, []).append(entry)
    result = {}
    for due, entries in sorted(groups.items()):
        marker = f"{MARKER}{due.isoformat()} -->"
        phase = "expired" if due <= today else "due within seven days"
        lines = [marker, "", f"Security assessments are **{phase}** on {due} (UTC).", "",
                 "Review the current baseline, upstream fixes, and evidence for both amd64 and arm64.",
                 "Prefer patched stable packages or official binaries. Do not extend dates without",
                 "a fresh review or weaken scanners, thresholds, or evidence requirements.", "",
                 "| Finding | Packages | Owner | Last reviewed |",
                 "| --- | --- | --- | --- |"]
        for entry in sorted(entries, key=lambda item: (item["id"], item["type"])):
            packages = ", ".join(f"{p['name']} {p['version']}" for p in entry["packages"])
            lines.append(f"| {entry['id']} | {packages} | {entry['owner']} | {entry['reviewed_on']} |")
        lines.extend(["", "Source: [vulnerability baseline](https://github.com/AZDane/access-pages/blob/main/security/vulnerability-baseline.json)",
                      "and [review policy](https://github.com/AZDane/access-pages/blob/main/security/README.md).", "",
                      "The vulnerability gate continues to reject expired assessments. This alert does",
                      "not renew or approve them. The scheduled check reopens this issue while these",
                      "assessments remain due; close it after the baseline has been reassessed."])
        result[marker] = {"title": f"Security assessments require review by {due} UTC",
                          "body": "\n".join(lines) + "\n"}
    return result


class GitHub:
    def __init__(self, repository):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Expected owner/repository")
        self.base = f"repos/{repository}/issues"
        self.executable = shutil.which("gh")
        if not self.executable:
            raise ValueError("GitHub CLI is required to write alerts")

    def request(self, method, path, payload=None):
        args = [self.executable, "api", "--method", method, path]
        if payload is not None:
            args += ["--input", "-"]
        output = subprocess.run(  # nosec B603 - no shell, validated repository, fixed API paths.
            args, input=json.dumps(payload) if payload is not None else None,
            text=True, capture_output=True, check=True, timeout=60,
        ).stdout
        return json.loads(output)

    def issues(self):
        result = []
        page = 1
        while True:
            items = self.request("GET", f"{self.base}?state=all&creator=github-actions%5Bbot%5D&per_page=100&page={page}")
            result.extend(item for item in items if "pull_request" not in item
                          and item.get("user", {}).get("login") == "github-actions[bot]")
            if len(items) < 100:
                return result
            page += 1


def synchronize(planned, api):
    if not planned:
        return
    existing = api.issues()
    for marker, content in planned.items():
        matches = [issue for issue in existing if (issue.get("body") or "").startswith(marker + "\n")]
        if len(matches) > 1:
            raise ValueError(f"Duplicate managed review alerts: {marker}")
        if not matches:
            api.request("POST", api.base, {**content, "assignees": ["AZDane"]})
            print("Created:", content["title"])
        else:
            issue = matches[0]
            if issue["state"] != "open" or any(issue.get(key) != value for key, value in content.items()):
                api.request("PATCH", f"{api.base}/{issue['number']}", {**content, "state": "open"})
                print("Updated:", content["title"])
            else:
                print("Unchanged:", content["title"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=Path("security/vulnerability-baseline.json"))
    parser.add_argument("--repository", default="AZDane/access-pages")
    parser.add_argument("--write-issues", action="store_true", help="Create/update alerts; otherwise print only")
    args = parser.parse_args()
    planned = alerts(json.loads(args.baseline.read_text()), datetime.now(timezone.utc).date())
    print(json.dumps(list(planned.values()), indent=2))
    if args.write_issues:
        synchronize(planned, GitHub(args.repository))


if __name__ == "__main__":
    main()
