"""Require reviewed, exact-package dispositions for unfiltered image findings."""

import argparse
from datetime import date
import json
from pathlib import Path
import re


SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def check_report(report, baseline, architecture, *, today=None):
    today = today or date.today()
    errors = []
    if baseline.get("schema_version") != 1:
        raise ValueError("Unsupported vulnerability baseline schema")
    metadata = report.get("Metadata", {})
    if (report.get("SchemaVersion") != 2
            or report.get("ArtifactType") != "container_image"
            or metadata.get("ImageConfig", {}).get("architecture") != architecture
            or metadata.get("OS", {}).get("Family") != "debian"
            or not str(metadata.get("OS", {}).get("Name", "")).startswith("13.")
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", metadata.get("ImageID", ""))):
        raise ValueError("Missing or unexpected image identity, architecture or OS")
    results = report.get("Results")
    if not isinstance(results, list) or not any(
        r.get("Class") == "os-pkgs" and r.get("Type") == "debian" for r in results
    ):
        raise ValueError("Missing operating-system scan results")
    scanned_binaries = {r.get("Target") for r in results if r.get("Type") == "gobinary"}
    if not {"usr/local/bin/qurl", "usr/local/bin/access-pages-guest-endpoint"} <= scanned_binaries:
        raise ValueError("Missing shipped Go binary scan results")
    accepted = {}
    for entry in baseline["dispositions"]:
        for field in ("id", "disposition", "justification", "evidence", "owner"):
            if not entry.get(field):
                raise ValueError(f"Missing baseline {field}")
        if entry["disposition"] not in {"component_absent", "mitigated"}:
            raise ValueError("Unknown vulnerability disposition")
        reviewed = date.fromisoformat(entry["reviewed_on"])
        due = date.fromisoformat(entry["review_due"])
        if reviewed > today or due <= reviewed or (due - reviewed).days > 30:
            raise ValueError("Invalid review dates; reviews must be renewed within 30 days")
        if entry["severity"] not in {"HIGH", "CRITICAL"}:
            raise ValueError("Baseline accepts only HIGH/CRITICAL dispositions")
        for package in entry["packages"]:
            key = (entry["type"], entry["id"], package["name"], package["version"])
            if key in accepted:
                raise ValueError("Duplicate vulnerability disposition")
            accepted[key] = entry
    counts = dict.fromkeys(sorted(SEVERITIES), 0)
    for result in results:
        for finding in result.get("Vulnerabilities") or []:
            severity = finding["Severity"]
            if severity not in SEVERITIES:
                raise ValueError("Unknown scanner severity")
            counts[severity] += 1
            if severity not in {"HIGH", "CRITICAL"}:
                continue
            key = (result["Type"], finding["VulnerabilityID"],
                   finding["PkgName"], finding["InstalledVersion"])
            label = "/".join(key)
            entry = accepted.get(key)
            if finding.get("FixedVersion"):
                errors.append(f"{label}: fix available: {finding['FixedVersion']}")
            elif entry is None or entry["severity"] != severity:
                errors.append(f"{label}: requires a reviewed disposition ({severity})")
            elif today >= date.fromisoformat(entry["review_due"]):
                errors.append(f"{label}: disposition expired {entry['review_due']}")
    return errors, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--baseline", type=Path, default=Path("security/vulnerability-baseline.json"))
    args = parser.parse_args()
    try:
        baseline = json.loads(args.baseline.read_text())
        dockerfile = Path("Dockerfile.ha-app").read_text()
        if f"FROM {baseline['runtime_base']}\n" not in dockerfile:
            raise ValueError("Runtime pin changed; reassess the vulnerability baseline")
        errors, counts = check_report(json.loads(args.report.read_text()), baseline, args.architecture)
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit(f"Vulnerability evidence invalid: {error}") from error
    print(f"Unfiltered {args.architecture} findings: {json.dumps(counts, sort_keys=True)}")
    for error in errors:
        print(error)
    if errors:
        raise SystemExit("Unreviewed, expired or fixable HIGH/CRITICAL findings block this image")
    print("All HIGH/CRITICAL findings have current exact-package dispositions; full report retained")


if __name__ == "__main__":
    main()
