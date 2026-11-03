"""Require reviewed, exact-package dispositions for unfiltered image findings."""

import argparse
from datetime import date, datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import os

try:
    from .image_evidence import bind_report, fingerprint
except ImportError:  # Direct invocation from the workflows.
    from image_evidence import bind_report, fingerprint


SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def finding_fingerprint(finding):
    return fingerprint({key: finding.get(key) for key in (
        "VulnerabilityID", "PkgName", "InstalledVersion", "Severity", "FixedVersion",
        "Title", "Description", "CweIDs", "CVSS", "DataSource", "PrimaryURL",
    )})


def _unreachable(entry, baseline, evidence, report, architecture, result, finding):
    target = result.get("Target") if result["Type"] == "gobinary" else result.get("Class")
    if entry["findings"].get(target) != finding_fingerprint(finding):
        return False
    if (not evidence or evidence.get("report_sha256") != fingerprint(report)
            or evidence.get("image_id") != report["Metadata"]["ImageID"]):
        return False
    try:
        bind_report(evidence["identity"], report)
    except (KeyError, TypeError, ValueError):
        return False
    probe = evidence.get("probe", {})
    return (
        probe.get("architecture") == architecture
        and probe.get("files") == baseline["unreachable_files"]
        and probe.get(entry["binary"]) == entry["artifacts"].get(architecture)
        and all(fingerprint(probe.get(key)) == digest for key, digest in entry["properties"].items())
    )


def check_report(report, baseline, architecture, *, today=None, evidence=None, approved=None):
    today = today or datetime.now(timezone.utc).date()
    errors = []
    if baseline.get("schema_version") != 1:
        raise ValueError("Unsupported vulnerability baseline schema")
    metadata = report.get("Metadata", {})
    if (architecture not in {"amd64", "arm64"}
            or report.get("SchemaVersion") != 2
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
        if entry["disposition"] not in {"component_absent", "mitigated", "unreachable"}:
            raise ValueError("Unknown vulnerability disposition")
        reviewed = date.fromisoformat(entry["reviewed_on"])
        due = date.fromisoformat(entry["review_due"])
        if reviewed > today or due <= reviewed or (due - reviewed).days > 30:
            raise ValueError("Invalid review dates; reviews must be renewed within 30 days")
        if entry["severity"] not in {"HIGH", "CRITICAL"}:
            raise ValueError("Baseline accepts only HIGH/CRITICAL dispositions")
        if entry["disposition"] == "unreachable":
            if not isinstance(entry.get("packages"), list) or not entry["packages"]:
                raise ValueError("Missing affected packages")
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", entry["id"]):
                raise ValueError("Unreachable disposition requires an exact CVE")
            for field in ("artifacts", "findings", "properties", "invalidated_by", "advisory"):
                if not entry.get(field):
                    raise ValueError(f"Missing unreachable {field}")
            if entry.get("binary") not in {"qurl_sha256", "sqlite_sha256"}:
                raise ValueError("Unsupported unreachable binary")
            if set(entry["artifacts"]) != {"amd64", "arm64"}:
                raise ValueError("Both exact architectures are required")
            if not baseline.get("unreachable_files"):
                raise ValueError("Missing packaged source evidence")
            for mapping in (entry["artifacts"], entry["findings"], entry["properties"],
                            baseline["unreachable_files"]):
                if not isinstance(mapping, dict) or any(
                    not key or any(char in key for char in "*?[")
                    or not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", value)
                    for key, value in mapping.items()
                ):
                    raise ValueError("Expected exact evidence identities without wildcards")
            for package in entry["packages"]:
                if any(not package.get(key) or any(c in package[key] for c in "*?[")
                       for key in ("name", "version")):
                    raise ValueError("Expected exact affected package and version")
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
            if entry is not None and entry["disposition"] == "unreachable":
                if today >= date.fromisoformat(entry["review_due"]):
                    errors.append(f"{label}: disposition expired {entry['review_due']}")
                elif entry["severity"] != severity or not _unreachable(
                    entry, baseline, evidence, report, architecture, result, finding
                ):
                    errors.append(f"{label}: unreachable evidence missing, changed or mismatched")
                elif approved is not None:
                    approved.append(f"{label}: unreachable; owner {entry['owner']}; expires {entry['review_due']} UTC")
            elif finding.get("FixedVersion"):
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
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        baseline = json.loads(args.baseline.read_text())
        dockerfile = Path("Dockerfile.ha-app").read_text()
        if f"FROM {baseline['runtime_base']}\n" not in dockerfile:
            raise ValueError("Runtime pin changed; reassess the vulnerability baseline")
        for path, digest in baseline["control_files"].items():
            if sha256(Path(path).read_bytes()).hexdigest() != digest:
                raise ValueError(f"Security control changed: {path}; reassess the baseline")
        evidence = json.loads(args.evidence.read_text()) if args.evidence else None
        approved = []
        errors, counts = check_report(json.loads(args.report.read_text()), baseline, args.architecture,
                                     evidence=evidence, approved=approved)
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit(f"Vulnerability evidence invalid: {error}") from error
    print(f"Unfiltered {args.architecture} findings: {json.dumps(counts, sort_keys=True)}")
    for approval in approved:
        print("APPROVED: " + approval)
    for error in errors:
        print(error)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            print(f"### {args.architecture} vulnerability policy\n\n"
                  f"Full unfiltered inventory: `{json.dumps(counts, sort_keys=True)}`\n\n"
                  "Approved unreachable findings:\n\n" + "\n".join("- " + a for a in approved)
                  + "\n\nRemaining blockers:\n\n" + ("\n".join("- " + e for e in errors) or "None")
                  + "\n", file=summary)
    if errors:
        raise SystemExit("Unreviewed, expired or fixable HIGH/CRITICAL findings block this image")
    print("All HIGH/CRITICAL findings have current exact-package dispositions; full report retained")


if __name__ == "__main__":
    main()
