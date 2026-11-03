"""Publish retained, validated OCI images; never build or accept arbitrary tags."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - fixed tools, argument lists, never a shell.

try:
    from .check_vulnerabilities import check_report
    from .image_evidence import bind_report
except ImportError:
    from check_vulnerabilities import check_report
    from image_evidence import bind_report


IMAGE = "ghcr.io/azdane/access-pages-app"


def run(*args):
    if args[0] not in {"docker", "cosign"} or not (executable := shutil.which(args[0])):
        raise ValueError("Expected installed Docker or Cosign CLI")
    return subprocess.check_output([executable, *args[1:]], text=True).strip()  # nosec B603


def candidates(directory, version):
    if not re.fullmatch(r"0\.1\.\d+", version):
        raise ValueError("Expected the repository's numeric beta version")
    baseline = json.loads(Path("security/vulnerability-baseline.json").read_text())
    result = []
    for architecture, suffix in (("amd64", "amd64"), ("arm64", "aarch64")):
        report = json.loads((directory / f"vulnerability-{architecture}.json").read_text())
        evidence = json.loads((directory / f"evidence-{architecture}.json").read_text())
        identity = evidence["identity"]
        bind_report(identity, report)
        if identity["architecture"] != architecture or not identity["attestation_digests"]:
            raise ValueError("Missing architecture/attestation evidence")
        if identity["config"]["config"]["Labels"]["io.hass.version"] != version:
            raise ValueError("Candidate version mismatch")
        errors, _ = check_report(report, baseline, architecture, evidence=evidence)
        if errors:
            raise ValueError("Release policy failed: " + "; ".join(errors))
        # This marker is written only after all packaged tests succeed.
        marker = json.loads((directory / f"tested-{architecture}.json").read_text())
        if marker != {"index_digest": identity["index_digest"]}:
            raise ValueError("Packaged test identity mismatch")
        local = json.loads(run("docker", "image", "inspect", identity["index_digest"]))[0]
        if local["Id"] != identity["index_digest"]:
            raise ValueError("Retained OCI image changed")
        result.append((suffix, identity))
    return result


def publish(directory, version, latest=False):
    # All checks for BOTH architectures finish before the first registry write.
    images = candidates(directory, version)
    references = []
    expected_children = set()
    for suffix, identity in images:
        tag = f"{IMAGE}:{version}-{suffix}"
        run("docker", "image", "tag", identity["index_digest"], tag)
        run("docker", "image", "push", tag)  # Never --platform: that drops attestations.
        remote = run("docker", "buildx", "imagetools", "inspect", "--raw", tag)
        # imagetools appends a newline to raw JSON output; the OCI bytes do not.
        if "sha256:" + sha256(remote.encode()).hexdigest() != identity["index_digest"]:
            raise ValueError("Published OCI index differs from validated artifact")
        references.append(IMAGE + "@" + identity["index_digest"])
        expected_children.add(identity["manifest_digest"])
        expected_children.update(identity["attestation_digests"])
    # Preview the merged index locally; reject missing images/attestations before tagging it.
    merged = run("docker", "buildx", "imagetools", "create", "--dry-run", *references)
    if {item["digest"] for item in json.loads(merged)["manifests"]} != expected_children:
        raise ValueError("Multi-architecture merge dropped an image or attestation")
    run("docker", "buildx", "imagetools", "create", "--tag", f"{IMAGE}:{version}", *references)
    actual = run("docker", "buildx", "imagetools", "inspect", "--raw", f"{IMAGE}:{version}")
    if actual != merged:
        raise ValueError("Published multi-architecture index differs from preview")
    digest = "sha256:" + sha256(actual.encode()).hexdigest()
    run("cosign", "sign", "--yes", IMAGE + "@" + digest)
    if latest:
        for suffix, identity in images:
            run("docker", "buildx", "imagetools", "create", "--tag", IMAGE + ":latest-" + suffix,
                IMAGE + "@" + identity["index_digest"])
        run("docker", "buildx", "imagetools", "create", "--tag", IMAGE + ":latest", IMAGE + "@" + digest)
    print(f"Published and signed {IMAGE}@{digest}; validated child identities preserved")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--directory", type=Path, default=Path("."))
    parser.add_argument("--latest", action="store_true")
    args = parser.parse_args()
    publish(args.directory, args.version, args.latest)
