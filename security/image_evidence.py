"""Bind a full scan and packaged evidence to retained Docker/OCI artifacts."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - fixed Docker CLI operations, argument lists, never a shell.
import tarfile
import tempfile


def fingerprint(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inspect_archive(path, architecture, *, version=None, require_attestations=False):
    with tarfile.open(path) as archive:
        def blob(descriptor, decode=True):
            digest = descriptor["digest"]
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                raise ValueError("Unsupported OCI digest")
            stream = archive.extractfile("blobs/sha256/" + digest[7:])
            data = stream.read()
            if len(data) != descriptor["size"] or sha256(data).hexdigest() != digest[7:]:
                raise ValueError("OCI blob identity mismatch")
            return json.loads(data) if decode else None

        roots = json.load(archive.extractfile("index.json"))["manifests"]
        if len(roots) != 1:
            raise ValueError("Expected exactly one retained architecture image")
        root = roots[0]
        index = blob(root)
        descriptors = index.get("manifests", [root])
        images, attestations = [], []
        for descriptor in descriptors:
            manifest = blob(descriptor)
            config = blob(manifest["config"])
            layers = manifest["layers"]
            if descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest":
                attestations.append((descriptor, [blob(layer) for layer in layers]))
            else:
                for layer in layers:
                    blob(layer, decode=False)
                images.append((descriptor, manifest, config))
        if len(images) != 1:
            raise ValueError("Expected one executable image, not an ambiguous index")
        descriptor, manifest, config = images[0]
        if config.get("os") != "linux" or config.get("architecture") != architecture:
            raise ValueError("OCI architecture mismatch")
        labels = config.get("config", {}).get("Labels", {})
        if version is not None and (labels.get("io.hass.version") != version
                                    or labels.get("org.opencontainers.image.version") != version):
            raise ValueError("OCI release version mismatch")
        predicates = set()
        for attestation, statements in attestations:
            if attestation["annotations"].get("vnd.docker.reference.digest") != descriptor["digest"]:
                raise ValueError("Attestation refers to a different image")
            for statement in statements:
                if not any(s.get("digest", {}).get("sha256") == descriptor["digest"][7:]
                           for s in statement.get("subject", [])):
                    raise ValueError("Attestation subject mismatch")
                predicates.add(statement["predicateType"])
        if require_attestations and not (
            "https://spdx.dev/Document" in predicates
            and any(p.startswith("https://slsa.dev/provenance/") for p in predicates)
        ):
            raise ValueError("Missing SBOM or provenance attestation")
        return {
            "architecture": architecture, "index_digest": root["digest"],
            "manifest_digest": descriptor["digest"], "config_digest": manifest["config"]["digest"],
            "attestation_digests": [a[0]["digest"] for a in attestations],
            "config": config,
        }


def bind_report(identity, report):
    if any(not re.fullmatch(r"sha256:[a-f0-9]{64}", identity[key]) for key in (
        "index_digest", "manifest_digest", "config_digest",
    )):
        raise ValueError("Malformed OCI identity")
    metadata = report["Metadata"]
    if metadata["ImageID"] not in {identity[key] for key in (
        "index_digest", "manifest_digest", "config_digest",
    )}:
        raise ValueError("Scan belongs to a different image")
    config = metadata["ImageConfig"]
    if (config["architecture"] != identity["architecture"]
            or config["rootfs"] != identity["config"]["rootfs"]
            or config.get("config") != identity["config"].get("config")):
        raise ValueError("Scan configuration/layers differ from retained image")


def collect(image, report, architecture, version=None, require_attestations=False):
    docker = shutil.which("docker")
    if not docker:
        raise ValueError("Docker CLI required for packaged evidence")
    info = json.loads(subprocess.check_output([docker, "image", "inspect", image]))[0]  # nosec B603
    image_id = info["Id"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise ValueError("Missing immutable local image identity")
    with tempfile.TemporaryDirectory(prefix="access-pages-evidence-") as directory:
        archive = Path(directory) / "image.tar"
        subprocess.run([docker, "image", "save", "--output", str(archive), image_id], check=True)  # nosec B603
        identity = inspect_archive(archive, architecture, version=version,
                                   require_attestations=require_attestations)
    if image_id not in {identity["index_digest"], identity["config_digest"]}:
        raise ValueError("Local image changed during export")
    bind_report(identity, report)
    probe = Path(__file__).with_name("verify_unreachable.py").resolve()
    evidence = json.loads(subprocess.check_output([  # nosec B603 - immutable verified image, fixed read-only probe.
        docker, "run", "--rm", "--pull=never", "--network", "none",
        "--platform", "linux/" + architecture, "--entrypoint", "python",
        "--volume", f"{probe}:/run/access-pages-evidence.py:ro", image_id,
        "/run/access-pages-evidence.py",
    ]))
    if evidence["architecture"] != architecture:
        raise ValueError("Packaged probe architecture mismatch")
    return {"image_id": report["Metadata"]["ImageID"], "report_sha256": fingerprint(report),
            "identity": identity, "probe": evidence}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("report", type=Path)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--version")
    parser.add_argument("--require-attestations", action="store_true")
    args = parser.parse_args()
    print(json.dumps(collect(args.image, json.loads(args.report.read_text()), args.architecture,
                             args.version, args.require_attestations), sort_keys=True))
