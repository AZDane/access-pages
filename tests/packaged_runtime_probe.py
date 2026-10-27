"""Inspect the packaged runtime outside AppArmor; package tools are not allowed by it."""

import hashlib
import platform
import shutil
import sqlite3
import ssl
import subprocess
import sys
import sysconfig
from pathlib import Path

assert sys.version_info[:3] == (3, 15, 2), sys.version
assert platform.freedesktop_os_release()["VERSION_CODENAME"] == "trixie"
for executable in (sys.executable, "/usr/local/bin/python", "/usr/local/bin/python3"):
    assert Path(executable).resolve() == Path("/usr/local/bin/python3.15")
for package, minimum in {
    "openssl": "3.5.7-1~deb13u3",
    "libssl3t64": "3.5.7-1~deb13u3",
    "libsqlite3-0": "3.46.1-7+deb13u2",
}.items():
    version = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${Version}", package], text=True
    ).strip()
    subprocess.run(
        ["dpkg", "--compare-versions", version, "ge", minimum], check=True
    )
    print(f"{package}: {version}")
print(f"Python: {sys.version}; TLS: {ssl.OPENSSL_VERSION}")
assert sqlite3.sqlite_version_info == (3, 46, 1), sqlite3.sqlite_version
print(f"SQLite: {sqlite3.sqlite_version}; libc: {platform.libc_ver()}")
assert not subprocess.check_output(["dpkg", "--audit"], text=True).strip()
subprocess.run(["apt-get", "check"], check=True)
assert shutil.which("mount") is None and shutil.which("umount") is None
# Source-package CVEs do not imply these optional components are shipped.
# Keep the component-absence dispositions in the vulnerability baseline honest.
assert not any(Path("/usr").glob("**/Archive/Tar.pm")), "Archive::Tar is now shipped; reassess CVE-2026-9538"
assert not any(Path("/usr").glob("**/systemd-homed")), "systemd-homed is now shipped; reassess CVE-2026-16742"
packages = subprocess.check_output(
    ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n"], text=True
)
assert not any(line.startswith("mount\t") and line.endswith("installed") for line in packages.splitlines())
print("Final system package inventory:\n" + packages)
assert not (Path(sysconfig.get_path("stdlib")) / "ensurepip").exists()
assert not list(Path(sysconfig.get_path("purelib")).glob("pip*"))
notices = Path("/app/third_party_licenses")
assert Path("/app/THIRD_PARTY_NOTICES.md").is_file()
assert Path("/app/LICENSE").is_file()
for license_file in (
    notices / "qurl-3.6.0-LICENSE",
    notices / "Go-1.26.10-and-1.27.3-LICENSE",
    notices / "Python-3.15.2-LICENSE",
    notices / "qurl-modules/github.com/layervai/qurl-connector@v0.14.2/LICENSE",
    notices / "qurl-modules/github.com/fatedier/yamux@v0.0.0-20250825093530-d0154be01cd6/LICENSE",
):
    assert license_file.is_file() and license_file.stat().st_size > 0, license_file
assert (notices / "Python-3.15.2-LICENSE").read_bytes() == (
    Path(sysconfig.get_path("stdlib")) / "LICENSE.txt"
).read_bytes()
assert (notices / "yamux-source/session.go").is_file()

# certifi 2026.10.19 distrusts only emSign ECC Root CA - G3, restoring the
# unaffected G1, C1 and C3 roots. Check the actual Python trust store, not names.
distrusted = "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"
trusted = {
    hashlib.sha256(cert).hexdigest()
    for cert in ssl.create_default_context().get_ca_certs(binary_form=True)
}
assert distrusted not in trusted, "Compromised emSign trust anchor remains trusted"
assert len(trusted) > 0
print("Packaged runtime, licenses, package fixes and system CA distrust: PASS")
