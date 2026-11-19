"""Candidate equivalent of the production runtime contract; run outside AppArmor."""

import hashlib
import importlib.util
from importlib.metadata import version as package_version
import json
from pathlib import Path
import platform
import pwd
import shutil
import sqlite3
import ssl
import sys
import sysconfig
from zoneinfo import ZoneInfo

assert sys.version_info[:3] == (3, 15, 2), sys.version
assert sys.version_info.releaselevel == 'final', sys.version
assert platform.freedesktop_os_release()['ID'] == 'wolfi'
assert platform.freedesktop_os_release()['VERSION_ID'] == '20230201'
for executable in (sys.executable, '/usr/local/bin/python', '/usr/local/bin/python3'):
    assert Path(executable).resolve() == Path('/usr/bin/python3.15')
assert sqlite3.sqlite_version_info == (3, 54, 1), sqlite3.sqlite_version
assert ssl.OPENSSL_VERSION.startswith('OpenSSL 4.0.3 '), ssl.OPENSSL_VERSION
packages = {}
for record in Path('/lib/apk/db/installed').read_text().strip().split('\n\n'):
    fields = dict(line.split(':', 1) for line in record.splitlines() if line[:2] in ('P:', 'V:'))
    if fields:
        assert fields['P'] not in packages
        packages[fields['P']] = fields['V']
assert len(packages) == 30, packages
for package, version in {
    'python-3.15': '3.15.2_git20261113-r0',
    'sqlite-libs': '3.54.1-r1',
    'openssl-4.0-libssl': '4.0.3-r8',
    'openssl-4.0-libcrypto': '4.0.3-r8',
    'ca-certificates-bundle': '20261020-r0',
}.items():
    assert packages[package] == version, (package, packages.get(package))
for command in ('sh', 'bash', 'apk', 'apt', 'dpkg', 'pip', 'mount', 'umount', 'nsenter', 'infocmp', 'perl'):
    assert shutil.which(command) is None, command
assert importlib.util.find_spec('pip') is None
assert importlib.util.find_spec('ensurepip') is None
assert not list(Path('/usr/share/python-wheels').glob('pip-*.whl'))
assert not any(Path('/usr').glob('**/Archive/Tar.pm'))
assert not any(Path('/usr').glob('**/systemd-homed'))
for uid in range(2100, 2108):
    account = pwd.getpwuid(uid)
    assert account.pw_gid == uid
    assert account.pw_passwd == "!"
    assert account.pw_shell == "/sbin/nologin"
for zone in ('America/Phoenix', 'America/New_York', 'Europe/Copenhagen', 'UTC'):
    assert ZoneInfo(zone).key == zone
assert package_version('tzdata') == '2026.6'
preparation = json.loads(Path('/usr/share/access-pages/runtime-preparation.json').read_text())
assert preparation['removed_files']
for removed in preparation['removed_files']:
    assert not Path(removed).exists(), removed
notices = Path('/app/third_party_licenses')
for name in ('qurl-4.2.0-LICENSE', 'Go-1.26.11-and-1.27.3-LICENSE', 'Python-3.15.2-LICENSE',
             'qurl-modules/github.com/layervai/qurl-connector@v0.14.5/LICENSE',
             'qurl-modules/github.com/fatedier/yamux@v0.2.0/LICENSE', 'yamux-source/session.go'):
    assert (notices / name).stat().st_size > 0, name
assert (notices / 'Python-3.15.2-LICENSE').read_bytes() == (
    Path(sysconfig.get_path('stdlib')) / 'LICENSE.txt').read_bytes()
assert Path('/app/LICENSE').is_file() and Path('/app/THIRD_PARTY_NOTICES.md').is_file()
trusted = {hashlib.sha256(cert).hexdigest()
           for cert in ssl.create_default_context().get_ca_certs(binary_form=True)}
assert trusted
assert '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b' not in trusted
print(json.dumps({'packages': packages, 'python': sys.version,
                  'openssl': ssl.OPENSSL_VERSION, 'sqlite': sqlite3.sqlite_version,
                  'trusted_roots': len(trusted)}, sort_keys=True))
print('Minimal runtime, accounts, timezone, package inventory, licenses and CA distrust: PASS')
