"""Prepare the candidate without installing a shell or a package manager."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import sysconfig
import zipfile


def add_service_accounts(root):
    """Append fixed, locked service identities without rewriting existing records."""
    groups = {'gateway-pages': 2000, 'policy-readers': 2001,
              'access-pages-secrets': 2003, 'guest-transport': 2004}
    accounts = dict(zip(('app-admin', 'app-guest', 'ha-broker', 'access-pages-broker',
                         'policy-store', 'connector', 'ingress', 'onboarding'),
                        range(2100, 2108)))
    groups.update(accounts)
    group_file = root / 'etc/group'
    account_file = root / 'etc/passwd'
    # Validate both files before either is changed. No existing account field
    # is passed to a write operation, including its credential placeholder.
    for path, count, additions in ((group_file, 4, groups), (account_file, 7, accounts)):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Expected a regular base identity file')
        data = path.read_text()
        if not data.endswith('\n'):
            raise ValueError('Malformed base identity file')
        rows = [line.split(':') for line in data.splitlines()]
        if any(len(row) != count or not row[0] or not row[2].isdigit() for row in rows):
            raise ValueError('Malformed base identity record')
        if any(row[1] not in ('x', '!', '*', '!!') for row in rows):
            raise ValueError('Base identity file contains an unexpected credential field')
        if {row[0] for row in rows} & additions.keys():
            raise ValueError('Reserved service identity name collision')
        if {int(row[2]) for row in rows} & set(additions.values()):
            raise ValueError('Reserved service identity ID collision')
    with group_file.open('a') as stream:
        stream.writelines(f'{name}:x:{gid}:\n' for name, gid in groups.items())
    with account_file.open('a') as stream:
        stream.writelines(f'{name}:!:{uid}:{uid}::/home/{name}:/sbin/nologin\n'
                          for name, uid in accounts.items())
    return accounts


def prepare():
    wheel = Path('/opt/build/tzdata.whl')
    expected = '0a10eec6e13ef16b627fabed9a5f2ba61a62b1c67f327305f4e7e412a70b4aec'
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != expected:
        raise ValueError('Timezone wheel checksum mismatch')
    destination = Path(sysconfig.get_path('purelib'))
    with zipfile.ZipFile(wheel) as archive:
        for item in archive.infolist():
            path = Path(item.filename)
            if path.is_absolute() or '..' in path.parts or path.parts[0] not in (
                'tzdata', 'tzdata-2026.6.dist-info'
            ):
                raise ValueError('Unexpected timezone archive member')
            target = destination / path
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(item))
                target.chmod(0o644)
    wheel.unlink()

    # Preserve APK inventory and vendor SBOMs. Record every removed installer
    # file; scanners must continue to see the original package attribution.
    removed = {}
    paths = [Path(sysconfig.get_path('stdlib')) / 'ensurepip', Path('/usr/bin/infocmp')]
    paths.extend(Path('/usr/share/python-wheels').glob('pip-*.whl'))
    for path in paths:
        for file in ([path] if path.is_file() else sorted(path.rglob('*'))):
            if file.is_file():
                removed[str(file)] = hashlib.sha256(file.read_bytes()).hexdigest()
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    manifest = Path('/usr/share/access-pages/runtime-preparation.json')
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({'removed_files': removed,
                                   'tzdata_wheel_sha256': expected}, sort_keys=True))

    accounts = add_service_accounts(Path("/"))
    for name, uid in accounts.items():
        home = Path('/home') / name
        home.mkdir(mode=0o700)
        os.chown(home, uid, uid)
    directories = {
        '/data/pages': (2100, 2000, 0o2750),
        '/data/admin-runtime': (2100, 2100, 0o700),
        '/data/policy-pages': (2104, 2001, 0o2750),
        '/data/guest-runtime': (2100, 2100, 0o700),
        '/data/secrets': (0, 2003, 0o750),
        '/data/connector-state': (2105, 2105, 0o700),
        '/data/connector-config': (2105, 2105, 0o700),
        '/data/logs/layer-v-connector': (2105, 2105, 0o700),
        '/data/access-pages-broker': (0, 0, 0o755),
    }
    for directory, (uid, gid, mode) in directories.items():
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        os.chown(path, uid, gid)
        path.chmod(mode)
    Path('/var/log/layerv').symlink_to('/data/logs/layer-v-connector')
    Path('/usr/local/bin').mkdir(parents=True, exist_ok=True)
    for alias in ('python', 'python3', 'python3.15'):
        Path('/usr/local/bin', alias).symlink_to('/usr/bin/python3.15')
    if not ssl.create_default_context().cert_store_stats()['x509_ca']:
        raise ValueError('Empty system CA trust store')
    Path(__file__).unlink()


if __name__ == '__main__':
    prepare()
