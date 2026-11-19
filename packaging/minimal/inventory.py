"""Read-only inventory from the exact candidate image, with no network access."""

import hashlib
import json
from pathlib import Path
import platform
import sysconfig


def collect():
    database = Path('/lib/apk/db/installed')
    packages = []
    for record in database.read_text().strip().split('\n\n'):
        fields = dict(line.split(':', 1) for line in record.splitlines()
                      if line[:2] in ('P:', 'V:', 'A:', 'o:'))
        if fields:
            packages.append({'name': fields['P'], 'version': fields['V'],
                             'arch': fields['A'], 'source': fields['o']})
    files = [Path('/usr/local/bin/qurl'), Path('/usr/local/bin/access-pages-guest-endpoint'),
             Path(sysconfig.get_path('stdlib')) / 'imaplib.py',
             Path(sysconfig.get_path('stdlib')) / 'http/client.py',
             Path('/usr/share/access-pages/runtime-backports.json'),
             Path('/usr/share/access-pages/runtime-preparation.json')]
    files.extend(sorted(Path('/app').glob('*.py')))
    files.extend(Path('/usr/local/bin').glob('*.py'))
    return {'architecture': {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()],
            'packages': sorted(packages, key=lambda item: item['name']),
            'apk_database_sha256': hashlib.sha256(database.read_bytes()).hexdigest(),
            'runtime_backports': json.loads(Path('/usr/share/access-pages/runtime-backports.json').read_text()),
            'files': {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}}


if __name__ == '__main__':
    print(json.dumps(collect(), sort_keys=True))
