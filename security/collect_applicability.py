"""Retain image-bound source, Go-linkage and native-library applicability evidence.

No vulnerability is waived by this collector. Failure to collect complete
evidence fails the CI step. The independent advisory gate remains authoritative.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - fixed commands and argument lists only.
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def native_symbols(symbols, dynamic, sections=''):
    if 'Symbol table' not in symbols and 'There are no dynamic symbols' not in symbols:
        # GNU readelf emits empty stdout for some static Go executables. Accept
        # that only with a successfully read ELF header and section inventory
        # explicitly showing no dynamic symbol table.
        if (symbols.strip() or 'ELF Header:' not in sections or 'Section Headers:' not in sections
                or re.search(r'\s\.dynsym\s', sections)):
            raise ValueError('Unrecognized native symbol evidence')
    undefined = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[6] == 'UND':
            undefined.append(fields[7].split('@')[0])
    return {'undefined': sorted(set(undefined)),
            'needed': sorted(re.findall(r'\(NEEDED\).*\[(.*?)\]', dynamic))}


def validate_runtime(data, architecture):
    if data['schema'] != 1 or data['architecture'] != architecture:
        raise ValueError('Wrong runtime architecture/schema')
    if not data['application']['files'] or data['qurl']['function_count'] < 1000:
        raise ValueError('Incomplete application/Go evidence')
    if set(data['commands']) != {'sqlite3', 'xmlwf', 'sh', 'bash', 'openssl'}:
        raise ValueError('Incomplete command inventory')
    for digest in [data['qurl']['sha256'], *data['application']['files'].values(),
                   *data['library_and_config_sha256'].values()]:
        if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
            raise ValueError('Malformed source/binary hash')
    if not data['python_tls']['default_ciphers']:
        raise ValueError('Missing actual TLS cipher evidence')


def collect(image, architecture, output):
    output.mkdir(parents=True, exist_ok=False)
    docker, readelf = shutil.which('docker'), shutil.which('readelf')
    if not docker or not readelf:
        raise ValueError('Docker and readelf are required')
    info = json.loads(subprocess.check_output([docker, 'image', 'inspect', image], timeout=30))[0]  # nosec B603
    identity = info['Id']
    if info['Architecture'] != architecture or not re.fullmatch('sha256:[a-f0-9]{64}', identity):
        raise ValueError('Missing immutable/native image identity')
    raw = subprocess.check_output([  # nosec B603 - fixed offline immutable image operation.
        docker, 'run', '--rm', '--pull=never', '--platform', 'linux/' + architecture,
        '--network', 'none', '--read-only', '--user', '2103:2103', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--entrypoint', 'python',
        '--env', 'PYTHONPATH=/review', '--env', 'PYTHONDONTWRITEBYTECODE=1',
        '--volume', f'{ROOT / "security"}:/review/security:ro',
        identity, '-m', 'security.runtime_applicability',
    ], timeout=90)
    (output / 'runtime.json').write_bytes(raw)
    runtime = json.loads(raw)
    validate_runtime(runtime, architecture)
    container = subprocess.check_output([  # nosec B603
        docker, 'create', '--network', 'none', identity,
    ], text=True, timeout=30).strip()
    entries = []
    try:
        with tempfile.TemporaryDirectory(prefix='native-applicability-') as temporary:
            directory = Path(temporary)
            archive_path = directory / 'rootfs.tar'
            subprocess.run([docker, 'export', '--output', str(archive_path), container],  # nosec B603
                           check=True, timeout=120)
            with tarfile.open(archive_path) as archive:
                for member in archive:
                    if not member.isfile() or member.size < 4:
                        continue
                    with archive.extractfile(member) as stream:
                        header = stream.read(4)
                        if header != b'\x7fELF':
                            continue
                        data = header + stream.read()
                    digest = hashlib.sha256(data).hexdigest()
                    # Never extract archive paths, symlinks or permissions.
                    binary = directory / digest
                    binary.write_bytes(data)
                    symbols = subprocess.check_output([readelf, '--dyn-syms', '--wide', str(binary)],  # nosec B603
                                                      text=True, timeout=20)
                    dynamic = subprocess.check_output([readelf, '--dynamic', '--wide', str(binary)],  # nosec B603
                                                      text=True, timeout=20)
                    sections = ''
                    if not symbols.strip():
                        sections = subprocess.check_output(  # nosec B603
                            [readelf, '--file-header', '--section-headers', '--wide', str(binary)],
                            text=True, timeout=20)
                    entries.append({'path': '/' + member.name.lstrip('/'), 'sha256': digest,
                                    **native_symbols(symbols, dynamic, sections)})
                    binary.unlink()
    finally:
        subprocess.run([docker, 'rm', container], check=True, stdout=subprocess.DEVNULL, timeout=30)  # nosec B603
    paths = {entry['path'] for entry in entries}
    if len(entries) < 50 or len(paths) != len(entries) or not {
        '/usr/local/bin/qurl', '/usr/local/bin/access-pages-guest-endpoint',
    } <= paths:
        raise ValueError('Incomplete native executable inventory')
    (output / 'native.json').write_text(json.dumps(sorted(entries, key=lambda e: e['path']),
                                                  indent=2, sort_keys=True) + '\n')
    evidence = {
        'schema': 1, 'complete': True, 'image_id': identity, 'architecture': architecture,
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'decision': 'observation_only',
        'inputs_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in output.iterdir()},
        'collector_sha256': {name: hashlib.sha256((ROOT / 'security' / name).read_bytes()).hexdigest()
                             for name in ('collect_applicability.py', 'runtime_applicability.py',
                                          'verify_unreachable.py')},
    }
    (output / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'image_id': identity, 'architecture': architecture, 'elf_files': len(entries),
                      'complete': True, 'decision': 'observation_only'}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    collect(args.image, args.architecture, args.output)
