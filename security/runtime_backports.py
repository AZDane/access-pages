"""Apply reviewed upstream Python hunks to an exact pinned runtime at build time.

No network, fuzzy patching, runtime monkeypatching or package-version rewriting.
Changed vendor bytes and expired reviews require a new review before building.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sysconfig


def digest(data):
    return hashlib.sha256(data).hexdigest()


def apply_diff(original, patch, source_file):
    lines = patch.splitlines(keepends=True)
    if lines[:2] != [f'--- a/{source_file}\n', f'+++ b/{source_file}\n']:
        raise ValueError('Patch target mismatch')
    result = original
    index = 2
    hunks = 0
    while index < len(lines):
        header = re.fullmatch(r'@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@[^\n]*\n', lines[index])
        if not header:
            raise ValueError('Malformed upstream patch hunk')
        old_count, new_count = (int(value) if value is not None else 1 for value in header.groups())
        before, after = [], []
        index += 1
        while index < len(lines) and not lines[index].startswith('@@ '):
            line = lines[index]
            if line[0] not in ' +-':
                raise ValueError('Unsupported upstream patch line')
            if line[0] in ' -':
                before.append(line[1:])
            if line[0] in ' +':
                after.append(line[1:])
            index += 1
        if len(before) != old_count or len(after) != new_count:
            raise ValueError('Truncated upstream patch hunk')
        old = ''.join(before).encode()
        if not old or result.count(old) != 1:
            raise ValueError('Upstream patch context does not match exactly once')
        result = result.replace(old, ''.join(after).encode(), 1)
        hunks += 1
    if not hunks:
        raise ValueError('Empty upstream patch')
    return result


BASE_LAYOUTS = {
    'sha256:d2711a21a494fa5c2efbfcf4226268395bad5d03406083ed0f3e7bed5199cfb2': '/usr/lib/python3.15',
    'sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd': '/usr/local/lib/python3.15',
}
HARDENED_BASE = next(iter(BASE_LAYOUTS))


def validate_manifest(manifest, now=None, *, expected_base=HARDENED_BASE):
    now = now or datetime.now(timezone.utc)
    if (expected_base not in BASE_LAYOUTS or manifest['schema'] != 1
            or manifest['base_index'] != expected_base):
        raise ValueError('Unreviewed base or backport schema')
    reviewed = datetime.fromisoformat(manifest['reviewed_at'])
    deadline = datetime.fromisoformat(manifest['review_before'])
    if reviewed.tzinfo is None or deadline.tzinfo is None or not reviewed <= now < deadline:
        raise ValueError('Temporary backports require a fresh review')
    if (deadline - reviewed).total_seconds() > 7 * 86400:
        raise ValueError('Temporary backport review exceeds seven days')
    entries = manifest['patches']
    scope = {'CVE-2026-103995', 'CVE-2026-115559'}
    if expected_base != HARDENED_BASE:
        scope.add('GH-161104')
    if {e['cve'] for e in entries} != scope or len(entries) != len(scope):
        raise ValueError('Unexpected backport scope')
    for entry in entries:
        path = Path(entry['installed_path'])
        stdlib = Path(BASE_LAYOUTS[expected_base])
        if path not in (stdlib / 'http/client.py', stdlib / 'imaplib.py'):
            raise ValueError('Unexpected installed path')
        if Path(entry['patch_file']).name != entry['patch_file']:
            raise ValueError('Invalid patch filename')
        if not re.fullmatch('[0-9a-f]{40}', entry['upstream_commit']):
            raise ValueError('Missing exact upstream commit')
        if entry['upstream_url'] != 'https://github.com/python/cpython/commit/' + entry['upstream_commit']:
            raise ValueError('Unexpected upstream source')
        for field in ('before_sha256', 'after_sha256', 'patch_sha256'):
            if not re.fullmatch('[0-9a-f]{64}', entry[field]):
                raise ValueError('Missing exact backport hash')


def prepare(root, patch_dir, now=None, *, expected_base=HARDENED_BASE):
    manifest_bytes = (patch_dir / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    validate_manifest(manifest, now, expected_base=expected_base)
    changes, removed = {}, {}
    for entry in manifest['patches']:
        target = root / entry['installed_path'].lstrip('/')
        if target.is_symlink() or not target.is_file():
            raise ValueError('Expected regular vendor module')
        original = changes.get(target, target.read_bytes())
        patch = (patch_dir / entry['patch_file']).read_bytes()
        if digest(original) != entry['before_sha256'] or digest(patch) != entry['patch_sha256']:
            raise ValueError('Vendor module or upstream patch changed; review required')
        updated = apply_diff(original, patch.decode(), entry['source_file'])
        if digest(updated) != entry['after_sha256']:
            raise ValueError('Backport output differs from reviewed bytes')
        compile(updated, str(target), 'exec')
        changes[target] = updated
    # All preflight checks finish before any installed file is modified.
    for target, updated in changes.items():
        target.write_bytes(updated)
        for bytecode in (target.parent / '__pycache__').glob(target.stem + '.*.pyc'):
            if bytecode.is_symlink():
                raise ValueError('Unexpected bytecode symlink')
            removed[str(bytecode.relative_to(root))] = digest(bytecode.read_bytes())
            bytecode.unlink()
    output = root / 'usr/share/access-pages/runtime-backports.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({'manifest': manifest, 'manifest_sha256': digest(manifest_bytes),
                                  'removed_bytecode': removed}, indent=2, sort_keys=True) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', choices=BASE_LAYOUTS, default=HARDENED_BASE)
    args = parser.parse_args()
    if sysconfig.get_path('stdlib') != BASE_LAYOUTS[args.base]:
        raise SystemExit('Unexpected runtime layout')
    prepare(Path('/'), Path('/usr/share/access-pages/backports'), expected_base=args.base)
