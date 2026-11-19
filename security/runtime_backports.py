"""Apply reviewed upstream Python hunks to an exact pinned runtime at build time.

No network, fuzzy patching, runtime monkeypatching or package-version rewriting.
Changed vendor bytes and expired reviews require a new review before building.
"""

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


def validate_manifest(manifest, now=None):
    now = now or datetime.now(timezone.utc)
    if manifest['schema'] != 1 or manifest['base_index'] != (
        'sha256:d2711a21a494fa5c2efbfcf4226268395bad5d03406083ed0f3e7bed5199cfb2'
    ):
        raise ValueError('Unreviewed base or backport schema')
    reviewed = datetime.fromisoformat(manifest['reviewed_at'])
    deadline = datetime.fromisoformat(manifest['review_before'])
    if reviewed.tzinfo is None or deadline.tzinfo is None or not reviewed <= now < deadline:
        raise ValueError('Temporary backports require a fresh review')
    if (deadline - reviewed).total_seconds() > 7 * 86400:
        raise ValueError('Temporary backport review exceeds seven days')
    entries = manifest['patches']
    if {e['cve'] for e in entries} != {'CVE-2026-103995', 'CVE-2026-115559'} or len(entries) != 2:
        raise ValueError('Unexpected backport scope')
    for entry in entries:
        path = Path(entry['installed_path'])
        if path not in (Path('/usr/lib/python3.15/http/client.py'), Path('/usr/lib/python3.15/imaplib.py')):
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


def prepare(root, patch_dir, now=None):
    manifest_bytes = (patch_dir / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    validate_manifest(manifest, now)
    changes, removed = [], {}
    for entry in manifest['patches']:
        target = root / entry['installed_path'].lstrip('/')
        if target.is_symlink() or not target.is_file():
            raise ValueError('Expected regular vendor module')
        original = target.read_bytes()
        patch = (patch_dir / entry['patch_file']).read_bytes()
        if digest(original) != entry['before_sha256'] or digest(patch) != entry['patch_sha256']:
            raise ValueError('Vendor module or upstream patch changed; review required')
        updated = apply_diff(original, patch.decode(), entry['source_file'])
        if digest(updated) != entry['after_sha256']:
            raise ValueError('Backport output differs from reviewed bytes')
        compile(updated, str(target), 'exec')
        changes.append((target, updated))
    # All preflight checks finish before any installed file is modified.
    for target, updated in changes:
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
    if sysconfig.get_path('stdlib') != '/usr/lib/python3.15':
        raise SystemExit('Unexpected runtime layout')
    prepare(Path('/'), Path('/usr/share/access-pages/backports'))
