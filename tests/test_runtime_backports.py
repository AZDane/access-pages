"""Backports must refuse drift, ambiguous hunks, stale reviews and partial input."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from security import runtime_backports as backports
DIRECTORY = Path(__file__).resolve().parents[1] / 'packaging/minimal/patches'
NOW = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)


class RuntimeBackportTests(unittest.TestCase):
    def test_exact_hunks_apply_without_line_number_dependency(self):
        patch = '--- a/Lib/x.py\n+++ b/Lib/x.py\n@@ -100,2 +100,2 @@\n same\n-old\n+new\n'
        self.assertEqual(backports.apply_diff(b'prefix\nsame\nold\n', patch, 'Lib/x.py'), b'prefix\nsame\nnew\n')

    def test_drift_ambiguous_and_truncated_patch_rejected(self):
        patch = '--- a/Lib/x.py\n+++ b/Lib/x.py\n@@ -1 +1 @@\n-old\n+new\n'
        for original, data, source in ((b'changed\n', patch, 'Lib/x.py'),
                                       (b'old\nold\n', patch, 'Lib/x.py'),
                                       (b'old\n', patch.replace('+new\n', ''), 'Lib/x.py'),
                                       (b'old\n', patch, 'Lib/other.py')):
            with self.assertRaises(ValueError):
                backports.apply_diff(original, data, source)

    def test_review_expiry_is_exclusive_and_cannot_be_silently_extended(self):
        manifest = json.loads((DIRECTORY / 'manifest.json').read_text())
        backports.validate_manifest(manifest, NOW)
        for when in (datetime(2026, 11, 18, tzinfo=timezone.utc),
                     datetime(2026, 11, 26, tzinfo=timezone.utc)):
            with self.assertRaises(ValueError):
                backports.validate_manifest(manifest, when)
        manifest['review_before'] = '2026-12-26T00:00:00+00:00'
        with self.assertRaises(ValueError):
            backports.validate_manifest(manifest, NOW)

    def test_standalone_manifest_cannot_replace_hardened_base_or_paths(self):
        manifest = json.loads((DIRECTORY.parents[1] / 'standalone/manifest.json').read_text())
        with self.assertRaises(ValueError):
            backports.validate_manifest(manifest, NOW)
        base = manifest['base_index']
        backports.validate_manifest(manifest, NOW, expected_base=base)
        manifest['patches'][0]['installed_path'] = '/usr/lib/python3.15/http/client.py'
        with self.assertRaises(ValueError):
            backports.validate_manifest(manifest, NOW, expected_base=base)
        with self.assertRaises(ValueError):
            backports.validate_manifest(manifest, NOW, expected_base='unreviewed')

    def test_sequential_standalone_hunks_are_preflighted_before_any_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            patch_dir = root / 'patches'
            patch_dir.mkdir()
            manifest = json.loads((DIRECTORY.parents[1] / 'standalone/manifest.json').read_text())
            expected = {}
            for index, entry in enumerate(manifest['patches']):
                target = root / entry['installed_path'].lstrip('/')
                before = expected.get(target, b'original = True\n')
                if target not in expected:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(before)
                after = f'updated_{index} = True\n'.encode()
                data = (f"--- a/{entry['source_file']}\n+++ b/{entry['source_file']}\n"
                        '@@ -1 +1 @@\n-' + before.decode() + '+' + after.decode()).encode()
                (patch_dir / entry['patch_file']).write_bytes(data)
                entry.update(before_sha256=backports.digest(before), after_sha256=backports.digest(after),
                             patch_sha256=backports.digest(data))
                expected[target] = after
            path = patch_dir / 'manifest.json'
            final_hash = manifest['patches'][-1]['after_sha256']
            manifest['patches'][-1]['after_sha256'] = 'f' * 64
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                backports.prepare(root, patch_dir, NOW, expected_base=manifest['base_index'])
            self.assertTrue(all(target.read_bytes() == b'original = True\n' for target in expected))
            manifest['patches'][-1]['after_sha256'] = final_hash
            path.write_text(json.dumps(manifest))
            backports.prepare(root, patch_dir, NOW, expected_base=manifest['base_index'])
            self.assertTrue(all(target.read_bytes() == data for target, data in expected.items()))

    def test_all_file_checks_precede_mutation_and_bytecode_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            patch_dir = root / 'patches'
            patch_dir.mkdir()
            manifest = deepcopy(json.loads((DIRECTORY / 'manifest.json').read_text()))
            targets = []
            for entry in manifest['patches']:
                target = root / entry['installed_path'].lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'old = True\n')
                targets.append(target)
                patch = f"--- a/{entry['source_file']}\n+++ b/{entry['source_file']}\n@@ -1 +1 @@\n-old = True\n+new = True\n".encode()
                (patch_dir / entry['patch_file']).write_bytes(patch)
                entry.update(before_sha256=backports.digest(b'old = True\n'),
                             after_sha256=backports.digest(b'new = True\n'),
                             patch_sha256=backports.digest(patch))
            manifest_path = patch_dir / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest))
            targets[1].write_bytes(b'vendor drift\n')
            with self.assertRaises(ValueError):
                backports.prepare(root, patch_dir, NOW)
            self.assertEqual(targets[0].read_bytes(), b'old = True\n')
            targets[1].write_bytes(b'old = True\n')
            cache = targets[0].parent / '__pycache__' / (targets[0].stem + '.cpython-315.pyc')
            cache.parent.mkdir()
            cache.write_bytes(b'stale bytecode')
            backports.prepare(root, patch_dir, NOW)
            self.assertFalse(cache.exists())
            self.assertTrue(all(target.read_bytes() == b'new = True\n' for target in targets))
            retained = json.loads((root / 'usr/share/access-pages/runtime-backports.json').read_text())
            self.assertEqual(retained['manifest'], manifest)
            self.assertIn(str(cache.relative_to(root)), retained['removed_bytecode'])


if __name__ == '__main__':
    unittest.main()
