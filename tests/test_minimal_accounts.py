"""Service account setup must never rewrite credentials or accept collisions."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('minimal_prepare', ROOT / 'packaging/minimal/prepare.py')
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class MinimalAccountTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'etc').mkdir()
        self.accounts = self.root / 'etc/passwd'
        self.groups = self.root / 'etc/group'
        self.accounts.write_text('root:x:0:0:root:/root:/sbin/nologin\n')
        self.groups.write_text('root:x:0:\n')

    def test_existing_records_unchanged_and_new_accounts_locked(self):
        before = self.accounts.read_bytes()
        identities = PREPARE.add_service_accounts(self.root)
        self.assertTrue(self.accounts.read_bytes().startswith(before))
        self.assertEqual(len(identities), 8)
        rows = [line.split(':') for line in self.accounts.read_text().splitlines()[1:]]
        self.assertEqual({int(row[2]) for row in rows}, set(range(2100, 2108)))
        self.assertTrue(all(row[1] == '!' and row[6] == '/sbin/nologin' for row in rows))
        self.assertTrue(all(row[2] == row[3] for row in rows))

    def assert_rejected_without_writes(self):
        before = self.accounts.read_bytes(), self.groups.read_bytes()
        with self.assertRaises(ValueError):
            PREPARE.add_service_accounts(self.root)
        self.assertEqual(before, (self.accounts.read_bytes(), self.groups.read_bytes()))

    def test_unexpected_credential_field_is_rejected_without_writing_or_echoing_it(self):
        marker = 'synthetic-unexpected-field'
        self.accounts.write_text(f'root:{marker}:0:0:root:/root:/sbin/nologin\n')
        self.assert_rejected_without_writes()
        try:
            PREPARE.add_service_accounts(self.root)
        except ValueError as error:
            self.assertNotIn(marker, str(error))

    def test_account_or_group_name_collision_rejects_both_writes(self):
        for path, record in ((self.accounts, 'app-admin:x:900:900::/:/sbin/nologin\n'),
                             (self.groups, 'gateway-pages:x:900:\n')):
            with self.subTest(file=path.name):
                original = path.read_text()
                path.write_text(original + record)
                self.assert_rejected_without_writes()
                path.write_text(original)

    def test_account_or_group_id_collision_rejects_both_writes(self):
        for path, record in ((self.accounts, 'other:x:2100:2100::/:/sbin/nologin\n'),
                             (self.groups, 'other:x:2000:\n')):
            with self.subTest(file=path.name):
                original = path.read_text()
                path.write_text(original + record)
                self.assert_rejected_without_writes()
                path.write_text(original)

    def test_empty_field_or_malformed_record_is_rejected(self):
        for record in ('root::0:0:root:/root:/sbin/nologin\n', 'root:x:0',
                       'root:x:invalid:0:root:/root:/sbin/nologin\n'):
            with self.subTest(record=record):
                self.accounts.write_text(record)
                self.assert_rejected_without_writes()

    def test_symlink_identity_file_is_rejected(self):
        original = self.accounts.read_bytes()
        target = self.root / 'original'
        self.accounts.rename(target)
        self.accounts.symlink_to(target)
        self.assert_rejected_without_writes()
        self.assertEqual(target.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
