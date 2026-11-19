"""A local backport must never become an unbound vulnerability suppression."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from security.backport_evidence import PATCHED_IDS, ROOT, verify
from security.check_runtime_advisories import EXPECTED

NOW = datetime(2026, 11, 19, 18, tzinfo=timezone.utc)
IMAGE = 'sha256:' + 'a' * 64


class BackportEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        raw = (ROOT / 'packaging/minimal/patches/manifest.json').read_bytes()
        manifest = json.loads(raw)
        self.inventory = {'runtime_backports': {'manifest': manifest,
            'manifest_sha256': hashlib.sha256(raw).hexdigest()},
            'files': {p['installed_path']: p['after_sha256'] for p in manifest['patches']}}
        modules = {'CVE-2026-103995': 'http.client', 'CVE-2026-115559': 'imaplib'}
        self.observations = {'schema': 1, 'machine': 'x86_64', 'python': '3.15.2',
            'checks': dict.fromkeys(EXPECTED, True),
            'library_sha256': {modules[p['cve']]: p['after_sha256'] for p in manifest['patches']}}
        self.decision = {'image_id': IMAGE, 'architecture': 'amd64', 'complete': True,
            'promotion_allowed': True, 'failed_checks': [], 'collected_at': NOW.isoformat(),
            'probe_sha256': hashlib.sha256((ROOT / 'tests/packaged_advisory_observations.py').read_bytes()).hexdigest()}
        self.publisher = {key: {'id': key, 'upstream': [cve],
            'affected': [{'package': {'name': 'python-3.15'}}]}
            for key, cve in PATCHED_IDS['amd64'].items()}
        self.write_evidence()

    def write_evidence(self):
        raw = json.dumps(self.observations).encode()
        (self.directory / 'observations.json').write_bytes(raw)
        self.decision['observations_sha256'] = hashlib.sha256(raw).hexdigest()
        (self.directory / 'evidence.json').write_text(json.dumps(self.decision))

    def verify(self, **changes):
        args = dict(inventory=self.inventory, image_id=IMAGE, architecture='amd64',
                    runtime_directory=self.directory, publisher=self.publisher, now=NOW)
        args.update(changes)
        return verify(**args)

    def test_only_exact_reviewed_advisories_are_recognized(self):
        self.publisher['CGA-other'] = {'upstream': ['CVE-unrelated']}
        self.assertEqual(self.verify()['advisory_ids'], sorted(PATCHED_IDS['amd64']))

    def test_different_image_and_architecture_cannot_reuse_proof(self):
        for changes in ({'image_id': 'sha256:' + 'b' * 64}, {'architecture': 'arm64'}):
            with self.assertRaises(ValueError):
                self.verify(**changes)

    def test_failed_missing_and_stale_evidence_blocks(self):
        for key, value in (('complete', False), ('promotion_allowed', False),
                           ('failed_checks', ['http.invalid']),
                           ('collected_at', '2026-11-18T00:00:00+00:00'),
                           ('collected_at', '2026-11-20T00:00:00+00:00'),
                           ('probe_sha256', '0' * 64)):
            with self.subTest(key=key):
                original = self.decision[key]
                self.decision[key] = value
                self.write_evidence()
                with self.assertRaises(ValueError):
                    self.verify()
                self.decision[key] = original
        (self.directory / 'observations.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_installed_hash_and_actual_probe_cannot_disagree(self):
        for module in ('http.client', 'imaplib'):
            original = self.observations['library_sha256'][module]
            self.observations['library_sha256'][module] = '0' * 64
            self.write_evidence()
            with self.assertRaises(ValueError):
                self.verify()
            self.observations['library_sha256'][module] = original
        self.observations['checks']['http.reject_chunk.+1'] = False
        self.write_evidence()
        with self.assertRaises(ValueError):
            self.verify()

    def test_publisher_scope_changes_require_new_review(self):
        for key in self.publisher:
            altered = deepcopy(self.publisher)
            altered[key]['upstream'].append('CVE-2026-999999')
            with self.assertRaises(ValueError):
                self.verify(publisher=altered)
            altered = deepcopy(self.publisher)
            altered[key]['affected'][0]['package']['name'] = 'different-package'
            with self.assertRaises(ValueError):
                self.verify(publisher=altered)

    def test_expired_or_modified_manifest_is_not_a_resolution(self):
        with self.assertRaises(ValueError):
            self.verify(now=datetime(2026, 11, 26, tzinfo=timezone.utc))
        self.inventory['runtime_backports']['manifest']['owner'] = 'unreviewed'
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == '__main__':
    unittest.main()
