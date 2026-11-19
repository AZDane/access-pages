"""Applicability cannot survive stale, changed, incomplete or transplanted proof."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from security.applicability_decisions import REVIEWED_CVES, digest, fingerprint, verify, verify_glibc_consumers


class ApplicabilityDecisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.now = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)
        self.image = 'sha256:' + 'a' * 64
        self.policy = json.loads(Path('packaging/minimal/applicability.json').read_text())
        for name in self.policy['controls_sha256']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'reviewed control')
            self.policy['controls_sha256'][name] = digest(path.read_bytes())
        runtime = {'schema': 1, 'architecture': 'amd64',
                   'application': {'files': {'/app/a.py': 'b' * 64}},
                   'qurl': {'sha256': 'c' * 64, 'function_count': 2000},
                   'commands': dict.fromkeys(('sqlite3', 'xmlwf', 'sh', 'bash', 'openssl')),
                   'library_and_config_sha256': {'ssl.py': 'd' * 64},
                   'python_tls': {'default_ciphers': ['TLS_AES_256_GCM_SHA384']}}
        self.write('runtime.json', runtime)
        self.write('native.json', [{'path': '/reviewed/fixture', 'sha256': 'e' * 64,
                                    'undefined': [], 'needed': []}])
        inputs = {name: digest((self.evidence / name).read_bytes())
                  for name in ('runtime.json', 'native.json')}
        collectors = {}
        for name in ('collect_applicability.py', 'runtime_applicability.py', 'verify_unreachable.py'):
            path = self.root / 'security' / name
            path.write_bytes(b'reviewed collector')
            collectors[name] = digest(path.read_bytes())
        self.publisher = {f'CGA-test-{i}': {'id': f'CGA-test-{i}', 'upstream': [cve]}
                          for i, cve in enumerate(sorted(REVIEWED_CVES))}
        self.policy['architectures']['amd64'] = {
            'inputs_sha256': inputs, 'collector_sha256': collectors,
            'advisories': {key: {'cve': value['upstream'][0], 'sha256': fingerprint(value)}
                           for key, value in self.publisher.items()},
        }
        self.observed = {'schema': 1, 'complete': True, 'image_id': self.image,
                         'architecture': 'amd64', 'decision': 'observation_only',
                         'collected_at': self.now.isoformat(), 'inputs_sha256': inputs,
                         'collector_sha256': collectors}
        self.save()

    def write(self, name, value):
        (self.evidence / name).write_text(json.dumps(value))

    def save(self):
        (self.root / 'packaging/minimal/applicability.json').write_text(json.dumps(self.policy))
        self.write('evidence.json', self.observed)

    def check(self, **kwargs):
        return verify(self.image, 'amd64', self.evidence, self.publisher,
                      now=kwargs.get('now', self.now), root=self.root)

    def test_exact_review_covers_only_named_advisories(self):
        self.publisher['CGA-new'] = {'id': 'CGA-new', 'upstream': ['CVE-2026-999999']}
        decision = self.check()
        self.assertEqual(set(decision['cves']), REVIEWED_CVES)
        self.assertNotIn('CGA-new', decision['advisory_ids'])

    def test_expiry_is_exclusive_and_cannot_exceed_seven_days(self):
        with self.assertRaises(ValueError):
            self.check(now=datetime(2026, 11, 26, tzinfo=timezone.utc))
        self.policy['review_before'] = '2026-12-01T00:00:00+00:00'
        self.save()
        with self.assertRaises(ValueError):
            self.check()

    def test_transplanted_wrong_architecture_stale_future_and_incomplete_evidence_fail(self):
        original = deepcopy(self.observed)
        for field, value in (
            ('image_id', 'sha256:' + 'f' * 64), ('architecture', 'arm64'),
            ('complete', False), ('decision', 'approved'),
            ('collected_at', (self.now - timedelta(hours=25)).isoformat()),
            ('collected_at', (self.now + timedelta(seconds=1)).isoformat()),
        ):
            with self.subTest(field=field, value=value):
                self.observed = {**original, field: value}
                self.save()
                with self.assertRaises(ValueError):
                    self.check()

    def test_self_consistent_modified_evidence_still_requires_reassessment(self):
        for name in ('runtime.json', 'native.json'):
            with self.subTest(name=name):
                original = (self.evidence / name).read_bytes()
                (self.evidence / name).write_bytes(original + b' ')
                self.observed['inputs_sha256'][name] = digest(original + b' ')
                self.write('evidence.json', self.observed)
                with self.assertRaises(ValueError):
                    self.check()
                (self.evidence / name).write_bytes(original)
                self.observed['inputs_sha256'][name] = digest(original)

    def test_changed_or_missing_advisory_is_not_silently_accepted(self):
        key = next(iter(self.publisher))
        self.publisher[key]['new_scope'] = 'expanded'
        with self.assertRaises(ValueError):
            self.check()
        del self.publisher[key]
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_control_and_collector_fail(self):
        control = self.root / 'Dockerfile.ha-minimal'
        control.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.check()
        control.write_bytes(b'reviewed control')
        (self.root / 'security/runtime_applicability.py').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_control_and_decision_fail(self):
        control = self.policy['controls_sha256'].pop('packaging/minimal/apparmor.txt')
        self.save()
        with self.assertRaises(ValueError):
            self.check()
        self.policy['controls_sha256']['packaging/minimal/apparmor.txt'] = control
        self.policy['decisions'].pop(next(iter(REVIEWED_CVES)))
        self.save()
        with self.assertRaises(ValueError):
            self.check()

    def test_glibc_aliases_internal_entrypoints_and_loaded_forms_require_review(self):
        for symbol in ('__isoc23_vswscanf', '__nldbl_vfwscanf', 'rpmatch', 'advance',
                       'step', '__re_compile_pattern', 're_search_2', 'regexec'):
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                verify_glibc_consumers([{'path': '/new/consumer', 'needed': [],
                                        'undefined': [symbol]}])
        verify_glibc_consumers([{'path': '/usr/lib/libform.so.6.6', 'needed': [],
                                'undefined': ['regcomp', 'regexec']}])
        with self.assertRaises(ValueError):
            verify_glibc_consumers([{'path': '/new/consumer', 'undefined': [],
                                    'needed': ['libform.so.6']}])


if __name__ == '__main__':
    unittest.main()
