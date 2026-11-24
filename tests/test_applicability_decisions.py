"""Applicability cannot survive stale, changed, incomplete or transplanted proof."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from security.applicability_decisions import (
    QURL_ADVISORIES, REVIEWED_CVES, digest, fingerprint, verify, verify_glibc_consumers, verify_qurl,
)
from security.check_vulnerabilities import finding_fingerprint


class ApplicabilityDecisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.now = datetime(2026, 11, 24, 17, tzinfo=timezone.utc)
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
            self.check(now=datetime(2026, 12, 1, 16, 57, tzinfo=timezone.utc))
        self.policy['review_before'] = '2026-12-24T16:57:00+00:00'
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
        for key in list(self.publisher):
            with self.subTest(advisory=key):
                original = deepcopy(self.publisher[key])
                self.publisher[key]['new_scope'] = 'expanded'
                with self.assertRaises(ValueError):
                    self.check()
                del self.publisher[key]
                with self.assertRaises(ValueError):
                    self.check()
                self.publisher[key] = original

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


class QurlApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.runtime = {'qurl': {'html_functions': [], 'openpgp_functions': [], 'function_count': 2000}}
        self.advisories = {key: {'id': key, 'aliases': [value]} for key, value in QURL_ADVISORIES.items()}
        findings = [{'VulnerabilityID': value, 'Severity': 'HIGH', 'PkgName': 'reviewed-fixture'}
                    for value in QURL_ADVISORIES.values()]
        self.policy = {'advisories': {key: fingerprint(value) for key, value in self.advisories.items()},
                       'findings': {v['VulnerabilityID']: finding_fingerprint(v) for v in findings}}
        targets = ['usr/local/bin/qurl', 'app/third_party_licenses/qurl-4.2.0-linux-amd64.spdx.json',
                   'app/third_party_licenses/qurl-4.2.0-linux-arm64.spdx.json']
        self.report = {'Results': [{'Type': 'gobinary', 'Target': target,
                                   'Vulnerabilities': deepcopy(findings)} for target in targets]}

    def check(self):
        return verify_qurl(self.report, self.runtime, self.policy, self.advisories)

    def test_only_exact_reviewed_target_findings_are_assessed(self):
        self.report['Results'].append({'Type': 'gobinary', 'Target': 'new-binary',
                                      'Vulnerabilities': deepcopy(self.report['Results'][0]['Vulnerabilities'])})
        result = self.check()
        self.assertEqual(len(result['finding_targets']), 9)
        self.assertNotIn('new-binary', {row[0] for row in result['finding_targets']})

    def test_changed_linkage_or_incomplete_function_table_fails(self):
        for field, value in [('html_functions', ['golang.org/x/net/html.Render']),
                             ('openpgp_functions', ['golang.org/x/crypto/openpgp.ReadMessage']),
                             ('function_count', 2)]:
            with self.subTest(field=field):
                original = self.runtime['qurl'][field]
                self.runtime['qurl'][field] = value
                with self.assertRaises(ValueError):
                    self.check()
                self.runtime['qurl'][field] = original

    def test_changed_official_scope_fails_even_when_scanner_is_unchanged(self):
        self.advisories['GO-2026-6860']['new_scope'] = 'expanded'
        with self.assertRaises(ValueError):
            self.check()

    def test_missing_duplicate_and_changed_findings_fail(self):
        original = deepcopy(self.report)
        for operation in ('missing', 'duplicate', 'changed', 'changed_duplicate'):
            with self.subTest(operation=operation):
                self.report = deepcopy(original)
                findings = self.report['Results'][0]['Vulnerabilities']
                if operation == 'missing':
                    findings.pop()
                elif operation == 'duplicate':
                    findings.append(deepcopy(findings[0]))
                elif operation == 'changed':
                    findings[0]['Severity'] = 'CRITICAL'
                else:
                    findings.append({**findings[0], 'Severity': 'CRITICAL'})
                with self.assertRaises(ValueError):
                    self.check()


if __name__ == '__main__':
    unittest.main()
