"""Fail-closed policy and artifact/publication boundary regressions."""

from copy import deepcopy
from datetime import date
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from security.check_vulnerabilities import check_report, finding_fingerprint
from security.image_evidence import bind_report, fingerprint, inspect_archive
from security.publish_validated import candidates, publish
from security.verify_unreachable import (
    SQL_FILES, go_functions, html_parser_evidence, sqlite_schema_evidence, sqlite_session_evidence,
)


class UnreachablePolicyTests(unittest.TestCase):
    def setUp(self):
        self.baseline = json.loads(Path('security/vulnerability-baseline.json').read_text())
        self.entry = deepcopy(next(e for e in self.baseline['dispositions']
                                  if e['id'] == 'CVE-2026-116587'))
        self.baseline['dispositions'] = [self.entry]
        self.finding = dict(VulnerabilityID=self.entry['id'], PkgName=self.entry['packages'][0]['name'],
                            InstalledVersion='v4.1.4', Severity='HIGH', FixedVersion='4.1.6',
                            Description='RSA JWK parser', Title='CPU exhaustion')
        self.report = {
            'SchemaVersion': 2, 'ArtifactType': 'container_image',
            'Metadata': {'ImageID': 'sha256:' + 'a' * 64,
                         'ImageConfig': {'architecture': 'amd64', 'rootfs': {'diff_ids': []}},
                         'OS': {'Family': 'debian', 'Name': '13.7'}},
            'Results': [{'Class': 'os-pkgs', 'Type': 'debian'},
                        {'Type': 'gobinary', 'Target': 'usr/local/bin/qurl',
                         'Vulnerabilities': [self.finding]},
                        {'Type': 'gobinary', 'Target': 'usr/local/bin/access-pages-guest-endpoint'}],
        }
        self.entry['findings'] = {'usr/local/bin/qurl': finding_fingerprint(self.finding)}
        self.entry['properties'] = {'jose_functions': fingerprint(['init'])}
        self.evidence = {
            'image_id': self.report['Metadata']['ImageID'], 'report_sha256': fingerprint(self.report),
            'identity': {'architecture': 'amd64', 'config': deepcopy(self.report['Metadata']['ImageConfig']),
                         'index_digest': 'sha256:' + 'a' * 64, 'manifest_digest': 'sha256:' + 'b' * 64,
                         'config_digest': 'sha256:' + 'c' * 64},
            'probe': {'architecture': 'amd64', 'files': self.baseline['unreachable_files'],
                      'qurl_sha256': self.entry['artifacts']['amd64'], 'jose_functions': ['init']},
        }
        self.today = date(2026, 11, 3)

    def check(self, **kwargs):
        return check_report(self.report, self.baseline, kwargs.pop('architecture', 'amd64'),
                            today=kwargs.pop('today', self.today), evidence=self.evidence, **kwargs)

    def test_exact_reviewed_unreachable_finding_remains_in_report(self):
        before = deepcopy(self.report)
        approved = []
        errors, counts = self.check(approved=approved)
        self.assertEqual(errors, [])
        self.assertEqual(counts['HIGH'], 1)
        self.assertEqual(len(approved), 1)
        self.assertEqual(self.report, before)

    def test_both_architectures_require_their_own_binary(self):
        self.report['Metadata']['ImageConfig']['architecture'] = 'arm64'
        self.evidence['report_sha256'] = fingerprint(self.report)
        self.assertTrue(self.check(architecture='arm64')[0])
        self.evidence['probe'].update(architecture='arm64', qurl_sha256=self.entry['artifacts']['arm64'])
        self.evidence['identity']['architecture'] = 'arm64'
        self.evidence['identity']['config']['architecture'] = 'arm64'
        self.assertFalse(self.check(architecture='arm64')[0])

    def test_expiry_is_exclusive_at_utc_date(self):
        self.assertIn('expired', self.check(today=date(2026, 11, 26))[0][0])

    def test_missing_or_changed_evidence_blocks(self):
        for key, value in [('qurl_sha256', 'f' * 64), ('files', {}),
                           ('jose_functions', ['JSONWebKey.UnmarshalJSON']), ('architecture', 'arm64')]:
            with self.subTest(key=key):
                original = self.evidence['probe'][key]
                self.evidence['probe'][key] = value
                self.assertTrue(self.check()[0])
                self.evidence['probe'][key] = original
        self.evidence = None
        self.assertTrue(self.check()[0])

    def test_mismatched_report_image_or_target_blocks(self):
        for mutate in (
            lambda r: r['Metadata'].update(ImageID='sha256:' + 'b' * 64),
            lambda r: r['Results'][1].update(Target='usr/local/bin/new-qurl'),
        ):
            before = deepcopy(self.report)
            mutate(self.report)
            try:
                self.assertTrue(self.check()[0])
            except ValueError:
                pass  # A required binary target disappeared: invalid scan, also fail-closed.
            self.report = before

    def test_changed_advisory_package_version_or_severity_blocks(self):
        for key, value in [('VulnerabilityID', 'CVE-2099-9999'), ('PkgName', 'other-module'),
                           ('InstalledVersion', 'v4.1.5'), ('Severity', 'CRITICAL'),
                           ('FixedVersion', '4.1.7'), ('Description', 'new attack path'),
                           ('CweIDs', ['CWE-999'])]:
            with self.subTest(key=key):
                original = deepcopy(self.finding)
                self.finding[key] = value
                self.evidence['report_sha256'] = fingerprint(self.report)
                self.assertTrue(self.check()[0])
                self.finding.clear()
                self.finding.update(original)

    def test_unrelated_high_and_critical_still_block(self):
        for severity in ('HIGH', 'CRITICAL'):
            self.report['Results'][0]['Vulnerabilities'] = [dict(
                VulnerabilityID='CVE-2099-9999', PkgName='unreviewed', InstalledVersion='1', Severity=severity,
            )]
            self.evidence['report_sha256'] = fingerprint(self.report)
            errors, counts = self.check()
            self.assertEqual(len(errors), 1)
            self.assertIn('requires a reviewed disposition', errors[0])
            self.assertGreater(counts[severity], 0)

    def test_malformed_incomplete_or_wildcard_records_block(self):
        for field in ('artifacts', 'findings', 'properties', 'invalidated_by', 'justification', 'owner'):
            original = self.entry.pop(field)
            with self.assertRaises((KeyError, ValueError)):
                self.check()
            self.entry[field] = original
        for field, value in [('id', 'CVE-*'), ('review_due', '2027-01-01'),
                             ('artifacts', {'amd64': '*'})]:
            original = self.entry[field]
            self.entry[field] = value
            with self.assertRaises(ValueError):
                self.check()
            self.entry[field] = original


class PackagedEvidenceTests(unittest.TestCase):
    def test_html_parser_or_wrapper_requires_reassessment(self):
        self.assertEqual(html_parser_evidence(['net/http.(*Client).Do']), [])
        for name in ('golang.org/x/net/html.Parse', 'golang.org/x/net/html.(*parser).addText',
                     'type:.eq.golang.org/x/net/html.Node'):
            with self.assertRaisesRegex(ValueError, 'code is linked'):
                html_parser_evidence([name])

    def test_session_binding_or_native_bridge_requires_reassessment(self):
        self.assertEqual(sqlite_session_evidence(Path('.')), [])
        with patch('security.verify_unreachable.sqlite3.Changeset', object(), create=True):
            with self.assertRaisesRegex(ValueError, 'session API'):
                sqlite_session_evidence(Path('.'))
        for source in ('import ctypes', 'from cffi import FFI', 'import apsw'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'new_consumer.py').write_text(source)
                with self.assertRaisesRegex(ValueError, 'bridge'):
                    sqlite_session_evidence(root)

    def test_sql_schema_is_reproducible_and_new_fts_or_dynamic_sql_blocks(self):
        evidence = sqlite_schema_evidence(Path('.'))
        self.assertEqual(evidence['sql_calls'], 147)
        for addition in ("db.execute('CREATE VIRTUAL TABLE f USING fts5(a, detail=none)')",
                         'db.execute(user_input)'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for filename in SQL_FILES:
                    (root / filename).write_bytes(Path(filename).read_bytes())
                with (root / 'activity.py').open('a') as output:
                    output.write('\n' + addition + '\n')
                with self.assertRaises(ValueError):
                    sqlite_schema_evidence(root)

    def test_unrecognizable_binary_never_means_parser_absent(self):
        with self.assertRaises(ValueError):
            go_functions(b'not an ELF function table')


class ArtifactTests(unittest.TestCase):
    def make_archive(self, directory, *, architecture='amd64', attest=True, corrupt=False):
        blobs = {}

        def add(value):
            raw = json.dumps(value, separators=(',', ':')).encode()
            digest = 'sha256:' + sha256(raw).hexdigest()
            blobs['blobs/sha256/' + digest[7:]] = raw
            return {'digest': digest, 'size': len(raw)}

        self.config = {'os': 'linux', 'architecture': architecture, 'rootfs': {'type': 'layers', 'diff_ids': []},
                       'config': {'Labels': {'io.hass.version': '0.1.147', 'org.opencontainers.image.version': '0.1.147'}}}
        config = add(self.config)
        image = add({'config': config, 'layers': []})
        descriptors = [image]
        if attest:
            layers = [add({'predicateType': kind, 'subject': [{'digest': {'sha256': image['digest'][7:]}}]})
                      for kind in ('https://spdx.dev/Document', 'https://slsa.dev/provenance/v0.2')]
            attestation = add({'config': add({}), 'layers': layers})
            attestation['annotations'] = {'vnd.docker.reference.type': 'attestation-manifest',
                                         'vnd.docker.reference.digest': image['digest']}
            descriptors.append(attestation)
        root = add({'manifests': descriptors})
        blobs['index.json'] = json.dumps({'manifests': [root]}).encode()
        if corrupt:
            blobs['blobs/sha256/' + config['digest'][7:]] = b'corrupt'
        path = Path(directory) / 'image.tar'
        with tarfile.open(path, 'w') as archive:
            for name, raw in blobs.items():
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        return path

    def test_digest_chain_preserves_attestations_and_separates_config_from_index(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_archive(directory)
            identity = inspect_archive(path, 'amd64', version='0.1.147', require_attestations=True)
            self.assertNotEqual(identity['index_digest'], identity['config_digest'])
            self.assertEqual(len(identity['attestation_digests']), 1)
            report = {'Metadata': {'ImageID': identity['config_digest'], 'ImageConfig': self.config}}
            bind_report(identity, report)
            report['Metadata']['ImageID'] = 'sha256:' + 'f' * 64
            with self.assertRaises(ValueError):
                bind_report(identity, report)

    def test_wrong_architecture_version_missing_attestations_or_corruption_blocks(self):
        for changes in ({'architecture': 'arm64'}, {'attest': False}, {'corrupt': True}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                path = self.make_archive(directory, **changes)
                with self.assertRaises(ValueError):
                    inspect_archive(path, 'amd64', require_attestations=True)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                inspect_archive(self.make_archive(directory), 'amd64', version='0.1.999')


class PublicationTests(unittest.TestCase):
    def test_arm_failure_prevents_even_amd64_publication(self):
        for failure in ('unreviewed', 'missing_test', 'wrong_test_image', 'changed_scan'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for arch in ('amd64', 'arm64'):
                    config = {'architecture': arch, 'rootfs': {'diff_ids': []},
                              'config': {'Labels': {'io.hass.version': '0.1.147'}}}
                    identity = dict(architecture=arch, config=config, index_digest='sha256:' + 'a' * 64,
                                    manifest_digest='sha256:' + 'b' * 64, config_digest='sha256:' + 'c' * 64,
                                    attestation_digests=['sha256:' + 'd' * 64])
                    report = dict(SchemaVersion=2, ArtifactType='container_image',
                                  Metadata=dict(ImageID=identity['config_digest'], ImageConfig=config,
                                                OS={'Family': 'debian', 'Name': '13.7'}),
                                  Results=[{'Class': 'os-pkgs', 'Type': 'debian'},
                                           {'Type': 'gobinary', 'Target': 'usr/local/bin/qurl'},
                                           {'Type': 'gobinary', 'Target': 'usr/local/bin/access-pages-guest-endpoint'}])
                    if arch == 'arm64' and failure == 'unreviewed':
                        report['Results'][0]['Vulnerabilities'] = [dict(
                            VulnerabilityID='CVE-2099-9999', PkgName='unreviewed', InstalledVersion='1', Severity='CRITICAL')]
                    if arch == 'arm64' and failure == 'changed_scan':
                        report['Metadata']['ImageID'] = 'sha256:' + 'f' * 64
                    (root / f'vulnerability-{arch}.json').write_text(json.dumps(report))
                    (root / f'evidence-{arch}.json').write_text(json.dumps({'identity': identity}))
                    if arch != 'arm64' or failure != 'missing_test':
                        marker = {'index_digest': identity['index_digest']}
                        if arch == 'arm64' and failure == 'wrong_test_image':
                            marker['index_digest'] = 'sha256:' + 'f' * 64
                        (root / f'tested-{arch}.json').write_text(json.dumps(marker))
                with patch('security.publish_validated.run', return_value=json.dumps([{'Id': 'sha256:' + 'a' * 64}])) as command:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        publish(root, '0.1.147', latest=True)
                    self.assertTrue(all(call.args[:3] == ('docker', 'image', 'inspect')
                                        for call in command.call_args_list))

    def test_failed_gate_never_calls_registry_or_signer(self):
        for reason in ('amd64 scan failed', 'arm64 test failed', 'expired disposition', 'identity changed'):
            with self.subTest(reason=reason), patch('security.publish_validated.candidates', side_effect=ValueError(reason)), \
                    patch('security.publish_validated.run') as command:
                with self.assertRaises(ValueError):
                    publish(Path('.'), '0.1.147', latest=True)
                command.assert_not_called()

    def test_missing_report_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory, patch('security.publish_validated.run') as command:
            with self.assertRaises(FileNotFoundError):
                candidates(Path(directory), '0.1.147')
            command.assert_not_called()

    def test_registry_digest_mismatch_prevents_release_index_signing_and_latest(self):
        identity = dict(index_digest='sha256:' + 'a' * 64, manifest_digest='sha256:' + 'b' * 64,
                        attestation_digests=['sha256:' + 'c' * 64])
        with patch('security.publish_validated.candidates', return_value=[('amd64', identity)]), \
                patch('security.publish_validated.run', return_value='{}') as command:
            with self.assertRaisesRegex(ValueError, 'differs from validated'):
                publish(Path('.'), '0.1.147', latest=True)
            commands = [call.args for call in command.call_args_list]
            self.assertFalse(any('create' in args or 'cosign' in args for args in commands))
            self.assertFalse(any(any('latest' in arg for arg in args) for args in commands))
