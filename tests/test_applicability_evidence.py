"""Regression coverage for native/source evidence completeness and attribution."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from security.collect_applicability import native_symbols, validate_runtime
from security.runtime_applicability import source_evidence


class ApplicabilityEvidenceTests(unittest.TestCase):
    def test_native_imports_are_not_confused_with_defined_exports(self):
        symbols = """Symbol table '.dynsym' contains 4 entries:
  1: 0000000000000000 0 FUNC GLOBAL DEFAULT UND regcomp@GLIBC_2.2.5 (2)
  2: 0000000000000010 5 FUNC GLOBAL DEFAULT 12 CMS_encrypt
  3: 0000000000000000 0 FUNC GLOBAL DEFAULT UND dlopen@GLIBC_2.34 (3)
"""
        dynamic = ' 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]\n'
        self.assertEqual(native_symbols(symbols, dynamic),
                         {'undefined': ['dlopen', 'regcomp'], 'needed': ['libc.so.6']})

    def test_static_binary_is_explicit_and_malformed_tool_output_fails(self):
        self.assertEqual(native_symbols('There are no dynamic symbols in this file.',
                                        'There is no dynamic section in this file.'),
                         {'undefined': [], 'needed': []})
        with self.assertRaises(ValueError):
            native_symbols('readelf failed', '')
        with self.assertRaises(ValueError):
            native_symbols('', '')
        self.assertEqual(native_symbols('', '', 'ELF Header:\nSection Headers:\n [1] .text PROGBITS'),
                         {'undefined': [], 'needed': []})
        with self.assertRaises(ValueError):
            native_symbols('', '', 'ELF Header:\nSection Headers:\n [1] .dynsym DYNSYM')

    def test_source_records_aliases_calls_and_bytes_for_manual_review(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app.py'
            path.write_text('from http.cookiejar import CookieJar as C\nx = C()\n')
            original = source_evidence([path])
            self.assertIn('http.cookiejar.CookieJar', original['imports'][str(path)])
            self.assertEqual(original['calls'][str(path)], ['C'])
            path.write_text('from http.cookiejar import CookieJar as C\nx = C() # changed\n')
            self.assertNotEqual(original['files'], source_evidence([path])['files'])

    def test_missing_source_cannot_be_evidence_of_absence(self):
        with self.assertRaises(ValueError):
            source_evidence([])

    def test_wrong_architecture_and_incomplete_observations_fail(self):
        original = {'schema': 1, 'architecture': 'amd64',
                    'application': {'files': {'/app/a.py': 'a' * 64}},
                    'qurl': {'sha256': 'b' * 64, 'function_count': 2000},
                    'commands': dict.fromkeys(('sqlite3', 'xmlwf', 'sh', 'bash', 'openssl')),
                    'library_and_config_sha256': {'ssl.py': 'c' * 64},
                    'python_tls': {'default_ciphers': ['TLS_AES_256_GCM_SHA384']}}
        validate_runtime(original, 'amd64')
        with self.assertRaises(ValueError):
            validate_runtime(original, 'arm64')
        for section, key, value in (
            ('application', 'files', {}), ('qurl', 'function_count', 10),
            ('qurl', 'sha256', 'not-a-hash'), ('python_tls', 'default_ciphers', []),
        ):
            data = deepcopy(original)
            data[section][key] = value
            with self.assertRaises(ValueError):
                validate_runtime(data, 'amd64')
        data = deepcopy(original)
        del data['commands']['sqlite3']
        with self.assertRaises(ValueError):
            validate_runtime(data, 'amd64')


if __name__ == '__main__':
    unittest.main()
