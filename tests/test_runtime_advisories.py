"""Runtime evidence cannot become a pass by omission, coercion or feed silence."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from security.check_runtime_advisories import EXPECTED, check, validate


class RuntimeAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.observation = {
            'schema': 1, 'python': 'test runtime', 'machine': 'x86_64',
            'library_sha256': {'http.client': 'a' * 64, 'imaplib': 'b' * 64},
            'checks': dict.fromkeys(EXPECTED, True),
        }

    def test_complete_fixed_runtime_passes_on_each_architecture(self):
        self.assertEqual(validate(self.observation, 'amd64'), [])
        self.observation['machine'] = 'aarch64'
        self.assertEqual(validate(self.observation, 'arm64'), [])

    def test_every_regression_and_control_is_blocking(self):
        for name in EXPECTED:
            with self.subTest(name=name):
                observation = deepcopy(self.observation)
                observation['checks'][name] = False
                self.assertEqual(validate(observation, 'amd64'), [name])

    def test_missing_check_and_truthy_strings_cannot_pass(self):
        for name in EXPECTED:
            for invalid in ('missing', 'true', 1, None):
                with self.subTest(name=name, invalid=invalid):
                    observation = deepcopy(self.observation)
                    if invalid == 'missing':
                        del observation['checks'][name]
                    else:
                        observation['checks'][name] = invalid
                    with self.assertRaises(ValueError):
                        validate(observation, 'amd64')

    def test_wrong_architecture_unknown_schema_and_missing_hashes_fail(self):
        for key, value in (('machine', 'aarch64'), ('schema', 2),
                           ('library_sha256', {}), ('python', '')):
            with self.subTest(key=key):
                observation = deepcopy(self.observation)
                observation[key] = value
                with self.assertRaises(ValueError):
                    validate(observation, 'amd64')

    def run_gate(self, responses):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence'
            with patch('security.check_runtime_advisories.shutil.which', return_value='/usr/bin/docker'), \
                 patch('security.check_runtime_advisories.subprocess.check_output', side_effect=responses) as run, \
                 patch('builtins.print'):
                status = check('mutable:tag', 'amd64', output)
            return status, json.loads((output / 'evidence.json').read_text()), run.call_args_list

    def test_gate_runs_immutable_image_and_retains_failed_observations(self):
        self.observation['checks']['imap.discards_pre_tls_buffer'] = False
        status, evidence, calls = self.run_gate([
            json.dumps([{'Id': 'sha256:' + 'c' * 64, 'Architecture': 'amd64'}]).encode(),
            json.dumps(self.observation).encode(),
        ])
        self.assertEqual(status, 1)
        self.assertTrue(evidence['complete'])
        self.assertFalse(evidence['promotion_allowed'])
        self.assertIn('observations_sha256', evidence)
        command = calls[1].args[0]
        self.assertIn('sha256:' + 'c' * 64, command)
        self.assertNotIn('mutable:tag', command)
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertIn('--read-only', command)
        self.assertEqual(calls[1].kwargs['timeout'], 60)

    def test_probe_timeout_missing_image_and_malformed_output_fail_closed(self):
        inspected = json.dumps([{'Id': 'sha256:' + 'c' * 64, 'Architecture': 'amd64'}]).encode()
        for responses in ([FileNotFoundError('missing image')],
                          [inspected, subprocess.TimeoutExpired('docker', 60)],
                          [inspected, b'{}'], [inspected, b'[]'], [inspected, b'not json']):
            status, evidence, _ = self.run_gate(responses)
            self.assertEqual(status, 1)
            self.assertFalse(evidence['complete'])
            self.assertFalse(evidence['promotion_allowed'])
            self.assertIn('error', evidence)


if __name__ == '__main__':
    unittest.main()
