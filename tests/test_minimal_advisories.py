"""A candidate cannot pass by dropping inventory, advisory pages or scan targets."""

from copy import deepcopy
import unittest
from unittest.mock import patch

from security.minimal_advisories import fetch, inventory_matches, query_package


class MinimalAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {'architecture': 'amd64', 'packages': [
            {'name': 'python-3.15', 'version': '3.15.2-r0', 'arch': 'x86_64', 'source': 'python-3.15'}]}
        self.report = {'Results': [
            {'Class': 'os-pkgs', 'Type': 'wolfi', 'Packages': [
                {'Name': 'python-3.15', 'Version': '3.15.2-r0'}]},
            {'Type': 'gobinary', 'Target': 'usr/local/bin/qurl'},
            {'Type': 'gobinary', 'Target': 'usr/local/bin/access-pages-guest-endpoint'},
            {'Type': 'python-pkg', 'Packages': [{'Name': 'tzdata', 'Version': '2026.6'}]},
        ]}

    def test_exact_inventory_and_binary_targets_match(self):
        inventory_matches(self.report, self.inventory, 'amd64')

    def test_missing_package_or_wrong_version_is_not_a_clean_scan(self):
        for packages in ([], [{'Name': 'python-3.15', 'Version': '3.15.3-r0'}]):
            report = deepcopy(self.report)
            report['Results'][0]['Packages'] = packages
            with self.assertRaises(ValueError):
                inventory_matches(report, self.inventory, 'amd64')

    def test_wrong_runtime_or_package_architecture_fails(self):
        with self.assertRaises(ValueError):
            inventory_matches(self.report, self.inventory, 'arm64')
        self.inventory['packages'][0]['arch'] = 'aarch64'
        with self.assertRaises(ValueError):
            inventory_matches(self.report, self.inventory, 'amd64')

    def test_missing_binary_or_timezone_scan_fails(self):
        for index in (1, 2, 3):
            report = deepcopy(self.report)
            del report['Results'][index]
            with self.assertRaises(ValueError):
                inventory_matches(report, self.inventory, 'amd64')

    def test_all_advisory_pages_are_retained(self):
        with patch('security.minimal_advisories.fetch', side_effect=[
            {'vulns': [{'id': 'CGA-first'}], 'next_page_token': 'second'},
            {'vulns': [{'id': 'CGA-second'}]},
        ]) as mocked:
            result = query_package(('Chainguard', 'python-3.15', '3.15.2-r0'))
        self.assertEqual({v['id'] for v in result['advisories']}, {'CGA-first', 'CGA-second'})
        self.assertEqual(len(result['responses']), 2)
        self.assertEqual(mocked.call_args.args[1]['page_token'], 'second')

    def test_repeated_page_token_cannot_truncate_results(self):
        with patch('security.minimal_advisories.fetch', return_value={'next_page_token': 'loop'}):
            with self.assertRaises(ValueError):
                query_package(('Chainguard', 'python-3.15', '3.15.2-r0'))

    def test_feed_failure_propagates(self):
        with patch('security.minimal_advisories.fetch', side_effect=TimeoutError('unavailable')):
            with self.assertRaises(TimeoutError):
                query_package(('Chainguard', 'python-3.15', '3.15.2-r0'))

    def test_malformed_feed_cannot_pass_as_empty(self):
        for response in ([], {'error': 'unavailable'}, {'vulns': None}, {'vulns': [{}]}):
            with self.subTest(response=response), patch('security.minimal_advisories.fetch', return_value=response):
                with self.assertRaises(ValueError):
                    query_package(('Chainguard', 'python-3.15', '3.15.2-r0'))

    def test_unrecognized_or_insecure_advisory_source_is_rejected(self):
        for url in ('file:///etc/passwd', 'http://api.osv.dev/v1/query', 'https://example.com/data'):
            with self.assertRaises(ValueError):
                fetch(url)


if __name__ == '__main__':
    unittest.main()
