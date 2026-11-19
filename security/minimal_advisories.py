"""Collect candidate evidence and block promotion on unresolved advisory evidence.

This candidate-only gate has no waiver mechanism. It supplements, and does not
replace, the production vulnerability baseline. OSV provides version matching;
the original publisher record is retained for every Chainguard result. Explicit
watch records prevent the known Python/OpenSSL feed omissions becoming a zero.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404 - fixed Docker operations with argument lists.
import tempfile
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

try:
    from .image_evidence import bind_report, fingerprint, inspect_archive
    from .backport_evidence import verify as verify_backports
except ImportError:
    from image_evidence import bind_report, fingerprint, inspect_archive
    from backport_evidence import verify as verify_backports

ROOT = Path(__file__).resolve().parents[1]
BASE = 'https://advisories.cgr.dev/chainguard/v3/osv/'


def fetch(url, payload=None):
    if urlparse(url).scheme != 'https' or urlparse(url).hostname not in (
        'api.osv.dev', 'advisories.cgr.dev',
    ):
        raise ValueError('Unrecognized advisory source')
    request = Request(url, data=None if payload is None else json.dumps(payload).encode(),
                      headers={'Content-Type': 'application/json', 'User-Agent': 'AccessPages-review'})
    with urlopen(request, timeout=45) as response:  # nosec B310 - HTTPS publisher allowlist above.
        return json.load(response)


def query_package(package):
    responses, vulnerabilities, token, seen = [], {}, None, set()
    while True:
        request = {'package': {'ecosystem': package[0], 'name': package[1]}, 'version': package[2]}
        if token:
            request['page_token'] = token
        response = fetch('https://api.osv.dev/v1/query', request)
        if not isinstance(response, dict) or set(response) - {'vulns', 'next_page_token'}:
            raise ValueError('Malformed OSV response')
        responses.append(response)
        records = response.get('vulns', [])
        if not isinstance(records, list):
            raise ValueError('Malformed OSV vulnerability list')
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get('id'), str):
                raise ValueError('Missing advisory identity')
            vulnerabilities[record['id']] = record
        token = response.get('next_page_token')
        if not token:
            return {'query': request, 'responses': responses, 'advisories': list(vulnerabilities.values())}
        if not isinstance(token, str) or token in seen:
            raise ValueError('Invalid/repeated OSV pagination token')
        seen.add(token)


def inventory_matches(report, inventory, architecture):
    expected_arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}[architecture]
    if inventory['architecture'] != architecture:
        raise ValueError('Native runtime architecture mismatch')
    os_results = [r for r in report['Results'] if r.get('Class') == 'os-pkgs']
    if len(os_results) != 1 or os_results[0]['Type'] != 'wolfi':
        raise ValueError('Missing or unexpected Wolfi inventory')
    scanned = {(p['Name'], p['Version']) for p in os_results[0]['Packages']}
    actual = {(p['name'], p['version']) for p in inventory['packages']}
    if not actual or len(actual) != len(inventory['packages']) or scanned != actual:
        raise ValueError('Scanner and actual installed package inventory differ')
    if any(p['arch'] not in (expected_arch, 'noarch') for p in inventory['packages']):
        raise ValueError('Installed package architecture mismatch')
    targets = {r['Target'].lstrip('/') for r in report['Results'] if r.get('Type') == 'gobinary'}
    if not {'usr/local/bin/qurl', 'usr/local/bin/access-pages-guest-endpoint'} <= targets:
        raise ValueError('Missing shipped Go binary scan')
    if not any(p['Name'] == 'tzdata' and p['Version'] == '2026.6'
               for r in report['Results'] for p in r.get('Packages', [])):
        raise ValueError('Timezone wheel missing from scanner inventory')


def collect(image, report_path, architecture, output, runtime_evidence):
    output.mkdir(parents=True, exist_ok=False)
    report = json.loads(report_path.read_text())
    (output / 'trivy.json').write_bytes(report_path.read_bytes())
    docker = shutil.which('docker')
    if not docker:
        raise ValueError('Docker CLI required')
    info = json.loads(subprocess.check_output([docker, 'image', 'inspect', image]))[0]  # nosec B603
    image_id = info['Id']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('Immutable image identity missing')
    with tempfile.TemporaryDirectory(prefix='minimal-evidence-') as directory:
        archive = Path(directory) / 'image.tar'
        subprocess.run([docker, 'image', 'save', '-o', str(archive), image_id], check=True)  # nosec B603
        identity = inspect_archive(archive, architecture, require_attestations=True)
    if image_id not in (identity['index_digest'], identity['config_digest']):
        raise ValueError('Image identity changed')
    bind_report(identity, report)
    probe = ROOT / 'packaging/minimal/inventory.py'
    inventory = json.loads(subprocess.check_output([  # nosec B603 - immutable image, offline read-only probe.
        docker, 'run', '--rm', '--pull=never', '--network', 'none', '--read-only',
        '--platform', 'linux/' + architecture, '--entrypoint', 'python',
        '--volume', f'{probe}:/run/access-pages-inventory.py:ro', image_id, '/run/access-pages-inventory.py',
    ]))
    inventory_matches(report, inventory, architecture)
    evidence = {'image_id': image_id, 'identity': identity, 'inventory': inventory,
                'trivy_sha256': fingerprint(report), 'size_bytes': info['Size'],
                'collected_at': datetime.now(timezone.utc).isoformat(), 'complete': False}
    (output / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True))
    queries = {('PyPI', 'tzdata', '2026.6')}
    for package in inventory['packages']:
        queries.add(('Chainguard', package['name'], package['version']))
        queries.add(('Chainguard', package['source'], package['version']))
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(query_package, sorted(queries)))
    (output / 'osv-queries.json').write_text(json.dumps(results, indent=2, sort_keys=True))
    apkarch = {'amd64': 'x86_64', 'arm64': 'aarch64'}[architecture]
    records = {}
    for result in results:
        for record in result['advisories']:
            if not record.get('affected'):
                raise ValueError('Advisory has no affected-package evidence')
            for affected in record['affected']:
                package = affected['package']
                arches = parse_qs(urlparse(package.get('purl', '')).query).get('arch', [])
                if package['name'] == result['query']['package']['name'] and (
                    not arches or apkarch in arches or 'noarch' in arches
                ):
                    records[record['id']] = record

    watch = json.loads((ROOT / 'packaging/minimal/advisory-watch.json').read_text())
    ids = set(records) | set(watch[architecture])
    publisher = {}
    for advisory_id in sorted(ids):
        if advisory_id.startswith('CGA-'):
            if not re.fullmatch(r'CGA-[a-z0-9-]+', advisory_id):
                raise ValueError('Malformed Chainguard advisory ID')
            data = fetch(BASE + advisory_id + '.json')
            if data.get('id') != advisory_id or not data.get('affected'):
                raise ValueError('Missing publisher advisory detail')
            publisher[advisory_id] = data
    (output / 'publisher-advisories.json').write_text(json.dumps(publisher, indent=2, sort_keys=True))
    # Never silently accept a watch record disappearing from the matching feed.
    # A new fix or applicability decision needs a review of the watch list too.
    missing_watch = sorted(set(watch[architecture]) - set(records))
    trivy_high = [v for result in report['Results'] for v in result.get('Vulnerabilities', [])
                  if v['Severity'] in ('HIGH', 'CRITICAL')]
    backports = verify_backports(inventory, image_id, architecture, runtime_evidence, publisher)
    for filename in ('evidence.json', 'observations.json'):
        (output / ('runtime-' + filename)).write_bytes((runtime_evidence / filename).read_bytes())
    unresolved = sorted(set(records) - set(backports['advisory_ids']))
    evidence.update({'verified_backports': backports, 'unresolved_vendor_advisory_ids': unresolved})
    evidence.update({'complete': True, 'query_count': len(queries),
                     'vendor_advisory_ids': sorted(records), 'watch_missing_from_osv': missing_watch,
                     'trivy_high_critical_records': len(trivy_high),
                     'promotion_allowed': not (unresolved or missing_watch or trivy_high)})
    evidence['inputs_sha256'] = {p.name: sha256(p.read_bytes()).hexdigest()
                                for p in output.iterdir() if p.name != 'evidence.json'}
    (output / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True))
    print(json.dumps({key: evidence[key] for key in ('image_id', 'size_bytes', 'query_count',
                     'vendor_advisory_ids', 'unresolved_vendor_advisory_ids', 'verified_backports',
                     'watch_missing_from_osv', 'promotion_allowed')}, indent=2))
    return 0 if evidence['promotion_allowed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('report', type=Path)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runtime-evidence', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(collect(args.image, args.report, args.architecture, args.output, args.runtime_evidence))
