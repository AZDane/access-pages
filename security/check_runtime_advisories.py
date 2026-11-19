"""Fail closed on known Python defects, independently of vulnerability scanners.

Runs the repository probe inside the actual immutable image without networking.
No baseline exemptions apply. Complete evidence survives detected defects; failed
execution, architecture mismatches and malformed/missing checks also block CI.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
# Fixed Docker argument lists, never a shell.
import subprocess  # nosec B404

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'http.valid_chunk_extension', 'http.valid_content_length',
    'http.valid_content_length_whitespace', 'imap.valid_post_tls_read',
    'imap.discards_pre_tls_buffer',
    *('http.reject_chunk.' + v for v in ('+1', '-1', '0x1', '1_0', ' 1')),
    *('http.ignore_length.' + v for v in ('+5', '-5', '5_0', '5 0', '\xb2')),
}
ADVISORIES = {
    'http': 'CVE-2026-103995',
    'imap': 'CVE-2026-115559',
}


def validate(observation, architecture):
    if not isinstance(observation, dict) or type(observation.get('schema')) is not int or observation['schema'] != 1:
        raise ValueError('Unknown runtime evidence schema')
    if observation.get('machine') != {'amd64': 'x86_64', 'arm64': 'aarch64'}[architecture]:
        raise ValueError('Runtime architecture mismatch')
    if not isinstance(observation.get('python'), str) or not observation['python']:
        raise ValueError('Missing Python runtime identity')
    hashes = observation.get('library_sha256', {})
    if not isinstance(hashes, dict) or set(hashes) != {'http.client', 'imaplib'} or any(
        not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
        for value in hashes.values()
    ):
        raise ValueError('Missing installed-library hashes')
    checks = observation.get('checks', {})
    if not isinstance(checks, dict) or set(checks) != EXPECTED or any(type(value) is not bool for value in checks.values()):
        raise ValueError('Missing, unknown or non-boolean runtime checks')
    return sorted(name for name, passed in checks.items() if not passed)


def check(image, architecture, output):
    output.mkdir(parents=True, exist_ok=False)
    probe = ROOT / 'tests/packaged_advisory_observations.py'
    evidence = {
        'schema': 1, 'architecture': architecture, 'complete': False,
        'promotion_allowed': False, 'advisories': ADVISORIES,
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'probe_sha256': hashlib.sha256(probe.read_bytes()).hexdigest(),
    }
    try:
        docker = shutil.which('docker')
        if not docker:
            raise ValueError('Docker CLI required')
        info = json.loads(subprocess.check_output(  # nosec B603
            [docker, 'image', 'inspect', image], timeout=30))[0]
        image_id = info['Id']
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
            raise ValueError('Missing immutable image identity')
        if info['Architecture'] != architecture:
            raise ValueError('Image architecture mismatch')
        evidence['image_id'] = image_id
        raw = subprocess.check_output([  # nosec B603
            docker, 'run', '--rm', '--pull=never', '--network', 'none', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--user', '2103:2103',
            '--platform', 'linux/' + architecture, '--entrypoint', 'python',
            '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--volume', f'{probe}:/run/runtime-advisory-probe.py:ro',
            image_id, '/run/runtime-advisory-probe.py',
        ], timeout=60)
        (output / 'observations.json').write_bytes(raw)
        evidence['observations_sha256'] = hashlib.sha256(raw).hexdigest()
        failures = validate(json.loads(raw), architecture)
        evidence.update(complete=True, failed_checks=failures, promotion_allowed=not failures)
    except (ValueError, KeyError, IndexError, TypeError, OSError, subprocess.SubprocessError) as exc:
        evidence['error'] = str(exc)
    (output / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence['promotion_allowed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(check(args.image, args.architecture, args.output))
