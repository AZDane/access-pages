"""Verify bounded candidate applicability reviews without filtering raw findings.

The owner adopts these proposed assessments through the protected PR workflow.
This is not a claim that the installed libraries are patched.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

try:
    from .collect_applicability import validate_runtime
except ImportError:
    from collect_applicability import validate_runtime

ROOT = Path(__file__).resolve().parents[1]
REVIEWED_CVES = {
    'CVE-2026-100290', 'CVE-2026-115819',
    'CVE-2026-107496', 'CVE-2026-115791', 'CVE-2026-119586',
    'CVE-2026-124249', 'CVE-2026-124317', 'CVE-2026-128241',
    'CVE-2026-16052', 'CVE-2026-19552', 'CVE-2026-88822',
    'CVE-2026-88823', 'CVE-2026-95691', 'CVE-2026-95692',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(data):
    return digest(json.dumps(data, sort_keys=True, separators=(',', ':')).encode())


def verify_glibc_consumers(native):
    # The source review also follows internal rpmatch/legacy regexp callers.
    # The complete native inventory is separately pinned, including providers.
    regex = re.compile(r'(regcomp|regexec|re_compile|re_search|re_match|re_comp|re_exec)')
    for entry in native:
        if any('wscanf' in symbol for symbol in entry['undefined']):
            raise ValueError('Wide scanf consumer requires reassessment')
        for symbol in entry['undefined']:
            if regex.search(symbol) or symbol in {'rpmatch', 'step', 'advance'}:
                if (entry['path'] not in {'/usr/lib/libform.so.6.6', '/usr/lib/libformw.so.6.6'}
                        or symbol not in {'regcomp', 'regexec'}):
                    raise ValueError('glibc regex consumer requires reassessment')
        if any('libform' in library for library in entry['needed']):
            raise ValueError('Loaded form library requires reassessment')


def verify(image_id, architecture, directory, publisher, *, now=None, root=ROOT):
    now = now or datetime.now(timezone.utc)
    raw_policy = (root / 'packaging/minimal/applicability.json').read_bytes()
    policy = json.loads(raw_policy)
    reviewed = datetime.fromisoformat(policy['reviewed_at'])
    expires = datetime.fromisoformat(policy['review_before'])
    if (policy['schema'] != 1 or not policy['owner']
            or reviewed.utcoffset() != timedelta(0) or expires.utcoffset() != timedelta(0)
            or not reviewed <= now < expires or expires - reviewed > timedelta(days=7)
            or set(policy['architectures']) != {'amd64', 'arm64'}):
        raise ValueError('Invalid, future or expired applicability review')
    decisions = policy['decisions']
    if set(decisions) != REVIEWED_CVES or any(
            row['disposition'] not in {'component_absent', 'unreachable'} or not row['reason']
            for row in decisions.values()):
        raise ValueError('Unreviewed applicability decision set')
    for name, expected in policy['controls_sha256'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts or digest((root / path).read_bytes()) != expected:
            raise ValueError('Applicability control/source review changed')
    required = {'Dockerfile.ha-minimal', '.dockerignore', 'packaging/minimal/prepare.py',
                'packaging/minimal/apparmor.txt', 'security/runtime_backports.py',
                'packaging/minimal/patches/manifest.json',
                'security/minimal-applicability-review.txt'}
    if not required <= set(policy['controls_sha256']):
        raise ValueError('Missing applicability controls')
    observed = json.loads((directory / 'evidence.json').read_text())
    observed_at = datetime.fromisoformat(observed['collected_at'])
    if (observed['schema'] != 1 or observed['complete'] is not True
            or observed['image_id'] != image_id or observed['architecture'] != architecture
            or observed['decision'] != 'observation_only'
            or observed_at.tzinfo is None or not now - timedelta(hours=24) <= observed_at <= now):
        raise ValueError('Missing fresh applicability evidence for this exact image')
    expected = policy['architectures'][architecture]
    if set(observed['inputs_sha256']) != {'runtime.json', 'native.json'}:
        raise ValueError('Incomplete applicability inputs')
    for name in ('runtime.json', 'native.json'):
        actual = digest((directory / name).read_bytes())
        if actual != observed['inputs_sha256'][name] or actual != expected['inputs_sha256'][name]:
            raise ValueError('Reviewed runtime, native binaries or application changed')
    validate_runtime(json.loads((directory / 'runtime.json').read_text()), architecture)
    verify_glibc_consumers(json.loads((directory / 'native.json').read_text()))
    collectors = {'collect_applicability.py', 'runtime_applicability.py', 'verify_unreachable.py'}
    if set(observed['collector_sha256']) != collectors:
        raise ValueError('Incomplete collector provenance')
    for name in collectors:
        actual = digest((root / 'security' / name).read_bytes())
        if actual != observed['collector_sha256'][name] or actual != expected['collector_sha256'][name]:
            raise ValueError('Applicability collector changed')
    covered, cves = [], set()
    for advisory_id, reviewed_advisory in expected['advisories'].items():
        record = publisher.get(advisory_id)
        if record is None or fingerprint(record) != reviewed_advisory['sha256']:
            raise ValueError('Publisher advisory changed or disappeared; reassess')
        cve = reviewed_advisory['cve']
        upstream_cves = {value for value in record.get('upstream', []) if value.startswith('CVE-')}
        if record['id'] != advisory_id or upstream_cves != {cve} or cve not in REVIEWED_CVES:
            raise ValueError('Applicability advisory scope mismatch')
        covered.append(advisory_id)
        cves.add(cve)
    if cves != REVIEWED_CVES:
        raise ValueError('Incomplete reviewed advisory set')
    return {'advisory_ids': sorted(covered), 'cves': sorted(cves), 'decisions': decisions,
            'policy_sha256': digest(raw_policy), 'review_before': policy['review_before'],
            'evidence_sha256': digest((directory / 'evidence.json').read_bytes())}
