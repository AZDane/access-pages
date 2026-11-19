"""Recognize exact, tested upstream backports without hiding vendor advisories."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

try:
    from .check_runtime_advisories import validate as validate_runtime
    from .runtime_backports import validate_manifest
except ImportError:
    from check_runtime_advisories import validate as validate_runtime
    from runtime_backports import validate_manifest

ROOT = Path(__file__).resolve().parents[1]
PATCHED_IDS = {
    'amd64': {'CGA-8fcw-58f5-fpfm': 'CVE-2026-103995', 'CGA-m8px-jh69-pj3g': 'CVE-2026-115559'},
    'arm64': {'CGA-2qh6-r99g-mcx2': 'CVE-2026-103995', 'CGA-6xgj-68hx-crr2': 'CVE-2026-115559'},
}


def verify(inventory, image_id, architecture, runtime_directory, publisher, now=None):
    now = now or datetime.now(timezone.utc)
    manifest_bytes = (ROOT / 'packaging/minimal/patches/manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    validate_manifest(manifest, now)
    retained = inventory['runtime_backports']
    if retained['manifest'] != manifest or retained['manifest_sha256'] != hashlib.sha256(manifest_bytes).hexdigest():
        raise ValueError('Installed backports differ from reviewed manifest')
    decision = json.loads((runtime_directory / 'evidence.json').read_text())
    raw = (runtime_directory / 'observations.json').read_bytes()
    observations = json.loads(raw)
    if (decision['image_id'] != image_id or decision['architecture'] != architecture
            or decision['complete'] is not True or decision['promotion_allowed'] is not True
            or decision['failed_checks'] != []):
        raise ValueError('Backports require a passing runtime gate for this exact image')
    observed_at = datetime.fromisoformat(decision['collected_at'])
    if observed_at.tzinfo is None or not now - timedelta(hours=24) <= observed_at <= now:
        raise ValueError('Stale or future runtime backport evidence')
    if decision['observations_sha256'] != hashlib.sha256(raw).hexdigest():
        raise ValueError('Runtime observation hash mismatch')
    probe = ROOT / 'tests/packaged_advisory_observations.py'
    if decision['probe_sha256'] != hashlib.sha256(probe.read_bytes()).hexdigest():
        raise ValueError('Runtime probe changed since validation')
    if validate_runtime(observations, architecture):
        raise ValueError('Runtime backport regression failed')
    modules = {'CVE-2026-103995': 'http.client', 'CVE-2026-115559': 'imaplib'}
    for patch in manifest['patches']:
        patch_file = ROOT / 'packaging/minimal/patches' / patch['patch_file']
        if hashlib.sha256(patch_file.read_bytes()).hexdigest() != patch['patch_sha256']:
            raise ValueError('Upstream patch changed since review')
        if (inventory['files'][patch['installed_path']] != patch['after_sha256'] or
                observations['library_sha256'][modules[patch['cve']]] != patch['after_sha256']):
            raise ValueError('Installed/executed module differs from the exact reviewed backport')
    matches = []
    for advisory_id, cve in PATCHED_IDS[architecture].items():
        if advisory_id not in publisher:
            raise ValueError('Missing original publisher record for backport')
        record = publisher[advisory_id]
        cves = {value for value in record.get('upstream', []) if value.startswith('CVE-')}
        if record['id'] != advisory_id or cves != {cve}:
            raise ValueError('Backported advisory changed scope; reassessment required')
        if any(item['package']['name'] != 'python-3.15' for item in record['affected']):
            raise ValueError('Backported advisory covers an unexpected package')
        matches.append(advisory_id)
    return {'advisory_ids': sorted(matches), 'manifest_sha256': retained['manifest_sha256'],
            'runtime_observations_sha256': decision['observations_sha256'],
            'review_before': manifest['review_before']}
