#!/usr/bin/env bash
# Run pinned upstream compatibility/regression suites against installed modules.
set -euo pipefail
image=${1:?image required}
architecture=${2:?architecture required}
output=${3:?evidence directory required}
case "$architecture" in amd64|arm64) ;; *) exit 1 ;; esac
mkdir "$output"
workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT
commit=5b9e3d044764cf59329fb8147177f54a88d1fb49
imap_commit=0df6664a83efea6e4a15c1f12def43ccf11fd45a
archive_sha=dfca5a2de0f4bc61eb6e506c43a201199627532e215ba7fd84e8a6d3d22c9950
imap_sha=424a1554cdf016cb36e040c896d0e1d6b952b85598256f6a40d2f5423017dd98
curl --fail --location --proto '=https' --tlsv1.2 --max-time 90 \
  "https://codeload.github.com/python/cpython/tar.gz/$commit" -o "$workspace/source.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 90 \
  "https://raw.githubusercontent.com/python/cpython/$imap_commit/Lib/test/test_imaplib.py" -o "$workspace/test_imaplib.py"
printf '%s  %s\n' "$archive_sha" "$workspace/source.tar.gz" "$imap_sha" "$workspace/test_imaplib.py" | sha256sum -c -
python3 - "$workspace" "$commit" <<'PY'
from pathlib import Path
import sys
import tarfile
root = Path(sys.argv[1])
source = root / 'source'
source.mkdir(mode=0o755)
prefix = 'cpython-' + sys.argv[2] + '/Lib/test/'
with tarfile.open(root / 'source.tar.gz') as archive:
    members = [member for member in archive.getmembers() if member.name.startswith(prefix)]
    if not members:
        raise ValueError('Missing upstream test package')
    archive.extractall(source, members=members, filter='data')
(source / prefix / 'test_imaplib.py').write_bytes((root / 'test_imaplib.py').read_bytes())
PY
identity=$(docker image inspect --format '{{.Id}}' "$image")
test "$(docker image inspect --format '{{.Architecture}}' "$image")" = "$architecture"
status=0
# Only Lib/test is mounted. All application/library imports use the image's
# installed runtime, including our exact backports, not the downloaded source.
timeout 300s docker run --rm --pull=never --platform "linux/$architecture" \
  --network none --read-only --user 2103:2103 --cap-drop=ALL \
  --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --env PYTHONDONTWRITEBYTECODE=1 --env PYTHONPATH=/upstream --workdir /tmp \
  --entrypoint python --volume "$workspace/source/cpython-$commit/Lib:/upstream:ro" \
  "$identity" -m unittest test.test_httplib test.test_imaplib -v > "$output/tests.log" 2>&1 || status=$?
python3 - "$output" "$identity" "$architecture" "$status" "$archive_sha" "$imap_sha" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
output, identity, architecture, status, archive_sha, imap_sha = sys.argv[1:]
root = Path(output)
evidence = {'image_id': identity, 'architecture': architecture, 'exit_code': int(status),
            'passed': status == '0', 'archive_sha256': archive_sha, 'imap_test_sha256': imap_sha,
            'log_sha256': hashlib.sha256((root / 'tests.log').read_bytes()).hexdigest()}
(root / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
print(json.dumps(evidence, indent=2, sort_keys=True))
PY
tail -6 "$output/tests.log"
exit "$status"
