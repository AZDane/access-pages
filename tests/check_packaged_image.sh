#!/usr/bin/env bash
# The same packaged checks run in native CI and on retained release images.
set -euo pipefail
image=${1:?image required}
architecture=${2:?architecture required}
case "$architecture" in amd64|arm64) ;; *) exit 1 ;; esac
variant=${3:-production}
case "$variant" in
  production) runtime_probe=packaged_minimal_runtime_probe; profile_file=homeassistant-app/apparmor.txt; profile_name=access_pages ;;
  minimal) runtime_probe=packaged_minimal_runtime_probe; profile_file=packaging/minimal/apparmor.txt; profile_name=access_pages_minimal ;;
  *) echo "Unknown runtime variant" >&2; exit 1 ;;
esac
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
python3 tests/packaged_tls_probe.py --generate-fixture "$fixture"
for probe in "$runtime_probe" packaged_security_probe packaged_app_probe packaged_tls_probe packaged_startup_probe packaged_permission_probe packaged_schedule_probe; do
  docker run --rm --pull=never --platform "linux/$architecture" --network none \
    --user root --entrypoint python --add-host supervisor:127.0.0.1 \
    --volume "$PWD/tests/fixtures/packaged-app-options.json:/data/options.json:ro" \
    --volume "$fixture:/tmp/tls:ro" --volume "$PWD/tests/$probe.py:/tmp/probe.py:ro" \
    "$image" /tmp/probe.py
done
docker run --rm --pull=never --platform "linux/$architecture" --network none \
  --user 2103:2103 --entrypoint python \
  --volume "$PWD/tests/packaged_qurl_probe.py:/tmp/probe.py:ro" "$image" /tmp/probe.py
if [[ "$architecture" == amd64 ]]; then
  docker run --rm --pull=never --network none --user 1000:1000 --entrypoint python \
    --volume "$PWD:/src:ro" --workdir /src --env PYTHONPATH=/src \
    "$image" -m unittest discover -s tests -v
fi
# ARM64's native UID/socket/runtime checks above complement this Linux policy test.
if [[ "$architecture" == amd64 ]]; then
(
case "$(docker info --format '{{json .SecurityOptions}}')" in
  *name=apparmor*) ;;
  *) echo "Required AppArmor enforcement unavailable on this runner" >&2; exit 1 ;;
esac
denied_mounts=()
if [[ "$variant" == minimal || "$variant" == production ]]; then
  # Missing utilities cannot prove execution denial. Mount the actual candidate
  # interpreter at the three forbidden paths and prove it runs unconfined first.
  docker run --rm --network none --entrypoint python "$image" -c \
    'import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.executable).read_bytes())' > "$fixture/denied-executable"
  chmod 0755 "$fixture/denied-executable"
  for target in /bin/sh /usr/bin/nsenter /usr/bin/infocmp; do
    denied_mounts+=(--volume "$fixture/denied-executable:$target:ro")
    docker run --rm --network none --entrypoint "$target" \
      --volume "$fixture/denied-executable:$target:ro" "$image" -c 'import ssl'
  done
fi
sudo apparmor_parser --replace "$profile_file"
trap 'sudo apparmor_parser --remove "$profile_file"' EXIT
docker run --rm --interactive --network none --entrypoint python \
  --security-opt "apparmor=$profile_name" "${denied_mounts[@]}" --env "RUNTIME_VARIANT=$variant" "$image" - <<'PY'
import os
import subprocess
import sys

assert sys.version_info[:2] == (3, 15), sys.version
for executable in ("/usr/local/bin/python", "/usr/local/bin/python3", "/usr/local/bin/python3.15"):
    subprocess.run([executable, "-c", "import ssl"], check=True)
for command in (["/bin/sh", "-c", "exit 0"], ["/usr/bin/nsenter", "--help"], ["/usr/bin/infocmp", "-V"]):
    if os.environ['RUNTIME_VARIANT'] in ('minimal', 'production'):
        command = [command[0], '-c', 'import ssl']
    try:
        subprocess.run(command, check=True)
    except PermissionError:
        print(f"AppArmor: execution denied for {command[0]}")
    else:
        raise AssertionError(f"AppArmor allowed {command[0]}")
PY
for probe in packaged_app_probe packaged_security_probe packaged_startup_probe packaged_tls_probe packaged_schedule_probe; do
  docker run --rm --network none --user root --entrypoint python \
    --add-host supervisor:127.0.0.1 --security-opt "apparmor=$profile_name" \
    --volume "$PWD/tests/fixtures/packaged-app-options.json:/data/options.json:ro" \
    --volume "$fixture:/tmp/tls:ro" \
    --volume "$PWD/tests/$probe.py:/tmp/probe.py:ro" \
    "$image" /tmp/probe.py
done
)
fi
