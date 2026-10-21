#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 0 ] && [ "$PWD" = /source ] \
    && [ "$(id -u):$(id -g)" = 1000:1000 ] \
    || { echo 'Video QoS controller test entry authority differs' >&2; exit 1; }
readonly WORK=/tmp/video-qos-controller
mkdir -m 0700 -- "$WORK"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
python3 -I -S - <<'PY'
import errno
import socket
with socket.socket() as canary:
    try:
        canary.connect(("192.0.2.1", 9))
    except OSError as error:
        if error.errno != errno.ENETUNREACH:
            raise
    else:
        raise SystemExit("Video QoS controller offline canary connected")
print("R-B10 canary: build confirmed network-isolated (offline compile stage).")
PY
source /source/scripts/linux-parent-test-build.sh
python3 -I -S - "$WORK" <<'PY'
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib

source = Path('/source')
private = Path(sys.argv[1]) / 'resolver'
before = (source / 'Cargo.lock').read_bytes()
shutil.copytree(source, private, symlinks=True,
                ignore=shutil.ignore_patterns('.git', 'target', 'online', '.harness-state'))
for directory, children, files in os.walk(private):
    Path(directory).chmod(0o700)
(private / 'Cargo.lock').chmod(0o600)
result = subprocess.run(['cargo', 'metadata', '--offline', '--format-version=1'],
                        cwd=private, capture_output=True, timeout=30)
if result.returncode:
    print(result.stderr[-8000:].decode(errors='replace'), flush=True)
    raise SystemExit(result.returncode)
after = (private / 'Cargo.lock').read_bytes()
assert (source / 'Cargo.lock').read_bytes() == before
key = lambda p: (p['name'], p['version'], p.get('source', ''))
old = {key(p): p for p in tomllib.loads(before.decode())['package']}
new = {key(p): p for p in tomllib.loads(after.decode())['package']}
delta = {'before_sha256': hashlib.sha256(before).hexdigest(),
         'after_sha256': hashlib.sha256(after).hexdigest(),
         'removed': [old[k] for k in sorted(old.keys() - new.keys())],
         'added': [new[k] for k in sorted(new.keys() - old.keys())],
         'modified': [{'before': old[k], 'after': new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]],
         'source_unchanged': True, 'purpose': 'private-copy resolver diagnostic; no build/test pass'}
body = json.dumps(delta, sort_keys=True)
assert len(body.encode()) < 16384
print('TLS_LOCK_DIAGNOSTIC=' + body, flush=True)
raise SystemExit(1)
PY
build_linux_parent_test "$WORK" VIDEO_QOS_CONTROLLER
execution_started=$SECONDS
execution_status=0
timeout --signal=TERM --kill-after=5s 30s \
    "$test_executable" server::video_qos::tests:: \
    --color never --test-threads=1 --show-output || execution_status=$?
[ "$(sha256sum "$test_executable" | cut -d ' ' -f 1)" = "$artifact_sha" ]
printf 'VIDEO_QOS_CONTROLLER_ARTIFACT_AFTER=observed sha256=%s tests=19 exit_code=%s unchanged=before-after\n' \
    "$artifact_sha" "$execution_status"
[ "$execution_status" -eq 0 ] || exit "$execution_status"
printf 'VIDEO_QOS_CONTROLLER_ARTIFACT=pass sha256=%s executable=%s tests=19 unchanged=before-after execution_seconds=%s\n' \
    "$artifact_sha" "$test_executable" "$((SECONDS - execution_started))"
