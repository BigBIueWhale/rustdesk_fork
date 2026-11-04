#!/usr/bin/env python3
"""Execute the production Windows service schema regression in the isolated VM."""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


repo = Path('/source')
work = Path('/tmp/windows-service-protocol')
require(Path.cwd() == repo and os.getuid() == os.getgid() == 1000
        and Path('/.dockerenv').is_file(), 'confined non-root builder required')
work.mkdir(mode=0o700)
spec = importlib.util.spec_from_file_location(
    'ipc_parser', repo / 'scripts/verify-linux-service-password-ipc.py')
parser = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = parser
spec.loader.exec_module(parser)
path = repo / 'src/ipc.rs'
source = parser.RustSource.parse(str(path), path.read_text())
definitions = ''
for kind, name in (
        ('enum', 'WindowsServiceCredentialRequest'),
        ('struct', 'WindowsCredentialReplicaState'),
        ('enum', 'WindowsServiceCredentialResponse'),
        ('enum', 'WindowsServiceControlRequest'),
        ('enum', 'WindowsServiceControlResponse')):
    start = source.all().require((kind, name), 'service protocol type', unique=True)
    offset = source.text.rindex('#[derive(', 0, source.tokens[start].offset)
    end = source.item(kind, name).end
    definitions += source.text[offset:source.tokens[end].offset + 1] + '\n'
name = 'windows_service_credential_and_control_channels_use_closed_directional_protocols'
starts = [i for i, token in enumerate(source.tokens[:-1])
          if token.text == 'fn' and source.tokens[i + 1].text == name]
require(len(starts) == 1, 'service protocol regression is ambiguous')
start = starts[0]
body = source.function(name, parent=source.brace_parent[start])
test = source.text[source.tokens[start].offset:source.tokens[body.end].offset + 1]
# The generic Data envelope is a one-variant fixture; the five service types
# and the complete existing test body above are copied without modification.
fixture = '''use serde::{Serialize, Deserialize};
#[derive(Serialize)]
#[serde(tag = "t", content = "c")]
enum Data { Close }
'''
(work / 'lib.rs').write_text(fixture + definitions
                           + '\n#[cfg(test)] mod test { use super::*; #[test]\n'
                           + test + '\n}\n')
(work / 'Cargo.toml').write_text('''[package]
name = "windows-service-protocol"
version = "0.0.0"
edition = "2021"
[lib]
path = "lib.rs"
[workspace]
[dependencies]
serde = { version = "=1.0.228", features = ["derive"] }
serde_json = "=1.0.118"
''')
shutil.copyfile(repo / 'Cargo.lock', work / 'Cargo.lock')
env = dict(os.environ, CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0',
           CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
subprocess.run(['cargo', 'test', '--manifest-path', str(work / 'Cargo.toml'),
                '--offline', '--lib', '--no-run', '--color', 'never'],
               env=env, check=True, timeout=120)
locked = tomllib.loads((repo / 'Cargo.lock').read_text())['package']
for package in tomllib.loads((work / 'Cargo.lock').read_text())['package']:
    if package['name'] != 'windows-service-protocol':
        require(any(all(package.get(k) == p.get(k)
                        for k in ('name', 'version', 'source', 'checksum'))
                    for p in locked), 'dependency escaped root lock')
artifacts = [p for p in Path('/cargo-target/debug/deps').glob('windows_service_protocol-*')
             if p.is_file() and not p.is_symlink() and os.access(p, os.X_OK)]
require(len(artifacts) == 1, 'test artifact inventory differs')
artifact = artifacts[0]
digest = sha(artifact)
print(f'WINDOWS_SERVICE_PROTOCOL_SOURCE=pass ipc={sha(path)} '
      f'types={hashlib.sha256(definitions.encode()).hexdigest()} '
      f'test={hashlib.sha256(test.encode()).hexdigest()} '
      f'lock={sha(work / "Cargo.lock")} data=close-variant-fixture', flush=True)
print(f'WINDOWS_SERVICE_PROTOCOL_ARTIFACT_BEFORE=sha256={digest}', flush=True)
result = subprocess.run([str(artifact), '--test-threads=1', '--color', 'never'],
                        env=env, timeout=10, check=False)
require(sha(artifact) == digest, 'test artifact changed')
require(result.returncode == 0, 'service protocol regression failed')
print(f'WINDOWS_SERVICE_PROTOCOL_ARTIFACT=pass sha256={digest} '
      'tests=1 unchanged=before-after', flush=True)
