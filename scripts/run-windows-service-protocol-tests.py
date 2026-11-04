#!/usr/bin/env python3
"""Exercise production service schemas and framed methods over isolated Unix sockets."""
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


def function(parsed, name, parent=None):
    starts = [i for i, token in enumerate(parsed.tokens[:-1])
              if token.text == 'fn' and parsed.tokens[i + 1].text == name
              and parsed.brace_parent[i] == parent]
    require(len(starts) == 1, f'function is ambiguous: {name}')
    start = starts[0]
    if parsed.tokens[start - 1].text == 'async':
        start -= 1
    body = parsed.function(name, parent=parent)
    return parsed.text[parsed.tokens[start].offset:parsed.tokens[body.end].offset + 1] + '\n'


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
start = source.all().require(('const', 'SERVICE_IPC_MAX_FRAME_BYTES'), 'frame limit', unique=True)
end = next(i for i in range(start, len(source.tokens)) if source.tokens[i].text == ';')
transport = source.text[source.tokens[start].offset:source.tokens[end].offset + 1] + '\n'
start = source.all().require(('struct', 'ConnectionTmpl'), 'connection type', unique=True)
end = source.item('struct', 'ConnectionTmpl').end
transport += source.text[source.tokens[start].offset:source.tokens[end].offset + 1] + '\n'
methods = source.impl(('impl', '<', 'T', '>', 'ConnectionTmpl', '<', 'T', '>'), 'connection methods')
transport += 'impl<T: AsyncRead + AsyncWrite + Unpin> ConnectionTmpl<T> {\n'
for name in ('new', 'new_with_max_packet_length', 'new_protected_service',
             'send_json', 'send_json_timeout', 'next_json', 'send_raw',
             'send_windows_service_credential_request_timeout',
             'next_windows_service_credential_request_timeout',
             'send_windows_service_credential_response_timeout',
             'next_windows_service_credential_response_timeout',
             'send_windows_service_control_request_timeout',
             'next_windows_service_control_request_timeout',
             'send_windows_service_control_response_timeout',
             'next_windows_service_control_response_timeout'):
    transport += function(source, name, methods.start - 1)
transport += '}\n'
common_path = repo / 'libs/hbb_common/src/lib.rs'
common = parser.RustSource.parse(str(common_path), common_path.read_text())
transport += function(common, 'timeout')
codec = (repo / 'libs/hbb_common/src/bytes_codec.rs').read_text()
test_marker = '\n#[cfg(test)]\nmod tests {'
require(codec.count(test_marker) == 1, 'codec test boundary differs')
codec = codec.split(test_marker)[0] + '\n'
(work / 'bytes_codec.rs').write_text(codec)
shutil.copyfile(repo / 'src/ipc/framed.rs', work / 'framed.rs')
shutil.copyfile(repo / 'scripts/test-windows-service-protocol.rs', work / 'framed_cases.rs')
# The generic Data envelope is a one-variant fixture; the five service types
# and the complete existing test body above are copied without modification.
fixture = '''extern crate self as hbb_common;
pub use tokio;
pub use tokio_util;
use anyhow::bail;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use serde::{Serialize, Deserialize};
type ResultType<T> = anyhow::Result<T>;
mod framed;
use framed::IpcFrameReader;
mod bytes_codec;
use bytes_codec::BytesCodec;
#[derive(Serialize)]
#[serde(tag = "t", content = "c")]
enum Data { Close }
'''
(work / 'lib.rs').write_text(fixture + definitions + transport
                           + '\n#[cfg(test)] mod test { use super::*; #[test]\n'
                           + test + '\n}\n#[cfg(test)] mod framed_cases;\n')
(work / 'Cargo.toml').write_text('''[package]
name = "windows-service-protocol"
version = "0.0.0"
edition = "2021"
[lib]
path = "lib.rs"
[workspace]
[dependencies]
anyhow = "=1.0.103"
bytes = "=1.11.1"
serde = { version = "=1.0.228", features = ["derive"] }
serde_json = "=1.0.118"
tokio = { version = "=1.44.2", features = ["rt", "net", "time", "io-util", "macros"] }
tokio-util = { version = "=0.7.15", features = ["codec"] }
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
      f'io={hashlib.sha256((transport + codec + (work / "framed.rs").read_text()).encode()).hexdigest()} '
      f'cases={sha(work / "framed_cases.rs")} '
      f'lock={sha(work / "Cargo.lock")} data=close-variant-fixture', flush=True)
print(f'WINDOWS_SERVICE_PROTOCOL_ARTIFACT_BEFORE=sha256={digest}', flush=True)
result = subprocess.run([str(artifact), '--test-threads=1', '--color', 'never'],
                        env=env, timeout=10, check=False)
require(sha(artifact) == digest, 'test artifact changed')
require(result.returncode == 0, 'service protocol regression failed')
print(f'WINDOWS_SERVICE_PROTOCOL_ARTIFACT=pass sha256={digest} '
      'tests=7 unchanged=before-after', flush=True)
