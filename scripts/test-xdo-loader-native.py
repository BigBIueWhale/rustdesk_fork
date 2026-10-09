#!/usr/bin/env python3
"""Build and exercise the production loader and Linux Enigo in guest-only containers.

This is a component test with real pinned dependencies and a partial common facade
with the production local-display selector, not full Cargo/app, package installation,
or a host-service test.
"""
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import tomllib

ROOT = Path('/work')
BUILD = Path('/loader-build')
RUSTC = '/usr/local/cargo/bin/rustc'
ENV = {'PATH': '/usr/local/cargo/bin:/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp',
       'RUSTUP_HOME': '/usr/local/rustup', 'CARGO_HOME': '/usr/local/cargo',
       'RUSTC': RUSTC, 'DISPLAY': ':98', 'XKB_CONFIG_ROOT': '/usr/share/X11/xkb',
       'LD_LIBRARY_PATH': '/xvfb-root/usr/lib/x86_64-linux-gnu'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(arguments, timeout=30, environment=None):
    result = subprocess.run(arguments, env=ENV if environment is None else environment,
                            capture_output=True, text=True, timeout=timeout)
    require(len(result.stdout) + len(result.stderr) <= 65536, 'component command output exceeded bound')
    if result.returncode:
        print(result.stdout, end='', flush=True)
        print(result.stderr, end='', flush=True)
    require(result.returncode == 0, f'component command failed: {arguments[:2]}')
    return result


def inputs():
    locked = {(item['name'], item['version']): item.get('checksum')
              for item in tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']}
    records = [line.split() for line in (ROOT / 'scripts/xdo-loader-inputs.txt').read_text().splitlines()
               if line and not line.startswith('#')]
    require(len(records) == 4 and len({record[0] for record in records}) == 4,
            'loader dependency closure differs')
    crates = {}
    for package, expected in records:
        directory = ROOT / 'xdo-vendor' / package
        checksum = directory / '.cargo-checksum.json'
        require(sha(checksum) == expected, f'loader input manifest differs: {package}')
        manifest = json.loads(checksum.read_bytes())
        metadata = tomllib.loads((directory / 'Cargo.toml').read_text())['package']
        require(manifest['package'] == locked[(metadata['name'], metadata['version'])],
                f'loader dependency root-lock identity differs: {package}')
        actual = {str(path.relative_to(directory)) for path in directory.rglob('*') if path.is_file()}
        require(actual == set(manifest['files']) | {'.cargo-checksum.json'},
                f'loader dependency file closure differs: {package}')
        for name, expected_file in manifest['files'].items():
            path = directory / name
            require(not path.is_symlink() and sha(path) == expected_file,
                    f'loader dependency bytes differ: {package}/{name}')
        crates[metadata['name']] = directory
    print('XDO_LOADER_INPUTS=pass crates=4 manifests=authenticated files=complete root_lock=matched', flush=True)
    return crates


def compile_crate(name, source, edition, arguments=()):
    output = BUILD / f'lib{name}.rlib'
    command([RUSTC, f'--edition={edition}', '--crate-name', name, '--crate-type=rlib',
             '-L', f'dependency={BUILD}', *arguments, str(source), '-o', str(output)])
    return output


def build():
    crates = inputs()
    cfg = compile_crate('cfg_if', crates['cfg-if'] / 'src/lib.rs', 2018)
    # Run the actual pinned build script, then apply only its explicit cfg directives.
    builder = BUILD / 'libc-build-script'
    command([RUSTC, '--edition=2021', str(crates['libc'] / 'build.rs'), '-o', str(builder)])
    result = command([str(builder)])
    flags = [line.removeprefix('cargo:rustc-cfg=') for line in result.stdout.splitlines()
             if line.startswith('cargo:rustc-cfg=')]
    require(flags == ['freebsd11', 'libc_const_extern_fn'], 'libc build configuration differs')
    libc = compile_crate('libc', crates['libc'] / 'src/lib.rs', 2021,
                         ['--cfg', 'feature="std"', *[arg for cfg in flags for arg in ('--cfg', cfg)]])
    loading = compile_crate('libloading', crates['libloading'] / 'src/lib.rs', 2015,
                            ['--extern', f'cfg_if={cfg}'])
    x11 = compile_crate('x11', crates['x11'] / 'src/lib.rs', 2021,
                        ['--extern', f'libc={libc}'])
    spec = importlib.util.spec_from_file_location('native_display', ROOT / 'scripts/test-x11-display-native.py')
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    required_exports = native.input_exports(ROOT)
    _, logging = native.logging_library(ROOT, ENV)
    logging = Path(shutil.move(str(logging), BUILD / 'liblog.rlib'))
    common = compile_crate('hbb_common', ROOT / 'scripts/fixtures/xdo-loader-common.rs', 2021,
                           ['--extern', f'libc={libc}', '--extern', f'libloading={loading}',
                            '--extern', f'x11={x11}', '--extern', f'log={logging}'])
    source = ROOT / 'libs/libxdo-sys-stub/src/lib.rs'
    loader = compile_crate('libxdo_sys', source, 2021, ['--extern', f'hbb_common={common}'])
    binary = BUILD / 'test-xdo-loader'
    command([RUSTC, '--edition=2021', '-L', f'dependency={BUILD}', '-L', 'dependency=/build',
             '--extern', f'hbb_common={common}', '--extern', f'libxdo_sys={loader}',
             '-l', 'X11', str(ROOT / 'scripts/test-xdo-loader.rs'), '-o', str(binary)])
    print(f'XDO_LOADER_BUILD=pass source=complete-production-module source_sha256={sha(source)} '
          f'binary_sha256={sha(binary)} common=partial dependencies=real '
          'x11_link=explicit libc_build_script=actual full_app=uncompiled', flush=True)
    enigo = compile_crate('enigo', ROOT / 'libs/enigo/src/lib.rs', 2018,
                          ['--extern', f'hbb_common={common}', '--extern', f'libxdo_sys={loader}',
                           '--extern', f'log={logging}'])
    retired_source = BUILD / 'retired-enigo-api.rs'
    retired_source.write_text('use enigo::{Enigo, Key, KeyboardControllable};\n'
                              'fn main() { let mut enigo = Enigo::new();\n'
                              'enigo.key_sequence("a"); enigo.key_down(Key::Shift);\n'
                              'enigo.key_up(Key::Shift); enigo.key_click(Key::Shift);\n'
                              'enigo.set_custom_keyboard(Box::new(Enigo::new()));\n'
                              'enigo.set_custom_mouse(Box::new(Enigo::new()));\n'
                              'let _ = enigo.get_custom_keyboard(); let _ = enigo.get_custom_mouse(); }\n')
    retired_binary = BUILD / 'retired-enigo-api'
    rejected = subprocess.run(
        [RUSTC, '--edition=2021', '--error-format=json', '-L', f'dependency={BUILD}',
         '--extern', f'enigo={enigo}', str(retired_source), '-o', str(retired_binary)],
        env=ENV, capture_output=True, text=True, timeout=30)
    require(rejected.returncode == 1 and not rejected.stdout
            and len(rejected.stderr) <= 32768 and not retired_binary.exists(),
            'retired Enigo API compiled or failed without bounded diagnostics')
    diagnostics = [json.loads(line) for line in rejected.stderr.splitlines()]
    errors = [item for item in diagnostics if item.get('level') == 'error' and item.get('code')]
    require(len(errors) == 8 and all(item['code']['code'] == 'E0599' for item in errors)
            and all(sum(f'`{name}`' in item['message'] for item in errors) == 1
                    for name in ('key_sequence', 'key_down', 'key_up', 'key_click',
                                 'set_custom_keyboard', 'set_custom_mouse',
                                 'get_custom_keyboard', 'get_custom_mouse')),
            'retired Enigo API refusal differs')
    print('XDO_ENIGO_RETIRED_API=refused emission_methods=4 custom_backend_methods=4 crate=complete-linux-source '
          'compiler=rustc-1.75.0 artifact=absent runtime=unexecuted', flush=True)
    enigo_binary = BUILD / 'test-xdo-enigo'
    command([RUSTC, '--edition=2021', '-L', f'dependency={BUILD}',
             '--extern', f'hbb_common={common}', '--extern', f'enigo={enigo}',
             '-l', 'X11', str(ROOT / 'scripts/test-xdo-enigo.rs'), '-o', str(enigo_binary)])
    print(f'XDO_ENIGO_BUILD=pass crate=complete-linux-source binary_sha256={sha(enigo_binary)} '
          f'backend_sha256={sha(ROOT / "libs/enigo/src/linux/xdo.rs")} '
          f'parent_sha256={sha(ROOT / "libs/enigo/src/linux/nix_impl.rs")} '
          'selector=complete-production-module common=partial cargo=unexecuted', flush=True)
    native_source = ROOT / 'libs/libxdo-sys-stub/native'
    for variant in ('complete', 'missing-mouse-up', 'missing-key-input', 'wrong-version', 'reject-text'):
        source_dir = native_source
        directory = BUILD / variant
        directory.mkdir(mode=0o700)
        if variant != 'complete':
            source_dir = BUILD / f'{variant}-source'
            shutil.copytree(native_source, source_dir)
            if variant == 'missing-mouse-up':
                path = source_dir / 'xdo.c'
                path.write_text('#define xdo_mouse_up rd_fixture_mouse_up\n' + path.read_text())
            elif variant == 'missing-key-input':
                path = source_dir / 'xdo.c'
                path.write_text('#define xdo_enter_text_scalar rd_fixture_key_input\n' + path.read_text())
            elif variant == 'wrong-version':
                path = source_dir / 'xdo_version.h'
                text = path.read_text()
                require(text.count('3.20160805.1-rustdesk16') == 1, 'fixture version source differs')
                path.write_text(text.replace('3.20160805.1-rustdesk16', '3.20160805.1-rustdesk15'))
            else:
                path = source_dir / 'xdo.c'
                path.write_text('#define XGetModifierMapping rd_fixture_x_get_modifier_mapping\n' + path.read_text()
                                + '\nXModifierKeymap *rd_fixture_x_get_modifier_mapping(Display *display) {\n'
                                + '  (void)display; return NULL;\n}\n')
        library = directory / 'libxdo.so.3'
        result = command(['/usr/bin/python3', '-I', '-S', str(source_dir / 'build.py'),
                          '--output', str(library)], 35)
        # The helper stamp describes production source; fixture differences are recorded here.
        exports = {line.split()[-1] for line in command(['/usr/bin/nm', '-D', '--defined-only', str(library)]).stdout.splitlines()}
        expected_exports = required_exports - ({'xdo_mouse_up'} if variant == 'missing-mouse-up' else
                                               {'xdo_enter_text_scalar'} if variant == 'missing-key-input' else set())
        require({name for name in exports if name.startswith('xdo_')} == expected_exports,
                'private loader provider input export closure differs')
        print(f'XDO_LOADER_PROVIDER variant={variant} library_sha256={sha(library)} '
              f'bytes={library.stat().st_size} c_sha256={sha(source_dir / "xdo.c")} '
              f'version_header_sha256={sha(source_dir / "xdo_version.h")} '
              f'mouse_up_export={str("xdo_mouse_up" in exports).lower()}', flush=True)
    require(sum(path.stat().st_size for path in BUILD.rglob('*') if path.is_file()) <= 64 * 1024 * 1024,
            'loader build artifacts exceeded bound')
    print('XDO_LOADER_BUILD_PHASE=pass source=readonly compile_uid=4000 providers=5', flush=True)


def resolved_dependencies(path, environment=None):
    result = command(['/usr/bin/ldd', str(path)], environment=environment)
    require('not found' not in result.stdout, 'native dependency is unavailable')
    dependencies = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == '=>':
            require(fields[2].startswith('/'), 'native dependency resolution is ambiguous')
            dependencies[fields[0]] = Path(fields[2])
    require(dependencies, 'native dependency inventory is empty')
    return dependencies


def runtime_stage():
    source = ROOT / 'scripts/stage-debian-systemd-runtime-libs.sh'
    text = source.read_text()
    spec = importlib.util.spec_from_file_location(
        'stage_authority', ROOT / 'scripts/verify-debian-systemd-lifecycle-authority.py')
    stage_authority = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage_authority)
    stage_authority.validate_stage(text)
    prefix = '    runtime_library_stage_run "$DEV_CHECK_IMAGE_CONFIG_ID"'
    require(text.count(prefix) == 1, 'production staging command is ambiguous')
    start = text.index(prefix)
    end = text.index('\n    binary_after=', start)
    # Parse the real shell-quoted command argument, without substituting or rewriting its body.
    body = shlex.split(text[start:end])[-1]
    require('stage_library() {' in body, 'production staging body is unavailable')
    provider_dependencies = resolved_dependencies('/input/libxdo.so.3')
    binary_dependencies = resolved_dependencies('/input/rustdesk')
    command(['/bin/bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', body])
    output = Path('/out')
    missing = sorted(name for name in provider_dependencies if not (output / name).is_file())
    require(not missing, f'runtime staging omitted private-provider dependencies: {missing}')
    require(not any(path.name.startswith('libxdo.so') for path in output.iterdir()),
            'runtime staging retained a distribution XDO provider')
    files = list(output.iterdir())
    require(1 <= len(files) <= 256 and sum(path.stat().st_size for path in files) <= 128 * 1024 * 1024,
            'component runtime staging exceeded its output bound')
    for path in files:
        metadata = path.lstat()
        require(path.is_file() and not path.is_symlink() and metadata.st_nlink == 1
                and metadata.st_uid == 4000 and not metadata.st_mode & 0o022,
                'component runtime library metadata differs')
    staged_env = dict(ENV, LD_LIBRARY_PATH='/out')
    for path, expected in (('/input/libxdo.so.3', provider_dependencies),
                           ('/input/rustdesk', binary_dependencies)):
        actual = resolved_dependencies(path, staged_env)
        require(set(actual) == set(expected) and all(value.parent == output for value in actual.values()),
                'native dependency resolution fell back outside the staged libraries')
    previous = ENV['LD_LIBRARY_PATH']
    try:
        ENV['LD_LIBRARY_PATH'] = '/out:/xvfb-root/usr/lib/x86_64-linux-gnu'
        run('complete')
    finally:
        ENV['LD_LIBRARY_PATH'] = previous
    print(f'XDO_RUNTIME_STAGE=pass source_sha256={sha(source)} body_sha256='
          f'{hashlib.sha256(body.encode()).hexdigest()} provider_dependencies={len(provider_dependencies)} '
          f'libraries={len(files)} distribution_xdo=absent resolution=staged input=actual '
          'native_input=delivered full_stage_cli=unexecuted cleanup=joined', flush=True)


def xtest_refusal_diagnostics(stderr, display, count):
    expected = f"xdo_new: XTEST extension unavailable on '{display}'"
    lines = stderr.splitlines()
    return (lines.count(expected) == count and len(lines) <= count * 2
            and all(line == expected or re.fullmatch(
                r'Xlib: +extension "XTEST" missing on display "' + re.escape(display) + r'"\.', line)
                    for line in lines))


def run(scenario):
    require(scenario in ('complete', 'no-xtest', 'missing-mouse-up', 'missing-key-input', 'wrong-version', 'writable', 'absent', 'reject-text'),
            'unknown loader scenario')
    with open('/tmp/xdo-loader-xvfb.log', 'xb') as log:
        arguments = ['/xvfb-root/usr/bin/Xvfb', ':98', '-screen', '0', '640x480x24',
                     '-nolisten', 'tcp', '-ac', '-noreset']
        if scenario == 'no-xtest':
            arguments += ['-extension', 'XTEST']
        child = subprocess.Popen(arguments, env=ENV,
                                 stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not Path('/tmp/.X11-unix/X98').is_socket():
                require(child.poll() is None and time.monotonic() < deadline, 'loader Xvfb readiness failed')
                time.sleep(0.05)
            if scenario != 'reject-text':
                result = command([str(BUILD / 'test-xdo-loader'), scenario], 10)
                expected = (f'XDO_LOADER_COMPONENT=pass scenario={scenario} constructors=refused descriptors=retired'
                            if scenario != 'complete' else
                            'XDO_LOADER_COMPONENT=pass scenario=complete pointer=absolute,relative '
                            'button=pressed,released shift=pressed,released key=a,a input=xtest '
                            'retired_lookups=62 retired_symbols=absent descriptors=retired')
                if scenario == 'no-xtest':
                    expected = expected.replace(' descriptors=',
                        ' extension=absent paths=3 borrowed_display=usable descriptors=')
                diagnostics = (xtest_refusal_diagnostics(result.stderr, ':98', 3)
                               if scenario == 'no-xtest' else not result.stderr)
                require(result.stdout.splitlines() == [expected] and diagnostics,
                        'loader native component result differs')
                print(expected, flush=True)
            result = command([str(BUILD / 'test-xdo-enigo'), scenario], 10)
            expected = (f'XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 '
                        'text=unavailable mouse=unavailable descriptors=retired'
                        if scenario not in ('complete', 'reject-text') else
                        f'XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 '
                        f'text={"delivered" if scenario == "complete" else "native-modifier-error"} '
                        'pointer=actual descriptors=retired')
            diagnostics = (xtest_refusal_diagnostics(result.stderr, 'unix/:98.0', 8)
                           if scenario == 'no-xtest' else not result.stderr)
            expected_lines = [expected]
            if scenario == 'complete':
                expected_lines.insert(0, 'XDO_ENIGO_STATE=pass contexts=8 queries=120 '
                                      'keys=Shift,Control,Alt,CapsLock,NumLock state=server-observed '
                                      'source=complete-linux-crate uncertainty=unproved')
            require(result.stdout.splitlines() == expected_lines and diagnostics,
                    'complete Enigo/private-loader result differs')
            print(result.stdout, end='', flush=True)
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        require(child.returncode == 0, 'loader Xvfb retirement failed')
    for name in ('tcp', 'tcp6'):
        require(not any(row.split()[3] == '0A' for row in Path('/proc/net', name).read_text().splitlines()[1:]),
                'loader test opened TCP')
    for name in ('udp', 'udp6'):
        require(len(Path('/proc/net', name).read_text().splitlines()) == 1, 'loader test opened UDP')
    print(f'XDO_LOADER_NATIVE=pass scenario={scenario} source=production network=none uid=4000 cleanup=joined', flush=True)


if __name__ == '__main__':
    require(os.getuid() == 4000 and os.getgid() == 4000 and Path('/.dockerenv').is_file(),
            'XDO loader test requires the guest-only nonroot container')
    require(command([RUSTC, '--version'], 5).stdout.strip() == 'rustc 1.75.0 (82e1608df 2023-12-21)',
            'loader compiler identity differs')
    require(len(sys.argv) == 2, 'exact loader phase required')
    if sys.argv[1] == 'build':
        build()
    elif sys.argv[1] == 'runtime-stage':
        runtime_stage()
    else:
        run(sys.argv[1])
