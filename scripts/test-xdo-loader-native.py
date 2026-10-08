#!/usr/bin/env python3
"""Build and exercise the complete production loader in guest-only containers.

This is a component test with real pinned dependencies and a re-export-only common
facade, not a full Cargo/app, package installation, or host-service test.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
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


def command(arguments, timeout=30):
    result = subprocess.run(arguments, env=ENV, capture_output=True, text=True, timeout=timeout)
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
    _, logging = native.logging_library(ROOT, ENV)
    logging = Path(shutil.move(str(logging), BUILD / 'liblog.rlib'))
    policy_source = ROOT / 'libs/hbb_common/src/platform/linux.rs'
    policy = policy_source.read_text()
    declarations = []
    for name in ('DISPLAY_SERVER_X11', 'DISPLAY_SERVER_WAYLAND'):
        prefix = f'pub const {name}:'
        lines = [line for line in policy.splitlines() if line.startswith(prefix)]
        require(len(lines) == 1, f'production display constant differs: {name}')
        declarations.append(lines[0])
    for name in ('get_display_server', 'is_desktop_wayland', 'is_x11_or_headless'):
        prefix = f'pub fn {name}('
        require(policy.count(prefix) == 1, f'production display function differs: {name}')
        start = policy.index(prefix)
        end = policy.index('\n}\n', start) + 2
        declarations.append(policy[start:end])
    selected_policy = BUILD / 'x11-policy.rs'
    selected_policy.write_text('\n'.join(declarations) + '\n')
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
          f'binary_sha256={sha(binary)} common=reexports-only dependencies=real '
          'x11_link=explicit libc_build_script=actual full_app=uncompiled', flush=True)
    enigo = compile_crate('enigo', ROOT / 'libs/enigo/src/lib.rs', 2018,
                          ['--extern', f'hbb_common={common}', '--extern', f'libxdo_sys={loader}',
                           '--extern', f'log={logging}'])
    enigo_binary = BUILD / 'test-xdo-enigo'
    command([RUSTC, '--edition=2021', '-L', f'dependency={BUILD}',
             '--extern', f'hbb_common={common}', '--extern', f'enigo={enigo}',
             '-l', 'X11', str(ROOT / 'scripts/test-xdo-enigo.rs'), '-o', str(enigo_binary)])
    print(f'XDO_ENIGO_BUILD=pass crate=complete-linux-source binary_sha256={sha(enigo_binary)} '
          f'backend_sha256={sha(ROOT / "libs/enigo/src/linux/xdo.rs")} '
          f'parent_sha256={sha(ROOT / "libs/enigo/src/linux/nix_impl.rs")} '
          f'policy_parent_sha256={sha(policy_source)} selected_policy_sha256={sha(selected_policy)} '
          'policy=production-source-extracted common=partial cargo=unexecuted', flush=True)
    native_source = ROOT / 'libs/libxdo-sys-stub/native'
    for variant in ('complete', 'missing-mouse-up', 'wrong-version', 'reject-key-down'):
        source_dir = native_source
        directory = BUILD / variant
        directory.mkdir(mode=0o700)
        if variant != 'complete':
            source_dir = BUILD / f'{variant}-source'
            shutil.copytree(native_source, source_dir)
            if variant == 'missing-mouse-up':
                path = source_dir / 'xdo.c'
                path.write_text('#define xdo_mouse_up rd_fixture_mouse_up\n' + path.read_text())
            elif variant == 'wrong-version':
                path = source_dir / 'xdo_version.h'
                text = path.read_text()
                require(text.count('3.20160805.1-rustdesk1') == 1, 'fixture version source differs')
                path.write_text(text.replace('3.20160805.1-rustdesk1', '3.20160805.1-wrong'))
            else:
                path = source_dir / 'xdo.c'
                text = path.read_text()
                call = 'return _xdo_send_keysequence_window_do(xdo, window, keyseq, True, NULL, delay);'
                require(text.count(call) == 1, 'native key-down fault boundary differs')
                path.write_text(text.replace(call, 'return 7; /* controlled native operation refusal */'))
        library = directory / 'libxdo.so.3'
        result = command(['/usr/bin/python3', '-I', '-S', str(source_dir / 'build.py'),
                          '--output', str(library)], 35)
        # The helper stamp describes production source; fixture differences are recorded here.
        exports = {line.split()[-1] for line in command(['/usr/bin/nm', '-D', '--defined-only', str(library)]).stdout.splitlines()}
        require(('xdo_mouse_up' in exports) == (variant != 'missing-mouse-up'),
                'missing-symbol provider fixture differs')
        require('xdo_version' in exports and 'xdo_new' in exports, 'native provider fixture lacks constructors/version')
        print(f'XDO_LOADER_PROVIDER variant={variant} library_sha256={sha(library)} '
              f'bytes={library.stat().st_size} c_sha256={sha(source_dir / "xdo.c")} '
              f'version_header_sha256={sha(source_dir / "xdo_version.h")} '
              f'mouse_up_export={str("xdo_mouse_up" in exports).lower()}', flush=True)
    require(sum(path.stat().st_size for path in BUILD.rglob('*') if path.is_file()) <= 64 * 1024 * 1024,
            'loader build artifacts exceeded bound')
    print('XDO_LOADER_BUILD_PHASE=pass source=readonly compile_uid=4000 providers=4', flush=True)


def run(scenario):
    require(scenario in ('complete', 'missing-mouse-up', 'wrong-version', 'writable', 'absent', 'reject-key-down'),
            'unknown loader scenario')
    with open('/tmp/xdo-loader-xvfb.log', 'xb') as log:
        child = subprocess.Popen(['/xvfb-root/usr/bin/Xvfb', ':98', '-screen', '0', '640x480x24',
                                  '-nolisten', 'tcp', '-ac', '-noreset'], env=ENV,
                                 stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not Path('/tmp/.X11-unix/X98').is_socket():
                require(child.poll() is None and time.monotonic() < deadline, 'loader Xvfb readiness failed')
                time.sleep(0.05)
            if scenario != 'reject-key-down':
                result = command([str(BUILD / 'test-xdo-loader'), scenario], 10)
                expected = (f'XDO_LOADER_COMPONENT=pass scenario={scenario} constructors=refused descriptors=retired'
                            if scenario != 'complete' else
                            'XDO_LOADER_COMPONENT=pass scenario=complete pointer=absolute,relative '
                            'button=pressed,released shift=pressed,released key=a,a descriptors=retired')
                require(result.stdout.splitlines() == [expected] and not result.stderr,
                        'loader native component result differs')
                print(expected, flush=True)
            result = command([str(BUILD / 'test-xdo-enigo'), scenario], 10)
            expected = (f'XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 '
                        'key_down=unavailable mouse=unavailable descriptors=retired'
                        if scenario not in ('complete', 'reject-key-down') else
                        f'XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 '
                        f'key_down={"delivered" if scenario == "complete" else "native-error"} '
                        'pointer=actual descriptors=retired')
            require(result.stdout.splitlines() == [expected] and not result.stderr,
                    'complete Enigo/private-loader result differs')
            print(expected, flush=True)
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
    else:
        run(sys.argv[1])
