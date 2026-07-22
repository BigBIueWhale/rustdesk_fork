#!/usr/bin/env python3

import os
import pathlib
import platform
import zipfile
import urllib.request
import shutil
import hashlib
import argparse
import re
import subprocess
import stat
import sys
from pathlib import Path

windows = platform.platform().startswith('Windows')
osx = platform.platform().startswith(
    'Darwin') or platform.platform().startswith("macOS")
hbb_name = 'rustdesk' + ('.exe' if windows else '')
exe_path = 'target/release/' + hbb_name
if windows:
    flutter_build_dir = 'build/windows/x64/runner/Release/'
elif osx:
    flutter_build_dir = 'build/macos/Build/Products/Release/'
else:
    flutter_build_dir = 'build/linux/x64/release/bundle/'
flutter_build_dir_2 = f'flutter/{flutter_build_dir}'
skip_cargo = False

DEBIAN_MAINTAINER_SCRIPTS = ("preinst", "postinst", "prerm", "postrm")
DEBIAN_CONFFILES = (
    "etc/init.d/rustdesk",
    "etc/rustdesk/startwm.sh",
    "etc/rustdesk/xorg.conf",
)
DEBIAN_CONTROL_MODES = {
    "control": 0o644,
    "conffiles": 0o644,
    "md5sums": 0o644,
    **{name: 0o755 for name in DEBIAN_MAINTAINER_SCRIPTS},
}
DEBIAN_DATA_EXECUTABLES = {
    "etc/init.d/rustdesk",
    "etc/rustdesk/startwm.sh",
    "usr/share/rustdesk/files/manual/rustdesk-service",
    "usr/share/rustdesk/files/openrc/rustdesk",
    "usr/share/rustdesk/files/runit/run",
    "usr/share/rustdesk/rustdesk",
}
DEBIAN_FLUTTER_LIBRARIES = {
    "usr/share/rustdesk/lib/libapp.so",
    "usr/share/rustdesk/lib/libdesktop_drop_plugin.so",
    "usr/share/rustdesk/lib/libdesktop_multi_window_plugin.so",
    "usr/share/rustdesk/lib/libflutter_custom_cursor_plugin.so",
    "usr/share/rustdesk/lib/libflutter_linux_gtk.so",
    "usr/share/rustdesk/lib/librustdesk.so",
    "usr/share/rustdesk/lib/libscreen_retriever_plugin.so",
    "usr/share/rustdesk/lib/libtexture_rgba_renderer_plugin.so",
    "usr/share/rustdesk/lib/liburl_launcher_linux_plugin.so",
    "usr/share/rustdesk/lib/libwindow_manager_plugin.so",
    "usr/share/rustdesk/lib/libwindow_size_plugin.so",
}
DEBIAN_DATA_REQUIRED_DIRECTORIES = {
    "etc",
    "etc/init.d",
    "etc/rustdesk",
    "usr",
    "usr/lib",
    "usr/lib/systemd",
    "usr/lib/systemd/system",
    "usr/share",
    "usr/share/applications",
    "usr/share/icons",
    "usr/share/icons/hicolor",
    "usr/share/icons/hicolor/256x256",
    "usr/share/icons/hicolor/256x256/apps",
    "usr/share/icons/hicolor/scalable",
    "usr/share/icons/hicolor/scalable/apps",
    "usr/share/polkit-1",
    "usr/share/polkit-1/actions",
    "usr/share/rustdesk",
    "usr/share/rustdesk/data",
    "usr/share/rustdesk/data/flutter_assets",
    "usr/share/rustdesk/files",
    "usr/share/rustdesk/files/manual",
    "usr/share/rustdesk/files/openrc",
    "usr/share/rustdesk/files/runit",
    "usr/share/rustdesk/lib",
}
DEBIAN_DATA_REQUIRED_FILES = {
    "etc/init.d/rustdesk",
    "etc/rustdesk/startwm.sh",
    "etc/rustdesk/xorg.conf",
    "usr/lib/systemd/system/rustdesk.service",
    "usr/share/applications/rustdesk-link.desktop",
    "usr/share/applications/rustdesk.desktop",
    "usr/share/icons/hicolor/256x256/apps/rustdesk.png",
    "usr/share/icons/hicolor/scalable/apps/rustdesk.svg",
    "usr/share/polkit-1/actions/com.carriez.RustDesk.policy",
    "usr/share/rustdesk/data/flutter_assets/AssetManifest.bin",
    "usr/share/rustdesk/data/flutter_assets/FontManifest.json",
    "usr/share/rustdesk/data/flutter_assets/NOTICES.Z",
    "usr/share/rustdesk/data/icudtl.dat",
    "usr/share/rustdesk/files/manual/rustdesk-service",
    "usr/share/rustdesk/files/openrc/rustdesk",
    "usr/share/rustdesk/files/runit/run",
    "usr/share/rustdesk/rustdesk",
}
DEBIAN_DATA_REQUIRED_FILES.update(DEBIAN_FLUTTER_LIBRARIES)
DEBIAN_VARIABLE_DATA_ROOT = "usr/share/rustdesk/data/flutter_assets"

os.environ["CARGO_PROFILE_RELEASE_RPATH"] = "false"


def get_deb_arch() -> str:
    custom_arch = os.environ.get("DEB_ARCH")
    if custom_arch is None:
        return "amd64"
    return custom_arch

def get_deb_extra_depends() -> str:
    custom_arch = os.environ.get("DEB_ARCH")
    if custom_arch == "armhf": # for arm32v7 libsciter-gtk.so
        return ", libatomic1"
    return ""

def system2(cmd):
    exit_code = os.system(cmd)
    if exit_code != 0:
        sys.stderr.write(f"Error occurred when executing: `{cmd}`. Exiting.\n")
        sys.exit(-1)


def get_version():
    with open("Cargo.toml", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("version"):
                return line.replace("version", "").replace("=", "").replace('"', '').strip()
    return ''


def parse_rc_features(feature):
    available_features = {}
    apply_features = {}
    if not feature:
        feature = []

    def platform_check(platforms):
        if windows:
            return 'windows' in platforms
        elif osx:
            return 'osx' in platforms
        else:
            return 'linux' in platforms

    def get_all_features():
        features = []
        for (feat, feat_info) in available_features.items():
            if platform_check(feat_info['platform']):
                features.append(feat)
        return features

    if isinstance(feature, str) and feature.upper() == 'ALL':
        return get_all_features()
    elif isinstance(feature, list):
        if windows:
            # download third party is deprecated, we use github ci instead.
            # feature.append('PrivacyMode')
            pass
        for feat in feature:
            if isinstance(feat, str) and feat.upper() == 'ALL':
                return get_all_features()
            if feat in available_features:
                if platform_check(available_features[feat]['platform']):
                    apply_features[feat] = available_features[feat]
            else:
                print(f'Unrecognized feature {feat}')
        return apply_features
    else:
        raise Exception(f'Unsupported features param {feature}')


def make_parser():
    parser = argparse.ArgumentParser(description='Build script.')
    parser.add_argument(
        '-f',
        '--feature',
        dest='feature',
        metavar='N',
        type=str,
        nargs='+',
        default='',
        help='Integrate features, windows only.'
             'Available: [Not used for now]. Special value is "ALL" and empty "". Default is empty.')
    parser.add_argument('--flutter', action='store_true',
                        help='Build flutter package', default=False)
    parser.add_argument(
        '--unix-file-copy-paste',
        action='store_true',
        help='Build with unix file copy paste feature'
    )
    parser.add_argument(
        '--skip-cargo',
        action='store_true',
        help='Skip cargo build process, only flutter version + Linux supported currently'
    )
    if osx:
        parser.add_argument(
            '--screencapturekit',
            action='store_true',
            help='Enable feature screencapturekit'
        )
    return parser


# Downloading third party resources is deprecated.
# We can use this function in an offline build environment.
# Even in an online environment, we recommend building third-party resources yourself.
def download_extract_features(features, res_dir):
    proxy = ''

    def req(url):
        if not proxy:
            return url
        else:
            r = urllib.request.Request(url)
            r.set_proxy(proxy, 'http')
            r.set_proxy(proxy, 'https')
            return r

    for (feat, feat_info) in features.items():
        includes = feat_info['include'] if 'include' in feat_info and feat_info['include'] else []
        includes = [re.compile(p) for p in includes]
        excludes = feat_info['exclude'] if 'exclude' in feat_info and feat_info['exclude'] else []
        excludes = [re.compile(p) for p in excludes]

        print(f'{feat} download begin')
        download_filename = feat_info['zip_url'].split('/')[-1]
        checksum_md5_response = urllib.request.urlopen(
            req(feat_info['checksum_url']))
        for line in checksum_md5_response.read().decode('utf-8').splitlines():
            if line.split()[1] == download_filename:
                checksum_md5 = line.split()[0]
                filename, _headers = urllib.request.urlretrieve(feat_info['zip_url'],
                                                                download_filename)
                md5 = hashlib.md5(open(filename, 'rb').read()).hexdigest()
                if checksum_md5 != md5:
                    raise Exception(f'{feat} download failed')
                print(f'{feat} download end. extract bein')
                zip_file = zipfile.ZipFile(filename)
                zip_list = zip_file.namelist()
                for f in zip_list:
                    file_exclude = False
                    for p in excludes:
                        if p.match(f) is not None:
                            file_exclude = True
                            break
                    if file_exclude:
                        continue

                    file_include = False if includes else True
                    for p in includes:
                        if p.match(f) is not None:
                            file_include = True
                            break
                    if file_include:
                        print(f'extract file {f}')
                        zip_file.extract(f, res_dir)
                zip_file.close()
                os.remove(download_filename)
                print(f'{feat} extract end')


def external_resources(flutter, args, res_dir):
    features = parse_rc_features(args.feature)
    if not features:
        return

    print(f'Build with features {list(features.keys())}')
    if os.path.isdir(res_dir) and not os.path.islink(res_dir):
        shutil.rmtree(res_dir)
    elif os.path.exists(res_dir):
        raise Exception(f'Find file {res_dir}, not a directory')
    os.makedirs(res_dir, exist_ok=True)
    download_extract_features(features, res_dir)
    if flutter:
        os.makedirs(flutter_build_dir_2, exist_ok=True)
        for f in pathlib.Path(res_dir).iterdir():
            print(f'{f}')
            if f.is_file():
                shutil.copy2(f, flutter_build_dir_2)
            else:
                shutil.copytree(f, f'{flutter_build_dir_2}{f.stem}')


def get_features(args):
    features = ['inline'] if not args.flutter else []
    if args.flutter:
        features.append('flutter')
    if args.unix_file_copy_paste:
        features.append('unix-file-copy-paste')
    if osx:
        if args.screencapturekit:
            features.append('screencapturekit')
    print("features:", features)
    return features


def generate_control_file(version, destination):
    content = """Package: rustdesk
Section: net
Priority: optional
Version: %s
Architecture: %s
Maintainer: rustdesk <info@rustdesk.com>
Homepage: https://rustdesk.com
Depends: init-system-helpers, libgtk-3-0t64 | libgtk-3-0, libxcb-randr0, libxdo3 | libxdo4, libxfixes3, libxcb-shape0, libxcb-xfixes0, libasound2t64 | libasound2, libsystemd0, curl, libgstreamer-plugins-base1.0-0, gstreamer1.0-pipewire%s
Recommends: libayatana-appindicator3-1
Description: A remote control software.

""" % (version, get_deb_arch(), get_deb_extra_depends())
    with Path(destination).open("x", encoding="utf-8", newline="\n") as file:
        file.write(content)
    os.chmod(destination, 0o644)


def stage_debian_control_files(version, source_dir, control_dir):
    source_dir = Path(source_dir)
    control_dir = Path(control_dir)
    source_dir_info = os.lstat(source_dir)
    if not stat.S_ISDIR(source_dir_info.st_mode):
        raise RuntimeError(f"Debian maintainer-script source is not a directory: {source_dir}")
    source_entries = {entry.name for entry in os.scandir(source_dir)}
    expected_sources = set(DEBIAN_MAINTAINER_SCRIPTS)
    if source_entries != expected_sources:
        raise RuntimeError(
            f"Debian maintainer-script inventory differs: {sorted(source_entries)}"
        )
    control_dir.mkdir(mode=0o755)
    os.chmod(control_dir, 0o755)
    generate_control_file(version, control_dir / "control")
    conffiles = control_dir / "conffiles"
    with conffiles.open("x", encoding="ascii", newline="\n") as output:
        for name in DEBIAN_CONFFILES:
            output.write(f"/{name}\n")
    os.chmod(conffiles, 0o644)
    for name in DEBIAN_MAINTAINER_SCRIPTS:
        source = source_dir / name
        source_info = os.lstat(source)
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1:
            raise RuntimeError(f"Debian maintainer script is not a non-hardlinked regular file: {source}")
        destination = control_dir / name
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o755)
        destination_info = os.lstat(destination)
        if (not stat.S_ISREG(destination_info.st_mode)
                or destination_info.st_nlink != 1
                or stat.S_IMODE(destination_info.st_mode) != 0o755
                or source.read_bytes() != destination.read_bytes()):
            raise RuntimeError(f"Debian maintainer script staging failed: {name}")


def inventory_debian_package_tree(root):
    directories = {}
    files = {}

    def visit(directory, relative):
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            if any(character in entry.name for character in ("/", "\n", "\r", "\0")):
                raise RuntimeError(f"unsupported Debian package entry name: {entry.name!r}")
            entry_relative = relative / entry.name
            relative_text = entry_relative.as_posix()
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                directories[relative_text] = info
                visit(Path(entry.path), entry_relative)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files[relative_text] = info
            else:
                raise RuntimeError(
                    f"Debian package tree contains a link, special file, or hardlink: {relative_text}"
                )

    root = Path(root)
    root_info = os.lstat(root)
    if not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeError(f"Debian package staging root is not a directory: {root}")
    visit(root, Path())
    return directories, files


def finalize_debian_package_tree(root):
    root = Path(root)
    directories, files = inventory_debian_package_tree(root)
    if {entry.name for entry in os.scandir(root)} != {"DEBIAN", "etc", "usr"}:
        raise RuntimeError("Debian package staging root has an unexpected top-level inventory")
    if not {"DEBIAN", "etc", "usr"}.issubset(directories):
        raise RuntimeError("Debian package staging root lacks a required top-level directory")
    if any(name.startswith("DEBIAN/") for name in directories):
        raise RuntimeError("Debian control area contains a nested directory")
    control_files = {
        name[len("DEBIAN/"):]
        for name in files
        if name.startswith("DEBIAN/")
    }
    expected_before_md5 = set(DEBIAN_CONTROL_MODES) - {"md5sums"}
    if control_files != expected_before_md5:
        raise RuntimeError(f"Debian control inventory differs: {sorted(control_files)}")

    data_directories = set(directories) - {"DEBIAN"}
    data_files = {name for name in files if not name.startswith("DEBIAN/")}
    missing_directories = DEBIAN_DATA_REQUIRED_DIRECTORIES - data_directories
    missing_files = DEBIAN_DATA_REQUIRED_FILES - data_files
    unexpected_directories = {
        name for name in data_directories
        if name not in DEBIAN_DATA_REQUIRED_DIRECTORIES
        and not name.startswith(f"{DEBIAN_VARIABLE_DATA_ROOT}/")
    }
    unexpected_files = {
        name for name in data_files
        if name not in DEBIAN_DATA_REQUIRED_FILES
        and not name.startswith(f"{DEBIAN_VARIABLE_DATA_ROOT}/")
    }
    if missing_directories or missing_files or unexpected_directories or unexpected_files:
        raise RuntimeError(
            "Debian package data inventory differs: "
            f"missing directories {sorted(missing_directories)}, "
            f"missing files {sorted(missing_files)}, "
            f"unexpected directories {sorted(unexpected_directories)}, "
            f"unexpected files {sorted(unexpected_files)}"
        )

    md5sums = root / "DEBIAN/md5sums"
    with md5sums.open("x", encoding="ascii", newline="\n") as output:
        for name in sorted(data_files - set(DEBIAN_CONFFILES)):
            digest = hashlib.md5()
            with (root / name).open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            output.write(f"{digest.hexdigest()}  /{name}\n")

    directories, files = inventory_debian_package_tree(root)
    control_files = {
        name[len("DEBIAN/"):]
        for name in files
        if name.startswith("DEBIAN/")
    }
    if control_files != set(DEBIAN_CONTROL_MODES):
        raise RuntimeError(f"final Debian control inventory differs: {sorted(control_files)}")

    os.chmod(root, 0o755)
    for name in sorted(directories):
        os.chmod(root / name, 0o755)
    for name in sorted(files):
        if name.startswith("DEBIAN/"):
            mode = DEBIAN_CONTROL_MODES[name[len("DEBIAN/"):]]
        else:
            mode = 0o755 if name in DEBIAN_DATA_EXECUTABLES else 0o644
        os.chmod(root / name, mode)

    root_info = os.lstat(root)
    if stat.S_IMODE(root_info.st_mode) != 0o755:
        raise RuntimeError("Debian package staging root mode is not 0755")
    final_directories, final_files = inventory_debian_package_tree(root)
    if set(final_directories) != set(directories) or set(final_files) != set(files):
        raise RuntimeError("Debian package inventory changed during mode finalization")
    for name, info in final_directories.items():
        if stat.S_IMODE(info.st_mode) != 0o755:
            raise RuntimeError(f"Debian package directory mode is not 0755: {name}")
    for name, info in final_files.items():
        if name.startswith("DEBIAN/"):
            expected = DEBIAN_CONTROL_MODES[name[len("DEBIAN/"):]]
        else:
            expected = 0o755 if name in DEBIAN_DATA_EXECUTABLES else 0o644
        if stat.S_IMODE(info.st_mode) != expected:
            raise RuntimeError(f"Debian package file mode differs for {name}: {stat.S_IMODE(info.st_mode):04o}")


def build_debian_archive(staging, destination):
    subprocess.run(
        ["dpkg-deb", "--root-owner-group", "-b", str(staging), str(destination)],
        check=True,
    )


def ffi_bindgen_function_refactor():
    # workaround ffigen
    system2(
        'sed -i "s/ffi.NativeFunction<ffi.Bool Function(DartPort/ffi.NativeFunction<ffi.Uint8 Function(DartPort/g" flutter/lib/generated_bridge.dart')


def build_flutter_deb(version, features):
    if not skip_cargo:
        system2(f'cargo build --locked --features {features} --lib --release')
        ffi_bindgen_function_refactor()
    os.chdir('flutter')
    system2('/bin/rm -rf build/linux')
    system2('flutter build linux --release')
    system2('/bin/rm -rf tmpdeb')
    system2('mkdir -p tmpdeb/usr/share/rustdesk')
    system2('mkdir -p tmpdeb/etc/init.d/')
    system2('mkdir -p tmpdeb/etc/rustdesk/')
    system2('mkdir -p tmpdeb/usr/lib/systemd/system/')
    system2('mkdir -p tmpdeb/usr/share/icons/hicolor/256x256/apps/')
    system2('mkdir -p tmpdeb/usr/share/icons/hicolor/scalable/apps/')
    system2('mkdir -p tmpdeb/usr/share/applications/')
    system2('mkdir -p tmpdeb/usr/share/polkit-1/actions')
    system2(
        f'cp -r {flutter_build_dir}/* tmpdeb/usr/share/rustdesk/')
    system2(
        'cp ../res/rustdesk.service tmpdeb/usr/lib/systemd/system/rustdesk.service')
    system2(
        'cp -r ../res/service-managers/. tmpdeb/usr/share/rustdesk/files/')
    system2('cp ../res/rustdesk.init tmpdeb/etc/init.d/rustdesk')
    system2(
        'cp ../res/128x128@2x.png tmpdeb/usr/share/icons/hicolor/256x256/apps/rustdesk.png')
    system2(
        'cp ../res/scalable.svg tmpdeb/usr/share/icons/hicolor/scalable/apps/rustdesk.svg')
    system2(
        'cp ../res/rustdesk.desktop tmpdeb/usr/share/applications/rustdesk.desktop')
    system2(
        'cp ../res/rustdesk-link.desktop tmpdeb/usr/share/applications/rustdesk-link.desktop')
    system2(
        'cp ../res/com.carriez.RustDesk.policy tmpdeb/usr/share/polkit-1/actions/')
    system2(
        'cp ../res/startwm.sh tmpdeb/etc/rustdesk/')
    system2(
        'cp ../res/xorg.conf tmpdeb/etc/rustdesk/')
    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")
    finalize_debian_package_tree("tmpdeb")
    build_debian_archive("tmpdeb", "rustdesk.deb")

    system2('/bin/rm -rf tmpdeb/')
    os.rename('rustdesk.deb', '../rustdesk-%s.deb' % version)
    os.chdir("..")


def build_flutter_dmg(version, features):
    if not skip_cargo:
        # set minimum osx build target, now is 10.14, which is the same as the flutter xcode project
        system2(
            f'MACOSX_DEPLOYMENT_TARGET=10.14 cargo build --locked --features {features} --release')
    # copy dylib
    system2(
        "cp target/release/liblibrustdesk.dylib target/release/librustdesk.dylib")
    os.chdir('flutter')
    system2('flutter build macos --release')
    system2('cp -rf ../target/release/service ./build/macos/Build/Products/Release/RustDesk.app/Contents/MacOS/')
    '''
    system2(
        "create-dmg --volname \"RustDesk Installer\" --window-pos 200 120 --window-size 800 400 --icon-size 100 --app-drop-link 600 185 --icon RustDesk.app 200 190 --hide-extension RustDesk.app rustdesk.dmg ./build/macos/Build/Products/Release/RustDesk.app")
    os.rename("rustdesk.dmg", f"../rustdesk-{version}.dmg")
    '''
    os.chdir("..")


def build_flutter_windows(features):
    if not skip_cargo:
        system2(f'cargo build --locked --features {features} --lib --release')
        if not os.path.exists("target/release/librustdesk.dll"):
            print("cargo build failed, please check rust source code.")
            exit(-1)
    os.chdir('flutter')
    system2('flutter build windows --release')
    os.chdir('..')
    # R-B2 (Windows byte-reproducibility): canonicalize EVERY embedded PE in the flutter dist Release dir
    # NOW -- after `flutter build windows --release` finalizes it and BEFORE the WiX .msi step in
    # scripts/build-windows.ps1 reads it. The setup bootstrapper later embeds that MSI from a dedicated
    # one-file payload directory; it never embeds this Flutter dist directly. cwd is the repo root here,
    # so these in-place edits persist for the later MSI packaging step.
    #
    # Normalize only the explicitly authorized PE reproducibility metadata before
    # WiX and the portable packer consume these embedded binaries.
    # Windows-only path: build_flutter_deb / the Android build never reach here (they run with
    # platform!=Windows), so the .deb/.apk stay byte-identical.
    release_pes = sorted(
        p for p in pathlib.Path(flutter_build_dir_2).rglob('*')
        if p.is_file() and p.suffix.lower() in ('.dll', '.exe'))
    if not release_pes:
        print(f'R-B2: no PE (*.dll/*.exe) under {flutter_build_dir_2} to canonicalize -- flutter build dir empty?')
        exit(-1)
    for pe in release_pes:
        canonicalizer_input = pe.with_name(f'.canonicalize-input-{pe.name}')
        if os.path.lexists(canonicalizer_input):
            raise RuntimeError(f'canonicalizer input path is already occupied: {canonicalizer_input}')
        os.link(pe, canonicalizer_input)
        os.unlink(pe)
        subprocess.run(
            [
                sys.executable,
                'scripts/canonicalize-pe.py',
                '--output',
                str(pe),
                str(canonicalizer_input),
            ],
            check=True,
        )
        canonicalizer_input.unlink()


def main():
    global skip_cargo
    parser = make_parser()
    args = parser.parse_args()

    if not args.flutter:
        raise SystemExit("build.py requires --flutter")
    if os.path.exists(exe_path):
        os.unlink(exe_path)
    # R-B6/R-R2: the Sciter pre-build steps are gone with the Sciter UI — the Arch `git checkout
    # src/ui/common.tis` and the non-flutter `res/inline-sciter.py` inliner referenced deleted files.
    # Every shipped target builds --flutter; there is no Sciter build path to prepare.
    version = get_version()
    features = ','.join(get_features(args))
    flutter = args.flutter
    print(args.skip_cargo)
    if args.skip_cargo:
        skip_cargo = True
    res_dir = 'resources'
    external_resources(flutter, args, res_dir)
    if windows:
        build_flutter_windows(features)
        return
    if osx:
        build_flutter_dmg(version, features)
    else:
        build_flutter_deb(version, features)


if __name__ == "__main__":
    main()
