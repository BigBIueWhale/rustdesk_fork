#!/usr/bin/env python3
import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


DATA_REQUIRED = {
    "./usr/share/rustdesk": ("dir", False),
    "./usr/share/rustdesk/rustdesk": ("file", True),
    "./usr/share/rustdesk/lib": ("dir", False),
    "./usr/share/rustdesk/lib/librustdesk.so": ("file", False),
    "./usr/share/rustdesk/files": ("dir", False),
    "./usr/share/rustdesk/files/systemd": ("dir", False),
    "./usr/share/rustdesk/files/systemd/rustdesk.service": ("file", False),
    "./usr/share/polkit-1/actions/com.carriez.RustDesk.policy": ("file", False),
}
CONTROL_REQUIRED = {
    "./control": ("file", False),
    "./md5sums": ("file", False),
    "./preinst": ("file", True),
    "./postinst": ("file", True),
    "./prerm": ("file", True),
    "./postrm": ("file", True),
}
AUTHORITY_PREFIXES = (
    "./usr/share/rustdesk",
    "./usr/share/polkit-1/actions",
    "./etc/rustdesk",
)


class ValidationError(Exception):
    pass


def fail(message):
    print(f"FAIL Debian package authority: {message}", file=sys.stderr)
    sys.exit(1)


def normalize_tar_name(name):
    if name in ("", "."):
        return "."
    if name.startswith("./"):
        return name.rstrip("/")
    return f"./{name.rstrip('/')}"


def is_under(name, prefix):
    return name == prefix or name.startswith(f"{prefix}/")


def tar_members_from_deb(deb, option):
    data = tar_stream_from_deb(deb, option)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            return {normalize_tar_name(member.name): member for member in archive.getmembers()}
    except tarfile.TarError as err:
        raise ValidationError(f"{deb}: failed to read {option} tar stream: {err}") from err


def tar_stream_from_deb(deb, option):
    if shutil.which("dpkg-deb") is None:
        raise ValidationError("dpkg-deb is required")
    try:
        return subprocess.check_output(["dpkg-deb", option, str(deb)])
    except subprocess.CalledProcessError as err:
        raise ValidationError(f"{deb}: dpkg-deb {option} failed with status {err.returncode}") from err


def require_root_unwritable(member, label):
    if member.uid != 0 or member.gid != 0:
        raise ValidationError(f"{label}: owner is {member.uid}/{member.gid}, expected 0/0")
    if (member.isfile() or member.isdir()) and member.mode & 0o022:
        raise ValidationError(f"{label}: mode {member.mode:o} is group/world writable")


def require_member(members, path, expected_kind, executable, label):
    member = members.get(path)
    if member is None:
        raise ValidationError(f"{label}: missing required archive member {path}")
    require_root_unwritable(member, f"{label}:{path}")
    if expected_kind == "dir" and not member.isdir():
        raise ValidationError(f"{label}:{path}: expected directory")
    if expected_kind == "file" and not member.isfile():
        raise ValidationError(f"{label}:{path}: expected regular file")
    if executable and member.mode & 0o111 == 0:
        raise ValidationError(f"{label}:{path}: expected executable mode, got {member.mode:o}")


def validate_authority_prefixes(members, label):
    for name, member in members.items():
        if not any(is_under(name, prefix) for prefix in AUTHORITY_PREFIXES):
            continue
        require_root_unwritable(member, f"{label}:{name}")
        if not member.isfile() and not member.isdir():
            raise ValidationError(f"{label}:{name}: authority tree must contain only regular files and directories")
        if member.issym() or member.islnk():
            raise ValidationError(f"{label}:{name}: authority tree must not contain links")


def validate_control_members(members, label):
    for name, member in members.items():
        require_root_unwritable(member, f"{label}:{name}")
        if not member.isfile() and not member.isdir():
            raise ValidationError(f"{label}:{name}: control archive must contain only regular files and directories")
        if member.issym() or member.islnk():
            raise ValidationError(f"{label}:{name}: control archive must not contain links")


def expected_elf_runpath(name):
    basename = Path(name).name
    if name == "./usr/share/rustdesk/rustdesk":
        return ("$ORIGIN/lib",)
    if is_under(name, "./usr/share/rustdesk/lib") and (
        basename == "libflutter_linux_gtk.so" or basename.endswith("_plugin.so")
    ):
        return ("$ORIGIN",)
    return ()


def parse_runpath_entries(readelf_output, label):
    entries = []
    for line in readelf_output.splitlines():
        if "(RPATH)" in line:
            raise ValidationError(f"{label}: legacy RPATH is forbidden")
        if "(RUNPATH)" not in line:
            continue
        match = re.search(r"\[(.*)\]", line)
        if match is None:
            raise ValidationError(f"{label}: malformed RUNPATH entry")
        value = match.group(1)
        if value:
            entries.extend(value.split(":"))
    return tuple(entries)


def validate_elf_runpaths(deb, data_tar, members):
    if shutil.which("readelf") is None:
        raise ValidationError("readelf is required")
    with tempfile.TemporaryDirectory(prefix="rustdesk-deb-elf.") as tmp:
        tmp = Path(tmp)
        try:
            with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:*") as archive:
                for name, member in sorted(members.items()):
                    if not is_under(name, "./usr/share/rustdesk") or not member.isfile():
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise ValidationError(f"{deb}:data:{name}: cannot read archive member")
                    contents = extracted.read()
                    if not contents.startswith(b"\x7fELF"):
                        continue
                    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name.lstrip("./"))
                    path = tmp / safe_name
                    path.write_bytes(contents)
                    path.chmod(0o755)
                    try:
                        dynamic = subprocess.check_output(
                            ["readelf", "-d", str(path)],
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                    except subprocess.CalledProcessError as err:
                        raise ValidationError(
                            f"{deb}:data:{name}: readelf -d failed with status {err.returncode}: {err.output.strip()}"
                        ) from err
                    actual = parse_runpath_entries(dynamic, f"{deb}:data:{name}")
                    expected = expected_elf_runpath(name)
                    if actual != expected:
                        raise ValidationError(
                            f"{deb}:data:{name}: unexpected RUNPATH {actual!r}, expected {expected!r}"
                        )
        except tarfile.TarError as err:
            raise ValidationError(f"{deb}: failed to inspect data archive ELF runpaths: {err}") from err


def validate_deb(deb):
    data_tar = tar_stream_from_deb(deb, "--fsys-tarfile")
    try:
        with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:*") as archive:
            data_members = {normalize_tar_name(member.name): member for member in archive.getmembers()}
    except tarfile.TarError as err:
        raise ValidationError(f"{deb}: failed to read --fsys-tarfile tar stream: {err}") from err
    control_members = tar_members_from_deb(deb, "--ctrl-tarfile")
    validate_authority_prefixes(data_members, f"{deb}:data")
    validate_control_members(control_members, f"{deb}:control")
    for path, (kind, executable) in DATA_REQUIRED.items():
        require_member(data_members, path, kind, executable, f"{deb}:data")
    for path, (kind, executable) in CONTROL_REQUIRED.items():
        require_member(control_members, path, kind, executable, f"{deb}:control")
    validate_elf_runpaths(deb, data_tar, data_members)


def validate_build_py(repo):
    path = repo / "build.py"
    text = path.read_text()
    cargo = (repo / "Cargo.toml").read_text()
    cmake = (repo / "flutter/linux/CMakeLists.txt").read_text()
    build_debian = (repo / "scripts/build-debian.sh").read_text()
    if re.search(r"(?m)^\s*rpath\s*=\s*true\s*$", cargo):
        raise ValidationError("Cargo.toml release profile must not enable Rust rpath")
    if not re.search(r"(?m)^\s*rpath\s*=\s*false\s*$", cargo):
        raise ValidationError("Cargo.toml release profile must pin rpath = false")
    if 'os.environ["CARGO_PROFILE_RELEASE_RPATH"] = "false"' not in text:
        raise ValidationError("build.py must force release Cargo rpath off")
    if "export CARGO_PROFILE_RELEASE_RPATH=false" not in build_debian:
        raise ValidationError("build-debian.sh must force release Cargo rpath off inside the package build")
    if "BUILD_WITH_INSTALL_RPATH TRUE" not in cmake or 'INSTALL_RPATH "$ORIGIN"' not in cmake:
        raise ValidationError("flutter/linux/CMakeLists.txt must make plugin RUNPATH bundle-relative")
    forced = re.findall(r"dpkg-deb\s+--root-owner-group\s+-b\s+tmpdeb\s+rustdesk\.deb", text)
    if len(forced) != 3:
        raise ValidationError(f"build.py must root-normalize all three Debian package creation paths; found {len(forced)}")
    for line_no, line in enumerate(text.splitlines(), 1):
        if "dpkg-deb" not in line or "-b tmpdeb" not in line:
            continue
        if "--root-owner-group" not in line:
            raise ValidationError(f"build.py:{line_no}: Debian package build lacks --root-owner-group")


def write_file(path, contents, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents)
    path.chmod(mode)


def make_synthetic_tree(root, group_writable_parent=False):
    write_file(
        root / "DEBIAN/control",
        "Package: rustdesk-authority-test\nVersion: 1.0\nArchitecture: all\nMaintainer: test <test@example.invalid>\nDescription: authority test\n",
        0o644,
    )
    write_file(root / "DEBIAN/md5sums", "", 0o644)
    for script in ("preinst", "postinst", "prerm", "postrm"):
        write_file(root / f"DEBIAN/{script}", "#!/bin/sh\nset -e\nexit 0\n", 0o755)
    write_file(root / "usr/share/rustdesk/rustdesk", "#!/bin/sh\nexit 0\n", 0o755)
    write_file(root / "usr/share/rustdesk/lib/librustdesk.so", "not an elf\n", 0o644)
    write_file(root / "usr/share/rustdesk/files/systemd/rustdesk.service", "[Service]\nExecStart=/usr/bin/rustdesk --service\n", 0o644)
    write_file(root / "usr/share/polkit-1/actions/com.carriez.RustDesk.policy", "<policyconfig/>\n", 0o644)
    for directory in (
        root / "DEBIAN",
        root / "usr",
        root / "usr/share",
        root / "usr/share/rustdesk",
        root / "usr/share/rustdesk/lib",
        root / "usr/share/rustdesk/files",
        root / "usr/share/rustdesk/files/systemd",
        root / "usr/share/polkit-1",
        root / "usr/share/polkit-1/actions",
    ):
        directory.chmod(0o755)
    if group_writable_parent:
        (root / "usr/share/rustdesk").chmod(0o775)


def build_synthetic_elf(path, runpath=None, shared=False):
    if shutil.which("cc") is None:
        raise ValidationError("cc is required for ELF RUNPATH self-test")
    with tempfile.TemporaryDirectory(prefix="rustdesk-elf-src.") as tmp:
        source = Path(tmp) / "synthetic.c"
        if shared:
            source.write_text("int rustdesk_synthetic_symbol(void) { return 0; }\n")
            cmd = ["cc", "-shared", "-fPIC", str(source), "-Wl,-soname," + path.name, "-o", str(path)]
        else:
            source.write_text("int main(void) { return 0; }\n")
            cmd = ["cc", str(source), "-o", str(path)]
        if runpath is not None:
            cmd.insert(-2, "-Wl,--enable-new-dtags")
            cmd.insert(-2, "-Wl,-rpath," + runpath)
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as err:
            raise ValidationError(f"synthetic ELF build failed with status {err.returncode}") from err
    path.chmod(0o644 if shared else 0o755)


def populate_valid_synthetic_elves(root):
    build_synthetic_elf(root / "usr/share/rustdesk/rustdesk", "$ORIGIN/lib")
    build_synthetic_elf(root / "usr/share/rustdesk/lib/librustdesk.so", None, shared=True)
    build_synthetic_elf(root / "usr/share/rustdesk/lib/libflutter_linux_gtk.so", "$ORIGIN", shared=True)
    build_synthetic_elf(root / "usr/share/rustdesk/lib/libexample_plugin.so", "$ORIGIN", shared=True)


def chown_tree(root, uid, gid):
    if os.geteuid() != 0:
        return
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        os.chown(path, uid, gid)
    os.chown(root, uid, gid)


def build_deb(staging, output, root_owner_group):
    cmd = ["dpkg-deb"]
    if root_owner_group:
        cmd.append("--root-owner-group")
    cmd.extend(["-b", str(staging), str(output)])
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as err:
        raise ValidationError(f"synthetic dpkg-deb build failed with status {err.returncode}") from err


def expect_validation_failure(deb, expected):
    try:
        validate_deb(deb)
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"{deb}: failed for {err!s}, expected failure containing {expected!r}") from err
    raise ValidationError(f"{deb}: verifier accepted an invalid package")


def run_self_test():
    if shutil.which("dpkg-deb") is None:
        raise ValidationError("dpkg-deb is required for self-test")
    with tempfile.TemporaryDirectory(prefix="rustdesk-deb-authority.") as tmp:
        tmp = Path(tmp)
        bad_owner_tree = tmp / "bad-owner-tree"
        make_synthetic_tree(bad_owner_tree)
        if os.geteuid() == 0:
            chown_tree(bad_owner_tree, 12345, 12345)
        bad_owner_deb = tmp / "bad-owner.deb"
        build_deb(bad_owner_tree, bad_owner_deb, root_owner_group=False)
        expect_validation_failure(bad_owner_deb, "owner is")

        bad_mode_tree = tmp / "bad-mode-tree"
        make_synthetic_tree(bad_mode_tree, group_writable_parent=True)
        bad_mode_deb = tmp / "bad-mode.deb"
        build_deb(bad_mode_tree, bad_mode_deb, root_owner_group=True)
        expect_validation_failure(bad_mode_deb, "group/world writable")

        bad_runpath_tree = tmp / "bad-runpath-tree"
        make_synthetic_tree(bad_runpath_tree)
        build_synthetic_elf(bad_runpath_tree / "usr/share/rustdesk/rustdesk", "/tmp/rustdesk-bad")
        bad_runpath_deb = tmp / "bad-runpath.deb"
        build_deb(bad_runpath_tree, bad_runpath_deb, root_owner_group=True)
        expect_validation_failure(bad_runpath_deb, "unexpected RUNPATH")

        good_tree = tmp / "good-tree"
        make_synthetic_tree(good_tree)
        populate_valid_synthetic_elves(good_tree)
        good_deb = tmp / "good.deb"
        build_deb(good_tree, good_deb, root_owner_group=True)
        validate_deb(good_deb)


def main():
    parser = argparse.ArgumentParser(description="Verify Debian package payload authority for the RustDesk root service.")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--deb", action="append", default=[], help="built .deb to validate; may be repeated")
    parser.add_argument("--self-test", action="store_true", help="run synthetic positive and negative package checks")
    args = parser.parse_args()

    try:
        validate_build_py(Path(args.repo).resolve())
        if args.self_test:
            run_self_test()
        for deb in args.deb:
            validate_deb(Path(deb).resolve())
    except ValidationError as err:
        fail(str(err))

    print("ok  Debian package payload authority is root-owned, non-writable, and source-gated")


if __name__ == "__main__":
    main()
