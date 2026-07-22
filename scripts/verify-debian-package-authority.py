#!/usr/bin/env python3
import argparse
import ast
import copy
import gzip
import hashlib
import importlib.util
import io
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
from pathlib import Path


CONFFILE_PATHS = (
    "./etc/init.d/rustdesk",
    "./etc/rustdesk/startwm.sh",
    "./etc/rustdesk/xorg.conf",
)
DATA_EXECUTABLES = {
    "./etc/init.d/rustdesk",
    "./etc/rustdesk/startwm.sh",
    "./usr/share/rustdesk/files/manual/rustdesk-service",
    "./usr/share/rustdesk/files/openrc/rustdesk",
    "./usr/share/rustdesk/files/runit/run",
    "./usr/share/rustdesk/rustdesk",
}
FLUTTER_LIBRARIES = {
    "./usr/share/rustdesk/lib/libapp.so",
    "./usr/share/rustdesk/lib/libdesktop_drop_plugin.so",
    "./usr/share/rustdesk/lib/libdesktop_multi_window_plugin.so",
    "./usr/share/rustdesk/lib/libflutter_custom_cursor_plugin.so",
    "./usr/share/rustdesk/lib/libflutter_linux_gtk.so",
    "./usr/share/rustdesk/lib/librustdesk.so",
    "./usr/share/rustdesk/lib/libscreen_retriever_plugin.so",
    "./usr/share/rustdesk/lib/libtexture_rgba_renderer_plugin.so",
    "./usr/share/rustdesk/lib/liburl_launcher_linux_plugin.so",
    "./usr/share/rustdesk/lib/libwindow_manager_plugin.so",
    "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
}
DATA_REQUIRED_DIRECTORIES = {
    ".",
    "./etc",
    "./etc/init.d",
    "./etc/rustdesk",
    "./usr",
    "./usr/bin",
    "./usr/lib",
    "./usr/lib/systemd",
    "./usr/lib/systemd/system",
    "./usr/share",
    "./usr/share/applications",
    "./usr/share/icons",
    "./usr/share/icons/hicolor",
    "./usr/share/icons/hicolor/256x256",
    "./usr/share/icons/hicolor/256x256/apps",
    "./usr/share/icons/hicolor/scalable",
    "./usr/share/icons/hicolor/scalable/apps",
    "./usr/share/polkit-1",
    "./usr/share/polkit-1/actions",
    "./usr/share/rustdesk",
    "./usr/share/rustdesk/data",
    "./usr/share/rustdesk/data/flutter_assets",
    "./usr/share/rustdesk/files",
    "./usr/share/rustdesk/files/manual",
    "./usr/share/rustdesk/files/openrc",
    "./usr/share/rustdesk/files/runit",
    "./usr/share/rustdesk/lib",
}
DATA_REQUIRED_FILES = {
    "./etc/init.d/rustdesk",
    "./etc/rustdesk/startwm.sh",
    "./etc/rustdesk/xorg.conf",
    "./usr/lib/systemd/system/rustdesk.service",
    "./usr/share/applications/rustdesk-link.desktop",
    "./usr/share/applications/rustdesk.desktop",
    "./usr/share/icons/hicolor/256x256/apps/rustdesk.png",
    "./usr/share/icons/hicolor/scalable/apps/rustdesk.svg",
    "./usr/share/polkit-1/actions/com.carriez.RustDesk.policy",
    "./usr/share/rustdesk/data/flutter_assets/AssetManifest.bin",
    "./usr/share/rustdesk/data/flutter_assets/FontManifest.json",
    "./usr/share/rustdesk/data/flutter_assets/NOTICES.Z",
    "./usr/share/rustdesk/data/icudtl.dat",
    "./usr/share/rustdesk/files/manual/rustdesk-service",
    "./usr/share/rustdesk/files/openrc/rustdesk",
    "./usr/share/rustdesk/files/runit/run",
    "./usr/share/rustdesk/rustdesk",
}
DATA_REQUIRED_FILES.update(FLUTTER_LIBRARIES)
DATA_REQUIRED_SYMLINKS = {
    "./usr/bin/rustdesk": "../share/rustdesk/rustdesk",
}
DATA_VARIABLE_ROOT = "./usr/share/rustdesk/data/flutter_assets"
MANDATORY_ELVES = {"./usr/share/rustdesk/rustdesk"} | FLUTTER_LIBRARIES
DATA_REQUIRED = {
    name: ("dir", 0o755) for name in DATA_REQUIRED_DIRECTORIES
}
DATA_REQUIRED.update({
    name: ("file", 0o755 if name in DATA_EXECUTABLES else 0o644)
    for name in DATA_REQUIRED_FILES
})
CONTROL_REQUIRED = {
    "./control": ("file", 0o644),
    "./conffiles": ("file", 0o644),
    "./md5sums": ("file", 0o644),
    "./preinst": ("file", 0o755),
    "./postinst": ("file", 0o755),
    "./prerm": ("file", 0o755),
    "./postrm": ("file", 0o755),
}
DYNAMIC_STRING_TAGS = {
    1: "NEEDED",
    14: "SONAME",
    15: "RPATH",
    29: "RUNPATH",
    0x6FFFFEFA: "CONFIG",
    0x6FFFFEFB: "DEPAUDIT",
    0x6FFFFEFC: "AUDIT",
    0x7FFFFFFD: "AUXILIARY",
    0x7FFFFFFF: "FILTER",
}
FORBIDDEN_DYNAMIC_LOADER_TAGS = {
    0x6FFFFEFA,
    0x6FFFFEFB,
    0x6FFFFEFC,
    0x7FFFFFFD,
    0x7FFFFFFF,
}
SAFE_NEEDED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+@-]*\Z")
EXPECTED_PROGRAM_INTERPRETER = b"/lib64/ld-linux-x86-64.so.2\0"


class ValidationError(Exception):
    pass


def fail(message):
    print(f"FAIL Debian package authority: {message}", file=sys.stderr)
    sys.exit(1)


def normalize_tar_name(name):
    if name.endswith("/"):
        name = name[:-1]
    if name == ".":
        return "."
    if name.startswith("./"):
        return name
    return f"./{name}"


def is_under(name, prefix):
    return name == prefix or name.startswith(f"{prefix}/")


def canonical_tar_text_field(field, label):
    nul = field.find(b"\0")
    if nul < 0:
        return field
    if any(field[nul + 1:]):
        raise ValidationError(f"{label}: tar text field has nonzero bytes after NUL")
    return field[:nul]


def raw_tar_member_name(archive, member, label):
    if member.pax_headers:
        raise ValidationError(f"{label}: extended tar path metadata is forbidden")
    archive.fileobj.seek(member.offset)
    header = archive.fileobj.read(512)
    if len(header) != 512:
        raise ValidationError(f"{label}: archive member header is truncated")
    type_flag = header[156:157]
    if member.isdir():
        expected_type = tarfile.DIRTYPE
    elif member.isfile():
        expected_type = tarfile.REGTYPE
    else:
        expected_type = member.type
    if type_flag != expected_type:
        raise ValidationError(f"{label}: extended or mismatched tar member header is forbidden")

    name_bytes = canonical_tar_text_field(header[:100], f"{label}:name")
    link_bytes = canonical_tar_text_field(header[157:257], f"{label}:linkname")
    user_bytes = canonical_tar_text_field(header[265:297], f"{label}:uname")
    group_bytes = canonical_tar_text_field(header[297:329], f"{label}:gname")
    prefix_bytes = canonical_tar_text_field(header[345:500], f"{label}:prefix")
    if (member.isfile() or member.isdir()) and link_bytes:
        raise ValidationError(f"{label}: regular file or directory has a nonempty tar link name")
    if member.issym():
        try:
            decoded_link = link_bytes.decode("utf-8")
        except UnicodeDecodeError as err:
            raise ValidationError(f"{label}: symbolic-link target is not UTF-8") from err
        if member.linkname != decoded_link:
            raise ValidationError(f"{label}: tar parser normalized the symbolic-link target")
    if user_bytes != b"root" or group_bytes != b"root":
        raise ValidationError(f"{label}: tar owner names are not canonical root/root")
    if prefix_bytes:
        name_bytes = prefix_bytes + b"/" + name_bytes
    try:
        return name_bytes.decode("utf-8")
    except UnicodeDecodeError as err:
        raise ValidationError(f"{label}: archive member name is not UTF-8") from err


def tar_members_from_stream(data, label):
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            members = {}
            for member in archive.getmembers():
                stored_name = raw_tar_member_name(archive, member, label)
                if stored_name.startswith("/"):
                    raise ValidationError(f"{label}: archive member has an absolute name: {stored_name!r}")
                if stored_name == "./":
                    if not member.isdir():
                        raise ValidationError(f"{label}: archive root is not a directory")
                    name = "."
                else:
                    if not stored_name.startswith("./"):
                        raise ValidationError(
                            f"{label}: archive member lacks the canonical ./ prefix: {stored_name!r}"
                        )
                    if stored_name.endswith("/"):
                        if not member.isdir():
                            raise ValidationError(
                                f"{label}: non-directory archive member has a trailing slash: {stored_name!r}"
                            )
                        if stored_name.endswith("//"):
                            raise ValidationError(
                                f"{label}: directory archive member has redundant trailing slashes: {stored_name!r}"
                            )
                        raw_name = stored_name[:-1]
                    elif member.isdir():
                        raise ValidationError(
                            f"{label}: directory archive member lacks its canonical trailing slash: {stored_name!r}"
                        )
                    else:
                        raw_name = stored_name
                    if any(character in raw_name for character in ("\n", "\r", "\0")):
                        raise ValidationError(f"{label}: archive member has an unsupported name")
                    relative = raw_name[2:]
                    if not relative or any(part in ("", ".", "..") for part in relative.split("/")):
                        raise ValidationError(f"{label}: archive member has a non-canonical name: {stored_name!r}")
                    name = raw_name
                if member.name != name:
                    raise ValidationError(
                        f"{label}: tar parser normalized {stored_name!r} to unexpected {member.name!r}"
                    )
                if name in members:
                    raise ValidationError(f"{label}: duplicate archive member: {name}")
                members[name] = member
            return members
    except tarfile.TarError as err:
        raise ValidationError(f"{label}: failed to read tar stream: {err}") from err


def tar_members_from_deb(deb, option):
    return tar_members_from_stream(tar_stream_from_deb(deb, option), f"{deb}:{option}")


def tar_stream_from_deb(deb, option):
    if shutil.which("dpkg-deb") is None:
        raise ValidationError("dpkg-deb is required")
    try:
        return subprocess.check_output(["dpkg-deb", option, str(deb)])
    except subprocess.CalledProcessError as err:
        raise ValidationError(f"{deb}: dpkg-deb {option} failed with status {err.returncode}") from err


def require_root_owned(member, label):
    if member.uid != 0 or member.gid != 0:
        raise ValidationError(f"{label}: owner is {member.uid}/{member.gid}, expected 0/0")


def require_member(members, path, expected_kind, expected_mode, label):
    member = members.get(path)
    if member is None:
        raise ValidationError(f"{label}: missing required archive member {path}")
    require_root_owned(member, f"{label}:{path}")
    if expected_kind == "dir" and not member.isdir():
        raise ValidationError(f"{label}:{path}: expected directory")
    if expected_kind == "file" and not member.isfile():
        raise ValidationError(f"{label}:{path}: expected regular file")
    if member.mode != expected_mode:
        raise ValidationError(f"{label}:{path}: mode {member.mode:o}, expected {expected_mode:o}")


def require_symlink(members, path, expected_target, label):
    member = members.get(path)
    if member is None:
        raise ValidationError(f"{label}: missing required archive member {path}")
    require_root_owned(member, f"{label}:{path}")
    if not member.issym():
        raise ValidationError(f"{label}:{path}: expected symbolic link")
    if member.mode != 0o777:
        raise ValidationError(f"{label}:{path}: mode {member.mode:o}, expected 777")
    if member.linkname != expected_target:
        raise ValidationError(
            f"{label}:{path}: target {member.linkname!r}, expected {expected_target!r}"
        )


def validate_data_members(members, label):
    for name, member in members.items():
        require_root_owned(member, f"{label}:{name}")
        expected = (
            0o777 if member.issym()
            else 0o755 if member.isdir() or name in DATA_EXECUTABLES
            else 0o644
        )
        if not member.isfile() and not member.isdir() and not member.issym():
            raise ValidationError(
                f"{label}:{name}: package tree must contain only regular files, directories, and the exact command symlink"
            )
        if member.mode != expected:
            raise ValidationError(f"{label}:{name}: mode {member.mode:o}, expected {expected:o}")

    directories = {name for name, member in members.items() if member.isdir()}
    files = {name for name, member in members.items() if member.isfile()}
    symlinks = {
        name: member.linkname for name, member in members.items() if member.issym()
    }
    missing_directories = DATA_REQUIRED_DIRECTORIES - directories
    missing_files = DATA_REQUIRED_FILES - files
    missing_symlinks = set(DATA_REQUIRED_SYMLINKS) - set(symlinks)
    unexpected_directories = {
        name for name in directories
        if name not in DATA_REQUIRED_DIRECTORIES
        and not is_under(name, DATA_VARIABLE_ROOT)
    }
    unexpected_files = {
        name for name in files
        if name not in DATA_REQUIRED_FILES
        and not is_under(name, DATA_VARIABLE_ROOT)
    }
    unexpected_symlinks = set(symlinks) - set(DATA_REQUIRED_SYMLINKS)
    wrong_symlinks = {
        name: target
        for name, target in symlinks.items()
        if DATA_REQUIRED_SYMLINKS.get(name) != target
    }
    if (missing_directories or missing_files or missing_symlinks
            or unexpected_directories or unexpected_files or unexpected_symlinks
            or wrong_symlinks):
        raise ValidationError(
            f"{label}: data inventory differs: "
            f"missing directories {sorted(missing_directories)}, "
            f"missing files {sorted(missing_files)}, "
            f"missing symlinks {sorted(missing_symlinks)}, "
            f"unexpected directories {sorted(unexpected_directories)}, "
            f"unexpected files {sorted(unexpected_files)}, "
            f"unexpected symlinks {sorted(unexpected_symlinks)}, "
            f"wrong symlinks {sorted(wrong_symlinks.items())}"
        )


def validate_control_members(members, label):
    expected_names = {".", *CONTROL_REQUIRED}
    if set(members) != expected_names:
        raise ValidationError(
            f"{label}: control inventory differs: {sorted(set(members) - expected_names)} extra, "
            f"{sorted(expected_names - set(members))} missing"
        )
    root = members["."]
    require_root_owned(root, f"{label}:.")
    if not root.isdir() or root.mode != 0o755:
        raise ValidationError(f"{label}:.: expected mode-755 directory")


def expected_elf_runpath(name):
    basename = Path(name).name
    if name == "./usr/share/rustdesk/rustdesk":
        return ("$ORIGIN/lib",)
    if is_under(name, "./usr/share/rustdesk/lib") and (
        basename == "libflutter_linux_gtk.so" or basename.endswith("_plugin.so")
    ):
        return ("$ORIGIN",)
    return ()


def dynamic_string_values(dynamic_entries, string_table, label):
    if not string_table or string_table[0] != 0 or string_table[-1] != 0:
        raise ValidationError(f"{label}: ELF dynamic string table must begin and end with NUL")
    values = {}
    for tag, offset in dynamic_entries:
        name = DYNAMIC_STRING_TAGS.get(tag)
        if name is None:
            continue
        if offset >= len(string_table):
            raise ValidationError(f"{label}: {name} string offset is out of bounds")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise ValidationError(f"{label}: {name} string is not NUL-terminated")
        try:
            value = string_table[offset:end].decode("ascii")
        except UnicodeDecodeError as err:
            raise ValidationError(f"{label}: {name} string is not ASCII") from err
        values.setdefault(tag, []).append(value)
    return values


def dynamic_runpath(dynamic_entries, string_table, name, label):
    values = dynamic_string_values(dynamic_entries, string_table, label)
    forbidden = sorted(
        DYNAMIC_STRING_TAGS[tag]
        for tag in FORBIDDEN_DYNAMIC_LOADER_TAGS
        if tag in values
    )
    if forbidden:
        raise ValidationError(f"{label}: forbidden dynamic loader tags are present: {forbidden}")

    for needed in values.get(1, []):
        if SAFE_NEEDED_NAME.fullmatch(needed) is None:
            raise ValidationError(f"{label}: NEEDED is not a safe dependency basename: {needed!r}")
    sonames = values.get(14, [])
    if len(sonames) > 1:
        raise ValidationError(f"{label}: multiple SONAME entries are forbidden")
    if sonames and sonames[0] != Path(name).name:
        raise ValidationError(
            f"{label}: SONAME {sonames[0]!r} does not match the installed basename {Path(name).name!r}"
        )

    rpaths = values.get(15, [])
    runpaths = values.get(29, [])
    if rpaths:
        raise ValidationError(f"{label}: legacy RPATH is forbidden")
    if len(runpaths) > 1:
        raise ValidationError(f"{label}: multiple RUNPATH entries are forbidden")
    if not runpaths:
        return (), False
    value = runpaths[0]
    return tuple(value.split(":")) if value else (), True


def validate_runpath_policy(actual, present, name, label):
    expected = expected_elf_runpath(name)
    if actual != expected or present != bool(expected):
        raise ValidationError(
            f"{label}: unexpected RUNPATH {actual!r} "
            f"(present={present}), expected {expected!r}"
        )


def validate_elf_identity(contents, name, label):
    if len(contents) < 64:
        raise ValidationError(f"{label}: ELF header is truncated")
    if contents[4] != 2:
        raise ValidationError(f"{label}: ELF class is not 64-bit")
    if contents[5] != 1:
        raise ValidationError(f"{label}: ELF byte order is not little-endian")
    if contents[6] != 1:
        raise ValidationError(f"{label}: ELF identification version is not current")
    try:
        (
            elf_type,
            machine,
            version,
            _entry,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_name_index,
        ) = struct.unpack_from("<HHIQQQIHHHHHH", contents, 16)
    except struct.error as err:
        raise ValidationError(f"{label}: ELF header cannot be decoded") from err
    if version != 1 or header_size != 64:
        raise ValidationError(f"{label}: ELF header version or size is invalid")
    if machine != 62:
        raise ValidationError(f"{label}: ELF machine is not x86-64")
    expected_types = (2, 3) if name == "./usr/share/rustdesk/rustdesk" else (3,)
    if elf_type not in expected_types:
        expected_text = "ET_EXEC or ET_DYN" if len(expected_types) == 2 else "ET_DYN"
        raise ValidationError(f"{label}: ELF type is {elf_type}, expected {expected_text}")
    if program_count == 0 or program_count == 0xffff or program_entry_size != 56:
        raise ValidationError(f"{label}: ELF program-header table is absent or unsupported")
    program_table_end = program_offset + program_entry_size * program_count
    if program_offset < header_size or program_table_end > len(contents):
        raise ValidationError(f"{label}: ELF program-header table is out of bounds")
    load_segments = []
    dynamic_segments = []
    interpreter_segments = []
    stack_segments = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        try:
            (
                segment_type,
                segment_flags,
                file_offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                align,
            ) = struct.unpack_from("<IIQQQQQQ", contents, offset)
        except struct.error as err:
            raise ValidationError(f"{label}: ELF program header cannot be decoded") from err
        if segment_type == 1:
            if file_size > memory_size or file_offset + file_size > len(contents):
                raise ValidationError(f"{label}: ELF load segment is out of bounds")
            if segment_flags & 1 and segment_flags & 2:
                raise ValidationError(f"{label}: ELF load segment is writable and executable")
            if (align not in (0, 1)
                    and (align & (align - 1) != 0 or file_offset % align != virtual_address % align)):
                raise ValidationError(f"{label}: ELF load segment alignment is invalid")
            load_segments.append((file_offset, virtual_address, file_size))
        elif segment_type == 2:
            dynamic_segments.append((file_offset, virtual_address, file_size, memory_size, align))
        elif segment_type == 3:
            interpreter_segments.append(
                (file_offset, virtual_address, file_size, memory_size, segment_flags, align)
            )
        elif segment_type == 0x6474E551:
            stack_segments.append((
                file_offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                segment_flags,
                align,
            ))

    if name == "./usr/share/rustdesk/rustdesk":
        if len(interpreter_segments) != 1:
            raise ValidationError(f"{label}: ELF runner must contain exactly one program interpreter")
        (
            interpreter_offset,
            interpreter_address,
            interpreter_size,
            interpreter_memory_size,
            interpreter_flags,
            interpreter_align,
        ) = interpreter_segments[0]
        if (interpreter_size != len(EXPECTED_PROGRAM_INTERPRETER)
                or interpreter_memory_size != interpreter_size
                or interpreter_flags != 4
                or interpreter_align != 1
                or interpreter_offset + interpreter_size > len(contents)
                or contents[interpreter_offset:interpreter_offset + interpreter_size] != EXPECTED_PROGRAM_INTERPRETER):
            raise ValidationError(f"{label}: ELF runner program interpreter is not exact")
        interpreter_loads = [
            segment for segment in load_segments
            if interpreter_offset >= segment[0]
            and interpreter_offset + interpreter_size <= segment[0] + segment[2]
            and interpreter_address >= segment[1]
            and interpreter_address + interpreter_size <= segment[1] + segment[2]
            and interpreter_offset - segment[0] == interpreter_address - segment[1]
        ]
        if len(interpreter_loads) != 1:
            raise ValidationError(f"{label}: ELF runner program interpreter is not consistently mapped")
    elif interpreter_segments:
        raise ValidationError(f"{label}: ELF shared object contains a program interpreter")

    if len(stack_segments) != 1:
        raise ValidationError(f"{label}: ELF must contain exactly one GNU stack header")
    (
        stack_offset,
        stack_address,
        stack_physical_address,
        stack_file_size,
        stack_memory_size,
        stack_flags,
        stack_align,
    ) = stack_segments[0]
    if (stack_offset != 0
            or stack_address != 0
            or stack_physical_address != 0
            or stack_file_size != 0
            or stack_memory_size != 0):
        raise ValidationError(f"{label}: ELF GNU stack header must not describe file or memory contents")
    if stack_flags != 6:
        raise ValidationError(f"{label}: ELF GNU stack permissions are not exact non-executable RW")
    if stack_align not in (0, 1) and stack_align & (stack_align - 1) != 0:
        raise ValidationError(f"{label}: ELF GNU stack alignment is not ABI-valid")
    if len(dynamic_segments) != 1:
        raise ValidationError(f"{label}: ELF must contain exactly one dynamic segment")
    dynamic_offset, dynamic_address, dynamic_size, dynamic_memory_size, dynamic_align = dynamic_segments[0]
    if (dynamic_size < 16
            or dynamic_size % 16 != 0
            or dynamic_size > dynamic_memory_size
            or dynamic_offset + dynamic_size > len(contents)):
        raise ValidationError(f"{label}: ELF dynamic segment is out of bounds")
    if (dynamic_align != 8
            or dynamic_offset % dynamic_align != dynamic_address % dynamic_align):
        raise ValidationError(f"{label}: ELF dynamic segment does not have canonical 8-byte alignment")
    dynamic_loads = [
        segment for segment in load_segments
        if dynamic_offset >= segment[0]
        and dynamic_offset + dynamic_size <= segment[0] + segment[2]
        and dynamic_address >= segment[1]
        and dynamic_address + dynamic_size <= segment[1] + segment[2]
        and dynamic_offset - segment[0] == dynamic_address - segment[1]
    ]
    if len(dynamic_loads) != 1:
        raise ValidationError(f"{label}: ELF dynamic segment is not consistently mapped by one load segment")

    dynamic_entries = []
    terminated = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        try:
            tag, value = struct.unpack_from("<QQ", contents, offset)
        except struct.error as err:
            raise ValidationError(f"{label}: ELF dynamic entry cannot be decoded") from err
        if terminated:
            if tag != 0 or value != 0:
                raise ValidationError(f"{label}: ELF dynamic segment has data after DT_NULL")
            continue
        if tag == 0:
            if value != 0:
                raise ValidationError(f"{label}: ELF DT_NULL entry has a nonzero value")
            terminated = True
        else:
            dynamic_entries.append((tag, value))
    if not terminated:
        raise ValidationError(f"{label}: ELF dynamic segment is not DT_NULL-terminated")

    string_addresses = [value for tag, value in dynamic_entries if tag == 5]
    string_sizes = [value for tag, value in dynamic_entries if tag == 10]
    if len(string_addresses) != 1 or len(string_sizes) != 1 or string_sizes[0] == 0:
        raise ValidationError(f"{label}: ELF must contain one bounded dynamic string table")
    string_address = string_addresses[0]
    string_size = string_sizes[0]
    string_loads = [
        segment for segment in load_segments
        if string_address >= segment[1]
        and string_address + string_size <= segment[1] + segment[2]
    ]
    if len(string_loads) != 1:
        raise ValidationError(f"{label}: ELF dynamic string table is not mapped by one load segment")
    string_load = string_loads[0]
    string_offset = string_load[0] + (string_address - string_load[1])
    if string_offset + string_size > len(contents):
        raise ValidationError(f"{label}: ELF dynamic string table is out of bounds")
    string_table = contents[string_offset:string_offset + string_size]
    return dynamic_runpath(dynamic_entries, string_table, name, label)


def validate_elf_runpaths(deb, data_tar, members):
    try:
        with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:*") as archive:
            for name, member in sorted(members.items()):
                if not member.isfile():
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValidationError(f"{deb}:data:{name}: cannot read archive member")
                contents = extracted.read()
                is_elf = contents.startswith(b"\x7fELF")
                if name in MANDATORY_ELVES and not is_elf:
                    raise ValidationError(f"{deb}:data:{name}: required runtime object is not ELF")
                if not is_elf:
                    continue
                actual, present = validate_elf_identity(contents, name, f"{deb}:data:{name}")
                validate_runpath_policy(actual, present, name, f"{deb}:data:{name}")
    except tarfile.TarError as err:
        raise ValidationError(f"{deb}: failed to inspect data archive ELF runpaths: {err}") from err


def archive_member_bytes(archive_data, member, label):
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:*") as archive:
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValidationError(f"{label}: cannot read archive member")
            return extracted.read()
    except tarfile.TarError as err:
        raise ValidationError(f"{label}: failed to read archive member: {err}") from err


def validate_conffiles(control_tar, control_members, label):
    contents = archive_member_bytes(
        control_tar,
        control_members["./conffiles"],
        f"{label}:./conffiles",
    )
    expected = "".join(f"{name[1:]}\n" for name in CONFFILE_PATHS).encode("ascii")
    if contents != expected:
        raise ValidationError(f"{label}:./conffiles: content differs from the exact configuration inventory")


def validate_md5sums(data_tar, data_members, control_tar, control_members, label):
    contents = archive_member_bytes(
        control_tar,
        control_members["./md5sums"],
        f"{label}:control:./md5sums",
    )
    try:
        text = contents.decode("ascii")
    except UnicodeDecodeError as err:
        raise ValidationError(f"{label}:control:./md5sums: content is not ASCII") from err
    if not text.endswith("\n"):
        raise ValidationError(f"{label}:control:./md5sums: missing final newline")

    recorded = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{32})  (/[^\r\n]+)", line)
        if match is None:
            raise ValidationError(f"{label}:control:./md5sums: malformed line")
        name = f".{match.group(2)}"
        if name in recorded:
            raise ValidationError(f"{label}:control:./md5sums: duplicate path {name}")
        recorded[name] = match.group(1)

    expected_names = {
        name for name, member in data_members.items()
        if member.isfile() and name not in CONFFILE_PATHS
    }
    if set(recorded) != expected_names:
        raise ValidationError(
            f"{label}:control:./md5sums: inventory differs: "
            f"{sorted(set(recorded) - expected_names)} extra, "
            f"{sorted(expected_names - set(recorded))} missing"
        )

    try:
        with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:*") as archive:
            for name in sorted(expected_names):
                extracted = archive.extractfile(data_members[name])
                if extracted is None:
                    raise ValidationError(f"{label}:data:{name}: cannot read for md5sums verification")
                digest = hashlib.md5()
                for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                    digest.update(chunk)
                if digest.hexdigest() != recorded[name]:
                    raise ValidationError(f"{label}:control:./md5sums: digest differs for {name}")
    except tarfile.TarError as err:
        raise ValidationError(f"{label}: failed to verify md5sums: {err}") from err


def validate_deb(deb, expected_systemd_unit=None):
    data_tar = tar_stream_from_deb(deb, "--fsys-tarfile")
    data_members = tar_members_from_stream(data_tar, f"{deb}:--fsys-tarfile")
    control_tar = tar_stream_from_deb(deb, "--ctrl-tarfile")
    control_members = tar_members_from_stream(control_tar, f"{deb}:--ctrl-tarfile")
    validate_data_members(data_members, f"{deb}:data")
    validate_control_members(control_members, f"{deb}:control")
    for path, (kind, mode) in DATA_REQUIRED.items():
        require_member(data_members, path, kind, mode, f"{deb}:data")
    for path, target in DATA_REQUIRED_SYMLINKS.items():
        require_symlink(data_members, path, target, f"{deb}:data")
    for path, (kind, mode) in CONTROL_REQUIRED.items():
        require_member(control_members, path, kind, mode, f"{deb}:control")
    validate_conffiles(control_tar, control_members, f"{deb}:control")
    if expected_systemd_unit is not None:
        actual_systemd_unit = archive_member_bytes(
            data_tar,
            data_members["./usr/lib/systemd/system/rustdesk.service"],
            f"{deb}:data:./usr/lib/systemd/system/rustdesk.service",
        )
        if actual_systemd_unit != expected_systemd_unit:
            raise ValidationError(
                f"{deb}:data:./usr/lib/systemd/system/rustdesk.service: bytes differ from res/rustdesk.service"
            )
    validate_elf_runpaths(deb, data_tar, data_members)
    validate_md5sums(data_tar, data_members, control_tar, control_members, str(deb))


def ast_reference_name(value):
    parts = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
        return ".".join(reversed(parts))
    return ""


def ast_call_name(call):
    return ast_reference_name(call.func)


def ast_string(node):
    if sys.version_info >= (3, 8):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
    elif isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = ast_string(node.left)
        right = ast_string(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.FormattedValue):
        value = ast_string(node.value)
        format_spec = "" if node.format_spec is None else ast_string(node.format_spec)
        if value is None or format_spec is None:
            return None
        if node.conversion == ord("r"):
            value = repr(value)
        elif node.conversion == ord("a"):
            value = ascii(value)
        elif node.conversion not in (-1, ord("s")):
            return None
        try:
            return format(value, format_spec)
        except (ValueError, TypeError):
            return None
    if isinstance(node, ast.JoinedStr):
        values = [ast_string(value) for value in node.values]
        if all(value is not None for value in values):
            return "".join(values)
    if (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], (ast.List, ast.Tuple))):
        separator = ast_string(node.func.value)
        values = [ast_string(value) for value in node.args[0].elts]
        if separator is not None and all(value is not None for value in values):
            return separator.join(values)
    return None


def ast_is_true(node):
    if sys.version_info >= (3, 8):
        return isinstance(node, ast.Constant) and node.value is True
    return isinstance(node, ast.NameConstant) and node.value is True


def ast_is_integer(node, expected):
    if sys.version_info >= (3, 8):
        return isinstance(node, ast.Constant) and type(node.value) is int and node.value == expected
    return isinstance(node, ast.Num) and type(node.n) is int and node.n == expected


def named_calls(tree, name):
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and ast_call_name(node) == name
    ]


def direct_call_statement(statement, name, arguments):
    if (not isinstance(statement, ast.Expr)
            or not isinstance(statement.value, ast.Call)
            or ast_call_name(statement.value) != name
            or statement.value.keywords
            or len(statement.value.args) != len(arguments)):
        return False
    return all(
        isinstance(actual, ast.Name) and actual.id == expected[1]
        if expected[0] == "name"
        else ast_string(actual) == expected[1]
        for actual, expected in zip(statement.value.args, arguments)
    )


def single_name_fstring(node, prefix, variable, suffix):
    if not isinstance(node, ast.JoinedStr) or len(node.values) != 3:
        return False
    first, middle, last = node.values
    return (
        ast_string(first) == prefix
        and isinstance(middle, ast.FormattedValue)
        and middle.conversion == -1
        and middle.format_spec is None
        and isinstance(middle.value, ast.Name)
        and middle.value.id == variable
        and ast_string(last) == suffix
    )


def validate_build_py(repo):
    path = repo / "build.py"
    text = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as err:
        raise ValidationError(f"build.py cannot be parsed: {err}") from err
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    package_authority_names = (
        "system2",
        "ffi_bindgen_function_refactor",
        "build_debian_archive",
        "stage_debian_control_files",
        "finalize_debian_package_tree",
        "build_flutter_deb",
    )
    process_authority_names = ("os", "sys", "subprocess")
    expected_imports = (
        ("import", None, 0, (("os", None),)),
        ("import", None, 0, (("pathlib", None),)),
        ("import", None, 0, (("platform", None),)),
        ("import", None, 0, (("zipfile", None),)),
        ("import", None, 0, (("urllib.request", None),)),
        ("import", None, 0, (("shutil", None),)),
        ("import", None, 0, (("hashlib", None),)),
        ("import", None, 0, (("argparse", None),)),
        ("import", None, 0, (("re", None),)),
        ("import", None, 0, (("subprocess", None),)),
        ("import", None, 0, (("stat", None),)),
        ("import", None, 0, (("sys", None),)),
        ("from", "pathlib", 0, (("Path", None),)),
    )
    import_nodes = [
        node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    actual_imports = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            actual_imports.append((
                "import", None, 0,
                tuple((item.name, item.asname) for item in node.names),
            ))
        elif isinstance(node, ast.ImportFrom):
            actual_imports.append((
                "from", node.module, node.level,
                tuple((item.name, item.asname) for item in node.names),
            ))
    if (tuple(actual_imports) != expected_imports
            or len(import_nodes) != len(actual_imports)
            or any(not isinstance(parents.get(node), ast.Module) for node in import_nodes)):
        raise ValidationError("build.py import inventory differs from the exact build authority")
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.decorator_list
        for node in ast.walk(tree)
    ):
        raise ValidationError("build.py authority must not use decorators")
    cargo = (repo / "Cargo.toml").read_text(encoding="utf-8")
    cmake = (repo / "flutter/linux/CMakeLists.txt").read_text(encoding="utf-8")
    build_debian = (repo / "scripts/build-debian.sh").read_text(encoding="utf-8")
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

    required_definitions = {
        "system2",
        "ffi_bindgen_function_refactor",
        "build_debian_archive",
        "stage_debian_control_files",
        "finalize_debian_package_tree",
        "build_flutter_deb",
    }
    authority_definitions = {}
    for name in required_definitions:
        definitions = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
        ]
        if (len(definitions) != 1
                or not isinstance(definitions[0], ast.FunctionDef)
                or not isinstance(parents.get(definitions[0]), ast.Module)):
            raise ValidationError(f"build.py must define one synchronous top-level {name} authority")
        authority_definitions[name] = definitions[0]

    system_defs = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "system2"
    ]
    if len(system_defs) != 1:
        raise ValidationError("build.py must define one exact shell wrapper")
    system_arguments = system_defs[0].args
    if ([argument.arg for argument in system_arguments.args] != ["cmd"]
            or getattr(system_arguments, "posonlyargs", [])
            or system_arguments.kwonlyargs
            or system_arguments.vararg is not None
            or system_arguments.kwarg is not None
            or system_arguments.defaults
            or system_arguments.kw_defaults
            or len(system_defs[0].body) != 2):
        raise ValidationError("build.py shell wrapper signature or body is not exact")
    system_assignment, system_failure = system_defs[0].body
    if (not isinstance(system_assignment, ast.Assign)
            or len(system_assignment.targets) != 1
            or not isinstance(system_assignment.targets[0], ast.Name)
            or system_assignment.targets[0].id != "exit_code"
            or not isinstance(system_assignment.value, ast.Call)
            or ast_call_name(system_assignment.value) != "os.system"
            or system_assignment.value.keywords
            or len(system_assignment.value.args) != 1
            or not isinstance(system_assignment.value.args[0], ast.Name)
            or system_assignment.value.args[0].id != "cmd"):
        raise ValidationError("build.py shell wrapper process call is not exact")
    if (not isinstance(system_failure, ast.If)
            or not isinstance(system_failure.test, ast.Compare)
            or not isinstance(system_failure.test.left, ast.Name)
            or system_failure.test.left.id != "exit_code"
            or len(system_failure.test.ops) != 1
            or not isinstance(system_failure.test.ops[0], ast.NotEq)
            or len(system_failure.test.comparators) != 1
            or not ast_is_integer(system_failure.test.comparators[0], 0)
            or len(system_failure.body) != 2
            or system_failure.orelse
            or not isinstance(system_failure.body[0], ast.Expr)
            or not isinstance(system_failure.body[0].value, ast.Call)
            or ast_call_name(system_failure.body[0].value) != "sys.stderr.write"
            or len(system_failure.body[0].value.args) != 1
            or system_failure.body[0].value.keywords
            or not isinstance(system_failure.body[1], ast.Expr)
            or not isinstance(system_failure.body[1].value, ast.Call)
            or ast_call_name(system_failure.body[1].value) != "sys.exit"
            or len(system_failure.body[1].value.args) != 1
            or system_failure.body[1].value.keywords
            or not isinstance(system_failure.body[1].value.args[0], ast.UnaryOp)
            or not isinstance(system_failure.body[1].value.args[0].op, ast.USub)
            or not ast_is_integer(system_failure.body[1].value.args[0].operand, 1)):
        raise ValidationError("build.py shell wrapper failure handling is not exact")

    ffi_defs = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "ffi_bindgen_function_refactor"
    ]
    if (len(ffi_defs) != 1
            or ffi_defs[0].args.args
            or getattr(ffi_defs[0].args, "posonlyargs", [])
            or ffi_defs[0].args.kwonlyargs
            or ffi_defs[0].args.vararg is not None
            or ffi_defs[0].args.kwarg is not None
            or ffi_defs[0].args.defaults
            or ffi_defs[0].args.kw_defaults
            or len(ffi_defs[0].body) != 1
            or not direct_call_statement(
                ffi_defs[0].body[0],
                "system2",
                ((
                    "string",
                    'sed -i "s/ffi.NativeFunction<ffi.Bool Function(DartPort/'
                    'ffi.NativeFunction<ffi.Uint8 Function(DartPort/g" '
                    "flutter/lib/generated_bridge.dart",
                ),),
            )):
        raise ValidationError("build.py FFI refactor helper is not exact")

    archive_defs = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "build_debian_archive"
    ]
    if len(archive_defs) != 1 or len(archive_defs[0].body) != 1:
        raise ValidationError("build.py must define one single-operation Debian archive boundary")
    archive_arguments = archive_defs[0].args
    if ([argument.arg for argument in archive_arguments.args] != ["staging", "destination"]
            or getattr(archive_arguments, "posonlyargs", [])
            or archive_arguments.kwonlyargs
            or archive_arguments.vararg is not None
            or archive_arguments.kwarg is not None
            or archive_arguments.defaults
            or archive_arguments.kw_defaults):
        raise ValidationError("build.py Debian archive boundary must accept only staging and destination")
    statement = archive_defs[0].body[0]
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        raise ValidationError("build.py Debian archive boundary must contain one checked process call")
    archive_run = statement.value
    if ast_call_name(archive_run) != "subprocess.run" or len(archive_run.args) != 1:
        raise ValidationError("build.py Debian archive boundary must use subprocess.run with one argv")
    argv = archive_run.args[0]
    if not isinstance(argv, (ast.List, ast.Tuple)) or len(argv.elts) != 5:
        raise ValidationError("build.py Debian archive boundary has an unexpected argv shape")
    if [ast_string(item) for item in argv.elts[:3]] != [
        "dpkg-deb", "--root-owner-group", "-b"
    ]:
        raise ValidationError("build.py Debian archive boundary does not pin dpkg-deb ownership normalization")
    for item, argument in zip(argv.elts[3:], ("staging", "destination")):
        if (not isinstance(item, ast.Call)
                or ast_call_name(item) != "str"
                or len(item.args) != 1
                or not isinstance(item.args[0], ast.Name)
                or item.args[0].id != argument):
            raise ValidationError("build.py Debian archive boundary does not bind its explicit paths")
    check_keywords = [keyword for keyword in archive_run.keywords if keyword.arg == "check"]
    if (len(check_keywords) != 1
            or not ast_is_true(check_keywords[0].value)
            or len(archive_run.keywords) != 1):
        raise ValidationError("build.py Debian archive boundary must use check=True and no other process options")

    subprocess_runs = named_calls(tree, "subprocess.run")
    if len(subprocess_runs) != 2 or archive_run not in subprocess_runs:
        raise ValidationError("build.py must contain only the Debian archiver and PE canonicalizer process launches")
    canonicalizer_run = next(call for call in subprocess_runs if call is not archive_run)
    if (len(canonicalizer_run.args) != 1
            or len(canonicalizer_run.keywords) != 1
            or canonicalizer_run.keywords[0].arg != "check"
            or not ast_is_true(canonicalizer_run.keywords[0].value)):
        raise ValidationError("build.py PE canonicalizer process launch has an unexpected shape")
    canonicalizer_argv = canonicalizer_run.args[0]
    if not isinstance(canonicalizer_argv, (ast.List, ast.Tuple)) or len(canonicalizer_argv.elts) != 5:
        raise ValidationError("build.py PE canonicalizer argv has an unexpected shape")
    executable = canonicalizer_argv.elts[0]
    if (not isinstance(executable, ast.Attribute)
            or executable.attr != "executable"
            or not isinstance(executable.value, ast.Name)
            or executable.value.id != "sys"
            or [ast_string(item) for item in canonicalizer_argv.elts[1:3]]
            != ["scripts/canonicalize-pe.py", "--output"]):
        raise ValidationError("build.py PE canonicalizer executable is not exact")
    for item, argument in zip(canonicalizer_argv.elts[3:], ("pe", "canonicalizer_input")):
        if (not isinstance(item, ast.Call)
                or ast_call_name(item) != "str"
                or len(item.args) != 1
                or item.keywords
                or not isinstance(item.args[0], ast.Name)
                or item.args[0].id != argument):
            raise ValidationError("build.py PE canonicalizer paths are not exact")
    forbidden_process_members = (
        "Popen",
        "Process",
        "ProcessPoolExecutor",
        "_exit",
        "call",
        "check_call",
        "check_output",
        "create_subprocess_exec",
        "create_subprocess_shell",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "fork",
        "forkpty",
        "getoutput",
        "getstatusoutput",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "spawn",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "startfile",
        "system",
        "vfork",
    )
    forbidden_dynamic_calls = (
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "eval",
        "exec",
        "compile",
        "__import__",
    )
    if any(named_calls(tree, name) for name in forbidden_dynamic_calls):
        raise ValidationError("build.py retains a dynamic namespace or evaluation API")
    if len(named_calls(tree, "os.system")) != 1:
        raise ValidationError("build.py must confine shell execution to its sole system2 wrapper")
    direct_call_functions = {
        node.func for node in ast.walk(tree) if isinstance(node, ast.Call)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            reference = ast_reference_name(node)
            reference_parts = reference.split(".") if reference is not None else ()
            if (reference not in ("os.system", "subprocess.run")
                    and (node.attr in forbidden_process_members
                         or "subprocess" in reference_parts)):
                raise ValidationError("build.py retains an unsupported process-launch authority")
        if (isinstance(node, ast.Attribute)
                and ast_reference_name(node) in ("subprocess.run", "os.system")
                and node not in direct_call_functions):
            raise ValidationError("build.py process callable references must be direct calls")
        if (isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in package_authority_names
                and node not in direct_call_functions):
            raise ValidationError("build.py package authority callable references must be direct calls")
        if (isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id in process_authority_names + package_authority_names):
            raise ValidationError("build.py must not rebind package or process authority names")
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == "subprocess":
            parent = parents.get(node)
            if (not isinstance(parent, ast.Attribute)
                    or parent.value is not node
                    or ast_reference_name(parent) != "subprocess.run"
                    or parent not in direct_call_functions):
                raise ValidationError("build.py subprocess module references must be exact direct run calls")
        if (isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in forbidden_dynamic_calls + ("__builtins__",)):
            raise ValidationError("build.py dynamic namespace APIs must not be referenced")
        if (isinstance(node, ast.Attribute)
                and (ast_reference_name(node) in ("sys.modules", "sys._getframe")
                     or node.attr in (
                         "__dict__",
                         "__getattr__",
                         "__getattribute__",
                         "__globals__",
                         "__code__",
                         "__delattr__",
                         "__setattr__",
                         "f_globals",
                         "f_locals",
                     ))):
            raise ValidationError("build.py must not reach a module namespace dynamically")
        if (isinstance(node, ast.arg)
                and node.arg in process_authority_names + package_authority_names):
            raise ValidationError("build.py must not shadow package authority names in parameters")
        if (isinstance(node, ast.ExceptHandler)
                and node.name in process_authority_names + package_authority_names):
            raise ValidationError("build.py must not shadow package authority names in exception handlers")
        if (isinstance(node, ast.ClassDef)
                and node.name in process_authority_names + package_authority_names):
            raise ValidationError("build.py must not shadow a package authority name with a class")
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in process_authority_names):
            raise ValidationError("build.py must not shadow a process authority module with a function")
    dpkg_mentions = [
        node for node in ast.walk(tree)
        if ast_string(node) is not None and "dpkg-deb" in ast_string(node)
    ]
    if len(dpkg_mentions) != 1 or dpkg_mentions[0] is not argv.elts[0]:
        raise ValidationError("build.py must contain one executable dpkg-deb authority")

    stage_calls = named_calls(tree, "stage_debian_control_files")
    if (len(stage_calls) != 1
            or len(stage_calls[0].args) != 3
            or not isinstance(stage_calls[0].args[0], ast.Name)
            or stage_calls[0].args[0].id != "version"
            or [ast_string(item) for item in stage_calls[0].args[1:]] != ["../res/DEBIAN", "tmpdeb/DEBIAN"]):
        raise ValidationError("build.py must stage the exact Debian control inventory once")
    finalizer_calls = named_calls(tree, "finalize_debian_package_tree")
    if (len(finalizer_calls) != 1
            or len(finalizer_calls[0].args) != 1
            or ast_string(finalizer_calls[0].args[0]) != "tmpdeb"):
        raise ValidationError("build.py must canonicalize the sole Debian package tree once")
    archive_calls = named_calls(tree, "build_debian_archive")
    if (len(archive_calls) != 1
            or [ast_string(item) for item in archive_calls[0].args] != ["tmpdeb", "rustdesk.deb"]):
        raise ValidationError("build.py must invoke the sole Debian archive boundary once")

    flutter_defs = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "build_flutter_deb"
    ]
    if len(flutter_defs) != 1:
        raise ValidationError("build.py must define one Flutter Debian constructor")
    flutter_arguments = flutter_defs[0].args
    if ([argument.arg for argument in flutter_arguments.args] != ["version", "features"]
            or getattr(flutter_arguments, "posonlyargs", [])
            or flutter_arguments.kwonlyargs
            or flutter_arguments.vararg is not None
            or flutter_arguments.kwarg is not None
            or flutter_arguments.defaults
            or flutter_arguments.kw_defaults):
        raise ValidationError("build.py Flutter Debian constructor must accept only version and features")
    flutter_calls = sorted(
        (node for node in ast.walk(flutter_defs[0]) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    if (stage_calls[0] not in flutter_calls
            or finalizer_calls[0] not in flutter_calls
            or archive_calls[0] not in flutter_calls):
        raise ValidationError("build.py Debian staging, finalization, and archive calls must share the Flutter constructor")
    flutter_body = flutter_defs[0].body
    if any(isinstance(node, (ast.Return, ast.Raise)) for node in ast.walk(flutter_defs[0])):
        raise ValidationError("build.py Flutter Debian constructor must not contain explicit terminating control flow")
    if any(
        ast_call_name(node) in ("exit", "quit", "sys.exit", "os._exit")
        for node in ast.walk(flutter_defs[0])
        if isinstance(node, ast.Call)
    ):
        raise ValidationError("build.py Flutter Debian constructor must not call a process-termination API")
    direct_call_positions = {
        statement.value: index
        for index, statement in enumerate(flutter_body)
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
    }
    if any(call not in direct_call_positions for call in (stage_calls[0], finalizer_calls[0], archive_calls[0])):
        raise ValidationError(
            "build.py must stage, finalize, and archive as direct Flutter constructor operations"
        )
    package_start = direct_call_positions[stage_calls[0]]
    package_prefix = flutter_body[:package_start]
    if len(package_prefix) != 26:
        raise ValidationError("build.py Flutter Debian constructor pre-package inventory differs")
    cargo_block = package_prefix[0]
    if (not isinstance(cargo_block, ast.If)
            or not isinstance(cargo_block.test, ast.UnaryOp)
            or not isinstance(cargo_block.test.op, ast.Not)
            or not isinstance(cargo_block.test.operand, ast.Name)
            or cargo_block.test.operand.id != "skip_cargo"
            or len(cargo_block.body) != 2
            or cargo_block.orelse):
        raise ValidationError("build.py Flutter Debian constructor Cargo block is not exact")
    cargo_statement = cargo_block.body[0]
    if (not isinstance(cargo_statement, ast.Expr)
            or not isinstance(cargo_statement.value, ast.Call)
            or ast_call_name(cargo_statement.value) != "system2"
            or cargo_statement.value.keywords
            or len(cargo_statement.value.args) != 1
            or not single_name_fstring(
                cargo_statement.value.args[0],
                "cargo build --locked --features ",
                "features",
                " --lib --release",
            )
            or not direct_call_statement(
                cargo_block.body[1], "ffi_bindgen_function_refactor", ()
            )):
        raise ValidationError("build.py Flutter Debian constructor Cargo operations are not exact")
    if not direct_call_statement(package_prefix[1], "os.chdir", (("string", "flutter"),)):
        raise ValidationError("build.py Flutter Debian constructor must enter the exact Flutter directory")
    static_package_commands = (
        "/bin/rm -rf build/linux",
        "flutter build linux --release",
        "/bin/rm -rf tmpdeb",
        "mkdir -p tmpdeb/usr/share/rustdesk",
        "mkdir -p tmpdeb/etc/init.d/",
        "mkdir -p tmpdeb/etc/rustdesk/",
        "mkdir -p tmpdeb/usr/bin/",
        "mkdir -p tmpdeb/usr/lib/systemd/system/",
        "mkdir -p tmpdeb/usr/share/icons/hicolor/256x256/apps/",
        "mkdir -p tmpdeb/usr/share/icons/hicolor/scalable/apps/",
        "mkdir -p tmpdeb/usr/share/applications/",
        "mkdir -p tmpdeb/usr/share/polkit-1/actions",
    )
    for statement, command in zip(package_prefix[2:14], static_package_commands):
        if not direct_call_statement(statement, "system2", (("string", command),)):
            raise ValidationError("build.py Flutter Debian constructor setup operations are not exact")
    bundle_copy = package_prefix[14]
    if (not isinstance(bundle_copy, ast.Expr)
            or not isinstance(bundle_copy.value, ast.Call)
            or ast_call_name(bundle_copy.value) != "system2"
            or bundle_copy.value.keywords
            or len(bundle_copy.value.args) != 1
            or not single_name_fstring(
                bundle_copy.value.args[0],
                "cp -r ",
                "flutter_build_dir",
                "/* tmpdeb/usr/share/rustdesk/",
            )):
        raise ValidationError("build.py Flutter Debian bundle copy is not exact")
    resource_copy_commands = (
        "cp ../res/rustdesk.service tmpdeb/usr/lib/systemd/system/rustdesk.service",
        "cp -r ../res/service-managers/. tmpdeb/usr/share/rustdesk/files/",
        "cp ../res/rustdesk.init tmpdeb/etc/init.d/rustdesk",
        "cp ../res/128x128@2x.png tmpdeb/usr/share/icons/hicolor/256x256/apps/rustdesk.png",
        "cp ../res/scalable.svg tmpdeb/usr/share/icons/hicolor/scalable/apps/rustdesk.svg",
        "cp ../res/rustdesk.desktop tmpdeb/usr/share/applications/rustdesk.desktop",
        "cp ../res/rustdesk-link.desktop tmpdeb/usr/share/applications/rustdesk-link.desktop",
        "cp ../res/com.carriez.RustDesk.policy tmpdeb/usr/share/polkit-1/actions/",
        "cp ../res/startwm.sh tmpdeb/etc/rustdesk/",
        "cp ../res/xorg.conf tmpdeb/etc/rustdesk/",
    )
    for statement, command in zip(package_prefix[15:25], resource_copy_commands):
        if not direct_call_statement(statement, "system2", (("string", command),)):
            raise ValidationError("build.py Flutter Debian resource copies are not exact")
    if not direct_call_statement(
        package_prefix[25],
        "os.symlink",
        (
            ("string", "../share/rustdesk/rustdesk"),
            ("string", "tmpdeb/usr/bin/rustdesk"),
        ),
    ):
        raise ValidationError("build.py Flutter Debian command symlink is not exact")
    if [
        direct_call_positions[stage_calls[0]],
        direct_call_positions[finalizer_calls[0]],
        direct_call_positions[archive_calls[0]],
    ] != [package_start, package_start + 1, package_start + 2]:
        raise ValidationError(
            "build.py must stage, finalize, and archive as contiguous direct operations"
        )
    package_tail = flutter_body[package_start + 3:]
    if (len(package_tail) != 3
            or any(not isinstance(item, ast.Expr) or not isinstance(item.value, ast.Call) for item in package_tail)):
        raise ValidationError("build.py Debian archive boundary must have one exact publication tail")
    cleanup_call, rename_call, chdir_call = [item.value for item in package_tail]
    if (ast_call_name(cleanup_call) != "system2"
            or len(cleanup_call.args) != 1
            or cleanup_call.keywords
            or ast_string(cleanup_call.args[0]) != "/bin/rm -rf tmpdeb/"):
        raise ValidationError("build.py must remove the finalized staging tree immediately after archiving")
    if (ast_call_name(rename_call) != "os.rename"
            or len(rename_call.args) != 2
            or rename_call.keywords
            or ast_string(rename_call.args[0]) != "rustdesk.deb"):
        raise ValidationError("build.py Debian archive publication rename is not exact")
    rename_destination = rename_call.args[1]
    if (not isinstance(rename_destination, ast.BinOp)
            or not isinstance(rename_destination.op, ast.Mod)
            or ast_string(rename_destination.left) != "../rustdesk-%s.deb"
            or not isinstance(rename_destination.right, ast.Name)
            or rename_destination.right.id != "version"):
        raise ValidationError("build.py Debian archive publication destination is not version-bound")
    if (ast_call_name(chdir_call) != "os.chdir"
            or len(chdir_call.args) != 1
            or chdir_call.keywords
            or ast_string(chdir_call.args[0]) != ".."):
        raise ValidationError("build.py Debian constructor must end by returning to the repository root")
    clean_lines = [
        node.lineno for node in flutter_calls
        if ast_call_name(node) == "system2"
        and len(node.args) == 1
        and ast_string(node.args[0]) == "/bin/rm -rf build/linux"
    ]
    build_lines = [
        node.lineno for node in flutter_calls
        if ast_call_name(node) == "system2"
        and len(node.args) == 1
        and ast_string(node.args[0]) == "flutter build linux --release"
    ]
    if len(clean_lines) != 1 or len(build_lines) != 1 or clean_lines[0] >= build_lines[0]:
        raise ValidationError("build.py must remove the Linux Flutter output before rebuilding it")

    system2_owners = {}
    for call in named_calls(tree, "system2"):
        owner = parents.get(call)
        while owner is not None and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            owner = parents.get(owner)
        owner_name = owner.name if owner is not None else "<module>"
        system2_owners[owner_name] = system2_owners.get(owner_name, 0) + 1
    if system2_owners != {
        "ffi_bindgen_function_refactor": 1,
        "build_flutter_deb": 25,
        "build_flutter_dmg": 4,
        "build_flutter_windows": 2,
    }:
        raise ValidationError("build.py shell execution ownership inventory differs")

    module = load_build_module(repo)
    for name, definition in authority_definitions.items():
        function = vars(module).get(name)
        if (not isinstance(function, types.FunctionType)
                or function.__name__ != name
                or function.__code__.co_firstlineno != definition.lineno):
            raise ValidationError(f"loaded build.py {name} authority differs from its checked definition")
    if {f"./{name}" for name in module.DEBIAN_CONFFILES} != set(CONFFILE_PATHS):
        raise ValidationError("build.py and artifact verifier conffile inventories differ")
    if {f"./{name}" for name in module.DEBIAN_FLUTTER_LIBRARIES} != FLUTTER_LIBRARIES:
        raise ValidationError("build.py and artifact verifier Flutter library inventories differ")
    if {f"./{name}" for name in module.DEBIAN_DATA_REQUIRED_DIRECTORIES} | {"."} != DATA_REQUIRED_DIRECTORIES:
        raise ValidationError("build.py and artifact verifier directory inventories differ")
    if {f"./{name}" for name in module.DEBIAN_DATA_REQUIRED_FILES} != DATA_REQUIRED_FILES:
        raise ValidationError("build.py and artifact verifier file inventories differ")
    if {
        f"./{name}": target
        for name, target in module.DEBIAN_DATA_REQUIRED_SYMLINKS.items()
    } != DATA_REQUIRED_SYMLINKS:
        raise ValidationError("build.py and artifact verifier symbolic-link inventories differ")
    if f"./{module.DEBIAN_VARIABLE_DATA_ROOT}" != DATA_VARIABLE_ROOT:
        raise ValidationError("build.py and artifact verifier variable data roots differ")

    option_strings = {
        option
        for action in module.make_parser()._actions
        for option in action.option_strings
    }
    if "--package" in option_strings or hasattr(module, "build_deb_from_folder"):
        raise ValidationError("build.py retains an unsupported alternate package API")
    forbidden_literals = ("cargo --locked bundle", "cp -a DEBIAN", "dpkg-deb -R")
    strings = [ast_string(node) for node in ast.walk(tree)]
    for token in forbidden_literals:
        if any(value is not None and token in value for value in strings):
            raise ValidationError(f"build.py retains an unsupported Debian package operation: {token}")

    scripts = [f"res/DEBIAN/{name}" for name in ("preinst", "postinst", "prerm", "postrm")]
    scripts.extend((
        "res/rustdesk.init",
        "res/service-managers/openrc/rustdesk",
        "res/service-managers/runit/run",
        "res/service-managers/manual/rustdesk-service",
    ))
    try:
        index = subprocess.check_output(
            ["git", "-C", str(repo), "ls-files", "-s", "--", *scripts],
            universal_newlines=True,
        ).splitlines()
    except (OSError, subprocess.CalledProcessError) as err:
        raise ValidationError(f"cannot inspect Debian maintainer-script Git modes: {err}") from err
    if len(index) != len(scripts) or any(not line.startswith("100755 ") for line in index):
        raise ValidationError(
            "all Debian lifecycle scripts and service-manager templates must be tracked as executable regular files"
        )

    lifecycle_validation = subprocess.run(
        [
            sys.executable,
            str(repo / "scripts/verify-debian-maintainer-scripts.py"),
            "--scripts-dir", str(repo / "res/DEBIAN"),
            "--init-script", str(repo / "res/rustdesk.init"),
            "--openrc-script", str(repo / "res/service-managers/openrc/rustdesk"),
            "--runit-run", str(repo / "res/service-managers/runit/run"),
            "--manual-run", str(repo / "res/service-managers/manual/rustdesk-service"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if lifecycle_validation.returncode != 0:
        detail = lifecycle_validation.stderr.strip() or lifecycle_validation.stdout.strip()
        raise ValidationError(
            f"Debian maintainer-script lifecycle authority differs: {detail}"
        )


def write_file(path, contents, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    path.chmod(mode)


def make_synthetic_tree(root):
    write_file(
        root / "DEBIAN/control",
        "Package: rustdesk-authority-test\nVersion: 1.0\nArchitecture: all\nMaintainer: test <test@example.invalid>\nDescription: authority test\n",
        0o644,
    )
    write_file(
        root / "DEBIAN/conffiles",
        "".join(f"{name[1:]}\n" for name in CONFFILE_PATHS),
        0o644,
    )
    write_file(root / "DEBIAN/md5sums", "", 0o644)
    for script in ("preinst", "postinst", "prerm", "postrm"):
        write_file(root / f"DEBIAN/{script}", "#!/bin/sh\nset -e\nexit 0\n", 0o755)
    for name in sorted(DATA_REQUIRED_FILES):
        path = root / name[2:]
        if name == "./etc/rustdesk/startwm.sh":
            contents = "#!/bin/sh\nset -e\nexit 0\n"
        elif name == "./usr/share/rustdesk/rustdesk":
            contents = "#!/bin/sh\nexit 0\n"
        elif name == "./usr/lib/systemd/system/rustdesk.service":
            contents = "[Service]\nExecStart=/usr/bin/rustdesk --service\n"
        elif name == "./usr/share/polkit-1/actions/com.carriez.RustDesk.policy":
            contents = "<policyconfig/>\n"
        else:
            contents = f"synthetic fixture for {name}\n"
        write_file(path, contents, 0o755 if name in DATA_EXECUTABLES else 0o644)
    for name in sorted(DATA_REQUIRED_DIRECTORIES, key=lambda item: item.count("/"), reverse=True):
        path = root if name == "." else root / name[2:]
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755)
    for name, target in sorted(DATA_REQUIRED_SYMLINKS.items()):
        (root / name[2:]).symlink_to(target)
    (root / "DEBIAN").chmod(0o755)
    root.chmod(0o755)


def build_synthetic_elf(path, runpath=None, shared=False, legacy_rpath=False):
    if shutil.which("cc") is None:
        raise ValidationError("cc is required for ELF RUNPATH self-test")
    with tempfile.TemporaryDirectory(prefix="rustdesk-elf-src.") as tmp:
        source = Path(tmp) / "synthetic.c"
        if shared:
            source.write_text("int rustdesk_synthetic_symbol(void) { return 0; }\n", encoding="utf-8")
            cmd = ["cc", "-shared", "-fPIC", str(source), "-Wl,-soname," + path.name, "-o", str(path)]
        else:
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            cmd = ["cc", str(source), "-o", str(path)]
        if runpath is not None:
            cmd.insert(-2, "-Wl,--disable-new-dtags" if legacy_rpath else "-Wl,--enable-new-dtags")
            cmd.insert(-2, "-Wl,-rpath," + runpath)
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as err:
            raise ValidationError(f"synthetic ELF build failed with status {err.returncode}") from err
    path.chmod(0o644 if shared else 0o755)


def populate_valid_synthetic_elves(root):
    build_synthetic_elf(root / "usr/share/rustdesk/rustdesk", "$ORIGIN/lib")
    for name in sorted(FLUTTER_LIBRARIES):
        basename = Path(name).name
        runpath = "$ORIGIN" if basename == "libflutter_linux_gtk.so" or basename.endswith("_plugin.so") else None
        build_synthetic_elf(root / name[2:], runpath, shared=True)


def chown_tree(root, uid, gid):
    if os.geteuid() != 0:
        return
    for path in sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        os.chown(path, uid, gid, follow_symlinks=False)
    os.chown(root, uid, gid)


def write_synthetic_md5sums(staging):
    lines = []
    for path in sorted(staging.rglob("*"), key=lambda item: os.fsencode(str(item.relative_to(staging)))):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(staging).as_posix()
        if relative.startswith("DEBIAN/") or f"./{relative}" in CONFFILE_PATHS:
            continue
        digest = hashlib.md5()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(f"{digest.hexdigest()}  /{relative}\n")
    write_file(staging / "DEBIAN/md5sums", "".join(lines), 0o644)


def build_deb(staging, output, root_owner_group, regenerate_md5=True):
    if regenerate_md5:
        write_synthetic_md5sums(staging)
    cmd = ["dpkg-deb"]
    if root_owner_group:
        cmd.append("--root-owner-group")
    cmd.extend(["-b", str(staging), str(output)])
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as err:
        raise ValidationError(f"synthetic dpkg-deb build failed with status {err.returncode}") from err


def rewrite_tar_stream(data, transform=None, additions=()):
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as source:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as destination:
            for original in source.getmembers():
                member = copy.copy(original)
                contents = None
                if original.isfile():
                    extracted = source.extractfile(original)
                    if extracted is None:
                        raise ValidationError(f"cannot read synthetic archive member {original.name}")
                    contents = extracted.read()
                result = (member, contents) if transform is None else transform(
                    normalize_tar_name(original.name), member, contents
                )
                if result is None:
                    continue
                member, contents = result
                member.size = len(contents) if member.isfile() and contents is not None else 0
                destination.addfile(member, io.BytesIO(contents) if member.isfile() else None)
            for member, contents in additions:
                member = copy.copy(member)
                member.size = len(contents) if member.isfile() else 0
                destination.addfile(member, io.BytesIO(contents) if member.isfile() else None)
    return output.getvalue()


def gzip_bytes(data):
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressor:
        compressor.write(data)
    return output.getvalue()


def ar_member(name, contents):
    header = (
        f"{name + '/':<16}{0:<12}{0:<6}{0:<6}"
        f"{format(0o100644, 'o'):<8}{len(contents):<10}`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise ValidationError("synthetic ar header has an invalid size")
    return header + contents + (b"\n" if len(contents) % 2 else b"")


def write_deb_from_tar_streams(control, data, output):
    contents = b"!<arch>\n"
    contents += ar_member("debian-binary", b"2.0\n")
    contents += ar_member("control.tar.gz", gzip_bytes(control))
    contents += ar_member("data.tar.gz", gzip_bytes(data))
    with output.open("xb") as package:
        package.write(contents)


def write_modified_deb(
    base_deb,
    output,
    control_transform=None,
    data_transform=None,
    control_additions=(),
    data_additions=(),
):
    control = rewrite_tar_stream(
        tar_stream_from_deb(base_deb, "--ctrl-tarfile"),
        transform=control_transform,
        additions=control_additions,
    )
    data = rewrite_tar_stream(
        tar_stream_from_deb(base_deb, "--fsys-tarfile"),
        transform=data_transform,
        additions=data_additions,
    )
    write_deb_from_tar_streams(control, data, output)


def tar_member_header_offset(data, target, purpose):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        matches = [member for member in archive.getmembers() if normalize_tar_name(member.name) == target]
        if len(matches) != 1:
            raise ValidationError(f"cannot locate one tar member for {purpose}: {target}")
        return matches[0].offset


def rewrite_tar_checksum(mutated, offset):
    mutated[offset + 148:offset + 156] = b"        "
    checksum = sum(mutated[offset:offset + 512])
    checksum_field = f"{checksum:06o}\0 ".encode("ascii")
    if len(checksum_field) != 8:
        raise ValidationError("mutated tar checksum has an invalid size")
    mutated[offset + 148:offset + 156] = checksum_field


def add_hidden_tar_field_padding(data, target, field_offset, field_size, field_name):
    mutated = bytearray(data)
    offset = tar_member_header_offset(data, target, f"raw-{field_name} mutation")
    field = mutated[offset + field_offset:offset + field_offset + field_size]
    nul = field.find(b"\0")
    if nul < 0 or nul + 1 >= len(field) or field[nul + 1] != 0:
        raise ValidationError(f"tar member lacks canonical {field_name} padding for mutation: {target}")
    mutated[offset + field_offset + nul + 1] = ord("X")
    rewrite_tar_checksum(mutated, offset)
    return bytes(mutated)


def replace_tar_type_flag(data, target, type_flag):
    if len(type_flag) != 1:
        raise ValidationError("replacement tar type flag must contain one byte")
    mutated = bytearray(data)
    offset = tar_member_header_offset(data, target, "raw-type mutation")
    mutated[offset + 156:offset + 157] = type_flag
    rewrite_tar_checksum(mutated, offset)
    return bytes(mutated)


def regular_tar_member(name, contents, mode=0o644):
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = mode
    member.size = len(contents)
    return member, contents


def linked_tar_member(name, target, symbolic):
    member = tarfile.TarInfo(name)
    member.type = tarfile.SYMTYPE if symbolic else tarfile.LNKTYPE
    member.linkname = target
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = 0o777
    return member, b""


def directory_tar_member(name, mode=0o755):
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = mode
    return member, b""


def special_tar_member(name):
    member = tarfile.TarInfo(name)
    member.type = tarfile.FIFOTYPE
    member.uid = 0
    member.gid = 0
    member.uname = "root"
    member.gname = "root"
    member.mode = 0o644
    return member, b""


def replace_tar_member(
    target,
    mode=None,
    contents=None,
    remove=False,
    replacement_name=None,
    linkname=None,
):
    def transform(name, member, original_contents):
        if name != target:
            return member, original_contents
        if remove:
            return None
        if replacement_name is not None:
            member.name = replacement_name
        if mode is not None:
            member.mode = mode
        if linkname is not None:
            member.linkname = linkname
        if contents is not None:
            original_contents = contents
        return member, original_contents

    return transform


def elf_dynamic_test_layout(contents):
    program_offset = struct.unpack_from("<Q", contents, 32)[0]
    program_entry_size = struct.unpack_from("<H", contents, 54)[0]
    program_count = struct.unpack_from("<H", contents, 56)[0]
    dynamic_headers = []
    load_segments = []
    program_headers = []
    for index in range(program_count):
        entry_offset = program_offset + index * program_entry_size
        header = struct.unpack_from("<IIQQQQQQ", contents, entry_offset)
        program_headers.append((entry_offset, header))
        if header[0] == 1:
            load_segments.append((header[2], header[3], header[5]))
        elif header[0] == 2:
            dynamic_headers.append((entry_offset, header))
    if len(dynamic_headers) != 1:
        raise ValidationError("synthetic ELF does not contain one dynamic program header")
    dynamic_header, dynamic = dynamic_headers[0]
    entries = []
    for entry_offset in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<QQ", contents, entry_offset)
        entries.append((entry_offset, tag, value))
        if tag == 0:
            break
    string_entries = [entry for entry in entries if entry[1] == 5]
    size_entries = [entry for entry in entries if entry[1] == 10]
    if len(string_entries) != 1 or len(size_entries) != 1:
        raise ValidationError("synthetic ELF dynamic string-table tags are not unique")
    string_address = string_entries[0][2]
    string_size = size_entries[0][2]
    string_loads = [
        segment for segment in load_segments
        if string_address >= segment[1]
        and string_address + string_size <= segment[1] + segment[2]
    ]
    if len(string_loads) != 1:
        raise ValidationError("synthetic ELF dynamic string table is not file-backed")
    string_offset = string_loads[0][0] + string_address - string_loads[0][1]
    return {
        "dynamic_header": dynamic_header,
        "dynamic_offset": dynamic[2],
        "dynamic_size": dynamic[5],
        "program_headers": program_headers,
        "entries": entries,
        "string_entry": string_entries[0],
        "size_entry": size_entries[0],
        "string_offset": string_offset,
        "string_size": string_size,
    }


def expect_validation_failure(deb, expected, expected_systemd_unit=None):
    try:
        validate_deb(deb, expected_systemd_unit)
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"{deb}: failed for {err!s}, expected failure containing {expected!r}") from err
    raise ValidationError(f"{deb}: verifier accepted an invalid package")


def expect_operation_failure(operation, expected):
    try:
        operation()
    except RuntimeError as err:
        if expected in str(err):
            return
        raise ValidationError(f"operation failed for {err!s}, expected {expected!r}") from err
    raise ValidationError("production Debian staging accepted an invalid tree")


def expect_source_validation_failure(operation, expected):
    try:
        operation()
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"source validation failed for {err!s}, expected {expected!r}") from err
    raise ValidationError("source validator accepted an invalid Debian constructor")


def expect_runpath_failure(dynamic_entries, string_table, expected, name="./usr/share/rustdesk/lib/librustdesk.so"):
    try:
        actual, present = dynamic_runpath(dynamic_entries, string_table, name, "synthetic-runpath")
        validate_runpath_policy(actual, present, name, "synthetic-runpath")
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"RUNPATH parser failed for {err!s}, expected {expected!r}") from err
    raise ValidationError("RUNPATH parser accepted an invalid dynamic-tag inventory")


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValidationError(f"source mutation anchor is not unique: {old!r}")
    return text.replace(old, new, 1)


def run_source_gate_mutations(repo, tmp):
    fixture = tmp / "source-gate"
    paths = (
        "build.py",
        "Cargo.toml",
        "flutter/linux/CMakeLists.txt",
        "scripts/build-debian.sh",
        "scripts/verify-debian-maintainer-scripts.py",
        "res/DEBIAN/preinst",
        "res/DEBIAN/postinst",
        "res/DEBIAN/prerm",
        "res/DEBIAN/postrm",
        "res/rustdesk.init",
        "res/service-managers/openrc/rustdesk",
        "res/service-managers/runit/run",
        "res/service-managers/manual/rustdesk-service",
    )
    for name in paths:
        destination = fixture / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / name, destination)
    try:
        subprocess.check_call(
            ["git", "init", "-q", str(fixture)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.check_call(
            [
                "git", "-C", str(fixture), "add", "--",
                "res/DEBIAN/preinst", "res/DEBIAN/postinst",
                "res/DEBIAN/prerm", "res/DEBIAN/postrm",
                "res/rustdesk.init",
                "res/service-managers/openrc/rustdesk",
                "res/service-managers/runit/run",
                "res/service-managers/manual/rustdesk-service",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as err:
        raise ValidationError(f"cannot construct source-gate mutation fixture: {err}") from err

    build_path = fixture / "build.py"
    baseline = build_path.read_text(encoding="utf-8")
    mutations = (
        (
            replace_once(
                baseline,
                "def build_flutter_deb(version, features):",
                "def replace_debian_constructor(function):\n"
                "    return lambda version, features: None\n\n"
                "@replace_debian_constructor\n"
                "def build_flutter_deb(version, features):",
            ),
            "authority must not use decorators",
        ),
        (
            "from os import spawnv\n" + baseline,
            "import inventory differs",
        ),
        (
            baseline + "\n\ndef alternate_spawn_archive():\n"
            "    os.spawnv(os.P_WAIT, b'/usr/bin/' + b'dpkg-deb', [b'dpkg-deb', b'-b', b'tmpdeb'])\n",
            "unsupported process-launch authority",
        ),
        (
            baseline + "\n\ndef alternate_exec_archive():\n"
            "    os.execve(b'/usr/bin/dpkg-deb', [b'dpkg-deb', b'-b', b'tmpdeb'], {})\n",
            "unsupported process-launch authority",
        ),
        (
            baseline + "\n\ndef reexported_subprocess_archive():\n"
            "    platform.subprocess.run([b'/usr/bin/dpkg-deb', b'-b', b'tmpdeb'])\n",
            "unsupported process-launch authority",
        ),
        (
            baseline + "\n\ndef alternate_debian_archive(staging, destination):\n"
            "    subprocess.run(['dpkg-deb', '-b', str(staging), str(destination)], check=True)\n",
            "only the Debian archiver and PE canonicalizer process launches",
        ),
        (
            baseline + "\n\ndef concatenated_debian_archive(staging, destination):\n"
            "    subprocess.run(['dpkg' + '-deb', '-b', str(staging), str(destination)], check=True)\n",
            "only the Debian archiver and PE canonicalizer process launches",
        ),
        (
            baseline + "\n\ndef aliased_debian_archive(staging, destination):\n"
            "    launch = subprocess.run\n"
            "    executable = ''.join(('dpkg', '-deb'))\n"
            "    launch([executable, '-b', str(staging), str(destination)], check=True)\n",
            "process callable references must be direct calls",
        ),
        (
            baseline + "\n\ndef alternate_shell_debian_archive():\n"
            "    system2('dpkg-deb -b tmpdeb alternate.deb')\n",
            "one executable dpkg-deb authority",
        ),
        (
            baseline + "\n\ndef alternate_fstring_debian_archive():\n"
            "    system2(f'dpkg-deb -b tmpdeb alternate.deb')\n",
            "one executable dpkg-deb authority",
        ),
        (
            baseline + "\n\ndef alternate_interpolated_archive():\n"
            "    system2(f\"{'dpkg'}-deb -b tmpdeb alternate.deb\")\n",
            "one executable dpkg-deb authority",
        ),
        (
            baseline + "\n\ndef alternate_joined_debian_archive():\n"
            "    system2(''.join(('dpkg', '-deb -b tmpdeb alternate.deb')))\n",
            "one executable dpkg-deb authority",
        ),
        (
            baseline + "\n\ndef alternate_percent_archive():\n"
            "    system2('%s-deb -b tmpdeb alternate.deb' % 'dpkg')\n",
            "shell execution ownership inventory differs",
        ),
        (
            replace_once(
                baseline,
                "    system2('flutter build linux --release')",
                "    system2('%s-deb -b tmpdeb alternate.deb' % 'dpkg')",
            ),
            "setup operations are not exact",
        ),
        (
            replace_once(
                baseline,
                "    exit_code = os.system(cmd)",
                "    cmd = 'true'\n    exit_code = os.system(cmd)",
            ),
            "shell wrapper signature or body is not exact",
        ),
        (
            replace_once(
                baseline,
                '        \'sed -i "s/ffi.NativeFunction<ffi.Bool Function(DartPort/ffi.NativeFunction<ffi.Uint8 Function(DartPort/g" flutter/lib/generated_bridge.dart\')',
                "        'true')",
            ),
            "FFI refactor helper is not exact",
        ),
        (
            replace_once(
                baseline,
                '    finalize_debian_package_tree("tmpdeb")\n'
                '    build_debian_archive("tmpdeb", "rustdesk.deb")',
                '    finalize_debian_package_tree("tmpdeb")\n'
                '    system2("touch tmpdeb/usr/share/rustdesk/data/flutter_assets/post-finalizer")\n'
                '    build_debian_archive("tmpdeb", "rustdesk.deb")',
            ),
            "stage, finalize, and archive as contiguous direct operations",
        ),
        (
            replace_once(
                baseline,
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
                '    return\n'
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
            ),
            "must not contain explicit terminating control flow",
        ),
        (
            replace_once(
                baseline,
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
                '    build_debian_archive = system2\n'
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
            ),
            "must not rebind package or process authority names",
        ),
        (
            replace_once(
                baseline,
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
                '    globals().__setitem__("finalize_debian_package_tree", lambda *args: None)\n'
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
            ),
            "dynamic namespace or evaluation API",
        ),
        (
            replace_once(
                baseline,
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
                '    sys.modules[__name__].finalize_debian_package_tree = lambda *args: None\n'
                '    stage_debian_control_files(version, "../res/DEBIAN", "tmpdeb/DEBIAN")',
            ),
            "must not reach a module namespace dynamically",
        ),
        (
            baseline + "\n\ndef finalize_debian_package_tree(root):\n    return None\n",
            "must define one synchronous top-level finalize_debian_package_tree authority",
        ),
        (
            "from pathlib import Path as finalize_debian_package_tree\n" + baseline,
            "import inventory differs",
        ),
        (
            "from builtins import globals as namespace\n" + baseline,
            "import inventory differs",
        ),
        (
            baseline + "\n\nclass finalize_debian_package_tree:\n    pass\n",
            "must not shadow a package authority name with a class",
        ),
        (
            baseline + "\n\ndef os():\n    return None\n",
            "must not shadow a process authority module with a function",
        ),
        (
            replace_once(
                baseline,
                "def build_flutter_deb(version, features):",
                "def build_flutter_deb(version, finalize_debian_package_tree):",
            ),
            "must not shadow package authority names in parameters",
        ),
        (
            replace_once(
                baseline,
                '    finalize_debian_package_tree("tmpdeb")\n'
                '    build_debian_archive("tmpdeb", "rustdesk.deb")',
                '    build_debian_archive("tmpdeb", "rustdesk.deb")\n'
                '    finalize_debian_package_tree("tmpdeb")',
            ),
            "stage, finalize, and archive as contiguous direct operations",
        ),
        (
            replace_once(
                baseline,
                '    build_debian_archive("tmpdeb", "rustdesk.deb")',
                '    system2("true")',
            ),
            "invoke the sole Debian archive boundary once",
        ),
        (
            replace_once(
                baseline,
                "    return parser\n\n\n# Downloading third party resources",
                '    parser.add_argument("--package")\n'
                "    return parser\n\n\n# Downloading third party resources",
            ),
            "unsupported alternate package API",
        ),
        (
            replace_once(baseline, "    system2('/bin/rm -rf build/linux')\n", ""),
            "pre-package inventory differs",
        ),
        (
            replace_once(
                baseline,
                "    system2('mkdir -p tmpdeb/usr/lib/systemd/system/')",
                "    system2('mkdir -p tmpdeb/usr/share/rustdesk/files/systemd/')",
            ),
            "setup operations are not exact",
        ),
        (
            replace_once(
                baseline,
                "        'cp ../res/rustdesk.service tmpdeb/usr/lib/systemd/system/rustdesk.service')",
                "        'cp ../res/rustdesk.service tmpdeb/usr/share/rustdesk/files/systemd/')",
            ),
            "resource copies are not exact",
        ),
        (
            replace_once(
                baseline,
                "    os.symlink('../share/rustdesk/rustdesk', 'tmpdeb/usr/bin/rustdesk')",
                "    os.symlink('/usr/share/rustdesk/rustdesk', 'tmpdeb/usr/bin/rustdesk')",
            ),
            "command symlink is not exact",
        ),
        (
            replace_once(
                baseline,
                "    os.symlink('../share/rustdesk/rustdesk', 'tmpdeb/usr/bin/rustdesk')",
                "    os.symlink('../share/rustdesk/rustdesk', 'tmpdeb/usr/bin/remote-control')",
            ),
            "command symlink is not exact",
        ),
        (
            replace_once(
                baseline,
                '    "usr/share/rustdesk/lib/libwindow_size_plugin.so",\n',
                "",
            ),
            "Flutter library inventories differ",
        ),
        (
            replace_once(
                baseline,
                "usr/share/rustdesk/lib/libwindow_size_plugin.so",
                "usr/share/rustdesk/lib/libunexpected_plugin.so",
            ),
            "Flutter library inventories differ",
        ),
    )
    for mutated, expected in mutations:
        build_path.write_text(mutated, encoding="utf-8")
        expect_source_validation_failure(lambda: validate_build_py(fixture), expected)
    build_path.write_text(baseline, encoding="utf-8")

    for script, anchor, injected, expected in (
        (
            "postinst",
            "\tupdate-rc.d \"$service\" defaults >/dev/null\n",
            "\tupdate-rc.d \"$service\" defaults >/dev/null\n"
            "\trm -f /etc/systemd/system/rustdesk.service\n",
            "systemd unit paths must be package-owned",
        ),
        (
            "prerm",
            "            update-rc.d \"$service\" remove >/dev/null\n",
            "            update-rc.d \"$service\" remove >/dev/null\n"
            "        rm -f /usr/lib/systemd/system/rustdesk.service\n",
            "systemd unit paths must be package-owned",
        ),
        (
            "postrm",
            "        rm -rf -- /root/.config/RustDesk /root/.config/rustdesk\n",
            "        rm -rf -- /root/.config/RustDesk /root/.config/rustdesk\n"
            "        rm -f /etc/systemd/system/rustdesk.service\n",
            "systemd unit paths must be package-owned",
        ),
        (
            "postrm",
            "            /bin/systemctl --system daemon-reload >/dev/null\n",
            "",
            "must reload systemd exactly once after package-file removal",
        ),
    ):
        script_path = fixture / f"res/DEBIAN/{script}"
        original = script_path.read_text(encoding="utf-8")
        script_path.write_text(replace_once(original, anchor, injected), encoding="utf-8")
        expect_source_validation_failure(lambda: validate_build_py(fixture), expected)
        script_path.write_text(original, encoding="utf-8")

    for script, anchor, injected in (
        (
            "preinst",
            "        sleep 1\n",
            "        sleep 1\n        rm -f /usr/bin/libsciter-gtk.so\n",
        ),
        (
            "preinst",
            "        sleep 1\n",
            "        sleep 1\n        chmod 0777 /usr/bin\n",
        ),
        (
            "postinst",
            "\tupdate-rc.d \"$service\" defaults >/dev/null\n",
            "\tln -f -s /usr/share/rustdesk/rustdesk /usr/bin/rustdesk\n"
            "\tupdate-rc.d \"$service\" defaults >/dev/null\n",
        ),
        (
            "prerm",
            "            update-rc.d \"$service\" remove >/dev/null\n",
            "            update-rc.d \"$service\" remove >/dev/null\n"
            "        rm -f /usr/bin/rustdesk\n",
        ),
    ):
        script_path = fixture / f"res/DEBIAN/{script}"
        original = script_path.read_text(encoding="utf-8")
        script_path.write_text(replace_once(original, anchor, injected), encoding="utf-8")
        expect_source_validation_failure(
            lambda: validate_build_py(fixture),
            "package-owned /usr/bin paths must not be mutated",
        )
        script_path.write_text(original, encoding="utf-8")

    generated_plugins = fixture / "flutter/linux/flutter/generated_plugins.cmake"
    if generated_plugins.exists():
        raise ValidationError("source-gate fixture unexpectedly contains generated Flutter plugin metadata")
    validate_build_py(fixture)
    generated_plugins.parent.mkdir(parents=True, exist_ok=True)
    generated_plugins.write_text("adversarial generated state\n", encoding="utf-8")
    validate_build_py(fixture)
    generated_plugins.write_text(
        "list(APPEND FLUTTER_PLUGIN_LIST\n"
        "  unexpected\n"
        ")\n"
        "list(APPEND FLUTTER_FFI_PLUGIN_LIST\n"
        ")\n",
        encoding="utf-8",
    )
    validate_build_py(fixture)


def load_build_module(repo):
    spec = importlib.util.spec_from_file_location("rustdesk_build_authority", repo / "build.py")
    if spec is None or spec.loader is None:
        raise ValidationError("cannot load build.py for Debian staging behavior proof")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_production_finalizer_self_test(repo, tmp):
    build_module = load_build_module(repo)
    staging = tmp / "private-production-tree"
    make_synthetic_tree(staging)
    populate_valid_synthetic_elves(staging)

    source_scripts = tmp / "private-source-scripts"
    source_scripts.mkdir(mode=0o700)
    for name in ("preinst", "postinst", "prerm", "postrm"):
        source = staging / f"DEBIAN/{name}"
        write_file(source_scripts / name, source.read_text(encoding="utf-8"), 0o700)
    shutil.rmtree(staging / "DEBIAN")

    for path in sorted(staging.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o700)
        else:
            relative = path.relative_to(staging).as_posix()
            path.chmod(0o700 if relative in build_module.DEBIAN_DATA_EXECUTABLES else 0o600)
    staging.chmod(0o700)

    old_umask = os.umask(0o077)
    try:
        build_module.stage_debian_control_files(
            "1.0", source_scripts, staging / "DEBIAN"
        )
        build_module.finalize_debian_package_tree(staging)
    finally:
        os.umask(old_umask)

    if stat.S_IMODE(os.lstat(staging).st_mode) != 0o755:
        raise ValidationError("production finalizer did not make the package root mode 0755")
    for path in staging.rglob("*"):
        relative = path.relative_to(staging).as_posix()
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode):
            expected = 0o755
        elif stat.S_ISLNK(info.st_mode):
            expected = 0o777
        elif relative.startswith("DEBIAN/"):
            expected = build_module.DEBIAN_CONTROL_MODES[relative[len("DEBIAN/"):]]
        else:
            expected = 0o755 if relative in build_module.DEBIAN_DATA_EXECUTABLES else 0o644
        if stat.S_IMODE(info.st_mode) != expected:
            raise ValidationError(
                f"production finalizer left {relative} mode {stat.S_IMODE(info.st_mode):o}, expected {expected:o}"
            )

    produced = tmp / "production-finalizer.deb"
    build_deb(staging, produced, root_owner_group=True, regenerate_md5=False)
    validate_deb(produced)

    unexpected = tmp / "unexpected-control"
    shutil.copytree(staging, unexpected, symlinks=True)
    (unexpected / "DEBIAN/md5sums").unlink()
    write_file(unexpected / "DEBIAN/triggers", "interest rustdesk-invalid\n", 0o600)
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(unexpected),
        "control inventory differs",
    )

    linked = tmp / "linked-payload"
    shutil.copytree(staging, linked, symlinks=True)
    (linked / "DEBIAN/md5sums").unlink()
    os.link(linked / "etc/rustdesk/startwm.sh", linked / "etc/rustdesk/hardlink")
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(linked),
        "special file or hardlink",
    )

    unexpected_data = tmp / "unexpected-data"
    shutil.copytree(staging, unexpected_data, symlinks=True)
    (unexpected_data / "DEBIAN/md5sums").unlink()
    write_file(unexpected_data / "usr/share/rustdesk/unexpected", "unexpected\n", 0o600)
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(unexpected_data),
        "data inventory differs",
    )

    missing_command_link = tmp / "missing-command-link"
    shutil.copytree(staging, missing_command_link, symlinks=True)
    (missing_command_link / "DEBIAN/md5sums").unlink()
    (missing_command_link / "usr/bin/rustdesk").unlink()
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(missing_command_link),
        "missing symlinks ['usr/bin/rustdesk']",
    )

    wrong_command_link = tmp / "wrong-command-link"
    shutil.copytree(staging, wrong_command_link, symlinks=True)
    (wrong_command_link / "DEBIAN/md5sums").unlink()
    (wrong_command_link / "usr/bin/rustdesk").unlink()
    (wrong_command_link / "usr/bin/rustdesk").symlink_to("/usr/share/rustdesk/rustdesk")
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(wrong_command_link),
        "wrong symlinks [('usr/bin/rustdesk', '/usr/share/rustdesk/rustdesk')]",
    )

    extra_command_link = tmp / "extra-command-link"
    shutil.copytree(staging, extra_command_link, symlinks=True)
    (extra_command_link / "DEBIAN/md5sums").unlink()
    (extra_command_link / "usr/bin/remote-control").symlink_to(
        "../share/rustdesk/rustdesk"
    )
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(extra_command_link),
        "unexpected symlinks ['usr/bin/remote-control']",
    )

    hardlinked_command_link = tmp / "hardlinked-command-link"
    shutil.copytree(staging, hardlinked_command_link, symlinks=True)
    (hardlinked_command_link / "DEBIAN/md5sums").unlink()
    os.link(
        hardlinked_command_link / "usr/bin/rustdesk",
        hardlinked_command_link / "usr/bin/remote-control",
        follow_symlinks=False,
    )
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(hardlinked_command_link),
        "special file or hardlink",
    )

    missing_plugin = tmp / "missing-plugin"
    shutil.copytree(staging, missing_plugin, symlinks=True)
    (missing_plugin / "DEBIAN/md5sums").unlink()
    (missing_plugin / "usr/share/rustdesk/lib/libwindow_size_plugin.so").unlink()
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(missing_plugin),
        "missing files ['usr/share/rustdesk/lib/libwindow_size_plugin.so']",
    )

    unexpected_plugin = tmp / "unexpected-plugin"
    shutil.copytree(staging, unexpected_plugin, symlinks=True)
    (unexpected_plugin / "DEBIAN/md5sums").unlink()
    write_file(
        unexpected_plugin / "usr/share/rustdesk/lib/libunexpected_plugin.so",
        "unexpected\n",
        0o600,
    )
    expect_operation_failure(
        lambda: build_module.finalize_debian_package_tree(unexpected_plugin),
        "unexpected files ['usr/share/rustdesk/lib/libunexpected_plugin.so']",
    )

    symlinked_sources = tmp / "symlinked-source-scripts"
    symlinked_sources.symlink_to(source_scripts, target_is_directory=True)
    expect_operation_failure(
        lambda: build_module.stage_debian_control_files(
            "1.0", symlinked_sources, tmp / "symlinked-control"
        ),
        "source is not a directory",
    )

    symlinked_script_sources = tmp / "symlinked-script-sources"
    shutil.copytree(source_scripts, symlinked_script_sources)
    (symlinked_script_sources / "postinst").unlink()
    (symlinked_script_sources / "postinst").symlink_to(source_scripts / "postinst")
    expect_operation_failure(
        lambda: build_module.stage_debian_control_files(
            "1.0", symlinked_script_sources, tmp / "symlinked-script-control"
        ),
        "not a non-hardlinked regular file",
    )

    hardlinked_script_sources = tmp / "hardlinked-script-sources"
    shutil.copytree(source_scripts, hardlinked_script_sources)
    os.link(hardlinked_script_sources / "postinst", tmp / "hardlinked-postinst-peer")
    expect_operation_failure(
        lambda: build_module.stage_debian_control_files(
            "1.0", hardlinked_script_sources, tmp / "hardlinked-script-control"
        ),
        "not a non-hardlinked regular file",
    )


def make_member_stream(names, directories=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name in names:
            member = tarfile.TarInfo(name)
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            member.mode = 0o644
            if name in directories:
                member.type = tarfile.DIRTYPE
            member.size = 0
            archive.addfile(member, io.BytesIO())
    return stream.getvalue()


def expect_member_stream_failure(names, expected, directories=()):
    try:
        tar_members_from_stream(make_member_stream(names, directories), "synthetic-member-stream")
    except ValidationError as err:
        if expected in str(err):
            return
        raise ValidationError(f"archive parsing failed for {err!s}, expected {expected!r}") from err
    raise ValidationError(
        f"archive parser accepted invalid members {names!r}; expected rejection containing {expected!r}"
    )


def run_self_test(repo):
    if shutil.which("dpkg-deb") is None:
        raise ValidationError("dpkg-deb is required for self-test")
    with tempfile.TemporaryDirectory(prefix="rustdesk-deb-authority.") as tmp:
        tmp = Path(tmp)
        expect_member_stream_failure(("./duplicate", "./duplicate"), "duplicate archive member")
        expect_member_stream_failure(("./../escape",), "non-canonical name")
        expect_member_stream_failure(("/",), "absolute name")
        expect_member_stream_failure(("plain",), "canonical ./ prefix")
        expect_member_stream_failure(("./.",), "non-canonical name")
        expect_member_stream_failure(("./file/",), "non-directory archive member has a trailing slash")
        expect_member_stream_failure(
            ("./directory//",),
            "directory archive member has redundant trailing slashes",
            directories=("./directory//",),
        )
        expect_runpath_failure(
            ((29, 1), (29, 9)),
            b"\0$ORIGIN\0$ORIGIN/lib\0",
            "multiple RUNPATH entries",
        )
        expect_runpath_failure(
            ((29, 0),),
            b"\0",
            "unexpected RUNPATH",
        )
        run_source_gate_mutations(repo, tmp)
        run_production_finalizer_self_test(repo, tmp)

        good_tree = tmp / "good-tree"
        make_synthetic_tree(good_tree)
        populate_valid_synthetic_elves(good_tree)
        good_deb = tmp / "good.deb"
        build_deb(good_tree, good_deb, root_owner_group=True)
        expected_systemd_unit = (
            good_tree / "usr/lib/systemd/system/rustdesk.service"
        ).read_bytes()
        validate_deb(good_deb, expected_systemd_unit)

        wrong_command_target_deb = tmp / "wrong-command-target.deb"
        write_modified_deb(
            good_deb,
            wrong_command_target_deb,
            data_transform=replace_tar_member(
                "./usr/bin/rustdesk",
                linkname="/usr/share/rustdesk/rustdesk",
            ),
        )
        expect_validation_failure(
            wrong_command_target_deb,
            "wrong symlinks [('./usr/bin/rustdesk', '/usr/share/rustdesk/rustdesk')]",
        )

        missing_command_link_deb = tmp / "missing-command-link.deb"
        write_modified_deb(
            good_deb,
            missing_command_link_deb,
            data_transform=replace_tar_member("./usr/bin/rustdesk", remove=True),
        )
        expect_validation_failure(missing_command_link_deb, "data inventory differs")

        regular_command_deb = tmp / "regular-command.deb"
        write_modified_deb(
            good_deb,
            regular_command_deb,
            data_transform=replace_tar_member("./usr/bin/rustdesk", remove=True),
            data_additions=(regular_tar_member(
                "./usr/bin/rustdesk",
                b"#!/bin/sh\nexit 1\n",
                mode=0o644,
            ),),
        )
        expect_validation_failure(regular_command_deb, "data inventory differs")

        wrong_command_mode_deb = tmp / "wrong-command-mode.deb"
        write_modified_deb(
            good_deb,
            wrong_command_mode_deb,
            data_transform=replace_tar_member("./usr/bin/rustdesk", mode=0o755),
        )
        expect_validation_failure(wrong_command_mode_deb, "mode 755, expected 777")

        wrong_systemd_unit_deb = tmp / "wrong-systemd-unit.deb"
        write_modified_deb(
            good_deb,
            wrong_systemd_unit_deb,
            data_transform=replace_tar_member(
                "./usr/lib/systemd/system/rustdesk.service",
                contents=b"[Service]\nExecStart=/usr/bin/false\n",
            ),
        )
        expect_validation_failure(
            wrong_systemd_unit_deb,
            "bytes differ from res/rustdesk.service",
            expected_systemd_unit,
        )

        bad_owner_tree = tmp / "bad-owner-tree"
        shutil.copytree(good_tree, bad_owner_tree, symlinks=True)
        if os.geteuid() == 0:
            chown_tree(bad_owner_tree, 12345, 12345)
        bad_owner_deb = tmp / "bad-owner.deb"
        build_deb(bad_owner_tree, bad_owner_deb, root_owner_group=False)
        expect_validation_failure(bad_owner_deb, "tar owner names are not canonical root/root")

        bad_mode_tree = tmp / "bad-mode-tree"
        shutil.copytree(good_tree, bad_mode_tree, symlinks=True)
        (bad_mode_tree / "usr/share/rustdesk").chmod(0o775)
        bad_mode_deb = tmp / "bad-mode.deb"
        build_deb(bad_mode_tree, bad_mode_deb, root_owner_group=True)
        expect_validation_failure(bad_mode_deb, "mode 775, expected 755")

        private_mode_tree = tmp / "private-mode-tree"
        shutil.copytree(good_tree, private_mode_tree, symlinks=True)
        for path in private_mode_tree.rglob("*"):
            relative = path.relative_to(private_mode_tree).as_posix()
            if relative == "DEBIAN" or relative.startswith("DEBIAN/"):
                continue
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o700)
            else:
                path.chmod(0o700 if f"./{relative}" in DATA_EXECUTABLES else 0o600)
        private_mode_deb = tmp / "private-mode.deb"
        build_deb(private_mode_tree, private_mode_deb, root_owner_group=True)
        expect_validation_failure(private_mode_deb, "mode 700, expected 755")

        private_file_deb = tmp / "private-file.deb"
        write_modified_deb(
            good_deb,
            private_file_deb,
            data_transform=replace_tar_member(
                "./usr/lib/systemd/system/rustdesk.service", mode=0o600
            ),
        )
        expect_validation_failure(private_file_deb, "mode 600, expected 644")

        control_mode_deb = tmp / "control-mode.deb"
        write_modified_deb(
            good_deb,
            control_mode_deb,
            control_transform=replace_tar_member("./preinst", mode=0o555),
        )
        expect_validation_failure(control_mode_deb, "mode 555, expected 755")

        extra_control_deb = tmp / "extra-control.deb"
        write_modified_deb(
            good_deb,
            extra_control_deb,
            control_additions=(regular_tar_member("./triggers", b"interest invalid\n"),),
        )
        expect_validation_failure(extra_control_deb, "control inventory differs")

        nested_control_deb = tmp / "nested-control.deb"
        write_modified_deb(
            good_deb,
            nested_control_deb,
            control_additions=(directory_tar_member("./nested/"),),
        )
        expect_validation_failure(nested_control_deb, "control inventory differs")

        for symbolic, label in ((False, "hardlink"), (True, "symlink")):
            linked_deb = tmp / f"{label}.deb"
            write_modified_deb(
                good_deb,
                linked_deb,
                data_additions=(linked_tar_member(
                    f"./usr/share/rustdesk/data/flutter_assets/{label}",
                    "./usr/share/rustdesk/data/icudtl.dat",
                    symbolic,
                ),),
            )
            expect_validation_failure(
                linked_deb,
                (
                    "unexpected symlinks ['./usr/share/rustdesk/data/flutter_assets/symlink']"
                    if symbolic
                    else "package tree must contain only regular files, directories, and the exact command symlink"
                ),
            )

        special_deb = tmp / "special.deb"
        write_modified_deb(
            good_deb,
            special_deb,
            data_additions=(special_tar_member(
                "./usr/share/rustdesk/data/flutter_assets/special"
            ),),
        )
        expect_validation_failure(
            special_deb,
            "package tree must contain only regular files, directories, and the exact command symlink",
        )

        trailing_runner_deb = tmp / "trailing-runner.deb"
        write_modified_deb(
            good_deb,
            trailing_runner_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/rustdesk",
                replacement_name="./usr/share/rustdesk/rustdesk/",
            ),
        )
        expect_validation_failure(trailing_runner_deb, "non-directory archive member has a trailing slash")

        hidden_name_padding_deb = tmp / "hidden-name-padding.deb"
        write_deb_from_tar_streams(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            add_hidden_tar_field_padding(
                tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                "./usr/share/rustdesk/rustdesk",
                0,
                100,
                "name",
            ),
            hidden_name_padding_deb,
        )
        expect_validation_failure(hidden_name_padding_deb, "nonzero bytes after NUL")

        hidden_uname_padding_deb = tmp / "hidden-uname-padding.deb"
        write_deb_from_tar_streams(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            add_hidden_tar_field_padding(
                tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                "./usr/share/rustdesk/rustdesk",
                265,
                32,
                "uname",
            ),
            hidden_uname_padding_deb,
        )
        expect_validation_failure(hidden_uname_padding_deb, "nonzero bytes after NUL")

        hidden_link_name_deb = tmp / "hidden-link-name.deb"
        write_deb_from_tar_streams(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            add_hidden_tar_field_padding(
                tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                "./usr/share/rustdesk/rustdesk",
                157,
                100,
                "linkname",
            ),
            hidden_link_name_deb,
        )
        expect_validation_failure(hidden_link_name_deb, "nonzero bytes after NUL")

        for label, type_flag in (
            ("alternate-regular", b"\0"),
            ("contiguous", b"7"),
            ("gnu-sparse", b"S"),
        ):
            alternate_type_deb = tmp / f"{label}-type.deb"
            write_deb_from_tar_streams(
                tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
                replace_tar_type_flag(
                    tar_stream_from_deb(good_deb, "--fsys-tarfile"),
                    "./usr/share/rustdesk/rustdesk",
                    type_flag,
                ),
                alternate_type_deb,
            )
            expect_validation_failure(alternate_type_deb, "mismatched tar member header")

        missing_runtime_deb = tmp / "missing-runtime.deb"
        write_modified_deb(
            good_deb,
            missing_runtime_deb,
            data_transform=replace_tar_member("./usr/share/rustdesk/rustdesk", remove=True),
        )
        expect_validation_failure(missing_runtime_deb, "data inventory differs")

        missing_plugin_deb = tmp / "missing-plugin.deb"
        write_modified_deb(
            good_deb,
            missing_plugin_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
                remove=True,
            ),
        )
        expect_validation_failure(
            missing_plugin_deb,
            "missing files ['./usr/share/rustdesk/lib/libwindow_size_plugin.so']",
        )

        extra_plugin_deb = tmp / "extra-plugin.deb"
        write_modified_deb(
            good_deb,
            extra_plugin_deb,
            data_additions=(regular_tar_member(
                "./usr/share/rustdesk/lib/libunexpected_plugin.so",
                b"unexpected\n",
            ),),
        )
        expect_validation_failure(
            extra_plugin_deb,
            "unexpected files ['./usr/share/rustdesk/lib/libunexpected_plugin.so']",
        )

        substituted_plugin_deb = tmp / "substituted-plugin.deb"
        write_modified_deb(
            good_deb,
            substituted_plugin_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
                remove=True,
            ),
            data_additions=(regular_tar_member(
                "./usr/share/rustdesk/lib/libunexpected_plugin.so",
                b"unexpected\n",
            ),),
        )
        expect_validation_failure(
            substituted_plugin_deb,
            "missing files ['./usr/share/rustdesk/lib/libwindow_size_plugin.so']",
        )

        non_elf_runtime_deb = tmp / "non-elf-runtime.deb"
        write_modified_deb(
            good_deb,
            non_elf_runtime_deb,
            data_transform=replace_tar_member("./usr/share/rustdesk/lib/librustdesk.so", contents=b"not ELF\n"),
        )
        expect_validation_failure(non_elf_runtime_deb, "required runtime object is not ELF")

        non_elf_plugin_deb = tmp / "non-elf-plugin.deb"
        write_modified_deb(
            good_deb,
            non_elf_plugin_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/libwindow_size_plugin.so",
                contents=b"not ELF\n",
            ),
        )
        expect_validation_failure(non_elf_plugin_deb, "required runtime object is not ELF")

        good_data_tar = tar_stream_from_deb(good_deb, "--fsys-tarfile")
        good_data_members = tar_members_from_stream(good_data_tar, "good-data")
        librustdesk = archive_member_bytes(
            good_data_tar,
            good_data_members["./usr/share/rustdesk/lib/librustdesk.so"],
            "good-librustdesk",
        )
        dynamic_layout = elf_dynamic_test_layout(librustdesk)
        elf_mutations = []
        wrong_class = bytearray(librustdesk)
        wrong_class[4] = 1
        elf_mutations.append(("wrong-class", bytes(wrong_class), "ELF class is not 64-bit"))
        wrong_endian = bytearray(librustdesk)
        wrong_endian[5] = 2
        elf_mutations.append(("wrong-endian", bytes(wrong_endian), "ELF byte order is not little-endian"))
        wrong_machine = bytearray(librustdesk)
        struct.pack_into("<H", wrong_machine, 18, 3)
        elf_mutations.append(("wrong-machine", bytes(wrong_machine), "ELF machine is not x86-64"))
        relocatable = bytearray(librustdesk)
        struct.pack_into("<H", relocatable, 16, 1)
        elf_mutations.append(("relocatable", bytes(relocatable), "expected ET_DYN"))
        no_dynamic = bytearray(librustdesk)
        dynamic_header = dynamic_layout["dynamic_header"]
        struct.pack_into("<I", no_dynamic, dynamic_header, 0)
        elf_mutations.append(("no-dynamic", bytes(no_dynamic), "exactly one dynamic segment"))

        mismatched_dynamic = bytearray(librustdesk)
        original_dynamic_offset = struct.unpack_from("<Q", mismatched_dynamic, dynamic_header + 8)[0]
        struct.pack_into("<Q", mismatched_dynamic, dynamic_header + 8, original_dynamic_offset + 16)
        elf_mutations.append((
            "mismatched-dynamic",
            bytes(mismatched_dynamic),
            "dynamic segment is not consistently mapped",
        ))

        misaligned_dynamic = bytearray(librustdesk)
        struct.pack_into("<Q", misaligned_dynamic, dynamic_header + 48, 4)
        elf_mutations.append((
            "misaligned-dynamic",
            bytes(misaligned_dynamic),
            "does not have canonical 8-byte alignment",
        ))

        unterminated_dynamic = bytearray(librustdesk)
        dynamic_offset = dynamic_layout["dynamic_offset"]
        dynamic_size = dynamic_layout["dynamic_size"]
        for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
            if struct.unpack_from("<Q", unterminated_dynamic, offset)[0] == 0:
                struct.pack_into("<Q", unterminated_dynamic, offset, 1)
        elf_mutations.append((
            "unterminated-dynamic",
            bytes(unterminated_dynamic),
            "dynamic segment is not DT_NULL-terminated",
        ))

        missing_strtab = bytearray(librustdesk)
        struct.pack_into("<Q", missing_strtab, dynamic_layout["string_entry"][0], 4)
        elf_mutations.append((
            "missing-strtab",
            bytes(missing_strtab),
            "one bounded dynamic string table",
        ))

        duplicate_candidate = next(
            entry for entry in dynamic_layout["entries"]
            if entry[1] not in (0, 5, 10)
        )
        duplicate_strtab = bytearray(librustdesk)
        struct.pack_into("<QQ", duplicate_strtab, duplicate_candidate[0], 5, dynamic_layout["string_entry"][2])
        elf_mutations.append((
            "duplicate-strtab",
            bytes(duplicate_strtab),
            "one bounded dynamic string table",
        ))

        zero_strsz = bytearray(librustdesk)
        struct.pack_into("<Q", zero_strsz, dynamic_layout["size_entry"][0] + 8, 0)
        elf_mutations.append((
            "zero-strsz",
            bytes(zero_strsz),
            "one bounded dynamic string table",
        ))

        unmapped_strtab = bytearray(librustdesk)
        struct.pack_into(
            "<Q",
            unmapped_strtab,
            dynamic_layout["string_entry"][0] + 8,
            0xFFFFFFFFFFFFF000,
        )
        elf_mutations.append((
            "unmapped-strtab",
            bytes(unmapped_strtab),
            "dynamic string table is not mapped",
        ))

        oversized_strtab = bytearray(librustdesk)
        struct.pack_into(
            "<Q",
            oversized_strtab,
            dynamic_layout["size_entry"][0] + 8,
            len(librustdesk) + 1,
        )
        elf_mutations.append((
            "oversized-strtab",
            bytes(oversized_strtab),
            "dynamic string table is not mapped",
        ))

        nonnul_first_strtab = bytearray(librustdesk)
        nonnul_first_strtab[dynamic_layout["string_offset"]] = ord("X")
        elf_mutations.append((
            "nonnul-first-strtab",
            bytes(nonnul_first_strtab),
            "dynamic string table must begin and end with NUL",
        ))

        nonnul_last_strtab = bytearray(librustdesk)
        string_end = dynamic_layout["string_offset"] + dynamic_layout["string_size"]
        nonnul_last_strtab[string_end - 1] = ord("X")
        elf_mutations.append((
            "nonnul-last-strtab",
            bytes(nonnul_last_strtab),
            "dynamic string table must begin and end with NUL",
        ))

        soname_entries = [entry for entry in dynamic_layout["entries"] if entry[1] == 14]
        if len(soname_entries) != 1:
            raise ValidationError("synthetic shared ELF does not contain one SONAME")
        soname_entry = soname_entries[0]
        out_of_bounds_soname = bytearray(librustdesk)
        struct.pack_into(
            "<Q",
            out_of_bounds_soname,
            soname_entry[0] + 8,
            dynamic_layout["string_size"],
        )
        elf_mutations.append((
            "out-of-bounds-soname",
            bytes(out_of_bounds_soname),
            "SONAME string offset is out of bounds",
        ))

        wrong_soname = bytearray(librustdesk)
        soname_string_offset = dynamic_layout["string_offset"] + soname_entry[2]
        wrong_soname[soname_string_offset] = ord("X")
        elf_mutations.append((
            "wrong-soname",
            bytes(wrong_soname),
            "does not match the installed basename",
        ))

        audit_tag = bytearray(librustdesk)
        struct.pack_into("<QQ", audit_tag, duplicate_candidate[0], 0x6FFFFEFC, soname_entry[2])
        elf_mutations.append((
            "audit-tag",
            bytes(audit_tag),
            "forbidden dynamic loader tags",
        ))

        shared_interpreter_candidate = next(
            entry for entry in dynamic_layout["program_headers"]
            if entry[1][0] not in (0, 1, 2, 3, 0x6474E551)
        )
        shared_interpreter = bytearray(librustdesk)
        struct.pack_into("<I", shared_interpreter, shared_interpreter_candidate[0], 3)
        elf_mutations.append((
            "shared-interpreter",
            bytes(shared_interpreter),
            "shared object contains a program interpreter",
        ))

        stack_headers = [
            entry for entry in dynamic_layout["program_headers"]
            if entry[1][0] == 0x6474E551
        ]
        if len(stack_headers) != 1:
            raise ValidationError("synthetic shared ELF does not contain one GNU stack header")
        stack_header = stack_headers[0]

        for label, alignment in (
            ("no-stack-alignment", 0),
            ("dart-stack-alignment", 1),
            ("gnu-stack-alignment", 16),
        ):
            valid_stack_alignment = bytearray(librustdesk)
            struct.pack_into("<Q", valid_stack_alignment, stack_header[0] + 48, alignment)
            validate_elf_identity(
                bytes(valid_stack_alignment),
                "./usr/share/rustdesk/lib/librustdesk.so",
                label,
            )

        missing_stack = bytearray(librustdesk)
        struct.pack_into("<I", missing_stack, stack_header[0], 0)
        elf_mutations.append((
            "missing-stack",
            bytes(missing_stack),
            "must contain exactly one GNU stack header",
        ))

        duplicate_stack = bytearray(librustdesk)
        struct.pack_into("<I", duplicate_stack, shared_interpreter_candidate[0], 0x6474E551)
        elf_mutations.append((
            "duplicate-stack",
            bytes(duplicate_stack),
            "must contain exactly one GNU stack header",
        ))

        for label, field_offset in (
            ("stack-file-offset", 8),
            ("stack-virtual-address", 16),
            ("stack-physical-address", 24),
            ("stack-file-size", 32),
            ("stack-memory-size", 40),
        ):
            nonempty_stack = bytearray(librustdesk)
            struct.pack_into("<Q", nonempty_stack, stack_header[0] + field_offset, 1)
            elf_mutations.append((
                label,
                bytes(nonempty_stack),
                "GNU stack header must not describe file or memory contents",
            ))

        executable_stack = bytearray(librustdesk)
        struct.pack_into("<I", executable_stack, stack_header[0] + 4, stack_header[1][1] | 1)
        elf_mutations.append((
            "executable-stack",
            bytes(executable_stack),
            "GNU stack permissions are not exact non-executable RW",
        ))

        for label, flags in (
            ("read-only-stack", 4),
            ("write-only-stack", 2),
            ("unexpected-stack-flags", 14),
        ):
            wrong_stack_flags = bytearray(librustdesk)
            struct.pack_into("<I", wrong_stack_flags, stack_header[0] + 4, flags)
            elf_mutations.append((
                label,
                bytes(wrong_stack_flags),
                "GNU stack permissions are not exact non-executable RW",
            ))

        invalid_stack_alignment = bytearray(librustdesk)
        struct.pack_into("<Q", invalid_stack_alignment, stack_header[0] + 48, 3)
        elf_mutations.append((
            "invalid-stack-alignment",
            bytes(invalid_stack_alignment),
            "GNU stack alignment is not ABI-valid",
        ))

        writable_load = next(
            entry for entry in dynamic_layout["program_headers"]
            if entry[1][0] == 1 and entry[1][1] & 2
        )
        writable_executable_load = bytearray(librustdesk)
        struct.pack_into(
            "<I",
            writable_executable_load,
            writable_load[0] + 4,
            writable_load[1][1] | 1,
        )
        elf_mutations.append((
            "writable-executable-load",
            bytes(writable_executable_load),
            "load segment is writable and executable",
        ))
        for label, contents, expected in elf_mutations:
            malformed_elf_deb = tmp / f"{label}.deb"
            write_modified_deb(
                good_deb,
                malformed_elf_deb,
                data_transform=replace_tar_member(
                    "./usr/share/rustdesk/lib/librustdesk.so",
                    contents=contents,
                ),
            )
            expect_validation_failure(malformed_elf_deb, expected)

        runner = archive_member_bytes(
            good_data_tar,
            good_data_members["./usr/share/rustdesk/rustdesk"],
            "good-runner",
        )
        runner_layout = elf_dynamic_test_layout(runner)
        interpreter_headers = [
            entry for entry in runner_layout["program_headers"] if entry[1][0] == 3
        ]
        if len(interpreter_headers) != 1:
            raise ValidationError("synthetic runner ELF does not contain one program interpreter")
        interpreter_header = interpreter_headers[0]
        bad_interpreter = bytearray(runner)
        interpreter_offset = interpreter_header[1][2]
        interpreter_size = interpreter_header[1][5]
        replacement_interpreter = b"/tmp/rustdesk-ld.so\0"
        if len(replacement_interpreter) > interpreter_size:
            raise ValidationError("synthetic runner interpreter is too short for mutation")
        bad_interpreter[interpreter_offset:interpreter_offset + interpreter_size] = (
            replacement_interpreter + b"\0" * (interpreter_size - len(replacement_interpreter))
        )

        missing_interpreter = bytearray(runner)
        struct.pack_into("<I", missing_interpreter, interpreter_header[0], 0)

        second_interpreter_candidate = next(
            entry for entry in runner_layout["program_headers"]
            if entry[1][0] not in (0, 1, 2, 3, 0x6474E551)
        )
        second_interpreter = bytearray(runner)
        struct.pack_into("<I", second_interpreter, second_interpreter_candidate[0], 3)

        for label, contents, expected in (
            ("bad-interpreter", bytes(bad_interpreter), "program interpreter is not exact"),
            ("missing-interpreter", bytes(missing_interpreter), "exactly one program interpreter"),
            ("second-interpreter", bytes(second_interpreter), "exactly one program interpreter"),
        ):
            interpreter_deb = tmp / f"{label}.deb"
            write_modified_deb(
                good_deb,
                interpreter_deb,
                data_transform=replace_tar_member(
                    "./usr/share/rustdesk/rustdesk",
                    contents=contents,
                ),
            )
            expect_validation_failure(interpreter_deb, expected)

        needed_entries = [entry for entry in runner_layout["entries"] if entry[1] == 1]
        if not needed_entries:
            raise ValidationError("synthetic runner ELF does not contain a NEEDED entry")
        unsafe_needed = bytearray(runner)
        needed_offset = runner_layout["string_offset"] + needed_entries[0][2]
        needed_end = unsafe_needed.find(b"\0", needed_offset)
        if needed_end - needed_offset < len("/tmp/x.so"):
            raise ValidationError("synthetic runner NEEDED name is too short for mutation")
        unsafe_needed[needed_offset:needed_offset + len("/tmp/x.so")] = b"/tmp/x.so"
        unsafe_needed[needed_offset + len("/tmp/x.so")] = 0
        unsafe_needed_deb = tmp / "unsafe-needed.deb"
        write_modified_deb(
            good_deb,
            unsafe_needed_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/rustdesk",
                contents=bytes(unsafe_needed),
            ),
        )
        expect_validation_failure(unsafe_needed_deb, "NEEDED is not a safe dependency basename")

        unexpected_data_deb = tmp / "unexpected-data.deb"
        write_modified_deb(
            good_deb,
            unexpected_data_deb,
            data_additions=(regular_tar_member("./usr/share/rustdesk/unexpected", b"unexpected\n"),),
        )
        expect_validation_failure(unexpected_data_deb, "data inventory differs")

        bad_runpath = tmp / "bad-runpath.so"
        build_synthetic_elf(bad_runpath, "/tmp/rustdesk-bad", shared=True)
        bad_runpath_deb = tmp / "bad-runpath.deb"
        write_modified_deb(
            good_deb,
            bad_runpath_deb,
            data_additions=(regular_tar_member(
                "./usr/share/rustdesk/data/flutter_assets/bad-runpath.so",
                bad_runpath.read_bytes(),
            ),),
        )
        expect_validation_failure(bad_runpath_deb, "unexpected RUNPATH")

        legacy_rpath = tmp / "legacy-rpath/librustdesk.so"
        legacy_rpath.parent.mkdir()
        build_synthetic_elf(legacy_rpath, "/tmp/rustdesk-legacy", shared=True, legacy_rpath=True)
        legacy_rpath_deb = tmp / "legacy-rpath.deb"
        write_modified_deb(
            good_deb,
            legacy_rpath_deb,
            data_transform=replace_tar_member(
                "./usr/share/rustdesk/lib/librustdesk.so",
                contents=legacy_rpath.read_bytes(),
            ),
        )
        expect_validation_failure(legacy_rpath_deb, "legacy RPATH is forbidden")

        bad_conffiles_deb = tmp / "bad-conffiles.deb"
        write_modified_deb(
            good_deb,
            bad_conffiles_deb,
            control_transform=replace_tar_member("./conffiles", contents=b"/etc/rustdesk/startwm.sh\n"),
        )
        expect_validation_failure(bad_conffiles_deb, "content differs from the exact configuration inventory")

        md5sums = archive_member_bytes(
            tar_stream_from_deb(good_deb, "--ctrl-tarfile"),
            tar_members_from_deb(good_deb, "--ctrl-tarfile")["./md5sums"],
            "good-md5sums",
        )
        if b"/usr/bin/rustdesk\n" in md5sums:
            raise ValidationError("good md5sums incorrectly contains the package command symlink")
        bad_md5_deb = tmp / "bad-md5.deb"
        write_modified_deb(
            good_deb,
            bad_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=b"0" * 32 + md5sums[32:]
            ),
        )
        expect_validation_failure(bad_md5_deb, "digest differs")

        malformed_md5_deb = tmp / "malformed-md5.deb"
        write_modified_deb(
            good_deb,
            malformed_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=md5sums.replace(b"  /", b" /", 1)
            ),
        )
        expect_validation_failure(malformed_md5_deb, "malformed line")

        md5_lines = md5sums.splitlines(keepends=True)
        duplicate_md5_deb = tmp / "duplicate-md5.deb"
        write_modified_deb(
            good_deb,
            duplicate_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=md5sums + md5_lines[0]
            ),
        )
        expect_validation_failure(duplicate_md5_deb, "duplicate path")

        missing_md5_deb = tmp / "missing-md5.deb"
        write_modified_deb(
            good_deb,
            missing_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums", contents=b"".join(md5_lines[1:])
            ),
        )
        expect_validation_failure(missing_md5_deb, "inventory differs")

        extra_md5_deb = tmp / "extra-md5.deb"
        write_modified_deb(
            good_deb,
            extra_md5_deb,
            control_transform=replace_tar_member(
                "./md5sums",
                contents=md5sums + b"00000000000000000000000000000000  /unexpected\n",
            ),
        )
        expect_validation_failure(extra_md5_deb, "inventory differs")


def main():
    parser = argparse.ArgumentParser(description="Verify Debian package payload authority for the RustDesk root service.")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--deb", action="append", default=[], help="built .deb to validate; may be repeated")
    parser.add_argument("--self-test", action="store_true", help="run synthetic positive and negative package checks")
    args = parser.parse_args()

    try:
        validate_build_py(Path(args.repo).resolve())
        if args.self_test:
            run_self_test(Path(args.repo).resolve())
        expected_systemd_unit = (Path(args.repo).resolve() / "res/rustdesk.service").read_bytes()
        for deb in args.deb:
            validate_deb(Path(deb).resolve(), expected_systemd_unit)
    except ValidationError as err:
        fail(str(err))

    print(
        "ok  Debian package tree is root-owned, exact-mode, exact-command-symlink-only, and source-gated"
    )


if __name__ == "__main__":
    main()
