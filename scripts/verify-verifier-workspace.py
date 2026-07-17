#!/usr/bin/env python3
import argparse
import array
import ast
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import selectors
import signal
import shlex
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path


if not sys.flags.isolated or not sys.flags.no_site:
    os.execve(
        "/usr/bin/python3",
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            os.path.abspath(__file__),
            *sys.argv[1:],
        ],
        dict(os.environ),
    )


WORKSPACE_BLOCKS = (
    (
        "workspace cleanup",
        (
            'VERIFY_TMP=""',
            'VERIFY_TMP_ID=""',
            'VERIFY_SUCCESS_MESSAGE=""',
            "cleanup_verify_tmp() {",
            "  local status=$? cleanup_failed=0",
            "  trap - EXIT",
            "  trap '' HUP INT TERM",
        ),
    ),
    (
        "workspace signal handling",
        (
            "trap cleanup_verify_tmp EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
        ),
    ),
    (
        "workspace creation",
        (
            "VERIFY_TMP=$(umask 077 && mktemp -d /tmp/rustdesk-verify.XXXXXXXXXX)",
            'VERIFY_TMP_ID="$(stat -c \'%d:%i\' -- "$VERIFY_TMP")"',
            "readonly VERIFY_TMP VERIFY_TMP_ID",
        ),
    ),
    (
        "workspace metadata proof",
        (
            'if ! python3 - "$VERIFY_TMP" <<\'PY\'',
            "import os",
            "import stat",
            "import sys",
            "",
            "metadata = os.lstat(sys.argv[1])",
            "if (",
            "    not stat.S_ISDIR(metadata.st_mode)",
            "    or metadata.st_uid != os.geteuid()",
            "    or stat.S_IMODE(metadata.st_mode) != 0o700",
            "):",
            '    raise SystemExit("verify: private workspace is not a current-UID mode-0700 directory")',
            "PY",
            "then",
            "  exit 1",
            "fi",
        ),
    ),
)

OLD_SCRATCH_PREFIX = re.compile(r"/tmp/(?:rd_verify|r_s11b3|r_s11c23)")
PUBLIC_TMP_REDIRECTION = re.compile(r"\d*(?:>>?|<<?)\s*['\"]?/tmp/")
SHELL_COMMAND_SEPARATORS = {"|", "||", "&", "&&", ";"}


class VerificationError(RuntimeError):
    pass


def attempt_cleanup(failures, label, function, *arguments):
    try:
        function(*arguments)
        return True
    except BaseException as error:
        failures.append((label, error))
        return False


def report_cleanup_failures(primary_error, context, failures):
    if not failures:
        return
    details = "; ".join(f"{label}: {error}" for label, error in failures)
    if primary_error is not None:
        primary_error.add_note(f"{context}: {details}")
        return
    error = VerificationError(f"{context}: {details}")
    for label, failure in failures[1:]:
        error.add_note(f"{label}: {failure}")
    raise error from failures[0][1]


def filesystem_identity(metadata):
    return metadata.st_dev, metadata.st_ino


def stable_file_metadata(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def directory_is_empty(descriptor):
    with os.scandir(descriptor) as entries:
        return next(entries, None) is None


def bounded_directory_names(descriptor, limit, diagnostic):
    names = []
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= limit:
                raise VerificationError(diagnostic)
            names.append(entry.name)
    return sorted(names, key=os.fsencode)


def descriptor_mount_id(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "rb", buffering=0) as information:
        content = information.read(65537)
    if len(content) > 65536:
        raise VerificationError("descriptor mount information exceeds its byte bound")
    prefix = b"mnt_id:\t"
    values = [line[len(prefix):] for line in content.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or re.fullmatch(br"[1-9][0-9]*", values[0]) is None:
        raise VerificationError("descriptor mount identity is unavailable")
    return int(values[0])


class ScratchDirectory:
    def __init__(self, root, descriptor, name, recorded_identity):
        self.root = root
        self.fd = descriptor
        self.name = name
        self.identity = recorded_identity

    @property
    def descriptor_path(self):
        return Path(f"/proc/self/fd/{self.fd}")

    @property
    def inherited_fds(self):
        return (self.fd,)

    def __fspath__(self):
        return os.fspath(self.descriptor_path)

    def __str__(self):
        return os.fspath(self)

    def __truediv__(self, component):
        return self.descriptor_path / component

    def assert_bound(self):
        self.root.assert_bound()
        metadata = os.fstat(self.fd)
        edge = os.stat(self.name, dir_fd=self.root.fd, follow_symlinks=False)
        if (
            filesystem_identity(metadata) != self.identity
            or filesystem_identity(edge) != self.identity
            or descriptor_mount_id(self.fd) != self.root.mount_id
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise VerificationError("fixture directory authority changed")

    def canonical_path(self):
        self.assert_bound()
        return Path(os.path.realpath(self.descriptor_path))


class ScratchRoot:
    def __init__(self, path):
        rendered = os.fspath(path)
        if not os.path.isabs(rendered) or os.path.normpath(rendered) != rendered:
            raise VerificationError("verifier fixture scratch is not an absolute normalized path")
        components = rendered.split("/")[1:]
        if not components or any(not component or component in (".", "..") for component in components):
            raise VerificationError("verifier fixture scratch path has an invalid component")
        current_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = None
        try:
            for index, component in enumerate(components):
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
                if index == len(components) - 1:
                    parent_fd = current_fd
                    current_fd = next_fd
                    break
                os.close(current_fd)
                current_fd = next_fd
            if parent_fd is None:
                raise VerificationError("verifier fixture scratch parent authority is unavailable")
            metadata = os.fstat(current_fd)
            edge = os.stat(components[-1], dir_fd=parent_fd, follow_symlinks=False)
            if filesystem_identity(edge) != filesystem_identity(metadata):
                raise VerificationError("verifier fixture scratch edge changed during acquisition")
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise VerificationError(
                    "verifier fixture scratch is not a current-principal mode-0700 directory"
                )
            if not directory_is_empty(current_fd):
                raise VerificationError("verifier fixture scratch is not initially empty")
            mount_id = descriptor_mount_id(current_fd)
        except BaseException:
            if parent_fd is not None:
                os.close(parent_fd)
            os.close(current_fd)
            raise
        self.path = rendered
        self.basename = components[-1]
        self.parent_fd = parent_fd
        self.fd = current_fd
        self.identity = filesystem_identity(metadata)
        self.device = metadata.st_dev
        self.mount_id = mount_id
        self.closed = False

    @property
    def descriptor_path(self):
        return Path(f"/proc/self/fd/{self.fd}")

    def assert_bound(self):
        if self.closed:
            raise VerificationError("verifier fixture scratch authority is closed")
        metadata = os.fstat(self.fd)
        if filesystem_identity(metadata) != self.identity:
            raise VerificationError("verifier fixture scratch descriptor identity changed")
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise VerificationError("verifier fixture scratch metadata changed")
        if descriptor_mount_id(self.fd) != self.mount_id:
            raise VerificationError("verifier fixture scratch mount identity changed")
        edge = os.stat(self.basename, dir_fd=self.parent_fd, follow_symlinks=False)
        if filesystem_identity(edge) != self.identity:
            raise VerificationError("verifier fixture scratch pathname was replaced")

    def _remove_contents(self, directory_fd, remaining):
        directory_metadata = os.fstat(directory_fd)
        if directory_metadata.st_uid != os.geteuid() or directory_metadata.st_gid != os.getegid():
            raise VerificationError("fixture cleanup encountered a foreign-owned directory")
        os.fchmod(directory_fd, 0o700)
        names = bounded_directory_names(
            directory_fd,
            remaining[0],
            "fixture cleanup exceeds its entry bound",
        )
        for name in names:
            remaining[0] -= 1
            if remaining[0] < 0:
                raise VerificationError("fixture cleanup exceeds its entry bound")
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if metadata.st_dev != self.device:
                raise VerificationError("fixture cleanup crosses a filesystem boundary")
            authority_fd = os.open(
                name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd
            )
            try:
                if (
                    filesystem_identity(os.fstat(authority_fd)) != filesystem_identity(metadata)
                    or descriptor_mount_id(authority_fd) != self.mount_id
                ):
                    raise VerificationError("fixture cleanup crosses a mount boundary")
                if stat.S_ISDIR(metadata.st_mode):
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(child_fd)
                        if filesystem_identity(opened) != filesystem_identity(metadata):
                            raise VerificationError("fixture directory changed during cleanup open")
                        if descriptor_mount_id(child_fd) != self.mount_id:
                            raise VerificationError("fixture directory changed mount during cleanup open")
                        self._remove_contents(child_fd, remaining)
                        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if filesystem_identity(current) != filesystem_identity(opened):
                            raise VerificationError("fixture directory changed before cleanup removal")
                        os.rmdir(name, dir_fd=directory_fd)
                        if os.fstat(authority_fd).st_nlink != 0:
                            raise VerificationError("fixture directory removal did not consume its edge")
                    finally:
                        os.close(child_fd)
                else:
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if filesystem_identity(current) != filesystem_identity(metadata):
                        raise VerificationError("fixture entry changed before cleanup removal")
                    os.unlink(name, dir_fd=directory_fd)
                    if os.fstat(authority_fd).st_nlink != metadata.st_nlink - 1:
                        raise VerificationError("fixture unlink did not consume the authenticated edge")
            finally:
                os.close(authority_fd)

    def _collect_inode_links(self, directory_fd, remaining, linked):
        names = bounded_directory_names(
            directory_fd,
            remaining[0],
            "fixture inode-closure inspection exceeds its entry bound",
        )
        for name in names:
            remaining[0] -= 1
            if remaining[0] < 0:
                raise VerificationError("fixture inode-closure inspection exceeds its entry bound")
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if metadata.st_dev != self.device:
                raise VerificationError("fixture inode-closure inspection crosses a filesystem boundary")
            authority_fd = os.open(
                name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd
            )
            try:
                if (
                    filesystem_identity(os.fstat(authority_fd)) != filesystem_identity(metadata)
                    or descriptor_mount_id(authority_fd) != self.mount_id
                ):
                    raise VerificationError("fixture inode-closure inspection crosses a mount boundary")
            finally:
                os.close(authority_fd)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child_fd)
                    if filesystem_identity(opened) != filesystem_identity(metadata):
                        raise VerificationError("fixture directory changed during inode-closure inspection")
                    self._collect_inode_links(child_fd, remaining, linked)
                finally:
                    os.close(child_fd)
            else:
                if metadata.st_nlink < 1:
                    raise VerificationError("fixture entry has an invalid link count")
                key = filesystem_identity(metadata)
                expected, count = linked.get(key, (metadata.st_nlink, 0))
                if expected != metadata.st_nlink:
                    raise VerificationError("fixture inode link count changed during inspection")
                linked[key] = expected, count + 1

    def _assert_inode_closure(self, directory_fd):
        linked = {}
        self._collect_inode_links(directory_fd, [131072], linked)
        if any(count != expected for expected, count in linked.values()):
            raise VerificationError("fixture contains a non-directory inode linked outside its boundary")

    @contextlib.contextmanager
    def directory(self, prefix):
        self.assert_bound()
        if re.fullmatch(r"[a-z0-9-]+", prefix) is None:
            raise VerificationError("fixture directory prefix is invalid")
        child_name = f"{prefix}{os.urandom(16).hex()}"
        os.mkdir(child_name, 0o700, dir_fd=self.fd)
        child_fd = None
        child_identity = None
        child_owned = False
        try:
            edge = os.stat(child_name, dir_fd=self.fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(edge.st_mode)
                or edge.st_uid != os.geteuid()
                or edge.st_gid != os.getegid()
                or stat.S_IMODE(edge.st_mode) != 0o700
            ):
                raise VerificationError("fixture directory edge has invalid creation metadata")
            child_identity = filesystem_identity(edge)
            child_fd = os.open(
                child_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=self.fd,
            )
            child_metadata = os.fstat(child_fd)
            if child_identity != filesystem_identity(child_metadata):
                raise VerificationError("fixture directory edge changed during creation")
            if descriptor_mount_id(child_fd) != self.mount_id:
                raise VerificationError("fixture directory was created across a mount boundary")
            child_owned = True
            yield ScratchDirectory(self, child_fd, child_name, child_identity)
        finally:
            cleanup_complete = False
            try:
                if child_owned:
                    edge = os.stat(child_name, dir_fd=self.fd, follow_symlinks=False)
                    if filesystem_identity(edge) != child_identity:
                        raise VerificationError("fixture directory edge changed before cleanup")
                    if child_fd is not None:
                        self._assert_inode_closure(child_fd)
                        self._remove_contents(child_fd, [131072])
                        if not directory_is_empty(child_fd):
                            raise VerificationError("fixture directory remains nonempty after cleanup")
                    edge = os.stat(child_name, dir_fd=self.fd, follow_symlinks=False)
                    if filesystem_identity(edge) != child_identity:
                        raise VerificationError("fixture directory edge changed before root removal")
                    os.rmdir(child_name, dir_fd=self.fd)
                    if os.fstat(child_fd).st_nlink != 0:
                        raise VerificationError("fixture root removal did not consume its edge")
                    cleanup_complete = True
            finally:
                if child_fd is not None:
                    os.close(child_fd)
            if cleanup_complete:
                self.assert_bound()

    def close(self):
        if self.closed:
            return
        try:
            self.assert_bound()
            if not directory_is_empty(self.fd):
                raise VerificationError("verifier fixture scratch retained state after self-test")
        finally:
            self.closed = True
            os.close(self.fd)
            os.close(self.parent_fd)


class ManagedSignal(BaseException):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
MANAGED_UNIT_COLLECTION_SECONDS = 30
VERIFIER_PROGRAM_LIMIT = 4 * 1024 * 1024
VERIFIER_PROGRAM_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)
_VERIFIER_PROGRAM_FD = None
_MANAGED_SIGNAL_STATE = None


def require_text(source, text, label):
    if text not in source:
        raise VerificationError(f"{label}: required contract is absent")


def require_count(source, text, minimum, label):
    count = source.count(text)
    if count < minimum:
        raise VerificationError(f"{label}: expected at least {minimum} occurrences, found {count}")


def require_exact_count(source, text, expected, label):
    count = source.count(text)
    if count != expected:
        raise VerificationError(f"{label}: expected exactly {expected} occurrences, found {count}")


def require_order(source, tokens, label):
    positions = []
    cursor = 0
    for token in tokens:
        position = source.find(token, cursor)
        if position < 0:
            raise VerificationError(f"{label}: missing ordered stage {token!r}")
        positions.append(position)
        cursor = position + len(token)
    if len(set(positions)) != len(positions):
        raise VerificationError(f"{label}: stages are not strictly ordered")


def extract_between(source, start_token, end_token, label):
    start = source.find(start_token)
    if start < 0:
        raise VerificationError(f"{label}: opening token is absent")
    end = source.find(end_token, start + len(start_token))
    if end < 0:
        raise VerificationError(f"{label}: closing token is absent")
    return source[start:end]


def extract_through(source, start_token, end_token, label):
    start = source.find(start_token)
    if start < 0:
        raise VerificationError(f"{label}: opening token is absent")
    end = source.find(end_token, start + len(start_token))
    if end < 0:
        raise VerificationError(f"{label}: closing token is absent")
    return source[start : end + len(end_token)]


def python_ast_span(source, node):
    lines = source.splitlines(keepends=True)
    line_offsets = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line))

    def source_position(line_number, byte_column):
        encoded = lines[line_number - 1].encode("utf-8")
        if byte_column > len(encoded):
            raise VerificationError("Python AST position exceeds its source line")
        try:
            prefix = encoded[:byte_column].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError("Python AST position splits a source character") from exc
        return line_offsets[line_number - 1] + len(prefix)

    return (
        source_position(node.lineno, node.col_offset),
        source_position(node.end_lineno, node.end_col_offset),
    )


def extract_python_definition(source, module, name, label):
    definitions = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == name
    ]
    if len(definitions) != 1:
        raise VerificationError(f"{label}: expected one top-level {name} definition")
    start, end = python_ast_span(source, definitions[0])
    return source[start:end]


def extract_python_method(source, module, class_name, method_name, label):
    classes = [
        node for node in module.body if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    if len(classes) != 1:
        raise VerificationError(f"{label}: expected one top-level {class_name} class")
    methods = [
        node
        for node in classes[0].body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name
    ]
    if len(methods) != 1:
        raise VerificationError(f"{label}: expected one {class_name}.{method_name} method")
    start, end = python_ast_span(source, methods[0])
    return source[start:end]


def validate_popen_finally_ownership(source, function_name, cleanup_name, reaped_name, label):
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise VerificationError(f"{label}: Python source does not parse: {exc}") from exc
    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
    ]
    if len(functions) != 1:
        raise VerificationError(f"{label}: expected one {function_name} function")
    function = functions[0]
    owner_tries = [statement for statement in function.body if isinstance(statement, ast.Try)]
    if len(owner_tries) != 1:
        raise VerificationError(f"{label}: Popen is not covered by one top-level teardown try")
    owner_try = owner_tries[0]
    owner_body = ast.Module(body=owner_try.body, type_ignores=[])
    popen_assignments = [
        node
        for node in ast.walk(owner_body)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "process" for target in node.targets)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == "subprocess"
        and node.value.func.attr == "Popen"
    ]
    all_popen_calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "Popen"
    ]
    if len(popen_assignments) != 1 or len(all_popen_calls) != 1:
        raise VerificationError(f"{label}: Popen assignment escapes the teardown-owning try")
    cleanup_ifs = [
        node
        for statement in owner_try.finalbody
        for node in ast.walk(statement)
        if isinstance(node, ast.If)
        and any(
            isinstance(descendant, ast.Call)
            and isinstance(descendant.func, ast.Name)
            and descendant.func.id == cleanup_name
            for descendant in ast.walk(node)
        )
    ]
    if len(cleanup_ifs) != 1:
        raise VerificationError(f"{label}: teardown finally does not conditionally call {cleanup_name}")
    expected_condition = ast.parse(f"process is not None and not {reaped_name}", mode="eval").body
    if ast.dump(cleanup_ifs[0].test) != ast.dump(expected_condition):
        raise VerificationError(f"{label}: teardown finally has the wrong ownership condition")


def find_unique_line(lines, expected, label):
    matches = [index for index, line in enumerate(lines) if line == expected]
    if len(matches) != 1:
        raise VerificationError(f"{label}: expected one exact line, found {len(matches)}")
    return matches[0]


def find_unique_block(lines, block, label):
    width = len(block)
    matches = [
        index
        for index in range(len(lines) - width + 1)
        if tuple(lines[index : index + width]) == block
    ]
    if len(matches) != 1:
        raise VerificationError(f"{label}: expected one exact block, found {len(matches)}")
    return matches[0]


def has_fixed_string_self_check(line):
    if "grep" not in line or "scripts/verify.sh" not in line:
        return False
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="|&;")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError as exc:
        raise VerificationError(f"cannot parse potential verify.sh self-check: {exc}") from exc
    for index, token in enumerate(tokens):
        if token != "grep":
            continue
        command = []
        for argument in tokens[index + 1 :]:
            if argument in SHELL_COMMAND_SEPARATORS:
                break
            command.append(argument)
        fixed = any(
            argument == "--fixed-strings"
            or argument.startswith("--fixed-strings=")
            or (argument.startswith("-") and not argument.startswith("--") and "F" in argument[1:])
            for argument in command
        )
        if fixed and "scripts/verify.sh" in command:
            return True
    return False


def validate_verify_workspace(source):
    lines = source.splitlines()
    cleanup = extract_between(
        source,
        "cleanup_verify_tmp() {",
        "\n}\n",
        "verify workspace cleanup",
    )
    root_index = find_unique_line(lines, 'cd "$(dirname "$0")/.."', "repository-root selection")
    version_index = find_unique_line(lines, "source scripts/fork-version.sh", "fork-version loading")
    positions = {}
    previous_end = root_index
    for label, block in WORKSPACE_BLOCKS:
        start = find_unique_block(lines, block, label)
        if start <= previous_end:
            raise VerificationError(f"{label}: block is outside the ordered startup sequence")
        positions[label] = start
        previous_end = start + len(block) - 1
    if previous_end >= version_index:
        raise VerificationError("workspace setup must finish before fork-version loading")
    for text, label in (
        ('[ -z "$VERIFY_TMP_ID" ]', "workspace recorded identity requirement"),
        ('"$(stat -c \'%d:%i\' -- "$VERIFY_TMP"', "workspace live identity proof"),
        ('--remove-private-root "$VERIFY_TMP" --expected-identity "$VERIFY_TMP_ID"', "identity-bound workspace removal"),
        ('[ -e "$VERIFY_TMP" ] || [ -L "$VERIFY_TMP" ]', "workspace removal postcondition"),
        ('trap \'\' HUP INT TERM', "workspace cleanup signal exclusion"),
        ('echo "$VERIFY_SUCCESS_MESSAGE"', "deferred verify success output"),
    ):
        require_text(cleanup, text, label)
    require_order(
        cleanup,
        (
            "trap '' HUP INT TERM",
            '"$(stat -c \'%d:%i\' -- "$VERIFY_TMP"',
            '--remove-private-root "$VERIFY_TMP" --expected-identity "$VERIFY_TMP_ID"',
            'echo "$VERIFY_SUCCESS_MESSAGE"',
            'exit "$status"',
        ),
        "verify success-after-cleanup ordering",
    )
    require_exact_count(
        source,
        'VERIFY_SUCCESS_MESSAGE="VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
        1,
        "deferred verify completion marker",
    )
    if 'echo "VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"' in source:
        raise VerificationError("verify completion marker bypasses workspace cleanup")
    require_text(source, "--self-test-workspace-missing", "missing-workspace behavioral test mode")
    require_text(
        source,
        'echo "verify workspace missing self-test: REACHED" >&2',
        "verify missing-workspace reached marker",
    )
    require_text(
        source,
        'native_watch_log=$(mktemp "$VERIFY_TMP/native-watch.XXXXXXXXXX")',
        "native watch log workspace ownership",
    )
    require_text(
        source,
        'readonly VERIFIER_FIXTURE_TMP="$VERIFY_TMP/verifier-fixtures"',
        "verifier fixture scratch ownership",
    )
    require_text(source, 'install -d -m 0700 "$VERIFIER_FIXTURE_TMP"', "verifier fixture scratch allocation")
    require_text(
        source,
        'verify-verifier-workspace.py --repo . --self-test --scratch "$VERIFIER_FIXTURE_TMP"',
        "verifier fixture scratch dispatch",
    )
    for line_number, line in enumerate(lines, 1):
        if OLD_SCRATCH_PREFIX.search(line):
            raise VerificationError(f"line {line_number}: predictable public scratch prefix is present")
        if PUBLIC_TMP_REDIRECTION.search(line):
            raise VerificationError(f"line {line_number}: direct public-/tmp redirection is present")
        if has_fixed_string_self_check(line):
            raise VerificationError(f"line {line_number}: fixed-string self-inspection is present")
    return lines, positions


def validate_build_release(source):
    normalizer = extract_between(
        source,
        "offline_normalize_exact_tree() {",
        "\n}\n\nverify_private_tree_authority_capacity() {",
        "private-tree normalizer",
    )
    capacity_check = extract_between(
        source,
        "verify_private_tree_authority_capacity() {",
        "\n}\n\nacquire_private_tree_closure_execution() {",
        "retained-authority capacity preflight",
    )
    execution_authority = extract_between(
        source,
        "acquire_private_tree_closure_execution() {",
        "\n}\n\nclose_private_tree_closure_execution() {",
        "private-tree helper execution authority",
    )
    execution_close = extract_between(
        source,
        "close_private_tree_closure_execution() {",
        "\n}\n\nrun_private_tree_closure_from_descriptor() {",
        "private-tree helper execution-authority close",
    )
    descriptor_executor = extract_between(
        source,
        "run_private_tree_closure_from_descriptor() {",
        "\n}\n\noffline_remove_exact_tree_contents() {",
        "private-tree descriptor executor",
    )
    tree_remover = extract_between(
        source,
        "offline_remove_exact_tree_contents() {",
        "\n}\n\nverify_private_tree_removal_capability() {",
        "private-tree terminal remover",
    )
    removal_capability = extract_between(
        source,
        "verify_private_tree_removal_capability() {",
        "\n}\n\nverify_private_tree_cleanup_preflight() {",
        "private-tree removal-capability preflight",
    )
    cleanup_preflight = extract_between(
        source,
        "verify_private_tree_cleanup_preflight() {",
        "\n}\n\nnormalize_snapshot_access() {",
        "complete private-tree cleanup preflight",
    )
    snapshot_normalizer = extract_between(
        source,
        "normalize_snapshot_access() {",
        "\n}\n\ncleanup_release_workspace() {",
        "snapshot normalizer",
    )
    cleanup = extract_between(
        source,
        "cleanup_release_workspace() {",
        "\n}\n\nrelease_preflight() {",
        "release cleanup",
    )
    create_snapshot = extract_between(
        source,
        "create_snapshot() {",
        "\n}\n\nreset_snapshot_build_state() {",
        "release snapshot creation",
    )
    reset = extract_between(
        source,
        "reset_snapshot_build_state() {",
        "\n}\n\nrun_child() {",
        "generated-state reset",
    )
    verification = extract_between(
        source,
        "run_verification() {",
        "\n}\n\ncopy_artifact() {",
        "release verification consumer",
    )
    target_invocation = extract_between(
        source,
        "invoke_target() {",
        "\n}\n\nbuild_snapshot() {",
        "release target invocation",
    )
    build_snapshot = extract_between(
        source,
        "build_snapshot() {",
        "\n}\n\nassert_exact_set() {",
        "snapshot build loop",
    )
    fixture_target = extract_between(
        source,
        "write_fixture_target() {",
        "\n}\n\nrun_reset_self_test() {",
        "release target fixture writer",
    )
    reset_self_test = extract_between(
        source,
        "run_reset_self_test() {",
        "\n}\n\nrun_self_test() {",
        "root-owned reset self-test",
    )
    publication_self_test = extract_between(
        source,
        "run_publication_reconciliation_self_test() {",
        "\n}\n\nrun_self_test() {",
        "publication reconciliation self-test",
    )
    transaction_self_test = extract_between(
        source,
        "run_self_test() {",
        "\n}\n\nmain() {",
        "release transaction self-test",
    )
    create_workspace = extract_between(
        source,
        "create_workspace() {",
        "\n}\n\nassert_release_online_snapshot() {",
        "release workspace creation",
    )
    publication_tool = extract_between(
        source,
        "publication_tool() {",
        "\n}\n\nprove_published_dist() {",
        "final release publisher dispatch",
    )
    published_proof = extract_between(
        source,
        "prove_published_dist() {",
        "\n}\n\nrecover_pending_publications() {",
        "published release-set proof dispatch",
    )
    reconciliation = extract_between(
        source,
        "reconcile_final_publication() {",
        "\n}\n\natomic_install_dist() {",
        "publication reconciliation",
    )
    recovery = extract_between(
        source,
        "recover_pending_publications() {",
        "\n}\n\nreconcile_final_publication() {",
        "restartable publication recovery",
    )
    atomic_install = extract_between(
        source,
        "atomic_install_dist() {",
        "\n}\n\nprepare_release_snapshots() {",
        "atomic final-dist installation",
    )
    main = extract_between(source, "main() {", "\n}\n\nmain\n", "release main transaction")
    normalization_command = extract_between(
        normalizer,
        "docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\",
        "\n    ); then",
        "descriptor-bound private-tree normalizer",
    )
    removal_command = extract_between(
        tree_remover,
        "docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\",
        "; then",
        "descriptor-bound private-tree terminal remover",
    )
    require_text(
        source,
        "#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc",
        "release empty-environment entrypoint",
    )
    require_text(source, 'readonly FINAL_OUT_DIR="$REPO_ROOT/dist"', "non-overridable final dist")
    if "readonly RELEASE_SRC_COMMIT ANDROID_KEY_ALIAS OUT_DIR" in source:
        raise VerificationError("fatal readonly OUT_DIR assignment remains")
    for variable in (
        "BASH_ENV",
        "PYTHONPATH",
        "HARNESS_PREFIX",
        "GIT_*",
        "DOCKER_*",
        "SOURCE_DATE_EPOCH",
        "DOUBLE_BUILD",
        "OUT_DIR",
        "WINDOWS_*",
        "RELEASE_*",
    ):
        require_text(source, variable, f"closed inherited environment {variable}")
    require_text(
        source,
        "run_child() {\n    assert_release_docker_config\n    /usr/bin/env -i",
        "child environment allowlist",
    )
    require_text(source, 'DOCKER_HOST_URI=unix:///var/run/docker.sock', "local Docker socket binding")
    require_text(source, 'DOCKER_CONFIG_DIR="$WORKSPACE/docker-config"', "private Docker config")
    require_text(source, 'ONLINE_SNAPSHOT_PARENT="$WORKSPACE/online-input"', "single online snapshot location")
    require_text(
        source,
        "require_cmd cmp git docker python3 sha256sum stat readlink install find date flock /usr/bin/grep",
        "release host-tool preflight",
    )
    require_text(
        source,
        'run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight',
        "release source-gate preflight",
    )
    require_order(
        source,
        (
            'require_cmd cmp git docker python3 sha256sum stat readlink install find date flock /usr/bin/grep',
            "acquire_publication_lock\n",
            "FINAL_PUBLICATION_RECONCILIATION=1",
            'recover_pending_publications "$REPO_ROOT" "$FINAL_OUT_DIR"',
            "assert_repo_state\n",
            'run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight',
            "require_online_complete\n",
            "verify_private_tree_cleanup_preflight",
            "create_release_online_snapshot\n",
        ),
        "release preflight ordering",
    )
    if source.count('create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"') != 1:
        raise VerificationError("release transaction must create exactly one private online snapshot")
    if "HOST_ONLINE_DIR" in source:
        raise VerificationError("release transaction retains the mutable canonical-online child path")
    require_text(source, "run_snapshot_consumer() {", "online snapshot consumer wrapper")
    require_exact_count(source, "run_snapshot_consumer ", 6, "before/after online snapshot consumption")
    require_text(
        source,
        'assert_release_online_snapshot "before final dist installation"',
        "pre-publication online snapshot proof",
    )
    require_text(source, "verify_all_release_builder_images", "pinned builder provenance checks")
    require_text(source, 'require_pinned_builder_image "$role" "$image_id"', "builder image helper contract")
    for mutable_name in (
        "rustdesk-fork-harness-deb-builder",
        "rustdesk-fork-harness-android-builder",
        "rustdesk-fork-harness-win-helper",
    ):
        if mutable_name in source:
            raise VerificationError(f"release transaction retains mutable image name {mutable_name}")
    require_text(source, 'create_snapshot A "$SOURCE_A"', "snapshot A creation")
    require_text(source, 'create_snapshot B "$SOURCE_B"', "snapshot B creation")
    for operation in ("add", "remove", "prune"):
        if re.search(rf"(?:^|\s)worktree\s+{operation}(?:\s|$)", source):
            raise VerificationError(
                f"release build retains production Git worktree {operation} authority"
            )
    for text, label in (
        ('git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow', "independent complete-history snapshot clone"),
        ('checkout --quiet --detach "$PINNED_HEAD"', "detached pinned-commit snapshot checkout"),
        ('assert_git_object_authority "$source"', "snapshot object-authority rejection"),
        ('run_private_tree_closure_from_descriptor --mount-root "$source"', "snapshot mount closure"),
        ('run_private_tree_closure_from_descriptor --inode-root "$source"', "snapshot inode-link closure"),
    ):
        require_text(create_snapshot, text, label)
    require_exact_count(
        source,
        'assert_git_object_authority "$source"',
        2,
        "snapshot object-authority rejection",
    )
    require_order(
        create_snapshot,
        (
            'git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source"',
            'git_closed -C "$source" checkout --quiet --detach "$PINNED_HEAD"',
            'git_closed -C "$source" remote remove origin',
            '[ "$common" = "$source/.git" ]',
            'assert_git_object_authority "$source"',
            'git_closed -C "$source" fsck --full --strict --no-reflogs',
            'chmod 0700 "$source"',
            'run_private_tree_closure_from_descriptor --mount-root "$source"',
            'run_private_tree_closure_from_descriptor --inode-root "$source"',
            'assert_snapshot_exact "$source" "snapshot $label creation"',
        ),
        "independent release snapshot acquisition",
    )
    require_text(create_snapshot, 'chmod 0700 "$source"', "private release snapshot mode")
    for text, label in (
        ('shallow="$common_dir/shallow"', "shallow declaration authority"),
        ('[ ! -e "$shallow" ] && [ ! -L "$shallow" ]', "shallow control-file rejection"),
        ('rev-parse --is-shallow-repository', "Git shallow-state query"),
        ('rev-parse --is-shallow-repository 2>/dev/null)" = false ]', "complete Git history requirement"),
    ):
        require_text(source, text, label)
    require_text(
        reset_self_test,
        'git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$fixture_repo"',
        "reset fixture complete-history Git clone",
    )
    require_text(
        reset_self_test,
        "verify_private_tree_cleanup_preflight",
        "reset fixture complete terminal-cleanup preflight",
    )
    require_exact_count(
        source,
        "--reject-shallow",
        2,
        "complete-history private clone policy",
    )
    require_text(
        create_snapshot,
        '[ "$(stat -c \'%u:%a\' "$source")" = "$(id -u):700" ]',
        "private release snapshot metadata proof",
    )
    require_text(reset, 'normalize_snapshot_access "$source" "$label"', "snapshot-scoped ownership reset")
    if 'normalize_snapshot_access "$WORKSPACE"' in reset:
        raise VerificationError("generated-state reset broadens ownership authority to the whole workspace")
    require_order(
        reset,
        (
            'normalize_snapshot_access "$source" "$label"',
            'run_private_tree_closure_from_descriptor --mount-root "$source"',
            'git_closed -C "$source" clean -ffdx',
            'git_closed -C "$source" clean -nffdx',
            'assert_snapshot_exact "$source" "$label after generated-state reset"',
        ),
        "generated-state reset ordering",
    )
    expected_normalization_command = (
        "docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n"
        "            --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=CHOWN \\\n"
        "            --security-opt no-new-privileges \\\n"
        "            --ulimit nofile=524544:524544 \\\n"
        '            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled" \\\n'
        '            "$DEBIAN_IMAGE_ID" /usr/bin/python3 -I -S -c "$PRIVATE_TREE_CLOSURE_EXECUTOR" \\\n'
        '            "$PRIVATE_TREE_CLOSURE_HASH" \\\n'
        '            --normalize-root /cleanup --expected-identity "$expected_identity" \\\n'
        '            --owner "$uid" --group "$gid" < "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"'
    )
    require_exact_count(normalizer, "docker_local run ", 1, "single descriptor-bound normalizer container")
    if normalization_command != expected_normalization_command:
        raise VerificationError("private-tree normalizer command is not the exact authority allowlist")
    for text, label in (
        ("--pull=never", "normalizer no-pull policy"),
        ("--network=none", "normalizer network isolation"),
        ("--read-only", "normalizer immutable container root"),
        ("--user 0:0", "normalizer root identity"),
        ("--cap-drop=ALL", "normalizer capability reset"),
        ("--cap-add=DAC_READ_SEARCH", "normalizer read-only inspection capability"),
        ("--cap-add=CHOWN", "normalizer chown capability"),
        ("--security-opt no-new-privileges", "normalizer privilege ceiling"),
        ("--ulimit nofile=524544:524544", "normalizer retained-authority descriptor budget"),
        ('"$DEBIAN_IMAGE_ID" /usr/bin/python3 -I -S -c "$PRIVATE_TREE_CLOSURE_EXECUTOR"', "authenticated normalizer executor"),
        ('"$PRIVATE_TREE_CLOSURE_HASH"', "normalizer committed helper digest"),
        ('--normalize-root /cleanup --expected-identity "$expected_identity"', "identity-bound normalization dispatch"),
        ('--owner "$uid" --group "$gid"', "normalizer destination ownership"),
        ('run_private_tree_closure_from_descriptor --mount-root "$path"', "normalizer mount closure proof"),
        ('< "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"', "descriptor-sourced normalizer implementation"),
        ("bind-recursive=disabled", "normalizer recursive-bind exclusion"),
        ('[ "$observed" = "$expected_identity" ]', "normalizer identity postcondition"),
    ):
        require_text(normalizer, text, label)
    if re.findall(r"--cap-add=([A-Z_]+)", normalizer) != ["DAC_READ_SEARCH", "CHOWN"]:
        raise VerificationError("normalizer capability allowlist is not exact")
    if re.findall(r"--cap-add=([A-Z_]+)", reset_self_test) != ["CHOWN"]:
        raise VerificationError("reset fixture capability set is not exactly CHOWN")
    require_exact_count(normalizer, "bind-recursive=disabled", 1, "normalizer recursive-bind exclusions")
    require_exact_count(normalizer, 'run_private_tree_closure_from_descriptor --mount-root "$path"', 2, "normalizer mount closure stages")
    require_exact_count(normalizer, '[ "$observed" = "$expected_identity" ]', 2, "normalizer identity stages")
    require_text(
        normalizer,
        'if ! (verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"); then\n'
        '        warn "$role normalization image failed provenance verification"\n'
        "        return 1\n"
        "    fi",
        "normalizer live image provenance",
    )
    require_order(
        normalizer,
        (
            '[ "$resolved" = "$path" ]',
            '[ "$observed" = "$expected_identity" ]',
            'run_private_tree_closure_from_descriptor --mount-root "$path"',
            'verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"',
            "--cap-add=DAC_READ_SEARCH",
            "--cap-add=CHOWN",
            "--normalize-root /cleanup",
            "disappeared after normalization",
            "identity changed during normalization",
            "gained a mount boundary during normalization",
        ),
        "private-tree authority ordering",
    )
    for forbidden in (
        "--privileged",
        "--cap-add=ALL",
        "--device",
        "--pid=host",
        "--ipc=host",
        "--uts=host",
        "--userns=host",
        "--cgroupns=host",
        "--network=host",
        "--volume",
        "--mount=",
        "/var/run/docker.sock",
        "--entrypoint",
        "seccomp=unconfined",
        "apparmor=unconfined",
        "/bin/sh",
        "/bin/chown",
        "/bin/chmod",
        "/usr/bin/find /cleanup",
    ):
        if forbidden in normalizer:
            raise VerificationError(f"private-tree normalizer retains forbidden Docker authority: {forbidden}")
    for text, label in (
        ('--check-descriptor-budget', "host retained-authority capacity proof"),
        ('--check-exact-descriptor-budget', "container exact retained-authority capacity proof"),
        ('--ulimit nofile=524544:524544', "capacity-preflight descriptor limit"),
        ('--pull=never', "capacity-preflight no-pull policy"),
        ('--network=none', "capacity-preflight network isolation"),
        ('--read-only', "capacity-preflight immutable container root"),
        ('--cap-drop=ALL', "capacity-preflight capability reset"),
        ('--security-opt no-new-privileges', "capacity-preflight privilege ceiling"),
    ):
        require_text(capacity_check, text, label)
    if "--cap-add=" in capacity_check:
        raise VerificationError("retained-authority capacity preflight adds a capability")
    for text, label in (
        ('path_state="$(stat -c \'%d:%i:%u:%g:%a:%h:%F\'', "helper pathname identity acquisition"),
        ('[ "$path_state" = "$(stat -c \'%d:%i\' -- "$PRIVATE_TREE_CLOSURE_PROBE"):$(id -u):$(id -g):500:1:regular file" ]', "helper pathname metadata proof"),
        ('exec {PRIVATE_TREE_CLOSURE_FD}< "$PRIVATE_TREE_CLOSURE_PROBE"', "open helper execution authority"),
        ('stat -Lc \'%d:%i:%u:%g:%a:%h:%F\'', "helper descriptor identity proof"),
        ('[ "$descriptor_state" = "$path_state" ]', "helper pathname/descriptor identity equality"),
        ('sha256sum "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"', "helper descriptor content proof"),
        ('[ "$observed_hash" = "$PRIVATE_TREE_CLOSURE_HASH" ]', "helper committed-content equality"),
        ('[ -z "$PRIVATE_TREE_CLOSURE_FD" ] || return 1', "duplicate helper-authority rejection"),
    ):
        require_text(execution_authority, text, label)
    for text, label in (
        ('[ -n "$PRIVATE_TREE_CLOSURE_FD" ] || return 0', "absent helper-close identity"),
        ('exec {PRIVATE_TREE_CLOSURE_FD}<&- || return 1', "helper descriptor close"),
        ('PRIVATE_TREE_CLOSURE_FD=""', "helper descriptor retirement"),
    ):
        require_text(execution_close, text, label)
    require_order(
        execution_close,
        (
            '[ -n "$PRIVATE_TREE_CLOSURE_FD" ] || return 0',
            'exec {PRIVATE_TREE_CLOSURE_FD}<&- || return 1',
            'PRIVATE_TREE_CLOSURE_FD=""',
        ),
        "helper descriptor close ordering",
    )
    for text, label in (
        ('[ -n "$PRIVATE_TREE_CLOSURE_FD" ] && [ -n "$PRIVATE_TREE_CLOSURE_HASH" ]', "descriptor executor authority precondition"),
        ('/usr/bin/python3 -I -S -c "$PRIVATE_TREE_CLOSURE_EXECUTOR"', "bounded descriptor executor"),
        ('"$PRIVATE_TREE_CLOSURE_HASH" "$@"', "descriptor executor committed digest"),
        ('< "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"', "descriptor executor byte source"),
    ):
        require_text(descriptor_executor, text, label)
    for text, label in (
        ('readonly PRIVATE_TREE_CLOSURE_EXECUTOR=', "immutable bounded helper executor"),
        ('sys.stdin.buffer.read(1048577)', "bounded terminal-removal helper input"),
        ('len(source) <= 1048576 or sys.exit(126)', "oversized terminal-removal helper rejection"),
        ('expected = sys.argv.pop(1)', "helper digest argument removal"),
        ('hashlib.sha256(source).hexdigest() == expected or sys.exit(126)', "in-memory helper digest proof"),
        ('exec(compile(source, "/probe.py", "exec"))', "authenticated in-memory helper execution"),
    ):
        require_text(source, text, label)
    expected_removal_command = (
        "docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n"
        "        --cap-drop=ALL --cap-add=DAC_OVERRIDE --cap-add=FOWNER \\\n"
        "        --security-opt no-new-privileges \\\n"
        "        --ulimit nofile=524544:524544 \\\n"
        '        --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled" \\\n'
        '        "$DEBIAN_IMAGE_ID" /usr/bin/python3 -I -S -c "$PRIVATE_TREE_CLOSURE_EXECUTOR" \\\n'
        '        "$PRIVATE_TREE_CLOSURE_HASH" \\\n'
        '        --remove-tree-contents /cleanup --expected-identity "$expected_identity" \\\n'
        '        --owner "$uid" --group "$gid" < "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"'
    )
    if removal_command != expected_removal_command:
        raise VerificationError("private-tree terminal remover command is not the exact authority allowlist")
    if re.findall(r"--cap-add=([A-Z_]+)", tree_remover) != [
        "DAC_OVERRIDE",
        "FOWNER",
    ]:
        raise VerificationError("private-tree terminal remover capability allowlist is not exact")
    for text, label in (
        ('[ "$observed" = "$expected_identity:$uid:$gid:700" ]', "terminal-removal root metadata proof"),
        ('run_private_tree_closure_from_descriptor --mount-root "$path"', "terminal-removal mount closure"),
        ('verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"', "terminal-removal image provenance"),
        ('"$PRIVATE_TREE_CLOSURE_HASH"', "terminal-removal helper digest"),
        ('< "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"', "descriptor-sourced terminal-removal helper"),
        ('--remove-tree-contents /cleanup', "terminal content-removal operation"),
        ('root authority changed during content removal', "terminal-removal root postcondition"),
    ):
        require_text(tree_remover, text, label)
    if '"$PRIVATE_TREE_CLOSURE_PROBE"' in tree_remover:
        raise VerificationError("private-tree terminal remover executes a mutable helper pathname")
    for forbidden in (
        '/usr/bin/python3 "$PRIVATE_TREE_CLOSURE_PROBE"',
        'src=$PRIVATE_TREE_CLOSURE_PROBE,dst=/probe.py',
    ):
        if forbidden in source:
            raise VerificationError(
                f"release transaction executes a mutable private-tree helper pathname: {forbidden}"
            )
    for forbidden in ("--privileged", "--cap-add=ALL", "--cap-add=CHOWN", "--network=host"):
        if forbidden in tree_remover:
            raise VerificationError(f"private-tree terminal remover retains forbidden authority: {forbidden}")
    require_text(snapshot_normalizer, '"$SOURCE_A"|"$SOURCE_B"', "snapshot normalizer scope")
    require_text(
        snapshot_normalizer,
        'offline_normalize_exact_tree "$source" "$expected" "$phase snapshot"',
        "snapshot normalizer exact-tree call",
    )
    require_text(snapshot_normalizer, '"$expected:$(id -u):$(id -g):700"', "snapshot root metadata proof")
    require_order(
        cleanup,
        (
            'if [ "$WINDOWS_UNSAFE" -eq 1 ] || [ "$KEEP_WORKSPACE" -eq 1 ]',
            "reconcile_final_publication",
            '[ -n "$PRIVATE_TREE_CLOSURE_FD" ] || cleanup_failed=1',
            "offline_remove_exact_tree_contents",
            "run_private_tree_closure_from_descriptor",
            '--remove-empty-private-root "$WORKSPACE"',
            "close_private_tree_closure_execution",
        ),
        "descriptor-bound terminal workspace cleanup ordering",
    )
    require_text(
        cleanup,
        "cleanup failed; recorded private workspace state is %s",
        "cleanup failure preservation",
    )
    require_text(cleanup, "workspace_state=absent", "missing-workspace failure state")
    require_text(cleanup, "workspace_state=invalid", "changed-workspace failure state")
    require_text(cleanup, 'elif [ ! -e "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ]', "missing workspace detection")
    if 'elif [ -n "$DEBIAN_IMAGE_ID" ]' in cleanup:
        raise VerificationError("workspace cleanup can delete without an installed closure probe")
    for forbidden in (
        "prepare_unprivileged_workspace_removal",
        'find -P "$WORKSPACE"',
        "chmod -R",
    ):
        if forbidden in source:
            raise VerificationError(
                f"workspace cleanup retains pathname mutation authority: {forbidden}"
            )
    require_text(
        cleanup,
        'if [ "$FIXTURE_MODE" -eq 0 ] && [ "$workspace_state" = valid ]',
        "production-only retained-authority workspace removal",
    )
    require_text(
        cleanup,
        "production cleanup lacks the pinned terminal-removal image; retained path",
        "missing production cleanup image rejection",
    )
    require_text(
        cleanup,
        'elif ! run_private_tree_closure_from_descriptor \\\n                --remove-private-root "$WORKSPACE"',
        "fixture-only recursive workspace removal",
    )
    for text, label in (
        ('install -d -m 0700 "$fixture"', "capability fixture private root"),
        ('install -d -m 1700 "$fixture/sticky"', "capability fixture sticky directory"),
        ('printf \'sticky-owner\\n\' > "$fixture/sticky/user-entry"', "capability fixture foreign sticky entry"),
        ('--cap-drop=ALL --cap-add=DAC_OVERRIDE --cap-add=FOWNER', "capability fixture exact capability set"),
        ('chmod 0000 /capability/root-entry', "capability fixture inaccessible root-owned file"),
        ('chmod 0000 /capability/locked', "capability fixture inaccessible root-owned directory"),
        ('[ "$observed" = "0:0:0" ]', "capability fixture root ownership proof"),
        ('offline_remove_exact_tree_contents "$fixture" "$fixture_id"', "capability fixture terminal removal"),
        ('--remove-empty-private-root "$fixture"', "capability fixture empty-root removal"),
        ('[ ! -e "$fixture" ] && [ ! -L "$fixture" ]', "capability fixture absence proof"),
    ):
        require_text(removal_capability, text, label)
    if re.findall(r"--cap-add=([A-Z_]+)", removal_capability) != [
        "DAC_OVERRIDE",
        "FOWNER",
    ]:
        raise VerificationError("terminal-removal capability preflight allowlist is not exact")
    require_order(
        cleanup_preflight,
        (
            '[ -n "$PRIVATE_TREE_CLOSURE_FD" ] || return 1',
            "verify_private_tree_authority_capacity",
            "verify_private_tree_removal_capability",
        ),
        "complete terminal-cleanup preflight ordering",
    )
    require_text(
        create_workspace,
        'install -m 0500 "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"',
        "private closure-probe installation",
    )
    require_order(
        create_workspace,
        ("trap cleanup_release_workspace EXIT", 'mktemp -d /tmp/rustdesk-release.', 'chmod 0700 "$WORKSPACE"'),
        "workspace trap installation",
    )
    require_order(
        create_workspace,
        (
            'PRIVATE_TREE_CLOSURE_PROBE="$WORKSPACE/private-tree-closure.py"',
            'install -m 0500 "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"',
            'PRIVATE_TREE_CLOSURE_HASH="$private_hash"',
            '"$PINNED_HEAD:scripts/verify-private-tree-closure.py"',
            '[ "$private_hash" = "$commit_hash" ]',
            'FINALIZE_RELEASE_SET_PROBE="$WORKSPACE/finalize-release-set.py"',
            'install -m 0500 "$FINALIZE_RELEASE_SET_SOURCE" "$FINALIZE_RELEASE_SET_PROBE"',
            '"$PINNED_HEAD:scripts/finalize-release-set.py"',
            '[ "$publisher_private_hash" = "$commit_hash" ]',
            'DOCKER_CONFIG_DIR="$WORKSPACE/docker-config"',
            "acquire_private_tree_closure_execution",
        ),
        "private release-helper installation",
    )
    require_order(
        main,
        (
            'DEBIAN_IMAGE_ID="${DEB_BUILDER_IMAGE_ID:-}"',
            "create_workspace",
            "release_preflight",
        ),
        "production cleanup image initialization",
    )
    require_text(cleanup, "trap '' HUP INT TERM", "cleanup signal exclusion")
    require_exact_count(cleanup, '[ "$status" -ne 0 ] || status=1', 1, "cleanup original-status preservation")
    require_order(
        cleanup,
        (
            "trap '' HUP INT TERM",
            "reconcile_final_publication",
            '--remove-empty-private-root "$WORKSPACE"',
            '[ "$status" -eq 0 ] && [ -n "$RELEASE_SUCCESS_MESSAGE" ]',
            'log "$RELEASE_SUCCESS_MESSAGE"',
            'exit "$status"',
        ),
        "success-after-cleanup finalization",
    )
    for marker in (
        'log "RELEASE OK:',
        'log "DOCTOR OK:',
        'log "build-release self-test: OK"',
        'log "build-release root-owned reset self-test: OK"',
    ):
        if marker in source:
            raise VerificationError("a build-release success marker bypasses final cleanup")
    for marker in (
        'RELEASE_SUCCESS_MESSAGE="RELEASE OK:',
        'RELEASE_SUCCESS_MESSAGE="DOCTOR OK:',
        'RELEASE_SUCCESS_MESSAGE="build-release self-test: OK"',
        'RELEASE_SUCCESS_MESSAGE="build-release root-owned reset self-test: OK"',
    ):
        require_text(source, marker, "deferred build-release success marker")
    require_text(
        source,
        '--mount "type=bind,src=$SOURCE_A,dst=/fixture,bind-recursive=disabled"',
        "reset fixture recursive-bind exclusion",
    )
    require_text(
        source,
        "printf 'build-release cleanup-missing self-test: REACHED\\n' >&2",
        "release missing-workspace reached marker",
    )
    require_order(
        verification,
        (
            'reset_snapshot_build_state "$source" "$label before verification"',
            'run_snapshot_consumer "$label complete release verification"',
            'reset_snapshot_build_state "$source" "$label after verification"',
        ),
        "verification reset envelope",
    )
    require_order(
        build_snapshot,
        (
            'run_verification "$source" "$label"',
            'invoke_target "$label" "$target"',
            'reset_snapshot_build_state "$source" "$label after $target"',
            "verify_all_release_builder_images",
        ),
        "post-target reset ordering",
    )
    require_text(
        build_snapshot,
        'invoke_target "$label" "$target" "$source" "$output/$target" "$set_dir"',
        "exact target-leaf invocation topology",
    )
    if re.search(r'(?m)^\s*(?:mkdir|install)\b[^\n]*\$output\b', target_invocation):
        raise VerificationError("release orchestrator precreates a target publication path")
    require_order(
        target_invocation,
        (
            '{ [ ! -e "$output" ] && [ ! -L "$output" ]; }',
            'case "$target" in',
            'windows_state="$(dirname "$source")/windows-state"',
            '{ [ ! -e "$windows_state" ] && [ ! -L "$windows_state" ]; }',
            "WINDOWS_UNSAFE=1",
            'HARNESS_STATE_DIR="$windows_state"',
            '"$source/scripts/build-windows-vm.sh"',
        ),
        "absent target publication and output-disjoint Windows state",
    )
    for text, label in (
        ('[ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ]', "fixture target-output absence proof"),
        ('[ ! -e "$HARNESS_STATE_DIR" ] && [ ! -L "$HARNESS_STATE_DIR" ]', "fixture Windows-state absence proof"),
        ('state_path="$(realpath -m -- "$HARNESS_STATE_DIR")"', "fixture canonical Windows-state path"),
        ('output_path="$(realpath -m -- "$fixture_output")"', "fixture canonical Windows-output path"),
        ('case "$state_path/" in "$output_path/"*) exit 1 ;; esac', "fixture Windows-state descendant rejection"),
        ('case "$output_path/" in "$state_path/"*) exit 1 ;; esac', "fixture Windows-state ancestor rejection"),
        ('OUT_DIR="$(mktemp -d "$(dirname "$fixture_output")/.windows-publish.XXXXXXXX")"', "fixture private Windows staging directory"),
        ('mv -T --no-clobber -- "$OUT_DIR" "$fixture_output"', "fixture atomic Windows publication"),
        ('[ -z "${HARNESS_STATE_DIR+x}" ]', "fixture non-Windows state-authority rejection"),
    ):
        require_text(fixture_target, text, label)
    require_exact_count(
        fixture_target,
        '[ ! -e "$fixture_output" ] && [ ! -L "$fixture_output" ]',
        1,
        "fixture post-state Windows-output absence proof",
    )
    for text, label in (
        ("release self-test target output topology is not exact", "exact target-output fixture topology"),
        ("release self-test gave non-Windows targets harness state authority", "non-Windows fixture state isolation"),
        ("release self-test Windows state is not pass-private and output-disjoint", "Windows fixture state isolation"),
    ):
        require_text(transaction_self_test, text, label)
    require_exact_count(source, "DOUBLE_BUILD=0", 3, "single target invocation per outer snapshot")
    require_text(source, 'build_snapshot A "$SOURCE_A"', "snapshot A target execution")
    require_text(source, 'build_snapshot B "$SOURCE_B"', "snapshot B target execution")
    require_text(source, "independent snapshot mismatch for $name", "all-artifact A/B comparison")
    require_text(source, "# reproducibility: independent-snapshots-a-equals-b", "manifest reproducibility identity")
    require_order(
        publication_tool,
        (
            '/usr/bin/python3 -I -S "$FINALIZE_RELEASE_SET_PROBE"',
            '"$@"',
        ),
        "isolated final release publisher dispatch",
    )
    require_order(
        published_proof,
        (
            'publication_tool --verify --path "$destination"',
            '--commit "$PINNED_HEAD" --version "$FORK_VER" --epoch "$SOURCE_DATE_EPOCH_PIN"',
        ),
        "exact published release-set proof dispatch",
    )
    require_order(
        recovery,
        (
            '[ "$(dirname "$destination")" = "$parent" ]',
            'base="$(basename "$destination")"',
            'publication_tool --recover --parent "$parent" --destination "$base"',
        ),
        "bounded publication recovery dispatch",
    )
    require_order(
        reconciliation,
        (
            '[ -n "$FINALIZE_RELEASE_SET_PROBE" ] || return 0',
            '[ -f "$FINALIZE_RELEASE_SET_PROBE" ] && [ ! -L "$FINALIZE_RELEASE_SET_PROBE" ]',
            'recover_pending_publications "$REPO_ROOT" "$FINAL_OUT_DIR"',
        ),
        "cleanup publication reconciliation authority",
    )
    require_order(
        atomic_install,
        (
            'parent="$(dirname "$destination")"',
            'base="$(basename "$destination")"',
            'publication_tool --publish --parent "$parent" --destination "$base"',
            '--source "$source" --commit "$PINNED_HEAD" --version "$FORK_VER"',
            '--epoch "$SOURCE_DATE_EPOCH_PIN"',
        ),
        "exact final release publication dispatch",
    )
    for forbidden in ("renameat2", "RENAME_EXCHANGE", "RENAME_NOREPLACE", "O_TMPFILE"):
        if forbidden in source:
            raise VerificationError(
                f"build-release retains inlined publication primitive {forbidden}"
            )
    require_text(source, "git --no-replace-objects", "Git replacement-object suppression")
    require_text(source, "Git grafts are forbidden for release builds", "Git graft rejection")
    require_text(source, "Git object alternates are forbidden for release builds", "Git alternate rejection")
    require_text(source, "Git replacement refs are forbidden for release builds", "Git replacement-ref rejection")
    require_text(source, "GIT_NO_REPLACE_OBJECTS=1", "child replacement-object suppression")
    for text, label in (
        ('exec {PUBLICATION_LOCK_FD}< "$common_dir"', "repository-directory publication lock descriptor"),
        ('flock -n "$PUBLICATION_LOCK_FD"', "exclusive publication lock"),
        ('"/proc/self/fd/$PUBLICATION_LOCK_FD"', "publication lock descriptor identity proof"),
    ):
        require_text(source, text, label)
    require_text(source, '--verify-apk "$SET_A/rustdesk-arm64.apk"', "staged final APK certificate proof")
    require_text(source, "WINDOWS_UNSAFE=1", "Windows-owned state guard")
    require_text(source, "workspace retained because VM ownership is unresolved", "Windows failure retention")
    require_text(source, "run_self_test()", "release behavioral fixture")
    require_text(source, "release self-test did not execute exactly six target commands", "target execution fixture")
    require_text(source, "release self-test did not use two independent snapshots", "snapshot independence fixture")
    require_text(source, "release self-test target outputs are not distinct", "output isolation fixture")
    for text, label in (
        ("verify_release_builder_image deb-builder", "reset fixture image provenance"),
        ("negative control removed inaccessible root-owned state", "reset fixture negative control"),
        ('reset_snapshot_build_state "$SOURCE_A" "root-owned reset self-test"', "reset fixture production-call proof"),
        ("external symlink target", "reset fixture no-follow proof"),
        ("accepted an inode linked outside the snapshot", "reset fixture external-hardlink rejection"),
        ("internal-a", "reset fixture closed internal hardlink"),
        ("special-mode", "reset fixture special-mode input"),
        ("both root-owned mode-0000 directories", "reset fixture dual hostile-mode proof"),
        ("hostile Flutter directory", "reset fixture dual negative control"),
        ("retained-authority normalization differs", "reset fixture retained-authority postcondition"),
        ("build-release root-owned reset self-test: OK", "reset fixture success marker"),
    ):
        require_text(reset_self_test, text, label)
    require_text(
        reset_self_test,
        'if git_closed -C "$SOURCE_A" clean -ffdx >/dev/null 2>"$WORKSPACE/negative-clean.log"; then',
        "reset fixture live negative control",
    )
    require_text(
        reset_self_test,
        "metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0",
        "reset fixture live hostile-mode predicate",
    )
    require_text(
        reset_self_test,
        'assert_exact_checkout_state "reset self-test"',
        "reset fixture branch-neutral exact-checkout caller",
    )
    require_text(source, 'assert_exact_checkout_state "cleanup-missing self-test"', "cleanup-missing branch-neutral exact-checkout caller")
    require_text(source, 'assert_exact_checkout_state "$phase"', "master-only release wrapper exact-checkout dispatch")
    require_text(source, 'release checkout is detached', "master-only release detached-checkout rejection")
    require_text(source, 'release branch must be master', "master-only release branch rejection")
    for text, label in (
        ('fixture-repository', "private fixture Git authority"),
        ('git_closed init --quiet --initial-branch=master', "transaction fixture private Git initialization"),
        ('git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow', "reset fixture complete-history Git clone"),
        ('assert_git_object_authority', "reset fixture independent object-authority proof"),
    ):
        require_text(source, text, label)
    require_exact_count(
        create_workspace,
        'if [ "$SELF_TEST" -eq 0 ]; then',
        2,
        "reset fixture pinned closure-probe provenance",
    )
    require_order(
        reset_self_test,
        (
            'offline_normalize_exact_tree "$SOURCE_A" "$source_identity" "external-hardlink rejection fixture"',
            'rm -rf -- "$SOURCE_A/target"',
            'docker_local run --rm --pull=never',
            "for path in sys.argv[1:]",
            'check-ignore -q target/reset-proof/locked',
            'if git_closed -C "$SOURCE_A" clean -ffdx',
            "negative control did not preserve the hostile directory",
            "negative control did not preserve the hostile Flutter directory",
            'offline_normalize_exact_tree "$SOURCE_A" "$source_identity"',
            '"$SOURCE_A/target/reset-proof/special-mode"',
            "retained-authority normalization differs",
            'reset_snapshot_build_state "$SOURCE_A" "root-owned reset self-test"',
            '[ ! -e "$SOURCE_A/target/reset-proof" ]',
            '[ ! -e "$SOURCE_A/flutter/.dart_tool/reset-proof" ]',
            "external symlink target",
        ),
        "reset fixture adversarial ordering",
    )
    require_text(
        main,
        'if [ "$SELF_TEST_RESET" -eq 1 ]; then\n        run_reset_self_test\n        return 0',
        "reset fixture main dispatch",
    )
    require_text(
        main,
        'if [ "$SELF_TEST_SOURCE_STATE" -eq 1 ]; then\n        run_source_state_self_test\n        return 0',
        "exact source-state fixture main dispatch",
    )
    require_text(source, 'assert_exact_checkout_state "source-state self-test"', "exact source-state fixture dispatch")
    require_text(source, 'build-release source-state self-test: OK', "exact source-state fixture marker")
    for text, label in (
        ('install -d -m 0770 "$writable"', "group-writable parent rejection fixture"),
        ("publication accepted a group-writable parent", "group-writable parent rejection diagnostic"),
        ("publication recovery deleted an unbound initializing payload", "unbound initializing-payload fixture"),
        ("publication recovery accepted a raced first destination", "first-publication no-clobber race fixture"),
        ("first-publication fixture", "no-prior-destination fixture"),
        ("first-publication restart fixture", "first-publication restart fixture"),
        ("publication restart fixture", "existing-destination restart fixture"),
        ("partial-rollback fixture could not resume payload deletion", "partial rollback resumption fixture"),
        ("publication recovery accepted an incomplete prepared payload", "incomplete prepared-payload rejection fixture"),
        ("publication recovery accepted an unknown reserved namespace entry", "reserved-namespace rejection fixture"),
        ("publication recovery did not classify malformed $category state exactly", "malformed reserved-namespace fixture"),
        ("publication recovery did not reject a canonical wrong-token payload", "wrong-token payload ownership fixture"),
        ("wrong-token payload rejection changed transaction state", "wrong-token payload preservation fixture"),
        ("publication recovery did not reject a canonical wrong-token next record", "wrong-token next-record ownership fixture"),
        ("wrong-token next-record rejection changed transaction state", "wrong-token next-record preservation fixture"),
        ("publication recovery accepted multiple active transaction records", "multiple-record rejection fixture"),
        ("publication recovery accepted an oversized transaction record", "record-size rejection fixture"),
        ("publication recovery accepted a missing displaced prior set", "missing-prior rejection fixture"),
        ("publication recovery accepted a content-equal replacement destination", "destination-ABA rejection fixture"),
        ("publication recovery accepted a writable published artifact", "published-mode rejection fixture"),
        ("publication recovery accepted a special release entry", "published-special-type rejection fixture"),
        ("publication recovery accepted a multiply-linked published artifact", "published-hardlink rejection fixture"),
        ("publication recovery accepted an artifact extended attribute", "published-xattr rejection fixture"),
        ('publication_tool --publish --parent "$parent" --destination "$(basename "$destination")"', "production publisher fixture dispatch"),
        ('recover_pending_publications "$parent" "$destination"', "production recovery fixture dispatch"),
        ("prove_published_dist", "published-set fixture proof"),
    ):
        require_text(publication_self_test, text, label)
    require_exact_count(
        publication_self_test,
        "for point in staging prepared rollback-record exchange cleanup-record payload-removal; do",
        2,
        "complete publication restart matrix",
    )
    require_exact_count(
        publication_self_test,
        "pre-exchange recovery at $point",
        2,
        "state-accurate pre-exchange recovery diagnostics",
    )
    if "prepared recovery" in publication_self_test:
        raise VerificationError("publication fixture conflates durable recovery states")
    require_text(
        publication_self_test,
        "for category in transaction next payload; do",
        "complete malformed reserved-namespace matrix",
    )
    require_text(
        source,
        'run_publication_reconciliation_self_test "$SET_A"',
        "publication reconciliation fixture dispatch",
    )
    require_exact_count(main, "compare_snapshots\n", 1, "release transaction")
    require_order(
        main,
        (
            'prepare_release_snapshots\n',
            'build_snapshot A "$SOURCE_A"',
            'build_snapshot B "$SOURCE_B"',
            'run_snapshot_consumer "final APK certificate proof"',
            'reset_snapshot_build_state "$SOURCE_A" "after final APK certificate proof"',
            "compare_snapshots\n",
            'write_manifest "$SET_A"',
            'assert_release_source_state "before final dist installation"',
            'assert_live_origin_master "before final dist installation"',
            'atomic_install_dist "$SET_A"',
            'RELEASE_SUCCESS_MESSAGE="RELEASE OK:',
        ),
        "release transaction",
    )


def validate_release_finalizer(source):
    try:
        module = ast.parse(source)
    except SyntaxError as exc:
        raise VerificationError(
            f"final release publisher syntax: Python source does not parse: {exc}"
        ) from exc

    assignments = {}
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name):
            try:
                assignments[target.id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    if assignments.get("ASSETS") != (
        "rustdesk-x86_64.deb",
        "rustdesk-arm64.apk",
        "rustdesk-setup.exe",
        "rustdesk.msi",
    ):
        raise VerificationError("final release publisher canonical asset set")
    if assignments.get("SUPPORTED_FILESYSTEMS") != {0xEF53: "ext4"}:
        raise VerificationError("final release publisher filesystem allowlist")
    if assignments.get("ACL_XATTRS") != {
        "system.posix_acl_access",
        "system.posix_acl_default",
    }:
        raise VerificationError("final release publisher complete POSIX ACL rejection")
    for declaration, name in (
        ("MANIFEST_LIMIT = 65536", "MANIFEST_LIMIT"),
        ("CONTENT_LIMIT = 2 * 1024 * 1024 * 1024", "CONTENT_LIMIT"),
        ("RECORD_LIMIT = 4096", "RECORD_LIMIT"),
        ("PARENT_ENTRY_LIMIT = 4096", "PARENT_ENTRY_LIMIT"),
        ("PARENT_NAME_LIMIT = 1024 * 1024", "PARENT_NAME_LIMIT"),
        ("MOUNTINFO_LIMIT = 4 * 1024 * 1024", "MOUNTINFO_LIMIT"),
        ("MOUNTINFO_ENTRY_LIMIT = 4096", "MOUNTINFO_ENTRY_LIMIT"),
        ("DEADLINE_SECONDS = 180", "DEADLINE_SECONDS"),
        ("FS_IOC_GETFSUUID = 0x80111500", "FS_IOC_GETFSUUID"),
        ("FILESYSTEM_UUID_SIZE = 16", "FILESYSTEM_UUID_SIZE"),
    ):
        require_text(source, declaration, f"final release publisher exact {name} bound")
    frozen_assignments = {}
    for node in module.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (
            not isinstance(target, ast.Name)
            or not isinstance(node.value, ast.Call)
            or not isinstance(node.value.func, ast.Name)
            or node.value.func.id != "frozenset"
            or len(node.value.args) != 1
            or node.value.keywords
        ):
            continue
        try:
            frozen_assignments[target.id] = frozenset(ast.literal_eval(node.value.args[0]))
        except (ValueError, TypeError):
            pass
    states = frozen_assignments.get("RECORD_STATES")
    if states != frozenset({
        "initializing",
        "staging",
        "prepared",
        "rollback",
        "cleanup",
    }):
        raise VerificationError("final release publisher durable staging and terminal states")
    if frozen_assignments.get("RECORD_TRANSITIONS") != frozenset(
        {
            ("initializing", "staging"),
            ("staging", "prepared"),
            ("prepared", "rollback"),
            ("prepared", "cleanup"),
        }
    ):
        raise VerificationError("final release publisher exact crash-state transitions")

    for node in ast.walk(module):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            if any(name.split(".", 1)[0] in {"subprocess", "shutil"} for name in names):
                raise VerificationError("final release publisher imports pathname-recursive authority")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr in {"system", "popen", "spawnl", "spawnv"}
        ):
            raise VerificationError("final release publisher invokes an unmanaged process")

    parent_init = extract_python_method(
        source, module, "ParentAuthority", "__init__", "publication parent acquisition"
    )
    parent_assert = extract_python_method(
        source, module, "ParentAuthority", "assert_bound", "publication parent authority"
    )
    path_authority = extract_python_method(
        source, module, "ParentAuthority", "path_authority", "publication path authority"
    )
    canonical_security = extract_python_definition(
        source, module, "require_canonical_security", "publication filesystem security"
    )
    mount_filesystem = extract_python_definition(
        source, module, "mount_filesystem_type", "publication mount-table authority"
    )
    filesystem_authority = extract_python_definition(
        source, module, "filesystem_authority", "publication filesystem UUID authority"
    )
    regular_open = extract_python_definition(
        source, module, "open_regular_at", "nonblocking regular-file acquisition"
    )
    bounded_inventory = extract_python_definition(
        source, module, "bounded_names", "publication bounded inventory"
    )
    release_set = "\n".join(
        extract_python_definition(source, module, name, "published release-set authority")
        for name in (
            "open_release_set",
            "prove_release_set",
            "verify_release_set",
            "finalize_staged_release_set",
            "source_release",
        )
    )
    record_validation = "\n".join(
        extract_python_definition(source, module, name, "durable publication record")
        for name in (
            "canonical_record",
            "validate_record",
            "create_record_file",
            "read_record",
            "require_record_transition",
            "replace_record",
            "install_initial_record",
            "update_record",
            "unlink_record",
        )
    )
    validate_record_functions = [
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "validate_record"
    ]
    if len(validate_record_functions) != 1:
        raise VerificationError("durable publication record: expected one validator")
    expected_key_assignments = [
        node
        for node in validate_record_functions[0].body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "expected_keys"
            for target in node.targets
        )
    ]
    expected_record_keys = {
        "format",
        "state",
        "token",
        "destination",
        "filesystem",
        "parent_handle",
        "payload",
        "payload_handle",
        "prior_handle",
        "commit",
        "version",
        "epoch",
        "manifest_sha256",
    }
    try:
        recorded_keys = (
            ast.literal_eval(expected_key_assignments[0].value)
            if len(expected_key_assignments) == 1
            else None
        )
    except (ValueError, TypeError):
        recorded_keys = None
    if recorded_keys != expected_record_keys:
        raise VerificationError("durable publication record key schema is not exact")
    create_record = extract_python_definition(
        source, module, "create_record_file", "durable publication record creation"
    )
    replace_record = extract_python_definition(
        source, module, "replace_record", "durable publication record transition"
    )
    unlink_record = extract_python_definition(
        source, module, "unlink_record", "durable publication record removal"
    )
    cleanup_payload = extract_python_definition(
        source, module, "cleanup_payload", "descriptor-bound publication cleanup"
    )
    create_payload = extract_python_definition(
        source, module, "create_payload_root", "durable publication payload creation"
    )
    stage_payload = extract_python_definition(
        source, module, "stage_payload", "durable publication staging"
    )
    namespace = extract_python_definition(
        source, module, "record_names", "publication reserved namespace"
    )
    transition = extract_python_definition(
        source, module, "require_record_transition", "publication state transition"
    )
    recovery = extract_python_definition(
        source, module, "recover", "restartable publication recovery"
    )
    finish_cleanup = extract_python_definition(
        source, module, "finish_cleanup", "committed publication cleanup"
    )
    finish_rollback = extract_python_definition(
        source, module, "finish_rollback", "durable publication rollback"
    )
    publish = extract_python_definition(
        source, module, "publish", "failure-atomic publication"
    )
    initial_record = extract_python_definition(
        source, module, "initial_record", "initial durable publication record"
    )
    run_with_parent = extract_python_definition(
        source, module, "run_with_parent", "publication parent lifecycle"
    )
    quiescent_verify = extract_python_definition(
        source, module, "verify_quiescent_release", "quiescent publication verification"
    )
    verify_path = extract_python_definition(
        source, module, "verify_path", "publication verification dispatch"
    )

    for text, label in (
        ("not os.path.isabs(parent)", "absolute publication parent"),
        ("os.path.normpath(parent) != parent", "normalized publication parent"),
        ("os.path.realpath(parent) != parent", "canonical publication parent"),
        ('destination in (".", "..")', "dot-destination rejection"),
        ("os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC", "no-follow parent descriptor"),
        ("self.metadata.st_uid != self.uid", "publication parent owner proof"),
        ("self.metadata.st_gid != self.gid", "publication parent group proof"),
        ("self.metadata.st_mode & stat.S_IRWXU != stat.S_IRWXU", "publication parent owner access"),
        ("fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)", "exclusive parent lock"),
        ('require_no_extended_acl(descriptor, "publication parent")', "publication parent ACL proof"),
        ("self.mount_id = descriptor_mount_id(descriptor)", "publication parent mount authority"),
        ("self.filesystem = filesystem_authority(descriptor, self.mount_id)", "publication filesystem UUID proof"),
        ("self.handle = persistent_handle(descriptor)", "durable publication parent identity"),
        ("os.fpathconf(descriptor, \"PC_NAME_MAX\")", "publication sibling-name bound"),
        ("self.metadata.st_mode & 0o022", "publication parent writer rejection"),
        ("stable_metadata(edge) != stable_metadata(self.metadata)", "publication parent edge binding"),
        ("close_descriptors(", "failed parent acquisition descriptor cleanup"),
    ):
        require_text(parent_init, text, label)
    for text, label in (
        ("identity(metadata) != self.identity", "retained publication parent identity"),
        ("stable_metadata(edge) != stable_metadata(metadata)", "live publication parent edge"),
        ("metadata.st_mode & 0o022", "live publication parent writer exclusion"),
        ("metadata.st_uid != self.uid", "live publication parent owner proof"),
        ("metadata.st_gid != self.gid", "live publication parent group proof"),
        ("descriptor_mount_id(self.fd) != self.mount_id", "live publication mount identity"),
        ("filesystem_authority(self.fd, self.mount_id) != self.filesystem", "live publication filesystem UUID"),
        ("persistent_handle(self.fd) != self.handle", "live durable publication parent identity"),
        ('require_no_extended_acl(self.fd, "publication parent")', "live publication ACL proof"),
    ):
        require_text(parent_assert, text, label)
    for text, label in (
        ("descriptor = os.open(", "publication path descriptor acquisition"),
        ("stable_metadata(edge) != stable_metadata(metadata)", "publication path edge binding"),
        ('"handle": persistent_handle(descriptor)', "publication path persistent object handle"),
        ("close_descriptors(", "publication path descriptor cleanup"),
    ):
        require_text(path_authority, text, label)
    for text, label in (
        ("names = os.listxattr(descriptor)", "complete publication xattr inventory"),
        ("if names:", "publication xattr rejection"),
        ("fcntl.ioctl(descriptor, FS_IOC_GETFLAGS", "publication inode-flag inspection"),
        ("flags[0] & ~FS_EXTENT_FL", "publication inode-flag allowlist"),
        ("fcntl.ioctl(descriptor, FS_IOC_FSGETXATTR", "publication extended inode inspection"),
        ("xflags, extsize, _nextents, project, cowextsize, pad0, pad1 = struct.unpack(", "publication extended inode field parsing"),
        ("if xflags or extsize or project or cowextsize or pad0 or pad1:", "publication writable extended inode-state rejection"),
    ):
        require_text(canonical_security, text, label)
    for text, label in (
        ('"/proc/self/mountinfo"', "kernel mount-table source"),
        ("while len(content) <= MOUNTINFO_LIMIT:", "bounded mount-table read"),
        ("if len(lines) > MOUNTINFO_ENTRY_LIMIT:", "bounded mount-table records"),
        ("if fields[0] == expected:", "runtime mount identity lookup"),
        ("if len(matches) != 1:", "unique runtime mount binding"),
        ('return matches[0].decode("ascii")', "canonical mount filesystem type"),
    ):
        require_text(mount_filesystem, text, label)
    for text, label in (
        ("LIBC.fstatfs(descriptor, ctypes.byref(result))", "descriptor-bound filesystem inspection"),
        ("expected = SUPPORTED_FILESYSTEMS.get(value)", "exact filesystem allowlist dispatch"),
        ("observed = mount_filesystem_type(mount_id)", "ext4 versus ext2/ext3 discrimination"),
        ("if expected is None or observed != expected:", "filesystem type agreement"),
        ("fcntl.ioctl(descriptor, FS_IOC_GETFSUUID, filesystem_uuid, True)", "descriptor-bound filesystem UUID"),
        ("filesystem_uuid[0] != FILESYSTEM_UUID_SIZE", "exact filesystem UUID size"),
        ("value == bytes(FILESYSTEM_UUID_SIZE)", "zero filesystem UUID rejection"),
        ('return f"{observed}:{value.hex()}"', "complete filesystem UUID authority encoding"),
    ):
        require_text(filesystem_authority, text, label)
    require_order(
        regular_open,
        (
            "os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC",
            "metadata = os.fstat(authority)",
            "not stat.S_ISREG(metadata.st_mode)",
            'f"/proc/self/fd/{authority}"',
            "os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC",
            "stable_metadata(current) != stable_metadata(metadata)",
            "return descriptor",
            "close_descriptors((authority,)",
        ),
        "nonblocking descriptor-bound regular-file acquisition",
    )
    for text, label in (
        ("with os.scandir(descriptor) as entries:", "streamed publication inventory"),
        ("if len(names) >= PARENT_ENTRY_LIMIT:", "publication entry-count bound"),
        ("if name_bytes > PARENT_NAME_LIMIT:", "publication name-byte bound"),
        ("return sorted(names, key=os.fsencode)", "canonical publication inventory ordering"),
    ):
        require_text(bounded_inventory, text, label)

    for text, label in (
        ("tuple(names) != tuple(sorted(ENTRY_NAMES, key=os.fsencode))", "exact five-file release inventory"),
        ("open_regular_at(", "nonblocking release entry descriptors"),
        ("not stat.S_ISREG(metadata.st_mode)", "regular release entries"),
        ("stat.S_IMODE(metadata.st_mode) != 0o444", "immutable release entry modes"),
        ("metadata.st_nlink != 1", "release entry hardlink rejection"),
        ("metadata.st_dev != parent.metadata.st_dev", "release entry filesystem binding"),
        ("descriptor_mount_id(descriptor) != parent.mount_id", "release entry mount binding"),
        ("require_canonical_security(descriptor", "release entry filesystem-security proof"),
        ("parse_manifest(manifest, commit, version, epoch)", "record-bound release manifest"),
        ("hash_exact(", "bounded release artifact hashing"),
        ("stable_metadata(current) != before[entry]", "retained release descriptor reproof"),
        ("os.fchmod(root_fd, 0o555)", "published root finalization"),
        ("name,\n        0o555,\n        False,", "exact published-root verification mode"),
        ("name,\n        0o700,\n        True,", "explicit staged-root finalization mode"),
        ("os.fsync(descriptor)", "published file durability"),
        ("os.fsync(root_fd)", "published directory durability"),
        ("parent.assert_bound()", "published parent reproof"),
    ):
        require_text(release_set, text, label)
    require_exact_count(
        release_set,
        "open_regular_at(",
        2,
        "nonblocking release and source entry acquisition",
    )

    for text, label in (
        ("ensure_ascii=True", "ASCII publication record"),
        ("allow_nan=False", "non-finite record exclusion"),
        ("sort_keys=True", "canonical record key ordering"),
        ("set(record) != expected_keys", "exact record shape"),
        ('record["destination"] != parent.destination', "record destination binding"),
        ('record["format"] != "rustdesk-release-transaction-v3"', "record format binding"),
        ('record["filesystem"] != parent.filesystem', "persistent record filesystem binding"),
        ('parse_handle(record["parent_handle"]) != parent.handle', "durable record parent binding"),
        ('for field in ("payload_handle", "prior_handle"):', "durable payload/prior handle validation"),
        ('record["payload"] != f".{parent.destination}-release-payload.{token}"', "record payload-name binding"),
        ("parse_handle(record[field])", "record object-handle validation"),
        ("canonical_record(record) != content", "canonical record encoding proof"),
        ("stat.S_IMODE(before.st_mode) != 0o400", "read-only record mode"),
        ("before.st_nlink != 1", "record hardlink rejection"),
        ("require_canonical_security(descriptor, \"publication record\")", "record filesystem-security proof"),
        ("parse_constant=reject_json_constant", "non-finite JSON record rejection"),
    ):
        require_text(record_validation, text, label)
    require_exact_count(
        record_validation,
        "open_regular_at(",
        4,
        "nonblocking publication record acquisition",
    )
    for text, label in (
        ('"filesystem": parent.filesystem', "initial durable record filesystem binding"),
        ('"parent_handle": parent.handle', "initial durable record parent binding"),
        ('"payload_handle": None', "initial durable record payload state"),
        ('"prior_handle": old_handle', "initial durable record prior binding"),
    ):
        require_text(initial_record, text, label)
    require_text(
        transition,
        '(current["state"], following["state"]) not in RECORD_TRANSITIONS',
        "exact publication transition allowlist",
    )
    for text, label in (
        ('current["state"] == "initializing" and following["state"] == "staging"', "payload-handle binding transition"),
        ('current_base["payload_handle"] = following_base["payload_handle"]', "payload-handle-only transition mutation"),
        ('current["state"] == "staging" and following["state"] == "prepared"', "manifest binding transition"),
        ('current_base["manifest_sha256"] = following_base["manifest_sha256"]', "manifest-only transition mutation"),
    ):
        require_text(transition, text, label)
    require_order(
        create_record,
        (
            "os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC",
            "if written <= 0:",
            "os.fchmod(descriptor, 0o400)",
            "require_canonical_security(descriptor",
            "os.fsync(descriptor)",
            "link_unnamed_file(descriptor, parent.fd, name)",
            "linked.st_nlink != 1",
            "os.fsync(parent.fd)",
        ),
        "durable unnamed publication record commit",
    )
    require_order(
        replace_record,
        (
            "parent.assert_bound()",
            "os.replace(next_name, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)",
            "displaced.st_nlink != 0",
            "path_metadata(parent.fd, next_name) is not None",
            "os.fsync(parent.fd)",
            "publication record transition changed after commit",
        ),
        "durable publication record transition",
    )
    require_order(
        unlink_record,
        (
            "identity(metadata) != expected_identity",
            "metadata.st_nlink != 1",
            "parent.assert_bound()",
            "os.unlink(name, dir_fd=parent.fd)",
            "removed.st_nlink != 0",
            "os.fsync(parent.fd)",
            "publication record removal changed after commit",
        ),
        "durable exact record removal",
    )

    for text, label in (
        ("os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC", "no-follow cleanup root"),
        ("identity(root) != expected_identity", "cleanup root identity"),
        ("descriptor_mount_id(root_fd) != parent.mount_id", "cleanup root mount binding"),
        ("any(entry not in ENTRY_NAMES for entry in names)", "bounded cleanup inventory"),
        ("metadata.st_nlink != 1", "cleanup hardlink rejection"),
        ("require_canonical_security(descriptor", "cleanup entry security proof"),
        ("os.fchmod(root_fd, 0o700)", "cleanup authorization mode"),
        ("os.unlink(entry, dir_fd=root_fd)", "descriptor-relative entry removal"),
        ("removed.st_nlink != 0", "cleanup edge-consumption proof"),
        ("os.fsync(root_fd)", "cleanup directory durability"),
        ("os.rmdir(name, dir_fd=parent.fd)", "descriptor-relative payload removal"),
        ("os.fsync(parent.fd)", "payload-removal parent durability"),
    ):
        require_text(cleanup_payload, text, label)
    require_exact_count(
        cleanup_payload,
        "open_regular_at(",
        1,
        "nonblocking cleanup entry acquisition",
    )
    require_order(
        create_payload,
        (
            "parent.assert_bound()",
            "os.mkdir(payload_name, 0o700, dir_fd=parent.fd)",
            "os.fsync(parent.fd)",
            "payload_fd = os.open(",
            "or bounded_names(payload_fd)",
            'require_canonical_security(payload_fd, "publication payload")',
            "payload_handle = persistent_handle(payload_fd)",
            "parent.assert_bound()",
        ),
        "durable empty payload authority before handle commit",
    )
    for text, label in (
        ('record["state"] != "staging"', "staging-record authorization"),
        ('persistent_handle(payload_fd) != expected_payload_handle', "staging persistent payload identity"),
        ("deadline = time.monotonic() + DEADLINE_SECONDS", "publication staging deadline"),
        ("os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC", "unnamed staged files"),
        ("if written <= 0:", "staging write-progress proof"),
        ("stable_metadata(os.fstat(source_descriptor)) != stable_metadata(", "stable source descriptor"),
        ("os.fchmod(destination, 0o444)", "staged entry immutable mode"),
        ("final.st_nlink != 0", "unnamed staged-entry proof"),
        ("os.fsync(destination)", "staged file durability"),
        ("link_unnamed_file(destination, payload_fd, name)", "descriptor-bound staged link"),
        ("linked.st_nlink != 1", "staged link binding"),
        ("os.fsync(payload_fd)", "staged directory durability"),
        ("os.fsync(parent.fd)", "staged payload-name durability"),
        ("finalize_staged_release_set(", "post-staging exact-set finalization proof"),
    ):
        require_text(stage_payload, text, label)
    for text, label in (
        ('reserved_prefix = f".{parent.destination}-release-"', "complete reserved namespace"),
        ("if name.startswith(reserved_prefix):", "unknown reserved-name rejection"),
        ('"record": re.compile(rf"\\.{escaped}-release-transaction\\.([0-9a-f]{{64}})")', "canonical record namespace"),
        ('"next": re.compile(rf"\\.{escaped}-release-next\\.([0-9a-f]{{64}})")', "canonical next-record namespace"),
        ('"payload": re.compile(rf"\\.{escaped}-release-payload\\.([0-9a-f]{{64}})")', "canonical payload namespace"),
        ("match = pattern.fullmatch(name)", "exact reserved-name classification"),
    ):
        require_text(namespace, text, label)

    require_order(
        recovery,
        (
            "parent.assert_bound()",
            "found = record_names(parent)",
            'if not found["record"]:',
            'if found["next"] or found["payload"]:',
            "os.fsync(parent.fd)",
            "parent.assert_bound()",
            "confirmed = record_names(parent)",
            "if any(confirmed.values()):",
            "return",
        ),
        "durable empty-recovery observation",
    )
    for text, label in (
        ("if next_token != token:", "next-record transaction ownership"),
        ("publication next record belongs to another transaction", "next-record ownership rejection"),
        ('if found["payload"] and found["payload"][0] != (record["payload"], token):', "payload transaction ownership"),
        ("publication payload belongs to another transaction", "payload ownership rejection"),
    ):
        require_text(recovery, text, label)
    require_order(
        recovery,
        (
            'if record["state"] == "initializing":',
            "verify_prior_release(parent, old_handle)",
            "if payload is not None:",
            "initial publication record has an unbound payload identity",
            "verify_prior_release(parent, old_handle)",
            "unlink_record(",
            "return",
            'if record["state"] == "staging":',
            "finish_rollback(",
        ),
        "unbound initialization rejection and bound staging rollback",
    )
    require_order(
        recovery,
        (
            'if record["state"] == "prepared":',
            "if before_exchange:",
            "verify_release_set(",
            'rollback_record["state"] = "rollback"',
            "update_record(",
            "record = rollback_record",
            'if record["state"] == "rollback":',
            "finish_rollback(",
        ),
        "durable prepared rollback authorization",
    )
    require_order(
        finish_rollback,
        (
            "verify_prior_release(parent, old_handle)",
            'payload["handle"] != new_handle',
            "cleanup_payload(",
            "(0o555, 0o700)",
            "verify_prior_release(parent, old_handle)",
            "unlink_record(",
        ),
        "resumable authorized publication rollback",
    )
    require_order(
        recovery,
        (
            "if not after_exchange:",
            "publication exchange outcome is ambiguous",
            "verify_release_set(",
            'cleanup_record["state"] = "cleanup"',
            "update_record(",
            "finish_cleanup(",
        ),
        "post-exchange recovery authorization",
    )
    require_order(
        finish_cleanup,
        (
            'destination is None or destination["handle"] != expected_new',
            "verify_release_set(",
            'payload["handle"] != old_handle',
            "cleanup_payload(",
            "parent.assert_bound()",
            "verify_release_set(",
            "unlink_record(",
        ),
        "published proof before displaced-set cleanup",
    )
    require_text(publish, "os.urandom(32).hex()", "publication transaction entropy")
    require_text(publish, "RENAME_NOREPLACE", "first-publication kernel no-clobber")
    require_text(publish, "RENAME_EXCHANGE", "existing-publication atomic exchange")
    require_order(
        publish,
        (
            "recover(parent)",
            "old = parent.path_authority(parent.destination)",
            "verify_release_set(parent, parent.destination)",
            "install_initial_record(",
            "create_payload_root(",
            'if stop_after == "payload-created":',
            'staging["state"] = "staging"',
            'staging["payload_handle"] = payload_handle',
            "update_record(",
            "stage_payload(",
            'prepared["state"] = "prepared"',
            "update_record(",
            "read_record(parent, record_name, token)",
            "record_names(parent)",
            "verify_release_set(",
            "renameat2(",
            "RENAME_NOREPLACE",
            "RENAME_EXCHANGE",
            "post_destination = parent.path_authority(parent.destination)",
            "os.fsync(parent.fd)",
            "publication exchange binding changed after commit",
            "verify_release_set(parent, parent.destination",
            'cleanup_record["state"] = "cleanup"',
            "update_record(",
            "cleanup_payload(",
            "verify_release_set(parent, parent.destination",
            "unlink_record(",
        ),
        "failure-atomic publication state machine",
    )
    require_order(
        quiescent_verify,
        (
            "parent.assert_bound()",
            "if any(record_names(parent).values()):",
            "verify_release_set(parent, parent.destination",
            "parent.assert_bound()",
            "if any(record_names(parent).values()):",
            "return proof",
        ),
        "non-repairing quiescent publication verification",
    )
    require_text(
        verify_path,
        "lambda parent: verify_quiescent_release(parent, commit, version, epoch)",
        "quiescent public verification dispatch",
    )
    require_text(
        run_with_parent,
        'report_cleanup_failures(primary, "publication parent descriptor close", failures)',
        "publication parent cleanup failure preservation",
    )
    for text, label in (
        ("def report_cleanup_failures(", "publication cleanup accumulator"),
        ("primary.add_note(note)", "publication primary-error preservation"),
        ("def close_descriptors(", "publication exhaustive descriptor cleanup"),
        ("require_deadline(deadline)", "publication deadline enforcement"),
        ("if written <= 0:", "publication zero-progress rejection"),
        ("def persistent_handle(", "durable filesystem-object identity"),
        ("LIBC.name_to_handle_at", "opaque filesystem-object handle acquisition"),
        ('source = os.fsencode(f"/proc/self/fd/{file_fd}")', "portable unnamed-file link source"),
        ("AT_SYMLINK_FOLLOW", "portable unnamed-file link authority"),
    ):
        require_text(source, text, label)


def validate_target_scripts(debian, android, pins):
    for source, label, mismatch, role, pin in (
        (debian, "Debian", "double-build SHA mismatch", "deb-builder", "DEB_BUILDER_IMAGE_ID"),
        (
            android,
            "Android",
            "double-build APK SHA mismatch",
            "android-builder",
            "ANDROID_BUILDER_IMAGE_ID",
        ),
    ):
        require_text(source, 'if [ "${DOUBLE_BUILD:-1}" = "1" ]; then', f"{label} default double build")
        require_text(source, mismatch, f"{label} A/B mismatch rejection")
        require_text(source, '--user "$BUILD_UID:$BUILD_GID"', f"{label} user-mapped container")
        require_text(source, "RELEASE_DOCKER_IMAGE_ID", f"{label} content-ID image binding")
        require_text(source, "unix:///var/run/docker.sock", f"{label} local Docker binding")
        require_text(source, f'IMAGE_ID="${{{pin}:-}}"', f"{label} pinned image ID selection")
        require_text(
            source,
            f'require_pinned_builder_image {role} "$IMAGE_ID"',
            f"{label} builder provenance verification",
        )
        require_text(source, "RUSTDESK_RELEASE_ONLINE_SNAPSHOT", f"{label} release snapshot contract")
        require_text(source, 'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"', f"{label} direct snapshot")
        require_text(source, 'ONLINE_DIR="$ONLINE_SNAPSHOT_PARENT/online"', f"{label} snapshot-only consumption")
        require_count(source, "verify_active_online_snapshot", 4, f"{label} consumer snapshot checks")
        require_text(source, "current-UID mode-0700 directory", f"{label} snapshot owner/mode proof")
        if "IMAGE_NAME=" in source or "docker image inspect" in source:
            raise VerificationError(f"{label} target retains mutable builder tag resolution")
    require_text(pins, 'ANDROID_SIGNING_CERT_SHA256="1091322BA0425AFA1EB50DEEAE439A5FFFE2B1DD82C82B04515D9290A0CEEFA9"', "Android certificate pin")
    require_text(android, "assert_private_signing_files", "Android private signing-file proof")
    require_text(android, "mode 0600", "Android signing-file mode")
    require_text(android, "mode 0700", "Android signing-parent mode")
    require_count(android, "ANDROID_SIGNING_CERT_SHA256", 6, "Android certificate identity checks")
    require_text(android, "apksigner verify -Werr", "final APK signature verification")
    require_text(android, "--verify-apk", "standalone final APK identity proof")


def validate_publisher(source):
    require_text(
        source,
        "#!/usr/bin/env -S -i /usr/bin/bash --noprofile --norc",
        "publisher empty-environment entrypoint",
    )
    if re.search(r"^\s*--push\)", source, re.MULTILINE):
        raise VerificationError("publisher source-push mode is present")
    if "release delete" in source or "git push --delete" in source or re.search(r"\bgh(?:_closed)?\s+release\b", source):
        raise VerificationError("publisher contains uncertain-state cleanup")
    require_text(source, "EXPECTED_REPO_ID=1268555599", "numeric GitHub repository identity pin")
    require_text(source, "EXPECTED_PUBLISHER_ID=85248530", "numeric publisher identity pin")
    require_text(source, "one canonical https://github.com/OWNER/REPO.git URL", "canonical Git origin")
    require_text(source, "GH_CONFIG_DIR=\"$GH_CONFIG_SNAPSHOT\" GH_HOST=github.com", "closed GitHub CLI context")
    require_text(source, "X-GitHub-Api-Version: $GITHUB_API_VERSION", "pinned GitHub REST version")
    require_text(source, "authenticated GitHub principal is not the authorized publisher", "publisher principal proof")
    require_text(source, "authenticated publisher lacks repository push permission", "draft-visible push authority proof")
    require_text(source, "flock -n 9", "exclusive publication lock")
    require_text(source, "set -o noclobber", "non-clobbering publication lock creation")
    require_text(source, "snapshot_commit_file FORK_VERSION", "commit-sourced version metadata")
    require_text(source, "dist is not the exact five-file publication set", "exact source dist set")
    require_text(source, "dist/{name} is mutable, hardlinked, or empty", "descriptor-based dist snapshot")
    require_text(source, 'repos/$REPO_SLUG/releases?per_page=100', "paginated release inventory")
    require_text(source, 'repos/$REPO_SLUG/releases/$RELEASE_ID/assets?per_page=100', "paginated numeric asset inventory")
    require_exact_count(source, "--paginate", 4, "exhaustive REST inventory calls and stub enforcement")
    if "--exclude-drafts" in source:
        raise VerificationError("publisher excludes drafts from uniqueness")
    require_text(source, 'rev-parse --verify "refs/tags/$tag^{commit}"', "existing release tag-to-commit proof")
    require_text(source, 'push --atomic "$ORIGIN_URL"', "atomic remote uniqueness ref")
    require_text(
        source,
        'TAG="fork-version-$FORK_VER-commit-$HEAD_FULL"',
        "version-and-full-commit release tag",
    )
    if "VERSION_TAG" in source:
        raise VerificationError("publisher retains a mutable secondary version tag")
    require_text(
        source,
        'gh_api "repos/$REPO_SLUG/immutable-releases" --method GET',
        "repository immutable-release policy proof",
    )
    require_text(source, 'value["enabled"] is not True', "enabled immutable-release policy")
    require_text(
        source,
        'value["immutable"] is not (draft == "0")',
        "published release immutability proof",
    )
    require_exact_count(source, "parse_constant=reject_nonfinite", 7, "non-finite JSON rejection")
    require_text(source, 'gh_api "repos/$REPO_SLUG/releases" --method POST --input "$create_payload"', "numeric-ID draft creation")
    require_text(source, 'gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method PATCH', "numeric-ID publication")
    require_text(source, 'gh_api "repos/$REPO_SLUG/releases/assets/$asset_id" --method GET', "numeric-ID asset download")
    require_text(source, "final_publication_barrier() {", "final pre-publication barrier")
    require_text(source, 'strict_release_inventory "$RELEASE_ID" 1', "barrier release inventory")
    require_text(source, 'assert_github_identity "final pre-publication barrier"', "barrier repository identity")
    require_text(
        source,
        'assert_immutable_release_policy "final pre-publication barrier"',
        "barrier immutable-release policy",
    )
    require_text(source, "TRANSACTION_STATE=draft-create-requested", "uncertain draft mutation state")
    require_text(source, 'TRANSACTION_STATE="asset-upload-requested:$name"', "uncertain asset mutation state")
    require_text(source, 'TRANSACTION_STATE="publish-requested:$RELEASE_ID"', "uncertain publish mutation state")
    require_exact_count(source, "--no-replace-objects -c core.hooksPath=/dev/null", 2, "publisher Git replacement suppression")
    require_text(source, "Git grafts are forbidden for publication", "publisher Git graft rejection")
    require_text(source, "GitHub release field {key} has a hostile or missing type", "hostile schema rejection")
    require_text(source, "GitHub release asset size differs", "remote size proof")
    require_exact_count(source, "GitHub release asset server digest differs", 2, "server digest proof")
    require_text(source, "remote digest differs", "remote digest proof")
    require_text(source, "no remote object was deleted", "explicit failure reconciliation")
    require_text(source, "write_stub_gh", "stub GitHub fixture")
    require_text(source, "write_stub_git", "stub Git fixture")
    require_text(source, "publisher self-test accepted a hostile asset schema", "hostile fixture")
    require_text(source, "publisher self-test accepted a hostile server digest", "hostile digest fixture")
    require_text(source, "publisher self-test accepted a hostile numeric release ID", "hostile ID fixture")
    require_text(source, "publisher self-test accepted a non-finite JSON number", "non-finite fixture")
    require_text(source, "publisher self-test accepted hostile downloaded bytes", "hostile download fixture")
    require_order(
        source,
        (
            "TRANSACTION_STATE=draft-create-requested",
            'gh_api "repos/$REPO_SLUG/releases" --method POST',
            "view_and_validate_release draft-created 1 0",
            'for name in "${PUBLICATION_ASSETS[@]}"',
            "view_and_validate_release draft-uploaded 1 5",
            "download_and_verify_remote_assets draft",
            "final_publication_barrier",
            'gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method PATCH',
            "view_and_validate_release published 0 5",
            "download_and_verify_remote_assets published",
        ),
        "draft-first publication postconditions",
    )


def validate_fork_version(source):
    require_text(source, "fork_version_real_date() {", "real calendar validation")
    require_text(source, 'date -u -d "$value 00:00:00Z" +%F', "calendar normalization")
    require_text(source, "for heading in \"${release_headings[@]}\"", "all-heading validation")
    require_text(source, "duplicate release version", "duplicate release rejection")
    require_text(source, "must increment", "same-base exact increment")
    require_text(source, "must start at hardened.1", "base-transition reset")
    require_text(source, "fork_version_base_is_newer", "base ordering")
    require_text(source, "release dates must be newest-first", "date ordering")


def validate_r_b2_version_metadata(sources):
    build_script = sources["build_rs"]
    fork_emitter = extract_between(
        build_script,
        "fn emit_fork_version(",
        "\n}\n\nfn generate_version(",
        "R-B2 fork-version emitter",
    )
    generator = extract_between(
        build_script,
        "fn generate_version(",
        "\n}\n\nfn main()",
        "R-B2 version-metadata generator",
    )
    for text, label in (
        ('let version = env::var("CARGO_PKG_VERSION")?;', "Cargo package version authority"),
        ('emit_fork_version(&version)?;', "fallible fork-version generation"),
        ('generate_version(&version)?;', "fallible version-metadata generation"),
        ("fn canonical_numeric_version(value: &str) -> bool", "canonical package-version grammar"),
    ):
        require_text(build_script, text, label)
    for text, label in (
        ('fs::symlink_metadata("FORK_VERSION")?.file_type().is_file()', "regular fork-version file"),
        ('let contents = fs::read_to_string("FORK_VERSION")?;', "fallible fork-version read"),
        ("contents.strip_suffix('\\n').ok_or_else", "newline-terminated fork-version input"),
        ('strip_prefix(&format!("{version}-hardened."))', "fork-version package-base equality"),
        ('!counter.bytes().all(|byte| byte.is_ascii_digit())', "numeric fork-version counter"),
        ("counter.starts_with('0')", "positive canonical fork-version counter"),
        ('cargo:rustc-env=RUSTDESK_FORK_VERSION={fork_version}', "required fork-version compile environment"),
    ):
        require_text(fork_emitter, text, label)
    require_order(
        fork_emitter,
        (
            'fs::symlink_metadata("FORK_VERSION")?.file_type().is_file()',
            'fs::read_to_string("FORK_VERSION")?',
            "contents.strip_suffix('\\n').ok_or_else",
            'strip_prefix(&format!("{version}-hardened."))',
            '!counter.bytes().all(|byte| byte.is_ascii_digit())',
            'cargo:rustc-env=RUSTDESK_FORK_VERSION={fork_version}',
        ),
        "R-B2 fork-version validation and emission ordering",
    )
    for forbidden in ("unwrap_or", "unwrap_or_default", "option_env!"):
        if forbidden in fork_emitter:
            raise VerificationError(f"R-B2 fork-version emitter retains fallback: {forbidden}")
    for text, label in (
        ('let out_dir = env::var_os("OUT_DIR")', "Cargo OUT_DIR authority"),
        ('PathBuf::from(out_dir).join("version.rs")', "Cargo OUT_DIR output path"),
        ('cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH', "epoch rerun authority"),
        ('!raw.bytes().all(|byte| byte.is_ascii_digit())', "explicit malformed epoch rejection"),
        ("raw.len() > 1 && raw.starts_with('0')", "explicit noncanonical epoch rejection"),
        ('raw.parse::<i64>().map_err', "explicit integer-overflow epoch rejection"),
        (
            'DateTime::<chrono::Utc>::from_timestamp(epoch, 0).ok_or_else',
            "explicit chrono-range epoch rejection",
        ),
        ('Err(env::VarError::NotPresent) => chrono::Local::now()', "absent developer epoch fallback"),
        ('Err(error) => return Err(error.into())', "explicit epoch read failure"),
        ('fs::write(PathBuf::from(out_dir).join("version.rs"), generated)?;', "fallible OUT_DIR write"),
    ):
        require_text(generator, text, label)
    require_order(
        generator,
        (
            'env::var("SOURCE_DATE_EPOCH")',
            '!raw.bytes().all(|byte| byte.is_ascii_digit())',
            'raw.parse::<i64>().map_err',
            'DateTime::<chrono::Utc>::from_timestamp(epoch, 0).ok_or_else',
            'Err(env::VarError::NotPresent) => chrono::Local::now()',
            'Err(error) => return Err(error.into())',
            'fs::write(PathBuf::from(out_dir).join("version.rs"), generated)?;',
        ),
        "R-B2 explicit epoch validation and output ordering",
    )
    for forbidden in ("unwrap_or", "unwrap_or_default", "./src/version.rs", "src/version.rs"):
        if forbidden in generator:
            raise VerificationError(
                f"R-B2 version-metadata generator retains fallback or source output: {forbidden}"
            )

    require_exact_count(
        sources["root_lib"],
        'include!(concat!(env!("OUT_DIR"), "/version.rs"));',
        1,
        "root OUT_DIR version include",
    )
    fork_version_branch = extract_between(
        sources["core_main"],
        '} else if args[0] == "--fork-version" {',
        '} else if args[0] == "--build-date" {',
        "required fork-version executable output",
    )
    require_exact_count(
        fork_version_branch,
        'println!("{}", env!("RUSTDESK_FORK_VERSION"));',
        1,
        "required fork-version compile-time environment",
    )
    if 'option_env!("RUSTDESK_FORK_VERSION")' in sources["core_main"]:
        raise VerificationError("fork-version executable retains optional compile-time metadata")
    fork_version_code = "\n".join(line.split("//", 1)[0] for line in fork_version_branch.splitlines())
    if "crate::VERSION" in fork_version_code:
        raise VerificationError("fork-version executable retains crate::VERSION fallback")
    if re.search(
        r"(?:gen_version|src/version[.]rs|File::create\s*\([^\n]*version[.]rs|fs::write\s*\([^\n]*version[.]rs)",
        sources["hbb_common_lib"],
    ):
        raise VerificationError("common source version writer absence: legacy writer remains")

    try:
        manifest = tomllib.loads(sources["root_cargo"])
    except tomllib.TOMLDecodeError as exc:
        raise VerificationError(f"root Cargo manifest cannot be parsed: {exc}") from exc
    package_version = manifest.get("package", {}).get("version")
    if not isinstance(package_version, str) or re.fullmatch(
        r"(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)", package_version
    ) is None:
        raise VerificationError("root Cargo package version is not canonical numeric metadata")
    build_dependencies = manifest.get("build-dependencies")
    if not isinstance(build_dependencies, dict):
        raise VerificationError("root Cargo build dependencies are absent")
    if build_dependencies.get("chrono") != "0.4":
        raise VerificationError("root Cargo build dependencies do not pin chrono 0.4")
    if "hbb_common" in build_dependencies:
        raise VerificationError("root Cargo build dependencies retain hbb_common")

    verify_run = extract_between(
        sources["verify"],
        "RUN=(docker run --rm\n",
        '\n  -w /work "$IMG")',
        "verifier Cargo container",
    )
    require_exact_count(verify_run, '-v "$PWD:/work:ro"', 1, "verifier read-only Cargo source bind")
    if '-v "$PWD:/work:rw"' in verify_run or '-v "$PWD:/work"' in verify_run:
        raise VerificationError("verifier Cargo source bind is mutable")
    for text, label in (
        ('"${RUN[@]}" cargo clean -p rustdesk', "version-metadata Cargo clean"),
        ('"${RUN[@]}" cargo check --features linux-pkg-config --color never', "version-metadata primary Cargo build"),
        ('if ! "${RUN[@]}" bash scripts/version-metadata-check.sh; then', "version-metadata behavioral checker invocation"),
    ):
        require_exact_count(sources["verify"], text, 1, label)
    require_order(
        sources["verify"],
        (
            '"${RUN[@]}" cargo clean -p rustdesk',
            '"${RUN[@]}" cargo check --features linux-pkg-config --color never',
            '"${RUN[@]}" cargo check --features linux-pkg-config,unix-file-copy-paste --color never',
            'if ! "${RUN[@]}" bash scripts/version-metadata-check.sh; then',
        ),
        "clean committed Cargo version-metadata proof ordering",
    )
    require_text(
        sources["verify"],
        "git check-ignore --no-index -q -- src/version.rs\nversion_ignore_status=$?",
        "Git ignore matching for source version output",
    )
    require_text(
        sources["verify"],
        '0) version_output_bad="$version_output_bad ignored-source-output"',
        "ignored source version output rejection",
    )
    require_text(
        sources["verify"],
        '*) version_output_bad="$version_output_bad ignore-matcher-failed"',
        "Git ignore matcher operational failure",
    )
    for text, label in (
        ("git ls-files -z --cached -- ':(glob)build.rs' ':(glob)**/build.rs'", "indexed Cargo build-script scan"),
        ("grep -oF '\"version.rs\"' \"$cargo_build_script\"", "exact Cargo version-output filename scan"),
        ('[ "$cargo_build_script" = build.rs ] && [ "$refs" -eq 1 ]', "sole root version-output reference"),
        ('[ "$version_ref_count" -eq 1 ]', "unique Cargo version-output reference"),
    ):
        require_text(sources["verify"], text, label)

    checker = sources["version_metadata_checker"]
    if not stat.S_ISREG(sources["version_metadata_checker_mode"]):
        raise VerificationError("version-metadata behavioral checker is not a regular file")
    if (sources["version_metadata_checker_mode"] & 0o111) == 0:
        raise VerificationError("version-metadata behavioral checker is not executable")
    invalid_epoch = extract_between(
        checker,
        "run_invalid_epoch() {",
        "\n}\n\nrun_invalid_package_version() {",
        "version-metadata invalid-epoch checker",
    )
    invalid_package = extract_between(
        checker,
        "run_invalid_package_version() {",
        "\n}\n\nrun_invalid_fork() {",
        "version-metadata invalid-package checker",
    )
    invalid_fork = extract_between(
        checker,
        "run_invalid_fork() {",
        "\n}\n\nfor build_script in",
        "version-metadata invalid-fork checker",
    )
    for text, label in (
        ('[ "$PWD" = /work ]', "checker fixed read-only source mount"),
        ('[ "${CARGO_TARGET_DIR:-}" = /build ]', "checker external Cargo target"),
        ('cargo metadata --locked --no-deps --format-version 1', "checker Cargo metadata authority"),
        ('if ("chrono", "build") not in build_dependencies:', "checker chrono build dependency"),
        ('if ("hbb_common", "build") in build_dependencies:', "checker hbb_common build-dependency rejection"),
        ("expected_date=\"$(date -u -d \"@$SOURCE_DATE_EPOCH\" '+%Y-%m-%d %H:%M')\"", "checker pinned UTC date"),
        ("find /build/debug/build -path '/build/debug/build/rustdesk-*/out/version.rs'", "checker Cargo OUT_DIR output discovery"),
        ("find /build/debug/build -path '/build/debug/build/rustdesk-*/build-script-build'", "checker executable build-script discovery"),
        ("for value in '' -1 +1 abc 01700000000 9223372036854775808 9223372036854775807; do", "checker malformed and out-of-range epochs"),
        ('run_invalid_epoch "$build_script" "$value"', "checker invalid-epoch dispatch"),
        ("for value in '' 1.4 1.04.7 1.4.7-beta; do", "checker invalid package-version fixtures"),
        ('run_invalid_package_version "$build_script" "$value"', "checker invalid package-version dispatch"),
        ('run_invalid_fork "$build_script" missing', "checker missing fork-version fixture"),
        ('run_invalid_fork "$build_script" directory', "checker directory fork-version fixture"),
        ('run_invalid_fork "$build_script" symlink', "checker symlink fork-version fixture"),
        ('run_invalid_fork "$build_script" multiline', "checker multiline fork-version fixture"),
        ('run_invalid_fork "$build_script" wrong-base', "checker mismatched fork-version fixture"),
        ('run_invalid_fork "$build_script" leading-zero-counter', "checker noncanonical fork-version fixture"),
        ('[ ! -e /work/src/version.rs ]', "checker source version-output absence"),
        ("VERSION-METADATA-CHECK: exact OUT_DIR bytes and fail-closed metadata inputs are GREEN", "checker completion marker"),
    ):
        require_text(checker, text, label)
    for text, label in (
        ('SOURCE_DATE_EPOCH="$value"', "checker explicit epoch injection"),
        ('if env \\', "checker invalid epoch must fail"),
        ('[ ! -e "$out/version.rs" ]', "checker invalid epoch no-output postcondition"),
    ):
        require_text(invalid_epoch, text, label)
    for text, label in (
        ('CARGO_PKG_VERSION="$value"', "checker explicit package-version injection"),
        ('[ ! -e "$out/version.rs" ]', "checker invalid package-version no-output postcondition"),
    ):
        require_text(invalid_package, text, label)
    for text, label in (
        ('missing) ;;', "checker missing fork-version setup"),
        ('directory) mkdir "$root/FORK_VERSION"', "checker non-file fork-version setup"),
        ('symlink)', "checker symlink fork-version setup"),
        ('[ ! -e "$root/generated/version.rs" ]', "checker invalid fork-version no-output postcondition"),
    ):
        require_text(invalid_fork, text, label)

    if any(
        line.strip() in ("src/version.rs", "/src/version.rs")
        for line in sources["gitignore"].splitlines()
    ):
        raise VerificationError("Git ignore matching permits src/version.rs")

    require_exact_count(
        sources["android_rust"],
        '--user "$(id -u):$(id -g)"',
        1,
        "Android target non-root user",
    )
    if re.search(r"--user(?:=|\s+)['\"]?0:0", sources["android_rust"]):
        raise VerificationError("Android target gate runs as root")


def validate_docs(sources):
    source = sources["docs"]
    for text in (
        "two independent `--no-hardlinks --reject-shallow`, mode-0700 private repositories",
        "independent target, Flutter, generated, output, and Windows state",
        "private same-parent payload",
        "required ext4 publication filesystem",
        "complete descriptor-retrieved ext4 UUID",
        "`initializing`, handle-bound `staging`, manifest-bound `prepared`",
        "immediately before installation",
        "rejects any unresolved reserved publication state without repairing it",
        "`O_PATH|O_NOFOLLOW`, reopened nonblocking through retained descriptors",
        "canonical state names to carry the active transaction token",
        "logical process-restart proofs, not",
        "the invoking UID is cooperative and root, the kernel, ext4, and storage are trusted",
        "public certificate SHA-256 pinned in `scripts/pins.env`",
        "All five assets are uploaded to that draft",
        "never deletes uncertain remote state",
    ):
        require_text(source, text, "versioning transaction documentation")
    if "proved again after installation" in source:
        raise VerificationError("versioning documentation reverses source proof and installation")
    for forbidden in (
        "persistent filesystem identity",
        "ext4, XFS",
        "XFS, and Btrfs",
        "prepared recovery",
    ):
        if forbidden in source:
            raise VerificationError("versioning documentation retains superseded release authority")

    requirements = sources["requirements"]
    for text in (
        "git clone --no-hardlinks --no-checkout --reject-shallow",
        "shallow declarations or state",
        "exact soft <code>RLIMIT_NOFILE</code> of 524,544",
        "at most 64 pre-existing descriptors",
        "before enumerating inherited descriptors",
        "file type, owner, group, mode, link count",
        "every host or container closure, normalization, preflight, and deletion invocation",
        "only <code>DAC_OVERRIDE</code> and <code>FOWNER</code>",
        "recursive host remover is fixture-only",
        "hashes the complete bytes in memory against the committed digest",
        "root-owned mode-<code>0000</code> file and directory",
        "refuses any late content instead of traversing it",
        "does not chown, chmod, or otherwise normalize the online snapshot",
        "complete-history clone, attaches <code>master</code>",
        "failed descriptor close preserve uncertainty and abort",
        "FS_IOC_GETFSUUID",
        "complete ext4 UUID",
        "folded <code>f_fsid</code>",
        "O_PATH|O_NOFOLLOW",
        "active transaction token",
        "wrong-token canonical names",
        "Logical process-restart fixtures",
        "They do not simulate physical power loss",
        "Processes under the invoking UID must cooperate",
        "Same-host release-smoke coexistence with an operational older RustDesk service",
        "This is a current-release harness defect",
        "The separate Linux service-child lifecycle redesign remains open for upcoming releases",
    ):
        require_text(requirements, text, "requirements release authority")
    for forbidden in (
        "ext4, XFS",
        "XFS, and Btrfs",
        "terminal discard",
        "mode-0600 non-hardlinked transaction",
        "prepared recovery",
        "canonical ext4 filesystem identity",
    ):
        if forbidden in requirements:
            raise VerificationError("requirements retain superseded release authority")

    hardening = sources["hardening"]
    for text in (
        "Current `.6` source verdict (2026-07-14)",
        "git clone --no-hardlinks --no-checkout --reject-shallow",
        "524,544",
        "no longer normalizes the workspace or its authenticated online snapshot",
        "hashes the complete bytes in memory",
        "no release operation executes or mounts the mutable helper pathname",
        "only `DAC_OVERRIDE` and `FOWNER`",
        "recursive host removal is confined",
        "root-owned mode-0000 state",
        "refuses any late content instead of traversing it",
        "complete-history, no-hardlink clone attached as `master`",
        "FS_IOC_GETFSUUID",
        "nonzero 16-byte external ext4 UUID",
        "wrong-token payload and next-record names",
        "logical process-restart proofs, not physical power-loss simulation",
        "The invoking UID must keep the namespace",
        "Implemented current-release closure",
        "does not close or advance the upcoming-release",
    ):
        require_text(hardening, text, "hardening-status current release authority")
    if "`f_fsid` must be nonzero" in hardening:
        raise VerificationError("hardening-status retains folded filesystem identity authority")

    changelog = sources["changelog"]
    for text in (
        "`--no-hardlinks --reject-shallow` private repository",
        "terminal privileged deletion instead of whole-workspace ownership normalization",
        "hashes the bounded descriptor bytes in memory against the committed digest",
        "no release operation executes or mounts its mutable pathname",
        "`DAC_OVERRIDE` and `FOWNER`",
        "host cleanup is fixture-only",
        "host refuses late content before removing only the exact",
        "private complete-history no-hardlink clone attached as `master`",
        "complete descriptor-retrieved ext4 UUID",
        "wrong-token canonical state",
        "process-restart proofs; they do not claim physical power-loss simulation",
        "Release-smoke coexistence",
        "installed service or close the separately tracked upcoming Linux service-child lifecycle redesign",
    ):
        require_text(changelog, text, "changelog current release authority")
    for forbidden in (
        "consumes the same recorded hardlink closure",
        "persistent filesystem identity",
        "prepared recovery",
    ):
        if forbidden in changelog:
            raise VerificationError("changelog retains superseded release authority")

    digest = hashlib.sha256(requirements.encode("utf-8")).hexdigest()
    if f"{digest}  requirements.html" not in hardening:
        raise VerificationError("hardening-status requirements hash is stale")
    native_watch = sources["native_watch"]
    if f"Requirements hash: {digest}" not in native_watch:
        raise VerificationError("native-codec requirements hash is stale")


def validate_scan_contract(scan, verify, apple, release):
    require_text(scan, "readonly VERIFY_SCAN_GREP=/usr/bin/grep", "fixed verifier scanner")
    require_text(scan, "metadata = os.lstat(path)", "scanner no-follow metadata proof")
    require_text(scan, "metadata.st_uid != 0", "scanner root-owner proof")
    require_text(scan, "metadata.st_mode & 0o022", "scanner write-mode proof")
    require_text(scan, 'else\n    status=$?\n  fi', "scanner status capture")
    require_text(scan, "if [ \"$status\" -eq 1 ]; then", "scanner no-match status")
    require_text(scan, "scanner failed with status", "scanner operational-failure diagnostic")
    require_text(scan, "exit 1", "scanner operational-failure termination")
    require_text(scan, "verify_scan_self_test() {", "scanner status self-test")
    for source, label, minimum in (
        (verify, "verify", 18),
        (apple, "Apple", 4),
    ):
        require_text(source, "source scripts/verify-scan.sh", f"{label} scanner loading")
        require_text(source, "verify_scan_preflight", f"{label} scanner preflight")
        require_text(source, "verify_scan_self_test", f"{label} scanner status self-test")
        require_count(source, "verify_scan_capture", minimum, f"{label} fail-loud scans")
        if re.search(r"(?:^|\W)rg(?:$|\W)", source):
            raise VerificationError(f"{label} retains an undeclared ripgrep dependency")
    require_text(release, "source scripts/verify-scan.sh", "release scanner loading")
    require_text(release, "verify_scan_preflight || exit 1", "release scanner preflight")
    require_text(release, "--preflight)", "release side-effect-free preflight mode")
    require_text(
        verify,
        "^[[:space:]]*virtual_display[[:space:]]*=",
        "anchored IDD dependency scan",
    )


def validate_systemd_smoke_contract(
    host,
    host_mode,
    guest,
    guest_mode,
    loginctl,
    loginctl_mode,
    online_fetch,
    pins,
    release,
    hardening,
):
    for mode, label in (
        (host_mode, "systemd VM host orchestrator mode"),
        (guest_mode, "systemd VM guest lifecycle mode"),
        (loginctl_mode, "systemd VM loginctl fixture mode"),
    ):
        if not smoke_readiness_mode_is_valid(mode):
            raise VerificationError(f"{label}: executable mode is absent")

    for text, label in (
        ('[ "$(id -u)" -ne 0 ]', "systemd VM unprivileged host boundary"),
        ('verify_sha512 "$IMAGE" "$SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE"', "systemd VM base hash proof"),
        ('qemu-img check -q "$IMAGE"', "systemd VM base structural proof"),
        ('docker run --rm --network none --read-only --pids-limit 64', "systemd VM dependency staging confinement"),
        ('--cap-drop ALL --security-opt no-new-privileges', "systemd VM dependency staging confinement"),
        ('--user "$host_uid:$host_gid"', "systemd VM dependency staging unprivileged user"),
        ('-v "$PWD:/work:ro"', "systemd VM dependency staging source boundary"),
        ('-nic none', "systemd VM host network isolation"),
        ('media=cdrom,readonly=on', "systemd VM immutable payload"),
        ('SOURCE_HASH_AFTER=$(sha256sum', "systemd VM source postcondition"),
        ('DEBIAN_SYSTEMD_VM_ISOLATION=pass network=none accel=kvm source=ro base=sha512', "systemd VM isolation result"),
    ):
        require_text(host, text, label)
    require_exact_count(host, "-nic none", 1, "systemd VM host network isolation")
    forbidden_host = re.compile(
        r"--privileged|--pid[= ]host|--network[= ]host|--publish|--cap-add|"
        r"/var/run/docker\.sock|-nic\s+(?:user|tap|bridge)|hostfwd|guestfwd|"
        r"-virtfs|-fsdev|sudo\s"
    )
    if forbidden_host.search(host):
        raise VerificationError("systemd VM host authority boundary: forbidden authority or connectivity is present")

    for text, label in (
        ('[ "$(id -u)" = 0 ]', "installed systemd guest root boundary"),
        ('[ "$(cat /proc/1/comm)" = systemd ]', "installed systemd real PID 1"),
        ('[ "${VERSION_CODENAME:-}" = bookworm ]', "installed systemd Debian fixture"),
        ('*,ro,*)', "installed systemd read-only payload proof"),
        ('cmp -s "$UNIT_SOURCE" /usr/lib/systemd/system/rustdesk.service', "installed systemd exact production unit"),
        ('systemd-analyze verify /usr/lib/systemd/system/rustdesk.service', "installed systemd unit verification"),
        ('not main_cgroup.endswith("/system.slice/rustdesk.service")', "installed systemd service cgroup identity"),
        ('status.get("PPid") != str(main_pid)', "installed systemd direct child identity"),
        ('status.get("Uid", "").split() != [str(seat_uid)] * 4', "installed systemd non-root child UID"),
        ('status.get("NoNewPrivs") != "1"', "installed systemd child no-new-privileges"),
        ('argv[1:] != [b"--server", b"--service-owned-server", b""]', "installed systemd exact child role"),
        ('systemd-run --unit="$PORTABLE_UNIT"', "installed systemd portable sibling fixture"),
        ('systemctl restart "$UNIT"', "installed systemd normal restart"),
        ('systemctl stop "$UNIT"', "installed systemd clean stop"),
        ('systemctl start "$UNIT"', "installed systemd clean start"),
        ('systemctl kill --kill-whom=main --signal=KILL "$UNIT"', "installed systemd unit-scoped crash"),
        ('systemctl show "$UNIT" -p NRestarts --value', "installed systemd automatic restart proof"),
        ('assert_process_gone "$precrash_child" "$precrash_child_start"', "installed systemd crashed-child exit proof"),
        ("journalctl -b -u \"$UNIT\" --no-pager", "installed systemd recovery diagnostic proof"),
        ('dpkg -r "$PACKAGE"', "installed systemd package removal"),
        ('dpkg --purge "$PACKAGE"', "installed systemd package purge"),
        ('DEBIAN_SYSTEMD_INSTALLED_LIFECYCLE=pass os=debian-%s systemd=%s seat_uid=%s portable_uid=%s crash_generation=%s', "installed systemd result marker"),
    ):
        require_text(guest, text, label)
    require_order(
        guest,
        (
            'systemctl kill --kill-whom=main --signal=KILL "$UNIT"',
            'wait_for_active_unit "$precrash_main"',
            'assert_process_gone "$precrash_child" "$precrash_child_start"',
            "assert_portable_alive\ncrash_generation=",
            'SYSTEMD_CRASH_RESTART=pass prior_generation=',
        ),
        "installed systemd crash/restart transaction",
    )

    for text, label in (
        ('"0:")', "systemd VM loginctl session listing"),
        ('"4:show-session -p State 1")', "systemd VM loginctl state query"),
        ('"4:show-session -p Type 1")', "systemd VM loginctl type query"),
        ('User=4001', "systemd VM loginctl non-root seat"),
        ('State=active', "systemd VM loginctl active seat"),
        ('Type=x11', "systemd VM loginctl X11 seat"),
        ('exit 64', "systemd VM loginctl unexpected-argv rejection"),
    ):
        require_text(loginctl, text, label)

    require_text(
        pins,
        'DEBIAN_SYSTEMD_SMOKE_IMAGE_BUILD="20260712-2537"',
        "systemd VM dated image pin",
    )
    require_text(
        pins,
        'SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE="6c2607f1846ee86040830c87d0b723f0967da3e884ea4673d9db4aa8eee13a4b7c663524bfa42082c16fc6919f3aa1bf425c004d07ff06c53a319ad0c42647bb"',
        "systemd VM publisher hash pin",
    )
    for text, label in (
        ("fetch_debian_systemd_smoke_image()", "systemd VM sole fetch mode"),
        ('[ -d "$harness_state" ] && [ ! -L "$harness_state" ]', "systemd VM private state root"),
        ('"$(stat -c \'%u:%a\' "$harness_state")" = "$current_uid:700"', "systemd VM private state authority"),
        ('curl -fsSL --proto \'=https\' --tlsv1.2 -o "$dest.part" "$url"', "systemd VM HTTPS fetch"),
        ('SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE', "systemd VM fetched-image hash proof"),
        ('"$(stat -c \'%u:%a:%h\' "$dest")" = "$current_uid:444:1"', "systemd VM fetched-image authority"),
        ("--debian-systemd-smoke-image)", "systemd VM explicit fetch dispatch"),
    ):
        require_text(online_fetch, text, label)
    require_text(
        release,
        "smoke-debian-systemd-lifecycle.sh|installed Debian systemd stop/restart/crash recovery + portable noninterference",
        "installed systemd release gate",
    )
    require_text(
        hardening,
        "R-S11c-27m — installed Debian systemd lifecycle",
        "installed systemd hardening ledger",
    )


def smoke_readiness_mode_is_valid(mode):
    return stat.S_ISREG(mode) and stat.S_IMODE(mode) in (0o700, 0o755)


def validate_smoke_contract(
    verify, smoke, stage, stage_mode, service_lifecycle, service_lifecycle_mode,
    debian_sysv_lifecycle, debian_sysv_lifecycle_mode, loginctl_fixture,
    loginctl_fixture_mode, process_guard, process_guard_mode, launcher, readiness,
    readiness_mode, typed_probe, session_probe, ipc_source, core_main, common_source,
    linux_source,
):
    for text, label in (
        ('cross-container service identity ignores identical path/bytes/role text (R-S11c-27n)', "cross-container source gate"),
        ("grep -qF 'R-S11c-27n — cross-container executable identity' HARDENING_STATUS.md", "cross-container hardening ledger gate"),
    ):
        require_text(verify, text, label)
    for text, label in (
        ('HOST_GUARD=$PWD/scripts/smoke-process-guard.py', "host process guard selection"),
        ('mktemp -d /tmp/rustdesk-smoke-host.XXXXXXXXXX', "private host guard workspace"),
        ('"$HOST_GUARD" record "$HOST_GUARD_ROOT/baseline.json"', "pre-smoke host selector baseline"),
        ('"$HOST_GUARD" monitor "$HOST_GUARD_ROOT/baseline.json"', "whole-smoke host selector monitor"),
        ('host_guard_checkpoint', "per-stage host monitor checkpoint"),
        ('if ! stop_host_guard; then', "final host monitor drain"),
        ("trap 'exit 129' HUP", "host guard hangup cleanup"),
        ("trap 'exit 130' INT", "host guard interrupt cleanup"),
        ("trap 'exit 143' TERM", "host guard termination cleanup"),
        ('BUILD_RUN=(docker run --rm', "writable build-only container"),
        ('LIFECYCLE_RUN=(docker run --rm --network none --cap-add SYS_PTRACE', "network-isolated lifecycle procfs authority"),
        ('-v "$PWD:/work:ro"', "read-only runtime source bind"),
        ('run_stage build_out "${BUILD_RUN[@]}"', "complete build transcript capture"),
        ('record_stage_status R-B4-build', "build status preservation"),
        ('record_stage_status R-S11c-27i', "hostile-record stage status preservation"),
        ('record_stage_status R-S11c-27j', "sibling Docker stage status preservation"),
        ('record_stage_status R-S11c-27k', "pre-pidfd fallback stage status preservation"),
        ('record_stage_status R-S11c-27l', "Debian SysV stage status preservation"),
        ('record_stage_status R-S11c-27n', "cross-container identity stage status preservation"),
        ('STAGE_STATUS=$?', "isolated command failure status preservation"),
        ('bash --noprofile --norc /work/scripts/smoke-ready.sh --self-test', "mounted readiness self-test"),
        ('bash --noprofile --norc /work/scripts/smoke-server-stage.sh password-nonroot', "mounted non-root stage"),
        ('bash --noprofile --norc /work/scripts/smoke-server-stage.sh service-lifecycle-manual', "mounted service lifecycle stage"),
        ('bash --noprofile --norc /work/scripts/smoke-server-stage.sh sibling-docker-server', "mounted sibling Docker stage"),
        ('bash --noprofile --norc /work/scripts/smoke-server-stage.sh debian-sysv-installed-lifecycle', "mounted Debian SysV stage"),
        ('start_sibling_docker()', "sibling Docker orchestrator"),
        ('stop_sibling_docker()', "sibling Docker survivor drain"),
        ('sibling_container_running', "sibling Docker running check"),
        ('sibling_out_file=$HOST_GUARD_ROOT/sibling-docker.log', "sibling Docker parent-shell output capture"),
        ('if stop_sibling_docker >"$sibling_out_file" 2>&1; then', "sibling Docker stop runs in parent shell"),
        ('sibling-docker.log', "sibling Docker output cleanup"),
        ('SIBLING_DOCKER_NONINTERFERENCE=pass cid=', "sibling Docker noninterference result"),
        ('CROSS_CONTAINER_EXECUTABLE_IDENTITY=pass path=/usr/bin/rustdesk', "cross-container executable identity result"),
        ('if [ "$main_source" = "$sibling_source" ]', "cross-container shared source-object proof"),
        ('&& [ "$main_sha256" = "$sibling_sha256" ]', "cross-container identical-byte proof"),
        ('&& [ "$main_executable" != "$main_source" ]', "main installed executable-object separation"),
        ('&& [ "$sibling_executable" != "$sibling_source" ]', "sibling installed executable-object separation"),
        ('&& [ "$main_executable" != "$sibling_executable" ]', "cross-container executable-object separation"),
        ('&& [ "$main_mount_namespace" != "$sibling_mount_namespace" ]', "cross-container mount-namespace separation"),
        ('&& [ "$main_pid_namespace" != "$sibling_pid_namespace" ]', "cross-container PID-namespace separation"),
        ('sibling_container_survived" == *" exe=$sibling_executable generation=$sibling_generation"', "cross-container survivor identity binding"),
    ):
        require_text(smoke, text, label)
    for forbidden in (
        "bash -euo pipefail -c", "--network=host", "--pid=host", "--privileged",
        "--publish", "--publish-all", "sudo ", "pkill",
    ):
        if forbidden in smoke:
            raise VerificationError(
                f"runtime smoke retains forbidden host argv/network/service authority: {forbidden}"
            )
    if re.search(r"(?m)^\s+-[pP](?:\s|$)", smoke):
        raise VerificationError("runtime smoke publishes a container port")
    if smoke.count("bash --noprofile --norc /work/scripts/smoke-server-stage.sh") != 19:
        raise VerificationError("runtime smoke does not preserve the exact mounted stage dispatch set")
    if smoke.count("run_stage out") != 14 or smoke.count("record_stage_status ") < 19:
        raise VerificationError("runtime smoke does not preserve every isolated stage status and transcript")
    if "rustdesk --server" in smoke:
        raise VerificationError("host smoke orchestrator retains historical-selector launch text")
    sibling_match = re.search(
        r'docker_out=\$\(docker run -d --name "\$SIBLING_NAME".*?sibling-docker-server 2>&1\)',
        smoke,
        re.S,
    )
    if not sibling_match:
        raise VerificationError("sibling Docker run block is missing or no longer uses mounted dispatch")
    sibling_block = sibling_match.group(0)
    require_text(sibling_block, "--network none", "sibling Docker network isolation")
    require_text(sibling_block, '-v "$PWD:/work:ro"', "sibling Docker read-only source bind")
    require_text(sibling_block, '-v "$SIBLING_ROOT:/sibling:rw"', "sibling Docker private control bind")
    if "--pid" in sibling_block:
        raise VerificationError("sibling Docker must not share a host or container PID namespace")

    if not smoke_readiness_mode_is_valid(stage_mode):
        raise VerificationError("mounted smoke stage is not a regular executable file")
    if not smoke_readiness_mode_is_valid(service_lifecycle_mode):
        raise VerificationError("mounted service lifecycle stage is not a regular executable file")
    if not smoke_readiness_mode_is_valid(debian_sysv_lifecycle_mode):
        raise VerificationError("mounted Debian SysV lifecycle stage is not a regular executable file")
    if not smoke_readiness_mode_is_valid(loginctl_fixture_mode):
        raise VerificationError("mounted loginctl fixture is not a regular executable file")
    if not smoke_readiness_mode_is_valid(process_guard_mode):
        raise VerificationError("smoke process guard is not a regular executable file")
    for text, label in (
        ('service-lifecycle-manual)', "service lifecycle dispatch"),
        ('sibling-docker-server)', "sibling Docker dispatch"),
        ('debian-sysv-installed-lifecycle)', "Debian SysV dispatch"),
        ('bash --noprofile --norc /work/scripts/smoke-debian-sysv-lifecycle.sh', "Debian SysV mounted script dispatch"),
        ('control=/sibling', "sibling Docker private control directory"),
        ('"$READY" --wait-parked "$SRV" "$SRV_START" /tmp/sibling-docker.log', "sibling Docker parked readiness"),
        ('"$READY" --hold-running "$SRV" "$SRV_START" /tmp/sibling-docker.log 1 "sibling docker stop poll"', "sibling Docker identity-monitored stop wait"),
        ('SIBLING_DOCKER_READY pid=', "sibling Docker ready marker"),
        ('SIBLING_DOCKER_SURVIVED=pass pid=', "sibling Docker survival marker"),
        ('install -o root -g root -m 0755 /work/target/debug/rustdesk /usr/bin/rustdesk', "identical installed-path fixture"),
        ('"$SERVER_LAUNCHER" "$installed_server" --service-owned-server', "sibling exact service-owned role"),
        ('"$PROCESS_GUARD" wait-service-server', "exact-role sibling identity proof"),
        ('SIBLING_CONTAINER_IDENTITY_READY pid=', "cross-container ready identity"),
        ('SIBLING_CONTAINER_IDENTITY_SURVIVED=pass pid=', "cross-container survivor identity"),
        ('chmod 0755 target/debug/rustdesk', "installed-mode lifecycle executable"),
        ('bash --noprofile --norc /work/scripts/smoke-service-lifecycle.sh', "mounted lifecycle script dispatch"),
        ('fixture=/tmp/rd-smoke-nonroot', "non-root fixture root"),
        ('install -d -o root -g "$gid" -m 0750 "$fixture" "$fixture/bin"', "protected fixture directories"),
        ('install -d -o rduser -g "$gid" -m 0700 "$fixture/home"', "private non-root home"),
        ('install -o root -g "$gid" -m 0550 target/debug/rustdesk "$fixture/bin/rustdesk"', "portable server fixture"),
        ('install -o root -g "$gid" -m 0550 target/debug/examples/seed_password "$fixture/bin/seed_password"', "password seeder fixture"),
        ('install -o root -g "$gid" -m 0550 target/debug/examples/probe_client "$fixture/bin/probe_client"', "probe client fixture"),
        ('install -o root -g "$gid" -m 0550 target/debug/examples/smoke_readiness "$fixture/bin/smoke_readiness"', "typed readiness probe fixture"),
        ('install -o root -g "$gid" -m 0440 target/smoke-bind-loopback.so "$fixture/bin/smoke-bind-loopback.so"', "bind shim fixture"),
        ('install -o root -g "$gid" -m 0550 target/smoke-server-launcher "$fixture/bin/smoke-server-launcher"', "neutral launcher fixture"),
        ('install -o root -g "$gid" -m 0550 scripts/smoke-ready.sh "$fixture/bin/smoke-ready.sh"', "readiness checker fixture"),
        ('install -o root -g "$gid" -m 0550 scripts/smoke-process-guard.py "$fixture/bin/smoke-process-guard.py"', "process proof fixture"),
        ('su -s /bin/bash -c /tmp/rd-smoke-nonroot/run.sh rduser', "non-root runner dispatch"),
        ('echo SOURCE_BIND_UNCHANGED=yes', "source-bind postcondition"),
        ('$READY --wait-parked "$SRV" "$SRV_START" /tmp/srv1.log /work/target/debug/examples/smoke_readiness 0', "parked-server readiness proof"),
        ('$READY --wait-user-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0', "root user-owned IPC readiness proof"),
        ('"$bin/smoke-ready.sh" --wait-user-server "$SRV" "$SRV_START" "$HOME/srv2c.log" "$bin/smoke_readiness" 4000', "non-root user-owned IPC readiness proof"),
        ('$READY --wait-key-failure', "key-failure observation proof"),
        ('$READY --wait-capacity-shed', "capacity-shed observation proof"),
        ('$READY --wait-tcp-listener', "tunnel-target listener proof"),
        ('$READY --interrupt "$TCPD" "$TCPD_START"', "capture completion proof"),
        ('$READY --hold-running "$SRV" "$SRV_START" /tmp/srv.log 64 "limiter-decay interval"', "identity-monitored limiter-decay interval"),
        ('LD_PRELOAD="$BIND_SHIM" "$SERVER_LAUNCHER" "$executable"', "neutral server launcher use"),
        ('"$PROCESS_GUARD" wait-server "$SRV" "$SRV_START" "$executable"', "exact executable and argv proof"),
    ):
        require_text(stage, text, label)
    for text, label in (
        ('[ "${ID:-}" = debian ]', "Debian SysV operating-system proof"),
        ('[ "${VERSION_CODENAME:-}" = bookworm ]', "Debian SysV release proof"),
        ('[ ! -e /run/systemd/system ]', "Debian SysV backend proof"),
        ('source_hash=$(sha256sum', "Debian SysV read-only source baseline"),
        ('dpkg -i "$FIXTURE/rustdesk-sysv-smoke-1.0.deb"', "Debian SysV initial installation"),
        ('/etc/init.d/rustdesk restart', "Debian SysV installed restart"),
        ('dpkg -i "$FIXTURE/rustdesk-sysv-smoke-2.0.deb"', "Debian SysV package upgrade"),
        ("assert_wrong_executable_alive() {", "Debian SysV wrong-executable survival proof"),
        ('printf \'%s\\n\' "$WRONG_PID" >/run/rustdesk.pid', "Debian SysV stale PID record fixture"),
        ('dpkg -r "$PACKAGE"', "Debian SysV package removal"),
        ('dpkg --purge "$PACKAGE"', "Debian SysV package purge"),
        ('DEBIAN_SYSV_INSTALLED_LIFECYCLE=pass os=debian-%s portable_uid=%s stale_wrong_exec=survived', "Debian SysV installed lifecycle result"),
        ("read-only source fixtures changed", "Debian SysV read-only source postcondition"),
    ):
        require_text(debian_sysv_lifecycle, text, label)
    for forbidden in (
        "docker ", "sudo ", "--network=host", "--pid=host", "--privileged",
        "--publish", "pkill", "killall", "pidof", "pgrep",
    ):
        if forbidden in debian_sysv_lifecycle:
            raise VerificationError(
                f"Debian SysV lifecycle retains forbidden host or broad process authority: {forbidden}"
            )
    if '[b"rd-smoke-server", b"--server", b"--service-owned-server", b""]' in service_lifecycle:
        raise VerificationError("portable role isolation: portable server acquired service-owned argv")
    for text, label in (
        ('readonly RECORD=/run/rustdesk/service-child.record', "root lifecycle record"),
        ('signal.pidfd_send_signal(pidfd_file.fileno()', "pidfd-only lifecycle signaling"),
        ('"STOP": signal.SIGSTOP', "kernel-stopped child fixture"),
        ('if expected_uid == "0" and argv[0] != b"/proc/self/exe":', "exact root service-child role proof"),
        ('re.fullmatch(rb"/proc/self/fd/[0-9]+", argv[0])', "descriptor-bound non-root role proof"),
        ('stat -c \'%u:%g:%a\' -- "$BINARY"', "installed executable owner-mode proof"),
        ('RUSTDESK_SERVICE_OWNED_SERVER_EXECUTABLE_FD', "service-child executable descriptor binding"),
        ('for capability_set in ("CapInh", "CapPrm", "CapEff", "CapAmb"):', "non-root capability clearing proof"),
        ('setpriv --reuid="$expected_uid" --regid="$expected_gid" --groups="$expected_groups"', "same-identity typed IPC proof"),
        ('[b"rd-smoke-server", b"--server", b""]', "exact portable role proof"),
        ('setpriv --reuid=4000', "non-root portable launch"),
        ('--inh-caps=-all --ambient-caps=-all --bounding-set=-all', "portable capability removal"),
        ('"$READY" --stop "$SVC" "$SVC_START"', "exact supervisor stop"),
        ('[ "$elapsed_ms" -ge 7500 ] && [ "$elapsed_ms" -le 20000 ]', "bounded forced-stop observation"),
        ('SERVICE_LIFECYCLE_GRACEFUL=pass', "graceful lifecycle result"),
        ('SERVICE_LIFECYCLE_RESTART=pass', "restart lifecycle result"),
        ('SERVICE_LIFECYCLE_FORCED=pass', "forced lifecycle result"),
        ('SERVICE_LIFECYCLE_PRIVILEGE_DROP=pass uid=4001', "non-root lifecycle result"),
        ('SERVICE_LIFECYCLE_HOSTILE_RECORDS=pass cases=malformed,metadata,reused-start,executable,uid,generation,portable-role', "hostile-record lifecycle result"),
        ('start_pre_pidfd_recorded_child', "pre-pidfd runtime recovery fixture"),
        ('assert_pre_pidfd_child_alive', "pre-pidfd runtime identity proof"),
        ('RD_SERVICE_SMOKE_FORCE_PRE_PIDFD=1', "forced pre-pidfd runtime exercise"),
        ('SERVICE_LIFECYCLE_PRE_PIDFD_RECOVERY=pass prior_generation=', "pre-pidfd runtime result"),
        ('PORTABLE_NONINTERFERENCE=pass uid=4000', "portable survival result"),
        ('readonly SOURCE_BINARY=/work/target/debug/rustdesk', "manual lifecycle source binary"),
        ('readonly BINARY=/usr/bin/rustdesk', "manual lifecycle identical installed path"),
        ('[ "$INSTALLED_BINARY_IDENTITY" != "$SOURCE_BINARY_IDENTITY" ]', "installed executable object separation"),
        ('expected_executable = os.stat(sys.argv[8])', "expected installed executable proof"),
        ('service child did not execute the installed binary object', "live child installed-object check"),
        ('SERVICE_LIFECYCLE_CONTAINER_IDENTITY=pass path=/usr/bin/rustdesk', "main container identity result"),
    ):
        require_text(service_lifecycle, text, label)
    for text, label in (
        ('os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC', "exclusive no-follow hostile-record fixture"),
        ('before_identity=$(stat -c \'%d:%i:%u:%g:%a:%h:%s:%Y:%Z\'', "hostile-record metadata snapshot"),
        ('[ "$after_identity" = "$before_identity" ]', "hostile-record metadata preservation"),
        ('[ "$(sha256sum -- "$RECORD" | awk', "hostile-record byte preservation"),
        ('[ ! -e "$RECORD.tmp" ] && [ ! -L "$RECORD.tmp" ]', "hostile-record temporary-file absence"),
        ('if [ "$service_status" -ne 1 ]; then', "hostile-record exact failure status"),
        ("grep -Fq -- 'Linux service lifecycle authority failed closed:'", "hostile-record fail-closed diagnostic"),
        ('remove_exact_hostile_service_record "$before_identity" "$before_sha256"', "exact hostile-record fixture removal"),
        ('SERVICE_LIFECYCLE_HOSTILE_RECORD=pass case=%s record_sha256=%s', "hostile-record per-case hash result"),
        ('pidfd_signal_only "$DECOY" "$DECOY_START" STOP', "hostile-record decoy pidfd stop"),
        ('  assert_decoy_alive\n  assert_portable_alive', "hostile-record sentinel survival"),
    ):
        require_text(service_lifecycle, text, label)
    if service_lifecycle.count("run_rejected_record_case ") != 7:
        raise VerificationError("hostile-record lifecycle does not preserve the exact seven-case matrix")
    for forbidden in ("pkill", "os.kill(", "kill -", "sudo ", "--pid=host", "--privileged"):
        if forbidden in service_lifecycle:
            raise VerificationError(
                f"service lifecycle smoke retains broad or host authority: {forbidden}"
            )
    for text, label in (
        ('readonly STATE=/tmp/rd-service-loginctl-state', "loginctl switch state"),
        ('"0:")', "loginctl session-list invocation"),
        ('uid=0', "loginctl root seat uid"),
        ('uid=4001', "loginctl non-root seat uid"),
        ('username=rdseat', "loginctl non-root seat identity"),
        ('printf \'1 %s %s seat0\\n\' "$uid" "$username"', "loginctl exact selected seat"),
        ('"4:show-session -p State 1")', "loginctl state query"),
        ('"4:show-session -p Type 1")', "loginctl type query"),
        ('"2:show-session 1")', "loginctl session query"),
        ('exit 64', "loginctl unexpected-argv rejection"),
    ):
        require_text(loginctl_fixture, text, label)
    require_exact_count(stage, '    wait "$TCPD"\n', 1, "capture exit-status proof")
    if stage.count('install -o root -g "$gid"') != 8:
        raise VerificationError("non-root smoke fixture must stage exactly eight root-owned runtime files")
    if stage.count('$READY --wait-server') < 10:
        raise VerificationError("runtime smoke does not readiness-gate every ordinary server startup")
    if stage.count('$READY --terminate-server') < 10:
        raise VerificationError("runtime smoke does not bound and prove ordinary server shutdown")
    if stage.count('start_server /work/target/debug/rustdesk') != 12:
        raise VerificationError("runtime smoke does not route every ordinary server through the launcher")
    if stage.count('start_server /usr/share/rustdesk/rustdesk') != 1:
        raise VerificationError("installed-layout smoke does not route through the launcher")
    if "rustdesk --server" in stage or re.search(r'rustdesk[" ]+--server', stage):
        raise VerificationError("mounted smoke stage retains historical-selector launch text")
    if "pkill" in stage or re.search(r'(?m)^\s*kill\s', stage):
        raise VerificationError("mounted smoke stage retains broad or raw signal authority")
    if re.search(r'(?:\./target/debug/examples/probe_client|"\$bin/probe_client")[^\n]*\|', stage):
        raise VerificationError("runtime smoke retains a lossy probe execution pipeline")
    if re.search(r'echo "\$out[0-9a-z]*"\s*\|\s*grep\s+-[^\n]*q', smoke):
        raise VerificationError("runtime smoke retains a pipefail-sensitive output assertion")
    for forbidden in ("timeout 15", "TCPDUMP_ABSENT", "SKIP R-A9"):
        if forbidden in stage:
            raise VerificationError(f"runtime smoke retains a forbidden fallback or stale bound: {forbidden}")
    if stage.count('timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))"') != 3:
        raise VerificationError("every password watchdog must derive from recovery and have a forced-kill ceiling")
    if stage.count('[ "$RECOVERY_SECONDS" = 600 ]') != 3:
        raise VerificationError("runtime smoke does not bind every password CLI watchdog to the exported recovery bound")
    fixed_delays = re.findall(r"(?<![A-Za-z0-9_-])sleep[ \t]+([0-9]+(?:\.[0-9]+)?)", stage)
    if fixed_delays:
        raise VerificationError("runtime smoke retains a fixed timing guess outside the real limiter-decay window")
    require_text(
        verify,
        "smoke_nonroot_stage=$(awk '/^  password-nonroot\\)/{capture=1}",
        "verify non-root smoke extraction follows the mounted stage form",
    )
    marker = 'cat > "$fixture/run.sh" <<\'EOS\'\n'
    start = stage.find(marker)
    if start < 0:
        raise VerificationError("non-root smoke runner heredoc is absent")
    start += len(marker)
    end = stage.find("\nEOS\n", start)
    if end < 0:
        raise VerificationError("non-root smoke runner heredoc is unterminated")
    runner = stage[start:end]
    for forbidden in ("/work", "target/debug", "pkill"):
        if forbidden in runner:
            raise VerificationError(f"non-root smoke runner retains forbidden source/process authority: {forbidden}")
    require_text(runner, 'export HOME=/tmp/rd-smoke-nonroot/home', "fixture-owned runner home")
    require_text(runner, 'SRV_START=$("$bin/smoke-ready.sh" --identity "$SRV")', "retained non-root server identity")
    require_text(runner, '"$bin/smoke-process-guard.py" wait-server', "non-root exact executable and argv proof")
    require_text(runner, '"$bin/smoke-server-launcher" "$bin/rustdesk"', "non-root neutral launcher")
    require_text(runner, '"$bin/smoke-ready.sh" --terminate-server "$SRV" "$SRV_START"', "bounded exact server stop")
    require_text(runner, 'wait "$SRV"', "exact server reap")
    require_text(runner, 'SERVICE_ROLE_MARKER=absent', "portable-role proof")

    for text, label in (
        ('SELECTOR = re.compile(br"rustdesk +--server")', "historical selector implementation"),
        ('NEUTRAL_ARGV0 = b"rd-smoke-server"', "neutral argv constant"),
        ('SERVICE_OWNED_ROLE = b"--service-owned-server"', "service-owned role constant"),
        ('cmdline.rstrip(b"\\0").replace(b"\\0", b" ")', "NUL argv reconstruction"),
        ('before = read_process_identity(pid, proc_root)', "pre-cmdline start identity"),
        ('after = read_process_identity(pid, proc_root)', "post-cmdline start identity"),
        ('matches = stable_baseline()', "stable host baseline"),
        ('violations = new_matches(baseline, current)', "new-match rejection"),
        ('time.sleep(MONITOR_INTERVAL_SECONDS)', "bounded host monitor polling"),
        ('os.stat("/proc/{}/exe".format(pid))', "running executable object proof"),
        ('return argv == expected_argv', "generic exact argv proof"),
        ('[NEUTRAL_ARGV0, SERVER_ROLE]', "exact neutral argv and role proof"),
        ('[NEUTRAL_ARGV0, SERVER_ROLE, SERVICE_OWNED_ROLE]', "exact service-owned sibling argv"),
        ('status.get("PPid") != str(expected_parent)', "service-owned launch-parent proof"),
        ('for capability_set in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")', "service-owned capability proof"),
        ('commands.add_parser("wait-service-server")', "service-owned identity command"),
        ('baseline fixture did not reject a new production-shaped match', "selector baseline regression fixture"),
    ):
        require_text(process_guard, text, label)
    require_exact_count(
        process_guard,
        "violations = new_matches(baseline, current)",
        2,
        "new-match rejection",
    )
    for text, label in (
        ('static const char *const SMOKE_ARGV0 = "rd-smoke-server";', "launcher neutral argv"),
        ('static const char *const SERVER_ROLE = "--server";', "launcher exact role"),
        ('static const char *const SERVICE_OWNED_ROLE = "--service-owned-server";', "launcher exact service-owned role"),
        ('argc != 2 && argc != 3', "launcher bounded optional role"),
        ('strcmp(argv[2], SERVICE_OWNED_ROLE) != 0', "launcher optional role allowlist"),
        ('server_argv[2] = (char *)SERVICE_OWNED_ROLE;', "launcher service-owned role forwarding"),
        ('O_RDONLY | O_CLOEXEC | O_NOFOLLOW', "launcher no-follow executable pin"),
        ('fstat(executable_fd, &metadata)', "launcher opened-object validation"),
        ('fexecve(executable_fd, server_argv, environ);', "descriptor-bound exact executable launch"),
    ):
        require_text(launcher, text, label)
    if "system(" in launcher or "popen(" in launcher:
        raise VerificationError("smoke launcher retains shell authority")

    args_collection = extract_between(
        core_main, "    let mut args = Vec::new();", "    #[cfg(any(target_os = \"linux\", target_os = \"windows\"))]",
        "core argv collection",
    )
    require_text(args_collection, "for arg in std::env::args()", "Rust role argv source")
    require_text(args_collection, "if i > 0", "Rust argv0 exclusion")
    require_text(args_collection, "args.push(arg);", "retained role argument collection")
    require_text(core_main, 'args[0] == "--server"', "server dispatch from argument one")
    require_text(common_source, 'std::env::args().nth(1) == Some("--server".to_owned())', "server role argument-one predicate")
    require_text(common_source, "SERVICE_OWNED_SERVER_EXECUTABLE_FD_ENV", "service executable descriptor environment binding")
    require_text(linux_source, "std::env::current_exe().ok()", "Linux executable identity source")
    require_text(
        linux_source,
        'const SERVICE_CHILD_FORCE_PRE_PIDFD_FOR_SMOKE_ENV: &str = "RD_SERVICE_SMOKE_FORCE_PRE_PIDFD";',
        "debug-only pre-pidfd smoke force constant",
    )
    pre_pidfd_force = extract_between(
        linux_source,
        "fn service_child_pidfd_open_is_forced_unsupported_for_smoke() -> bool {",
        "\nfn open_service_child_pidfd",
        "pre-pidfd smoke force helper",
    )
    for text, label in (
        ('#[cfg(debug_assertions)]', "pre-pidfd smoke force debug gate"),
        ('std::env::var_os(SERVICE_CHILD_FORCE_PRE_PIDFD_FOR_SMOKE_ENV)', "pre-pidfd smoke force environment lookup"),
        ('#[cfg(not(debug_assertions))]', "pre-pidfd smoke force release closure"),
        ('false', "pre-pidfd smoke force release-disabled result"),
    ):
        require_text(pre_pidfd_force, text, label)
    pidfd_open = extract_between(
        linux_source,
        "fn open_service_child_pidfd(pid: u32) -> ResultType<PidFdOpen> {",
        "\nfn service_child_pidfd_exited",
        "service child pidfd open helper",
    )
    for text, label in (
        ('if service_child_pidfd_open_is_forced_unsupported_for_smoke()', "pre-pidfd smoke force dispatch"),
        ('Smoke forced pidfd_open unavailable for service child pid', "pre-pidfd smoke force diagnostic"),
        ('return Ok(PidFdOpen::Unsupported);', "forced pre-pidfd unsupported branch"),
    ):
        require_text(pidfd_open, text, label)
    for text, label in (
        ('recover_previous_child_without_pidfd(&self, record: &ServiceChildRecord)', "pre-pidfd recovery branch"),
        ('require_service_child_identity_match(record, "pre-pidfd kill fallback")', "pre-pidfd signal revalidation"),
        ('wait_revalidated_service_child_pid_exit(record, SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT)', "pre-pidfd graceful wait revalidation"),
        ('wait_revalidated_service_child_pid_exit(record, SERVICE_CHILD_FORCED_STOP_TIMEOUT)', "pre-pidfd forced wait revalidation"),
        ('final identity-check-to-kill race cannot be eliminated', "pre-pidfd residual race diagnostic"),
    ):
        require_text(linux_source, text, label)
    require_text(
        core_main,
        'log::error!("Linux service lifecycle authority failed closed: {err}");',
        "actual service fail-closed diagnostic",
    )
    require_order(
        linux_source,
        (
            "let runtime = ServiceRuntime::acquire()?;",
            "runtime.recover_previous_child()?;",
            "stop_subprocess();",
            "ipc::start(crate::POSTFIX_SERVICE)",
        ),
        "hostile-record recovery precedes signal and listener authority",
    )
    for text, label in (
        ('.custom_flags(hbb_common::libc::O_CLOEXEC)', "service executable parent close-on-exec"),
        ('format!("/proc/self/fd/{}", executable.as_raw_fd())', "service executable descriptor path"),
        ('hbb_common::libc::SYS_fcntl', "fork-only descriptor inheritance"),
        ('nix::unistd::close(executable_fd)', "final-image descriptor close"),
    ):
        require_text(linux_source, text, label)
    for source in (core_main, common_source):
        if re.search(r"std::env::args(?:_os)?\(\)\.(?:next\(\)|nth\(0\))", source):
            raise VerificationError("Rust server role regressed to semantic argv0 use")
    if not smoke_readiness_mode_is_valid(readiness_mode):
        raise VerificationError(
            "private release-snapshot readiness executable mode is invalid"
        )
    for text, label in (
        ("readonly READY_WAIT_SECONDS=60", "fixed 60-second readiness bound"),
        ('[[ "$1" =~ ^[1-9][0-9]*$ ]] || fail "invalid duration: $1"', "strict monitored-duration validation"),
        ("monotonic_millis()", "millisecond monotonic readiness clock"),
        ('[[ "$uptime" =~ ^([0-9]+)\\.([0-9]+)$ ]]', "validated monotonic clock syntax"),
        ('rest=${stat##*) }', "pid stat command-name parsing"),
        ('start=${fields[19]}', "pid start identity extraction"),
        ('[ "$start" = "$expected_start" ] || return 2', "pid start identity enforcement"),
        ('capture_pid_start "$2"', "dedicated retained-identity capture"),
        ('pidfd = os.pidfd_open(pid, 0)', "pidfd acquisition"),
        ('signal.pidfd_send_signal(pidfd, signals[signal_name], None, 0)', "pidfd signal delivery"),
        ('pid_owns_listener "$pid" "$SERVER_LISTEN_HEX"', "server listener process ownership"),
        ('inode=$(unix_listener_inode "$path")', "Unix listener kernel-inode lookup"),
        ('$4 == "00010000" && $5 == "0001" && $6 == "01"', "Unix stream listening-state proof"),
        ('pid_owns_socket_inode "$pid" "$inode"', "Unix listener exact-process ownership"),
        ('pid_owns_unix_listener "$pid" "$socket" || return 1', "both IPC paths bound to the exact process"),
        ('[ "$(tcp_listen_count)" = 1 ]', "exact TCP listener count"),
        ('[ "$(udp_socket_count)" = 0 ]', "zero UDP socket count"),
        ('[ "$(stat -c %u:%a -- "$parent")" = "$uid:700" ]', "IPC parent ownership and mode"),
        ('[ "$(stat -c %u:%a -- "$socket")" = "$uid:600" ]', "IPC socket ownership and mode"),
        ('[ -S "$socket" ] && [ ! -L "$socket" ]', "IPC socket type and symlink rejection"),
        ('typed_ipc_ready "$probe" "$expected" "$pid" "$expected_start" "$deadline"', "successful typed IPC readiness transaction"),
        ('[ "$output" = "SMOKE_TYPED_IPC_READY state=$expected" ]', "exact typed IPC output comparison"),
        ('timeout --signal=TERM --kill-after=1s "$duration" "$probe" "$expected" "$pid" "$expected_start" "$remaining"', "hard outer typed-probe deadline"),
        ('if "$predicate" "$pid" "$expected_start" "$pinned_log" "$deadline" "$@"; then', "retained identity passed into every predicate"),
        ('[ "$now" -le "$deadline" ] && pid_is_same_and_running "$pid" "$expected_start"', "post-observation PID identity and deadline enforcement"),
        ('self-test accepted socket files without a successful typed IPC transaction', "stale-socket rejection self-test"),
        ('self-test accepted IPC listeners owned by another process', "foreign IPC owner rejection self-test"),
        ('self-test accepted a typed IPC transaction past its hard deadline', "hard typed deadline self-test"),
        ('deadline=$((now + seconds * 1000))', "bounded readiness deadline"),
        ('sleep 0.05', "condition polling interval"),
        ('signal_and_wait "$READY_WAIT_SECONDS" TERM', "bounded exact-pid termination"),
        ('wait_for_condition "$READY_WAIT_SECONDS"', "bounded external readiness dispatch"),
        ('wait_for_duration 1 "$SELF_TEST_SERVER_PID" "$SELF_TEST_SERVER_START"', "monitored-duration behavioral self-test"),
        ('wait_for_duration "$5" "$2" "$3" "$4" "$6"', "bounded monitored-duration dispatch"),
        ('self-test accepted readiness from a dead process', "dead-process rejection self-test"),
        ('SELF_TEST_IPC_PARENT_ID=$(path_identity "$parent")', "self-test IPC root inode retention"),
        ('SELF_TEST_IPC_MAIN_ID=$(path_identity "$parent/ipc")', "self-test main IPC inode retention"),
        ('SELF_TEST_IPC_PASSWORD_ID=$(path_identity "$parent/ipc_password")', "self-test password IPC inode retention"),
        ('preserving changed self-test IPC root', "changed self-test IPC preservation"),
        ('rm -- "$parent/ipc" "$parent/ipc_password"', "exact self-test IPC entry removal"),
    ):
        require_text(readiness, text, label)
    if "SMOKE_READY_TIMEOUT" in readiness or "READY_WAIT_SECONDS:-" in readiness:
        raise VerificationError("smoke readiness deadline accepts ambient override authority")
    if "rm -rf" in readiness:
        raise VerificationError("smoke readiness self-test retains recursive cleanup authority")
    if re.search(r'(?m)^\s*kill\s', readiness):
        raise VerificationError("smoke readiness retains raw kill signal authority")
    readiness_fail = extract_between(readiness, "fail() {", "\n}\n", "smoke readiness failure helper")
    require_text(readiness_fail, "exit 1", "terminal smoke readiness failure")
    if "return 1" in readiness_fail:
        raise VerificationError("smoke readiness failure can continue in a conditional context")
    for text, label in (
        ("ipc::get_main_readiness_snapshot_for_process(", "typed process-bound main-IPC readiness transaction"),
        ('"parked" => (false, false, None)', "parked password/listener state proof"),
        ('"server" => (true, true, None)', "listening state proof"),
        ('"user-server" => (true, true, Some(true))', "user-owned password authority proof"),
        ('if actual_values.0 != expected_values.0', "individual readiness fact comparison"),
        ("ipc::PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS", "exported password recovery bound"),
        ('SMOKE_TYPED_IPC_READY state={expected}', "exact typed readiness result"),
    ):
        require_text(typed_probe, text, label)
    for text, label in (
        ("pub const PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS: u64 = 600;", "password recovery source constant"),
        ("std::time::Duration::from_secs(PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS)", "password recovery duration derivation"),
        ("pub struct MainReadinessSnapshot", "dedicated readiness response type"),
        ("MainIpcRequest::ReadinessSnapshot", "dedicated readiness request handler"),
        ("get_main_readiness_snapshot_for_process", "process-bound readiness API"),
        ("peer_pid != expected_pid", "SO_PEERCRED peer-pid binding"),
        ("linux_proc_start_time(peer_pid)? != expected_start_time", "peer start-identity binding"),
        ("tokio::time::timeout_at(deadline, async {", "one hard readiness transaction deadline"),
    ):
        require_text(ipc_source, text, label)
    for text, label in (
        ("peer_username_nonempty = !peer.username.is_empty();", "file-transfer PeerInfo semantic proof"),
        ("FT-LOGIN-SEND-ERROR", "file-transfer login send-error propagation"),
        ("FT-READDIR-SEND-ERROR", "file-transfer ReadDir send-error propagation"),
        ("FT-LOGIN-SERIALIZE-ERROR", "file-transfer login serialization-error propagation"),
        ("FT-READDIR-SERIALIZE-ERROR", "file-transfer ReadDir serialization-error propagation"),
        ("let login_bytes = match msg.write_to_bytes()", "file-transfer login serialization result"),
        ("let readdir_bytes = match m.write_to_bytes()", "file-transfer ReadDir serialization result"),
        ('mode != "filetransfer" || file_transfer_ok', "file-transfer semantic pass condition"),
        ("if !peer_username_nonempty || !readdir_send_ok", "missing/empty PeerInfo failure"),
    ):
        require_text(session_probe, text, label)


def validate_faillo_contract(source):
    output_contract = extract_between(
        source,
        "script_die_output_is_expected() {",
        "\n}\nrun_script_die() {",
        "fail-loud result classifier",
    )
    probe_cleanup = extract_between(
        source,
        "  cleanup_dirty_probe() {",
        "\n  }\n  trap cleanup_dirty_probe EXIT",
        "dirty-probe cleanup",
    )
    probe_lifecycle = extract_between(
        source,
        "run_with_dirty_probe() (",
        "\n)\n\nexercise_dirty_probe_cleanup_failure() (",
        "dirty-probe lifecycle",
    )
    production_fixture = extract_between(
        source,
        "run_production_dirty_probe() (",
        "\n)\n\nexercise_dirty_probe_cleanup_failure() (",
        "production dirty-source fixture",
    )
    reached_contract = extract_between(
        source,
        "reached_failure_is_expected() {",
        "\n}\nrun_script_die_reached_without_marker() {",
        "reached-state failure classifier",
    )
    wrong_sha_fixture = extract_between(
        source,
        "run_wrong_online_sha_probe() (",
        "\n)\n\nrun_with_dirty_probe() (",
        "independent wrong-SHA fixture",
    )
    require_text(source, "release source-gate preflight accepts the fixed scanner", "scanner preflight proof")
    require_text(source, "verifier scanner rejects an operational error", "scanner error proof")
    require_text(
        source,
        "pinned offline reset removes root-owned inaccessible generated state",
        "root-owned reset behavioral proof",
    )
    require_text(
        source,
        '"build-release root-owned reset self-test: OK"',
        "root-owned reset success marker",
    )
    require_text(
        source,
        'scripts/build-release.sh --self-test-reset',
        "root-owned reset exact command",
    )
    for text, label in (
        ('run_script_die "verify_online_shas wrong SHA" "SHA-256 mismatch for " run_wrong_online_sha_probe', "independent wrong-SHA dispatch"),
        ('"--self-test-source-state=$EXPECTED_SOURCE_COMMIT"', "exact source-state self-test command"),
        ('--self-test-source-state=0000000000000000000000000000000000000000', "wrong source-state commit rejection"),
        ('build-release source-state self-test: OK', "exact source-state success marker"),
        ('source-state self-test: source tree is not clean, including untracked files', "exact source-state dirty rejection"),
        ('production release source gate rejects a dirty checkout', "production release-source behavioral gate"),
        ('run_production_dirty_probe', "production release-source fixture dispatch"),
    ):
        require_text(source, text, label)
    for text, label in (
        ('mktemp -d /tmp/rustdesk-faillo-sha.XXXXXXXXXX', "private wrong-SHA root"),
        ('fixture_id="$(stat -c \'%d:%i\' -- "$fixture")"', "wrong-SHA root identity"),
        ('printf \'independent wrong-sha fixture\\n\'', "independent wrong-SHA bytes"),
        ('ONLINE_DIR="$fixture" bash -c', "fixture-local online directory"),
        ('--remove-private-root "$fixture" --expected-identity "$fixture_id"', "wrong-SHA descriptor-bound cleanup"),
        ('[ ! -e "$fixture" ] && [ ! -L "$fixture" ]', "wrong-SHA absence proof"),
        ('[ "$cleanup_failed" -eq 0 ] || status=125', "wrong-SHA cleanup status"),
        ('exit "$status"', "wrong-SHA original-status propagation"),
    ):
        require_text(wrong_sha_fixture, text, label)
    if '${ONLINE_DIR:-$REPO_ROOT/online}/rust-${RV}.tar.xz' in source:
        raise VerificationError("fail-loud wrong-SHA proof depends on the ignored online cache")
    require_exact_count(
        source,
        "run_production_dirty_probe",
        2,
        "production release-source fixture dispatch",
    )
    for text, label in (
        ("run_with_dirty_probe()", "exclusive dirty-probe lifecycle"),
        ('mktemp "$probe_parent/.faillo-${label}.XXXXXXXXXX"', "random exclusive dirty probe"),
        ("verify.sh emits success only after workspace removal", "verify cleanup success fixture"),
        ("verify.sh rejects a missing recorded workspace", "verify missing-workspace fixture"),
        ("build-release.sh rejects a missing recorded workspace", "release missing-workspace fixture"),
        ("run_script_die_reached_without_marker", "reached-state premature marker rejection"),
        ('[ "$observed" = "$probe_id" ] || cleanup_failed=1', "dirty-probe identity verification"),
        ('rm -f -- "$probe" || cleanup_failed=1', "dirty-probe exact removal"),
        ('[ ! -e "$probe" ] && [ ! -L "$probe" ] || cleanup_failed=1', "dirty-probe absence postcondition"),
        (
            "printf 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE: %s\\n' \"$probe\" >&2",
            "dirty-probe cleanup failure marker emission",
        ),
        ("grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:'", "dirty-probe cleanup rejection"),
        ('[ "$rc" -ne 125 ]', "dirty-probe cleanup status rejection"),
        ("status=125", "distinct dirty-probe cleanup status"),
        ("exercise_dirty_probe_cleanup_failure()", "dirty-probe cleanup behavioral fixture"),
        ('[ "$rc" -eq 125 ]', "dirty-probe fixture status proof"),
        ("dirty-probe cleanup failure cannot satisfy a fail-loud case", "dirty-probe fixture dispatch"),
        ("BUILD-FAILLO: DIRTY-PROBE-READY:", "dirty-probe reached-state marker"),
        ('grep -qF "$expected"', "exact fail-loud diagnostic classification"),
        ("verify workspace missing self-test: REACHED", "verify missing-workspace target-state proof"),
        ("build-release cleanup-missing self-test: REACHED", "release missing-workspace target-state proof"),
        ("exercise_reached_failure_classifier()", "reached-state classifier behavioral fixture"),
        ("reached-state classifier rejects every incomplete lifecycle result", "reached-state fixture dispatch"),
    ):
        require_text(source, text, label)
    require_text(
        output_contract,
        "grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:'",
        "dirty-probe cleanup rejection",
    )
    require_text(output_contract, '[ "$rc" -ne 125 ]', "dirty-probe cleanup status rejection")
    require_text(
        probe_cleanup,
        "printf 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE: %s\\n' \"$probe\" >&2",
        "dirty-probe cleanup failure marker emission",
    )
    require_text(probe_cleanup, "status=125", "distinct dirty-probe cleanup status")
    require_text(
        probe_lifecycle,
        "printf 'BUILD-FAILLO: DIRTY-PROBE-READY: %s\\n' \"$probe\" >&2",
        "dirty-probe reached-state marker",
    )
    for text, label in (
        ("umask 077", "production fixture private creation mask"),
        ('mktemp -d /tmp/rustdesk-faillo-doctor.XXXXXXXXXX', "production fixture private root"),
        ('clone \\\n    --quiet --no-hardlinks --no-checkout --reject-shallow', "production fixture independent complete clone"),
        ('checkout --quiet -B master "$EXPECTED_SOURCE_COMMIT"', "production fixture attached exact master"),
        ('symbolic-ref --quiet --short HEAD', "production fixture attached-branch proof"),
        ("rev-parse --verify 'HEAD^{commit}'", "production fixture exact-commit proof"),
        ('status --porcelain=v1 --untracked-files=all', "production fixture clean baseline proof"),
        ('DIRTY_PROBE_PARENT="$fixture_repo" run_with_dirty_probe doctor', "production fixture sole dirty mutation"),
        ('"$fixture_repo/scripts/build-release.sh" --doctor', "production fixture committed release entrypoint"),
        ('--mount-root "$fixture_root"', "production fixture mount-closure cleanup"),
        ('--inode-root "$fixture_root"', "production fixture inode-closure cleanup"),
        ('--remove-private-root "$fixture_root" --expected-identity "$fixture_id"', "production fixture descriptor-bound cleanup"),
        ('[ ! -e "$fixture_root" ] && [ ! -L "$fixture_root" ]', "production fixture absence proof"),
        ('status=$?', "production fixture original-status capture"),
        ("status=125", "production fixture distinct cleanup status"),
        ('exit "$status"', "production fixture final-status propagation"),
    ):
        require_text(production_fixture, text, label)
    require_order(
        production_fixture,
        (
            "status=$?",
            "trap - EXIT",
            "status=125",
            'exit "$status"',
        ),
        "production dirty-source cleanup status preservation",
    )
    require_order(
        production_fixture,
        (
            'mktemp -d /tmp/rustdesk-faillo-doctor.XXXXXXXXXX',
            'clone \\\n    --quiet --no-hardlinks --no-checkout --reject-shallow',
            'checkout --quiet -B master "$EXPECTED_SOURCE_COMMIT"',
            'symbolic-ref --quiet --short HEAD',
            "rev-parse --verify 'HEAD^{commit}'",
            'status --porcelain=v1 --untracked-files=all',
            'DIRTY_PROBE_PARENT="$fixture_repo" run_with_dirty_probe doctor',
        ),
        "production dirty-source fixture authority ordering",
    )
    if "rm -rf" in production_fixture:
        raise VerificationError("production dirty-source fixture retains recursive pathname deletion")
    if "grep -qiE 'FATAL|FAIL" in source or 'grep -qiE \'FATAL|FAIL' in source:
        raise VerificationError("fail-loud suite accepts a broad unrelated failure diagnostic")
    require_order(
        reached_contract,
        (
            '[ "$rc" -ne 0 ] || return 1',
            'grep -qF "$reached"',
            'grep -qF "$expected"',
            '! printf \'%s\\n\' "$out" | grep -qF "$marker"',
        ),
        "reached-state failure classification",
    )
    for forbidden in (".faillo_ct_probe", ".faillo_dirt_probe"):
        if forbidden in source:
            raise VerificationError("fail-loud suite retains a fixed followable dirty probe")
    if "every misconfiguration" in source:
        raise VerificationError("fail-loud suite overclaims every possible misconfiguration")


def validate_private_tree_closure(source):
    try:
        module = ast.parse(source)
    except SyntaxError as exc:
        raise VerificationError(
            f"private-tree closure syntax: Python source does not parse: {exc}"
        ) from exc
    closure_main = extract_python_definition(
        source, module, "main", "private-tree closure main dispatch"
    )
    cleanup = extract_python_method(
        source, module, "PrivateTreeRoot", "remove_contents", "closure cleanup traversal"
    )
    inode_closure = extract_python_method(
        source,
        module,
        "PrivateTreeRoot",
        "collect_inode_links",
        "closure inode-closure traversal",
    )
    inode_closure_acquisition = extract_python_method(
        source,
        module,
        "PrivateTreeRoot",
        "acquire_inode_closure",
        "retained inode-closure acquisition",
    )
    normalization_init = extract_python_method(
        source,
        module,
        "TreeNormalizationAuthority",
        "__init__",
        "normalization authority initialization",
    )
    normalization_collect = extract_python_method(
        source,
        module,
        "TreeNormalizationAuthority",
        "_collect",
        "normalization authority acquisition",
    )
    normalization_assert = extract_python_method(
        source,
        module,
        "TreeNormalizationAuthority",
        "assert_bound",
        "normalization authority reproof",
    )
    normalization_mutation = extract_python_method(
        source,
        module,
        "TreeNormalizationAuthority",
        "normalize",
        "normalization authority mutation",
    )
    normalization_dispatch = extract_python_definition(
        source, module, "normalize_tree", "normalization authority dispatch"
    )
    retained_descriptor_budget = extract_python_definition(
        source,
        module,
        "require_retained_descriptor_budget",
        "retained-authority descriptor budget",
    )
    close_collection = extract_python_definition(
        source,
        module,
        "collect_descriptor_close_failures",
        "descriptor close failure collection",
    )
    cleanup_reporting = extract_python_definition(
        source, module, "report_cleanup_failures", "cleanup failure reporting"
    )
    descriptor_close = extract_python_definition(
        source, module, "close_descriptors", "descriptor cleanup"
    )
    scratch_close = extract_python_method(
        source, module, "PrivateTreeRoot", "close", "private-tree root authority cleanup"
    )
    normalization_close = extract_python_method(
        source,
        module,
        "TreeNormalizationAuthority",
        "close",
        "normalization authority cleanup",
    )
    tree_contents_acquisition = extract_python_method(
        source,
        module,
        "PrivateTreeRoot",
        "for_tree_contents",
        "terminal tree-contents authority acquisition",
    )
    tree_contents_removal = extract_python_method(
        source,
        module,
        "PrivateTreeRoot",
        "remove_tree_contents",
        "terminal tree-contents removal",
    )
    empty_root_removal = extract_python_method(
        source,
        module,
        "PrivateTreeRoot",
        "remove_empty_root",
        "terminal empty-root removal",
    )
    for method, label in (
        (cleanup, "closure cleanup mount-boundary proof"),
        (inode_closure, "closure inode-closure mount-boundary proof"),
        (normalization_collect, "normalization mount-boundary proof"),
    ):
        require_text(method, "descriptor_mount_id(authority_fd) != self.mount_id", label)
    for text, label in (
        ("os.lstat(path)", "physical inode inspection"),
        ("followlinks=False", "symlink traversal exclusion"),
        ("metadata.st_nlink", "inode link-count proof"),
        (
            "for expected, count in linked.values():\n        if count != expected:",
            "external hardlink rejection",
        ),
        ('mount_path.startswith(prefix)', "descendant mount rejection"),
        ('modes.add_argument("--self-test"', "closure behavioral self-test"),
        ("os.link(internal", "internally closed hardlink fixture"),
        ("os.link(external", "external hardlink fixture"),
        ("internal-symlink-b", "internally closed hardlinked-symlink fixture"),
        ("external-symlink-link", "external hardlinked-symlink fixture"),
        ("0:1 /bound", "same-filesystem descendant mount fixture"),
        ("space\\040tab\\011line\\012slash\\134", "complete mountinfo escape fixture"),
        ('parser.add_argument("--scratch-fd", type=int)', "closure fixture scratch descriptor option"),
        ('PrivateTreeRoot(inherited_fd=arguments.scratch_fd)', "closure inherited scratch authority"),
        ('descriptor = os.dup(inherited_fd)', "closure scratch descriptor duplication"),
        ('mount_id = descriptor_mount_id(descriptor)', "closure scratch mount authority acquisition"),
        ('descriptor_mount_id(self.fd) != self.mount_id', "closure scratch live mount authority"),
        ('os.mkdir(name, 0o700, dir_fd=self.fd)', "closure descriptor-relative fixture creation"),
        ('os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC', "closure entry mount authority descriptor"),
        ('descriptor_mount_id(authority_fd) != self.mount_id', "closure entry mount-boundary proof"),
        ('def bounded_directory_names(descriptor, limit):\n    names = []\n    with os.scandir(f"/proc/self/fd/{descriptor}") as entries:', "closure descriptor-bound streamed cleanup inventory"),
        ('os.rmdir(name, dir_fd=self.fd)', "closure descriptor-relative fixture removal"),
        ('self-test fixture edge changed before cleanup', "closure live fixture edge cleanup gate"),
        ('metadata.st_uid != os.geteuid()', "closure fixture scratch owner proof"),
        ('metadata.st_gid != os.getegid()', "closure fixture scratch group proof"),
        ('stat.S_IMODE(metadata.st_mode) != 0o700', "closure fixture scratch mode proof"),
        ('modes.add_argument("--remove-private-root")', "closure private-root removal mode"),
        ('modes.add_argument("--remove-empty-private-root")', "terminal empty-root removal mode"),
        ('modes.add_argument("--remove-tree-contents")', "terminal tree-contents removal mode"),
        ('modes.add_argument("--check-descriptor-budget"', "host descriptor-budget preflight mode"),
        ('modes.add_argument("--check-exact-descriptor-budget"', "exact descriptor-budget preflight mode"),
        ('scratch.remove_root((int(match.group(1)), int(match.group(2))))', "closure recorded root identity dispatch"),
        ('scratch.remove_empty_root((int(match.group(1)), int(match.group(2))))', "terminal empty-root identity dispatch"),
        ('os.rmdir(self.basename, dir_fd=self.parent_fd)', "closure descriptor-relative root removal"),
        ('raise ClosureError("tree authority options are valid only with their tree modes")', "closure misplaced authority rejection"),
        ('closure constructor leaked a descriptor after acquisition failure', "closure constructor descriptor inventory proof"),
        ('closure child leaked a descriptor after acquisition failure', "closure child descriptor inventory proof"),
        ('closure child acquisition failure did not preserve one ambiguous edge', "closure ambiguous-edge preservation proof"),
        ('preserved closure child acquisition state is not exact', "closure preserved-edge metadata proof"),
        ('modes.add_argument("--normalize-root")', "normalization mode dispatch"),
        ('parser.add_argument("--owner", type=int)', "normalization owner authority"),
        ('parser.add_argument("--group", type=int)', "normalization group authority"),
        ('PROTECTED_HARDLINKS = "/proc/sys/fs/protected_hardlinks"', "kernel hardlink-protection source"),
        ("TREE_ENTRY_LIMIT = 524288", "retained-authority exact entry bound"),
        ("MAX_DIRECTORY_DEPTH = 128", "retained-authority directory-depth bound"),
        ("MAX_PREEXISTING_DESCRIPTORS = 64", "retained-authority inherited-descriptor bound"),
        ("MAX_TRANSIENT_DESCRIPTORS = 8", "retained-authority transient-descriptor bound"),
        ("RETAINED_DESCRIPTOR_RESERVE = 256", "retained-authority descriptor reserve"),
        ("TREE_ENTRY_LIMIT + RETAINED_DESCRIPTOR_RESERVE", "retained-authority descriptor limit derivation"),
        ('if content != b"1\\n":', "exact kernel hardlink-protection policy"),
        ('raise ClosureError("kernel hardlink protection is not enabled")', "disabled hardlink-protection rejection"),
        ('return (stat.S_IMODE(mode) | required) & 0o755', "normalization special-mode stripping"),
        ('exercise_normalization_authority(scratch)', "normalization behavioral fixture dispatch"),
        ('require_retained_descriptor_budget()\n    parse_protected_hardlinks(b"1\\n")', "retained-authority live descriptor-budget fixture"),
        ('require_rejection(parse_protected_hardlinks, b"0\\n")', "disabled hardlink-protection fixture"),
        ('normalization constructor leaked a directory descriptor', "normalization descriptor-leak fixture"),
        ('normalization directory inventory changed', "normalization complete-inventory fixture"),
        ('normalization mode policy retained a special permission bit', "normalization special-mode fixture"),
        ('exercise_cleanup_failure_accounting()', "descriptor cleanup-failure fixture dispatch"),
        ('exercise_authority_bounds(scratch)', "retained-authority bound fixture dispatch"),
        ('descriptor close failure fixture did not exhaust cleanup', "exhaustive descriptor-close fixture"),
        ('descriptor close failure fixture replaced its primary error', "primary-error preservation fixture"),
        ('descriptor close failure fixture lost cleanup errors', "complete close-error reporting fixture"),
        ('print("verify-private-tree-closure: DETAIL: {}".format(note)', "concrete cleanup-error diagnostics"),
        ('descriptor inventory ran before the exact budget was established', "exact-boundary descriptor-order fixture"),
        ('require_rejection(empty_authority.remove_empty_root, empty_authority.identity)', "late empty-root content rejection fixture"),
    ):
        require_text(source, text, label)
    for text, label in (
        ("for descriptor in descriptors:", "complete descriptor close iteration"),
        ("if descriptor is None or descriptor in seen:", "descriptor close ownership deduplication"),
        ("closer(descriptor)", "descriptor close sink"),
        ("except BaseException as error:", "descriptor close failure capture"),
        ("failures.append(error)", "descriptor close failure retention"),
    ):
        require_text(close_collection, text, label)
    for text, label in (
        ("if primary is not None:", "primary cleanup-error preservation"),
        ("primary.add_note(note)", "primary cleanup-error annotation"),
        ("for note in notes:", "complete cleanup-error reporting"),
        ('raise error from failures[0]', "cleanup failure causality"),
    ):
        require_text(cleanup_reporting, text, label)
    require_order(
        descriptor_close,
        (
            "collect_descriptor_close_failures(descriptors)",
            "report_cleanup_failures(",
        ),
        "descriptor close collection before reporting",
    )
    for text, label in (
        ("failures.extend(collect_descriptor_close_failures((self.fd, self.parent_fd)))", "complete scratch descriptor close"),
        ("self.fd = None", "scratch descriptor ownership retirement"),
        ("self.parent_fd = None", "scratch parent-descriptor ownership retirement"),
        ('report_cleanup_failures(primary, "private-tree root cleanup", failures)', "private-tree cleanup failure preservation"),
    ):
        require_text(scratch_close, text, label)
    for text, label in (
        ('descriptors = [authority["fd"] for authority in self.inodes.values()]', "complete normalization inode cleanup"),
        ('descriptors.extend(directory["fd"] for directory in reversed(self.directories))', "complete normalization directory cleanup"),
        ('close_descriptors(descriptors, "normalization authority close", primary)', "normalization cleanup failure preservation"),
    ):
        require_text(normalization_close, text, label)
    require_exact_count(
        source,
        "os.close",
        1,
        "centralized descriptor-close authority",
    )
    for text, label in (
        ("resource.getrlimit(resource.RLIMIT_NOFILE)", "normalization descriptor-limit inspection"),
        ("hard < RETAINED_DESCRIPTOR_LIMIT", "retained-authority descriptor hard-limit rejection"),
        ("resource.setrlimit(", "retained-authority soft descriptor-limit establishment"),
        ("(RETAINED_DESCRIPTOR_LIMIT, hard)", "bounded retained-authority descriptor limit"),
        ("observed_soft != RETAINED_DESCRIPTOR_LIMIT", "retained-authority exact soft-limit reproof"),
        ("observed_hard != RETAINED_DESCRIPTOR_LIMIT", "retained-authority exact hard-limit reproof"),
        ("len(live_descriptor_inventory()) > MAX_PREEXISTING_DESCRIPTORS", "pre-existing descriptor rejection"),
        ("required_reserve > RETAINED_DESCRIPTOR_RESERVE", "descriptor-reserve arithmetic proof"),
    ):
        require_text(retained_descriptor_budget, text, label)
    require_order(
        retained_descriptor_budget,
        (
            "resource.getrlimit(resource.RLIMIT_NOFILE)",
            "resource.setrlimit(",
            "observed_soft, observed_hard = resource.getrlimit(resource.RLIMIT_NOFILE)",
            "len(live_descriptor_inventory()) > MAX_PREEXISTING_DESCRIPTORS",
        ),
        "descriptor limit establishment before live inventory",
    )
    require_order(
        normalization_dispatch,
        (
            "require_retained_descriptor_budget()",
            "require_protected_hardlinks()",
            "authority = TreeNormalizationAuthority(path, expected_identity)",
            "authority.normalize(owner, group)",
            "authority.close(sys.exc_info()[1])",
        ),
        "normalization authority dispatch",
    )
    require_text(
        normalization_init,
        "[TREE_ENTRY_LIMIT]",
        "normalization collection uses its descriptor-derived tree bound",
    )
    require_order(
        inode_closure_acquisition,
        (
            "require_retained_descriptor_budget()",
            "self.collect_inode_links(descriptor, [TREE_ENTRY_LIMIT], linked)",
        ),
        "retained inode-closure descriptor budget",
    )
    for method, label in (
        (cleanup, "cleanup directory-depth enforcement"),
        (inode_closure, "inode-closure directory-depth enforcement"),
        (normalization_collect, "normalization directory-depth enforcement"),
    ):
        require_text(method, "if depth >= MAX_DIRECTORY_DEPTH:", label)
        require_text(method, 'raise ClosureError("tree exceeds its directory-depth bound")', label)
    for method, label in (
        (cleanup, "cleanup special-object rejection"),
        (inode_closure, "inode-closure special-object rejection"),
    ):
        require_text(method, "elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):", label)
        require_text(method, 'raise ClosureError("tree contains a special filesystem object")', label)
    for text, label in (
        ("require_real_directory(path)", "terminal-removal canonical root"),
        ("identity(metadata) != expected_identity", "terminal-removal descriptor identity"),
        ("identity(edge) != expected_identity", "terminal-removal pathname identity"),
        ("metadata.st_uid != owner", "terminal-removal root owner"),
        ("metadata.st_gid != group", "terminal-removal root group"),
        ("stat.S_IMODE(metadata.st_mode) != 0o700", "terminal-removal private root mode"),
        ("mount_id = descriptor_mount_id(descriptor)", "terminal-removal mount authority"),
    ):
        require_text(tree_contents_acquisition, text, label)
    require_order(
        tree_contents_removal,
        (
            "self.assert_bound()",
            "self.acquire_inode_closure(self.fd)",
            "self.remove_contents(self.fd, [TREE_ENTRY_LIMIT], authorities)",
            "self.require_inode_authorities_consumed(authorities)",
            "self.close_inode_authorities(authorities",
            "directory_is_empty(self.fd)",
            "self.assert_bound()",
        ),
        "terminal tree-contents retained-authority removal",
    )
    require_order(
        empty_root_removal,
        (
            "self.assert_bound()",
            "self.identity != expected_identity",
            "directory_is_empty(self.fd)",
            "os.stat(self.basename, dir_fd=self.parent_fd, follow_symlinks=False)",
            "self.cleanup_started = True",
            "os.rmdir(self.basename, dir_fd=self.parent_fd)",
            "os.fstat(self.fd).st_nlink != 0",
            "os.fsync(self.parent_fd)",
            "self.removed = True",
        ),
        "terminal empty-root exact removal",
    )
    for forbidden in ("acquire_inode_closure", "remove_contents", "os.fchmod", "os.unlink"):
        if forbidden in empty_root_removal:
            raise VerificationError(
                f"terminal empty-root removal retains recursive mutation authority: {forbidden}"
            )
    for text, label in (
        ("child_retained = False", "normalization child descriptor ownership"),
        ("if not child_retained:", "normalization failed-acquisition descriptor cleanup"),
        ("close_descriptors(", "normalization failed-acquisition descriptor close"),
    ):
        require_text(normalization_collect, text, label)
    for text, label in (
        ('bounded_directory_names(directory["fd"], len(directory["names"]) + 1)', "normalization complete inventory reproof"),
        ('(current.st_mode, current.st_uid, current.st_gid, current.st_nlink)', "normalization complete inode metadata reproof"),
        ('(edge.st_mode, edge.st_uid, edge.st_gid, edge.st_nlink)', "normalization complete edge metadata reproof"),
        ('expected_directory_metadata(directory, index)', "normalization directory metadata reproof"),
        ('expected_inode_metadata(authority)', "normalization inode metadata reproof"),
        ('descriptor_mount_id(authority["fd"]) != self.mount_id', "normalization retained mount reproof"),
    ):
        require_text(normalization_assert, text, label)
    for text, label in (
        ('"uid": root.st_uid', "normalization root owner acquisition"),
        ('"gid": root.st_gid', "normalization root group acquisition"),
        ('"nlink": root.st_nlink', "normalization root link-count acquisition"),
    ):
        require_text(normalization_init, text, label)
    for text, label in (
        ('"uid": metadata.st_uid', "normalization child owner acquisition"),
        ('"gid": metadata.st_gid', "normalization child group acquisition"),
        ('"nlink": metadata.st_nlink', "normalization child link-count acquisition"),
        ('inode["uid"] != metadata.st_uid', "normalization hardlink owner consistency"),
        ('inode["gid"] != metadata.st_gid', "normalization hardlink group consistency"),
    ):
        require_text(normalization_collect, text, label)
    require_exact_count(
        normalization_collect,
        '"uid": metadata.st_uid',
        2,
        "normalization child owner acquisition",
    )
    require_exact_count(
        normalization_collect,
        '"gid": metadata.st_gid',
        2,
        "normalization child group acquisition",
    )
    require_exact_count(
        normalization_collect,
        '"nlink": metadata.st_nlink',
        2,
        "normalization child link-count acquisition",
    )
    require_order(
        normalization_mutation,
        (
            "self.assert_bound()",
            'os.fchown(directory["fd"], 0, 0)',
            "descriptor_chown(authority[\"fd\"], 0, 0",
            "os.fchmod(descriptor, normalized_mode(authority[\"mode\"]))",
            "os.fchown(descriptor, owner, group)",
            'os.fchown(directory["fd"], owner, group)',
            "self.assert_bound(owner, group)",
        ),
        "retained-authority normalization ordering",
    )
    for text, label in (
        ('if authority["internal"] != authority["nlink"]:', "initial external-hardlink rejection"),
        ("normalization tree contains a non-directory inode linked outside its boundary", "external-hardlink rejection diagnostic"),
    ):
        require_text(normalization_init, text, label)
    for text, label in (
        ("current.st_uid != owner or current.st_gid != group", "normalized inode ownership postcondition"),
        ("normalization inode ownership postcondition differs", "normalized inode ownership rejection"),
        ('!= normalized_mode(authority["mode"])', "normalized inode mode postcondition"),
        ("normalization inode mode postcondition differs", "normalized inode mode rejection"),
    ):
        require_text(normalization_mutation, text, label)
    require_text(
        closure_main,
        "scratch.remove_tree_contents(expected)",
        "terminal tree-contents removal dispatch",
    )
    require_text(
        closure_main,
        "exercise_authority_bounds(scratch)",
        "retained-authority bound fixture dispatch",
    )
    require_text(
        closure_main,
        "exercise_scratch_acquisition_failures(scratch)",
        "closure scratch acquisition fixture dispatch",
    )
    require_text(
        closure_main,
        "exercise_scratch_external_link_rejection(scratch)",
        "closure scratch hardlink fixture dispatch",
    )
    require_text(
        closure_main,
        "exercise_scratch_root_removal(scratch)",
        "closure scratch root-removal fixture dispatch",
    )
    require_order(
        source,
        (
            'yield f"/proc/self/fd/{child}"',
            "current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)",
            "if identity(current) != child_identity:",
            'raise ClosureError("self-test fixture edge changed before cleanup")',
            "authorities = self.acquire_inode_closure(child)",
            "self.remove_contents(child, [TREE_ENTRY_LIMIT], authorities)",
            "self.require_inode_authorities_consumed(authorities)",
            "self.close_inode_authorities(authorities",
        ),
        "closure retained-authority cleanup gate",
    )
    require_order(
        source,
        (
            "child_owned = False",
            "child = os.open(",
            "if descriptor_mount_id(child) != self.mount_id:",
            "child_owned = True",
            'yield f"/proc/self/fd/{child}"',
        ),
        "closure fixture acquisition authority",
    )
    if "TemporaryDirectory" in source or "tempfile" in source:
        raise VerificationError("private-tree closure probe retains pathname temporary-directory authority")
    if "followlinks=True" in source:
        raise VerificationError("private-tree closure probe follows filesystem aliases")
    for node in ast.walk(module):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "stat"
        ):
            continue
        nofollow = [keyword.value for keyword in node.keywords if keyword.arg == "follow_symlinks"]
        if len(nofollow) != 1 or not isinstance(nofollow[0], ast.Constant) or nofollow[0].value is not False:
            raise VerificationError("private-tree closure descriptor stat can follow a filesystem alias")


def validate_sources(sources):
    validate_verify_workspace(sources["verify"])
    validate_build_release(sources["build"])
    validate_release_finalizer(sources["finalizer"])
    validate_target_scripts(sources["debian"], sources["android"], sources["pins"])
    validate_publisher(sources["publish"])
    validate_fork_version(sources["version"])
    validate_r_b2_version_metadata(sources)
    validate_docs(sources)
    validate_scan_contract(sources["scan"], sources["verify"], sources["apple"], sources["release"])
    validate_systemd_smoke_contract(
        sources["systemd_smoke_host"],
        sources["systemd_smoke_host_mode"],
        sources["systemd_smoke_guest"],
        sources["systemd_smoke_guest_mode"],
        sources["systemd_smoke_loginctl"],
        sources["systemd_smoke_loginctl_mode"],
        sources["online_fetch"],
        sources["pins"],
        sources["release"],
        sources["hardening"],
    )
    validate_smoke_contract(
        sources["verify"],
        sources["smoke"],
        sources["smoke_stage"],
        sources["smoke_stage_mode"],
        sources["service_lifecycle"],
        sources["service_lifecycle_mode"],
        sources["debian_sysv_lifecycle"],
        sources["debian_sysv_lifecycle_mode"],
        sources["loginctl_fixture"],
        sources["loginctl_fixture_mode"],
        sources["smoke_process_guard"],
        sources["smoke_process_guard_mode"],
        sources["smoke_launcher"],
        sources["smoke_ready"],
        sources["smoke_ready_mode"],
        sources["smoke_typed_probe"],
        sources["session_probe"],
        sources["ipc_source"],
        sources["core_main"],
        sources["common_source"],
        sources["linux_source"],
    )
    validate_faillo_contract(sources["faillo"])
    validate_private_tree_closure(sources["closure"])
    validate_workspace_verifier_self_contract(sources["workspace_verifier"])


def handle_managed_signal(signum, frame):
    del frame
    state = _MANAGED_SIGNAL_STATE
    if state is None:
        raise ManagedSignal(signum)
    state["caught"] = True
    if state["acquiring_process"]:
        if state["pending_signum"] is None:
            state["pending_signum"] = signum
        return
    signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    raise ManagedSignal(signum)


def enter_managed_signal_scope():
    global _MANAGED_SIGNAL_STATE
    if threading.current_thread() is not threading.main_thread():
        raise VerificationError("managed signal scope requires the main thread")
    entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    if _MANAGED_SIGNAL_STATE is not None:
        return {"entry_mask": entry_mask, "outer": False}

    previous_handlers = {}
    try:
        for signum in MANAGED_SIGNALS:
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, handle_managed_signal)
        state = {
            "acquiring_process": False,
            "acquiring_process_object": None,
            "caught": False,
            "pending_signum": None,
            "previous_handlers": previous_handlers,
            "previous_mask": entry_mask,
        }
        _MANAGED_SIGNAL_STATE = state
    except BaseException:
        signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        _MANAGED_SIGNAL_STATE = None
        signal.pthread_sigmask(signal.SIG_SETMASK, entry_mask)
        raise
    return {"entry_mask": entry_mask, "outer": True}


def activate_managed_signal_scope(scope):
    signal.pthread_sigmask(signal.SIG_SETMASK, scope["entry_mask"])


def begin_managed_process_acquisition():
    state = _MANAGED_SIGNAL_STATE
    if state is None:
        raise VerificationError("managed process acquisition has no signal scope")
    if state["acquiring_process"]:
        raise VerificationError("managed process acquisition is already active")
    state["acquiring_process"] = True
    state["acquiring_process_object"] = None


def finish_managed_process_acquisition():
    state = _MANAGED_SIGNAL_STATE
    if state is None:
        raise VerificationError("managed process acquisition finish has no signal scope")
    if not state["acquiring_process"]:
        raise VerificationError("managed process acquisition is not active at finish")
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    state["acquiring_process"] = False
    state["acquiring_process_object"] = None
    pending_signum = state["pending_signum"]
    state["pending_signum"] = None
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return pending_signum


def leave_managed_signal_scope(scope, finalization_mask):
    global _MANAGED_SIGNAL_STATE
    state = _MANAGED_SIGNAL_STATE
    if state is None:
        raise VerificationError("managed signal scope ownership is unavailable")
    if not scope["outer"]:
        signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask)
        return
    if state["acquiring_process"]:
        raise VerificationError("outer managed signal scope retained process acquisition")

    previous_handlers = state["previous_handlers"]
    previous_mask = state["previous_mask"]
    if state["caught"]:
        for signum in MANAGED_SIGNALS:
            signal.signal(signum, signal.SIG_IGN)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    for signum, handler in previous_handlers.items():
        signal.signal(signum, handler)
    _MANAGED_SIGNAL_STATE = None
    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def close_process_pipes(process):
    if process is None:
        return
    failures = []
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            try:
                stream.close()
            except OSError as exc:
                failures.append(exc)
    if failures:
        raise VerificationError("managed-command process pipes could not all be closed") from failures[0]


class ExactChildProcess:
    def __init__(self, pid, pidfd, command, stdout, stderr):
        self.pid = pid
        self.pidfd = pidfd
        self.args = command
        self.returncode = None
        self.stdin = None
        self.stdout = stdout
        self.stderr = stderr

    def _record_status(self, status):
        self.returncode = os.waitstatus_to_exitcode(status)
        pidfd = self.pidfd
        self.pidfd = None
        if pidfd is not None:
            os.close(pidfd)
        return self.returncode

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError as exc:
            raise VerificationError("exact child process lost reap authority") from exc
        if pid == 0:
            return None
        if pid != self.pid:
            raise VerificationError("exact child process reaped an unexpected PID")
        return self._record_status(status)

    def wait(self, timeout=None):
        if self.returncode is not None:
            return self.returncode
        if timeout is None:
            while True:
                try:
                    pid, status = os.waitpid(self.pid, 0)
                    break
                except InterruptedError:
                    continue
            if pid != self.pid:
                raise VerificationError("exact child process reaped an unexpected PID")
            return self._record_status(status)
        deadline = time.monotonic() + timeout
        while True:
            result = self.poll()
            if result is not None:
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(min(0.01, remaining))

    def send_signal(self, signum):
        if self.returncode is not None:
            return
        if self.pidfd is None:
            raise VerificationError("exact child process has no signal authority")
        try:
            signal.pidfd_send_signal(self.pidfd, signum)
        except ProcessLookupError:
            self.poll()
        except OSError as pidfd_error:
            try:
                os.kill(self.pid, signum)
            except ProcessLookupError:
                self.poll()
            except OSError as pid_error:
                error = VerificationError("exact child process lost signal authority")
                error.add_note(f"pidfd signaling failed: {pidfd_error}")
                raise error from pid_error

    def terminate(self):
        self.send_signal(signal.SIGTERM)

    def kill(self):
        self.send_signal(signal.SIGKILL)

    def communicate(self, timeout=None, max_output_bytes=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        output = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        for name, stream in (("stdout", self.stdout), ("stderr", self.stderr)):
            if stream is not None and not stream.closed:
                selector.register(stream, selectors.EVENT_READ, name)
        try:
            while selector.get_map():
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(
                        self.args,
                        timeout,
                        output=bytes(output["stdout"]),
                        stderr=bytes(output["stderr"]),
                    )
                events = selector.select(remaining)
                if not events:
                    raise subprocess.TimeoutExpired(
                        self.args,
                        timeout,
                        output=bytes(output["stdout"]),
                        stderr=bytes(output["stderr"]),
                    )
                for key, _ in events:
                    chunk = os.read(key.fd, 65536)
                    if chunk:
                        if (
                            max_output_bytes is not None
                            and len(output["stdout"]) + len(output["stderr"]) + len(chunk)
                            > max_output_bytes
                        ):
                            raise VerificationError("exact child process output exceeds its bound")
                        output[key.data].extend(chunk)
                    else:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            self.wait(timeout=remaining)
            return bytes(output["stdout"]), bytes(output["stderr"])
        finally:
            selector.close()


def open_descriptor_inventory():
    descriptors = set()
    for name in os.listdir("/proc/self/fd"):
        if re.fullmatch(r"[0-9]+", name) is None:
            raise VerificationError("process descriptor inventory is malformed")
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            descriptors.add(descriptor)
    return descriptors


def require_single_native_thread():
    tasks = os.listdir("/proc/self/task")
    expected = str(os.getpid())
    if tasks != [expected]:
        raise VerificationError("exact child process creation requires one native thread")


def open_exact_pipe():
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    descriptors = [read_fd, write_fd]
    duplicates = []
    try:
        for index, descriptor in enumerate(descriptors):
            if descriptor >= 3:
                continue
            duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
            duplicates.append(duplicate)
            os.close(descriptor)
            descriptors[index] = duplicate
            duplicates.remove(duplicate)
        return tuple(descriptors)
    except BaseException as primary_error:
        failures = []
        for descriptor in descriptors + duplicates:
            try:
                os.close(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    failures.append(exc)
        for failure in failures:
            primary_error.add_note(f"exact pipe cleanup failed: {failure}")
        raise


def reap_failed_exact_child(pid, pidfd):
    failures = []
    signaled = False
    try:
        if pidfd is not None:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
        signaled = True
    except ProcessLookupError:
        signaled = True
    except OSError as pidfd_error:
        try:
            os.kill(pid, signal.SIGKILL)
            signaled = True
        except ProcessLookupError:
            signaled = True
        except BaseException as pid_error:
            error = VerificationError("failed exact child process lost termination authority")
            error.add_note(f"pidfd signaling failed: {pidfd_error}")
            failures.append(error)
            failures.append(pid_error)
    if signaled:
        try:
            while True:
                try:
                    waited_pid, _ = os.waitpid(pid, 0)
                    break
                except InterruptedError:
                    continue
            if waited_pid != pid:
                failures.append(VerificationError("failed exact child cleanup reaped an unexpected PID"))
        except ChildProcessError:
            pass
        except BaseException as exc:
            failures.append(exc)
    if pidfd is not None:
        try:
            os.close(pidfd)
        except BaseException as exc:
            failures.append(exc)
    if failures:
        error = VerificationError("failed exact child process could not be fully reaped")
        for failure in failures[1:]:
            error.add_note(str(failure))
        raise error from failures[0]


def set_child_parent_death_signal(parent_pid):
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if os.getppid() != parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)


def descriptor_fork_identity(descriptor):
    metadata = os.fstat(descriptor)
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        fcntl.fcntl(descriptor, fcntl.F_GETFL),
    )


def close_unlisted_child_descriptors(inherited, identities):
    open_descriptors = open_descriptor_inventory()
    for descriptor, expected in identities.items():
        if descriptor_fork_identity(descriptor) != expected:
            raise VerificationError("exact child inherited descriptor changed across fork")
    for descriptor in open_descriptors:
        if descriptor > 2 and descriptor not in inherited:
            try:
                os.close(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise


def spawn_exact_process(command, cwd, environment, stdin_fd, pass_fds=()):
    if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
        raise VerificationError("exact child process creation requires the sole main thread")
    require_single_native_thread()
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        raise VerificationError("exact child process creation requires default SIGCHLD ownership")
    inherited = set(pass_fds)
    if any(descriptor < 3 for descriptor in inherited) or len(inherited) != len(pass_fds):
        raise VerificationError("exact child process descriptor allowlist is invalid")
    for descriptor in inherited:
        os.fstat(descriptor)
    os.fstat(stdin_fd)
    stdin_authority = None
    stdout_read = None
    stdout_write = None
    stderr_read = None
    stderr_write = None
    pid = None
    pidfd = None
    process = None
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
    try:
        stdin_authority = fcntl.fcntl(stdin_fd, fcntl.F_DUPFD_CLOEXEC, 3)
        stdout_read, stdout_write = open_exact_pipe()
        stderr_read, stderr_write = open_exact_pipe()
        child_inherited = set(inherited)
        child_inherited.update((stdin_authority, stdout_write, stderr_write))
        inherited_identities = {
            descriptor: descriptor_fork_identity(descriptor) for descriptor in child_inherited
        }
        parent_pid = os.getpid()
        require_single_native_thread()
        pid = os.fork()
        if pid == 0:
            try:
                set_child_parent_death_signal(parent_pid)
                for signum in MANAGED_SIGNALS:
                    signal.signal(signum, signal.SIG_DFL)
                os.setsid()
                os.chdir(cwd)
                os.dup2(stdin_authority, 0, inheritable=True)
                os.dup2(stdout_write, 1, inheritable=True)
                os.dup2(stderr_write, 2, inheritable=True)
                for descriptor in inherited:
                    os.set_inheritable(descriptor, True)
                close_unlisted_child_descriptors(inherited, inherited_identities)
                target_mask = set(previous_mask) - set(MANAGED_SIGNALS)
                signal.pthread_sigmask(signal.SIG_SETMASK, target_mask)
                os.execve(command[0], command, environment)
            except BaseException:
                os._exit(127)
        pidfd = os.pidfd_open(pid, 0)
        stdout = os.fdopen(stdout_read, "rb", buffering=0)
        stdout_read = None
        try:
            stderr = os.fdopen(stderr_read, "rb", buffering=0)
        except BaseException:
            stdout.close()
            raise
        stderr_read = None
        process = ExactChildProcess(pid, pidfd, command, stdout, stderr)
        pidfd = None
        state = _MANAGED_SIGNAL_STATE
        if state is not None and state["acquiring_process"]:
            state["acquiring_process_object"] = process
        failures = []
        for descriptor in (stdout_read, stdout_write, stderr_read, stderr_write):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        failures.append(exc)
        stdout_read = stdout_write = stderr_read = stderr_write = None
        try:
            os.close(stdin_authority)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                failures.append(exc)
        stdin_authority = None
        if failures:
            error = VerificationError("exact child parent descriptors could not all be closed")
            for failure in failures[1:]:
                error.add_note(str(failure))
            raise error from failures[0]
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        previous_mask = None
        return process
    except BaseException as primary_error:
        cleanup_failures = []
        if process is not None:
            try:
                process.kill()
            except BaseException as exc:
                cleanup_failures.append(exc)
            try:
                process.wait()
            except BaseException as exc:
                cleanup_failures.append(exc)
            try:
                close_process_pipes(process)
            except BaseException as exc:
                cleanup_failures.append(exc)
        elif pid is not None:
            try:
                reap_failed_exact_child(pid, pidfd)
            except BaseException as exc:
                cleanup_failures.append(exc)
            pidfd = None
        for descriptor in (stdout_read, stdout_write, stderr_read, stderr_write, stdin_authority):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        cleanup_failures.append(exc)
        if previous_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except BaseException as exc:
                cleanup_failures.append(exc)
            previous_mask = None
        for failure in cleanup_failures:
            primary_error.add_note(f"exact child acquisition cleanup failed: {failure}")
        raise


MANAGED_GATE_HELPER = r'''
import array
import fcntl
import json
import os
import socket
import signal
import sys

token = sys.argv[1]
command = sys.argv[2:]
if not command or not os.path.isabs(command[0]):
    raise SystemExit(70)
print(f"RUSTDESK-MANAGED-READY {token} {os.getpid()}", flush=True)
channel = socket.socket(fileno=0)
descriptor_capacity = 64
descriptor_size = array.array("i").itemsize
frame, controls, flags, address = channel.recvmsg(
    1024 * 1024 + 1,
    socket.CMSG_SPACE(descriptor_capacity * descriptor_size),
    socket.MSG_CMSG_CLOEXEC,
)
if address is not None or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
    raise SystemExit(71)
payload = json.loads(frame)
if not isinstance(payload, dict) or set(payload) != {"token", "environment", "descriptors"}:
    raise SystemExit(72)
if (
    payload["token"] != token
    or not isinstance(payload["environment"], dict)
    or not isinstance(payload["descriptors"], list)
    or len(payload["descriptors"]) > descriptor_capacity
    or any(
        isinstance(descriptor, bool)
        or not isinstance(descriptor, int)
        or descriptor < 3
        or descriptor > 1048575
        for descriptor in payload["descriptors"]
    )
    or len(set(payload["descriptors"])) != len(payload["descriptors"])
):
    raise SystemExit(73)
environment = payload["environment"]
if any(
    not isinstance(key, str)
    or not isinstance(value, str)
    or not key
    or "=" in key
    or "\0" in key
    or "\0" in value
    for key, value in environment.items()
):
    raise SystemExit(74)
received = array.array("i")
for level, kind, data in controls:
    if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(data) % descriptor_size:
        raise SystemExit(75)
    received.frombytes(data)
if len(received) != len(payload["descriptors"]):
    raise SystemExit(76)
temporary = []
reservations = []
targets = set(payload["descriptors"])
try:
    try:
        for descriptor in received:
            while True:
                duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
                if duplicate in targets:
                    reservations.append(duplicate)
                    continue
                temporary.append(duplicate)
                break
    except BaseException:
        for descriptor in temporary + reservations:
            os.close(descriptor)
        raise
finally:
    for descriptor in received:
        os.close(descriptor)
try:
    for descriptor in reservations:
        os.close(descriptor)
    reservations.clear()
    for descriptor, target in zip(temporary, payload["descriptors"]):
        os.dup2(descriptor, target, inheritable=True)
finally:
    for descriptor in temporary + reservations:
        os.close(descriptor)
channel.close()
descriptor = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
if descriptor != 0:
    os.dup2(descriptor, 0)
    os.close(descriptor)
else:
    os.set_inheritable(0, True)
signal.pthread_sigmask(signal.SIG_UNBLOCK, (signal.SIGHUP, signal.SIGINT, signal.SIGTERM))
os.execve(command[0], command, environment)
'''


def require_system_tool(path):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise VerificationError(f"managed-command control tool path is not absolute: {path}")
    current = "/"
    for component in path.split("/")[1:]:
        current = os.path.join(current, component)
        metadata = os.lstat(current)
        if metadata.st_uid != 0 or (
            not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022
        ):
            raise VerificationError(f"managed-command control path is not protected: {current}")
    resolved = os.path.realpath(path)
    if not os.path.isabs(resolved):
        raise VerificationError(f"managed-command control tool target is not absolute: {path}")
    metadata = os.stat(resolved, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        raise VerificationError(f"managed-command control tool is not trusted: {path}")


def systemd_control_environment():
    runtime = Path(f"/run/user/{os.geteuid()}")
    metadata = runtime.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise VerificationError("systemd user runtime directory is not exact authority")
    bus = runtime / "bus"
    bus_metadata = bus.stat()
    if not stat.S_ISSOCK(bus_metadata.st_mode) or bus_metadata.st_uid != os.geteuid():
        raise VerificationError("systemd user bus is not current-UID socket authority")
    return {
        "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "XDG_RUNTIME_DIR": str(runtime),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
    }


def run_systemd_control(arguments, environment, timeout_seconds=5):
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=timeout_seconds,
    )
    if len(result.stdout) + len(result.stderr) > 1024 * 1024:
        raise VerificationError("systemd control output exceeds its byte bound")
    return result


def systemd_unit_properties(unit, environment):
    properties = (
        "Id",
        "Names",
        "Description",
        "LoadState",
        "ActiveState",
        "Transient",
        "CollectMode",
        "InvocationID",
        "ControlGroup",
        "Slice",
        "Delegate",
        "KillMode",
        "KillSignal",
        "FinalKillSignal",
        "SendSIGKILL",
        "TimeoutStopUSec",
        "RuntimeMaxUSec",
    )
    command = ["/usr/bin/systemctl", "--user", "show", unit, "--no-pager"]
    for name in properties:
        command.extend(("--property", name))
    result = run_systemd_control(command, environment)
    if result.returncode != 0:
        raise VerificationError(
            "cannot inspect managed-command unit: "
            + result.stderr.decode("utf-8", errors="surrogateescape")
        )
    parsed = {}
    for line in result.stdout.splitlines():
        if b"=" not in line:
            raise VerificationError("systemd unit property output is malformed")
        raw_name, value = line.split(b"=", 1)
        name = raw_name.decode("ascii")
        if name in parsed or name not in properties:
            raise VerificationError("systemd unit property output has an unexpected key")
        parsed[name] = value.decode("utf-8", errors="surrogateescape")
    if set(parsed) != set(properties):
        raise VerificationError("systemd unit property output is incomplete")
    return parsed


def unit_is_absent(unit, environment):
    properties = systemd_unit_properties(unit, environment)
    return properties["LoadState"] == "not-found"


def parse_systemd_second_duration(value):
    scales = {
        "w": 7 * 24 * 60 * 60,
        "d": 24 * 60 * 60,
        "h": 60 * 60,
        "min": 60,
        "s": 1,
    }
    order = {name: index for index, name in enumerate(scales)}
    tokens = value.split(" ")
    if not tokens or any(not token for token in tokens):
        raise VerificationError("managed-command unit duration property is malformed")
    total = 0
    previous = -1
    for token in tokens:
        match = re.fullmatch(r"([0-9]+)(w|d|h|min|s)", token)
        if match is None or order[match.group(2)] <= previous:
            raise VerificationError("managed-command unit duration property is malformed")
        previous = order[match.group(2)]
        total += int(match.group(1)) * scales[match.group(2)]
    return total


def open_cgroup_authority(control_group):
    if not control_group.startswith("/"):
        raise VerificationError("managed-command cgroup path is not absolute")
    components = control_group.split("/")[1:]
    if not components or any(not part or part in (".", "..") for part in components):
        raise VerificationError("managed-command cgroup path has an invalid component")
    descriptor = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    events = None
    kill = None
    processes = None
    controllers = None
    kind = None
    try:
        controllers = os.open("cgroup.controllers", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        owned_controllers = controllers
        controllers = None
        os.close(owned_controllers)
        for component in components:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            previous = descriptor
            descriptor = child
            os.close(previous)
        events = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        kill = os.open("cgroup.kill", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        processes = os.open("cgroup.procs", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        kind = os.open("cgroup.type", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        primary_error = None
        try:
            cgroup_type = os.read(kind, 128)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            failures = []
            attempt_cleanup(failures, "cgroup type descriptor", os.close, kind)
            kind = None
            report_cleanup_failures(
                primary_error,
                "managed-command cgroup type cleanup failed",
                failures,
            )
        if cgroup_type != b"domain\n":
            raise VerificationError("managed-command cgroup is not a domain cgroup")
        return {
            "directory": descriptor,
            "events": events,
            "kill": kill,
            "processes": processes,
            "identity": filesystem_identity(os.fstat(descriptor)),
            "path": "/sys/fs/cgroup" + control_group,
        }
    except BaseException as primary_error:
        failures = []
        for label, owned in (
            ("cgroup type descriptor", kind),
            ("cgroup controller descriptor", controllers),
            ("cgroup processes descriptor", processes),
            ("cgroup kill descriptor", kill),
            ("cgroup events descriptor", events),
            ("cgroup directory descriptor", descriptor),
        ):
            if owned is not None:
                attempt_cleanup(failures, label, os.close, owned)
        report_cleanup_failures(
            primary_error,
            "managed-command cgroup acquisition cleanup failed",
            failures,
        )
        raise


def close_cgroup_authority(authority):
    if authority is None:
        return
    failures = []
    for name in ("events", "kill", "processes", "directory"):
        descriptor = authority.get(name)
        if descriptor is not None:
            authority[name] = None
            try:
                os.close(descriptor)
            except OSError as exc:
                failures.append((name, exc))
    if failures:
        names = ", ".join(name for name, _ in failures)
        raise VerificationError(f"managed-command cgroup descriptors could not be closed: {names}") from failures[0][1]


def cgroup_is_populated(authority):
    if filesystem_identity(os.fstat(authority["directory"])) != authority["identity"]:
        raise VerificationError("managed-command cgroup descriptor identity changed")
    try:
        os.lseek(authority["events"], 0, os.SEEK_SET)
        content = os.read(authority["events"], 4096)
    except OSError as exc:
        if exc.errno == errno.ENODEV and not os.path.lexists(authority["path"]):
            return False
        raise VerificationError("managed-command cgroup events became unavailable") from exc
    if len(content) == 4096:
        raise VerificationError("managed-command cgroup events exceed their byte bound")
    values = {}
    for line in content.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in values:
            raise VerificationError("managed-command cgroup events are malformed")
        values[fields[0]] = fields[1]
    if values.get(b"populated") not in (b"0", b"1"):
        raise VerificationError("managed-command cgroup population state is unavailable")
    return values[b"populated"] == b"1"


def authenticate_managed_unit(
    unit, description, token, target_pid, environment, stop_limit, runtime_limit
):
    properties = systemd_unit_properties(unit, environment)
    expected = {
        "Id": unit,
        "Names": unit,
        "Description": description,
        "LoadState": "loaded",
        "ActiveState": "active",
        "Transient": "yes",
        "CollectMode": "inactive-or-failed",
        "Slice": "app.slice",
        "Delegate": "no",
        "KillMode": "control-group",
        "KillSignal": "15",
        "FinalKillSignal": "9",
        "SendSIGKILL": "yes",
    }
    for name, value in expected.items():
        if properties[name] != value:
            raise VerificationError(f"managed-command unit property differs: {name}")
    if (
        parse_systemd_second_duration(properties["TimeoutStopUSec"]) != stop_limit
        or parse_systemd_second_duration(properties["RuntimeMaxUSec"]) != runtime_limit
    ):
        raise VerificationError("managed-command unit duration policy differs")
    if re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"]) is None:
        raise VerificationError("managed-command invocation identity is malformed")
    if not properties["ControlGroup"].endswith("/" + unit):
        raise VerificationError("managed-command cgroup is not bound to its exact unit")
    authority = open_cgroup_authority(properties["ControlGroup"])
    try:
        process_cgroup = read_process_cgroup(target_pid)
        if process_cgroup != f"0::{properties['ControlGroup']}\n".encode("ascii"):
            raise VerificationError("managed-command gate process is outside its authenticated cgroup")
        repeated = systemd_unit_properties(unit, environment)
        if (
            repeated["InvocationID"] != properties["InvocationID"]
            or repeated["ControlGroup"] != properties["ControlGroup"]
            or repeated["Description"] != description
        ):
            raise VerificationError("managed-command unit identity changed during acquisition")
        if not cgroup_is_populated(authority):
            raise VerificationError("managed-command cgroup is empty before target release")
        authority["unit"] = unit
        authority["description"] = description
        authority["invocation"] = properties["InvocationID"]
        authority["control_group"] = properties["ControlGroup"]
        authority["token"] = token
        return authority
    except BaseException as primary_error:
        failures = []
        attempt_cleanup(
            failures,
            "unacquired cgroup authority",
            close_cgroup_authority,
            authority,
        )
        report_cleanup_failures(
            primary_error,
            "unacquired managed-command authority cleanup failed",
            failures,
        )
        raise


def cgroup_process_ids(authority):
    os.lseek(authority["processes"], 0, os.SEEK_SET)
    content = os.read(authority["processes"], 1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise VerificationError("managed-command cgroup process inventory exceeds its byte bound")
    process_ids = []
    seen = set()
    for line in content.splitlines():
        if re.fullmatch(br"[1-9][0-9]*", line) is None:
            raise VerificationError("managed-command cgroup process inventory is malformed")
        process_id = int(line)
        if process_id not in seen:
            seen.add(process_id)
            process_ids.append(process_id)
    return process_ids


def read_process_cgroup(process_id):
    descriptor = os.open(
        f"/proc/{process_id}/cgroup",
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        content = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(content) > 4096:
        raise VerificationError("managed-command process cgroup exceeds its byte bound")
    return content


def signal_managed_unit(authority, environment, signum):
    del environment
    numeric_signal = signal.Signals["SIG" + signum]
    for process_id in cgroup_process_ids(authority):
        try:
            pidfd = os.pidfd_open(process_id, 0)
        except ProcessLookupError:
            continue
        try:
            try:
                process_cgroup = read_process_cgroup(process_id)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if process_cgroup != f"0::{authority['control_group']}\n".encode("ascii"):
                raise VerificationError("managed-command process left its authenticated cgroup")
            try:
                signal.pidfd_send_signal(pidfd, numeric_signal)
            except ProcessLookupError:
                pass
        finally:
            os.close(pidfd)


def wait_cgroup_empty(authority):
    while cgroup_is_populated(authority):
        time.sleep(0.01)


def hard_kill_cgroup(authority):
    if cgroup_is_populated(authority):
        os.write(authority["kill"], b"1")
    wait_cgroup_empty(authority)


def gracefully_stop_managed_unit(authority, environment, cleanup_grace_seconds):
    deadline = time.monotonic() + cleanup_grace_seconds
    while cgroup_is_populated(authority):
        signal_managed_unit(authority, environment, "TERM")
        if time.monotonic() >= deadline:
            hard_kill_cgroup(authority)
            return
        time.sleep(0.01)


def authenticate_unacquired_unit(unit, description, environment):
    properties = systemd_unit_properties(unit, environment)
    if properties["LoadState"] == "not-found":
        return None
    if (
        properties["Description"] != description
        or properties["Transient"] != "yes"
        or re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"]) is None
        or not properties["ControlGroup"].endswith("/" + unit)
    ):
        raise VerificationError("unacquired managed-command unit identity is ambiguous")
    authority = open_cgroup_authority(properties["ControlGroup"])
    try:
        repeated = systemd_unit_properties(unit, environment)
        if (
            repeated["InvocationID"] != properties["InvocationID"]
            or repeated["ControlGroup"] != properties["ControlGroup"]
            or repeated["Description"] != description
        ):
            raise VerificationError("unacquired managed-command unit changed during acquisition")
        authority["unit"] = unit
        authority["description"] = description
        authority["invocation"] = properties["InvocationID"]
        authority["control_group"] = properties["ControlGroup"]
        return authority
    except BaseException as primary_error:
        failures = []
        attempt_cleanup(
            failures,
            "unacquired cgroup authority close",
            close_cgroup_authority,
            authority,
        )
        report_cleanup_failures(
            primary_error,
            "unacquired managed-command authority cleanup failed",
            failures,
        )
        raise


def terminate_and_reap_unacquired_launcher(process):
    if process.returncode is not None:
        return
    failures = []
    try:
        process.terminate()
    except BaseException as error:
        failures.append(("launcher termination", error))
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except BaseException as error:
            failures.append(("launcher forced termination", error))
        try:
            process.wait()
        except BaseException as error:
            failures.append(("launcher reap", error))
    except BaseException as error:
        failures.append(("launcher reap", error))
    if process.returncode is None:
        failures.append(
            (
                "launcher absence proof",
                VerificationError("managed-command launcher remains unreaped"),
            )
        )
    report_cleanup_failures(
        None,
        "unacquired managed-command launcher cleanup failed",
        failures,
    )


def kill_observed_target(target_pidfd):
    if target_pidfd is None:
        return
    try:
        signal.pidfd_send_signal(target_pidfd, signal.SIGKILL)
    except ProcessLookupError:
        return


def resolve_unacquired_unit(process, target_pidfd, unit, description, environment):
    invocation = None
    authority = None
    launcher_reaped = False
    deadline = time.monotonic() + MANAGED_UNIT_COLLECTION_SECONDS
    primary_error = None
    try:
        authority = authenticate_unacquired_unit(unit, description, environment)
        if authority is not None:
            invocation = authority["invocation"]
            hard_kill_cgroup(authority)
        terminate_and_reap_unacquired_launcher(process)
        launcher_reaped = True
        if authority is not None:
            close_cgroup_authority(authority)
            authority = None
        while True:
            if time.monotonic() >= deadline:
                raise VerificationError("unacquired managed-command unit survived collection deadline")
            properties = systemd_unit_properties(unit, environment)
            if properties["LoadState"] == "not-found":
                return
            if invocation is None:
                authority = authenticate_unacquired_unit(unit, description, environment)
                if authority is None:
                    continue
                invocation = authority["invocation"]
                hard_kill_cgroup(authority)
                close_cgroup_authority(authority)
                authority = None
                continue
            if properties["InvocationID"] != invocation:
                raise VerificationError("unacquired managed-command unit was replaced during cleanup")
            time.sleep(0.01)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        failures = []
        attempt_cleanup(
            failures,
            "unacquired cgroup authority close",
            close_cgroup_authority,
            authority,
        )
        attempt_cleanup(
            failures,
            "unacquired target termination",
            kill_observed_target,
            target_pidfd,
        )
        if not launcher_reaped:
            attempt_cleanup(
                failures,
                "unacquired launcher termination and reap",
                terminate_and_reap_unacquired_launcher,
                process,
            )
        report_cleanup_failures(
            primary_error,
            "unacquired managed-command finalization failed",
            failures,
        )


def read_managed_ready(process, token, deadline, output, max_output_bytes):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    ready = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerificationError("managed-command cgroup acquisition exceeded its deadline")
            events = selector.select(remaining)
            if not events:
                raise VerificationError("managed-command cgroup acquisition exceeded its deadline")
            for key, _ in events:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    raise VerificationError("managed-command gate exited before authority acquisition")
                if key.data == "stderr":
                    output["stderr"].extend(chunk)
                else:
                    ready.extend(chunk)
                if len(ready) + len(output["stderr"]) > max_output_bytes:
                    raise VerificationError("managed command output exceeds its bound during acquisition")
                if b"\n" in ready:
                    line, remainder = bytes(ready).split(b"\n", 1)
                    match = re.fullmatch(
                        rb"RUSTDESK-MANAGED-READY " + token.encode("ascii") + rb" ([1-9][0-9]*)",
                        line,
                    )
                    if match is None or remainder:
                        raise VerificationError("managed-command gate returned a malformed readiness frame")
                    return int(match.group(1))
    finally:
        selector.close()


def finalize_managed_unit(process, authority, environment):
    control_group_path = authority["path"]
    unit = authority["unit"]
    invocation = authority["invocation"]
    failures = []
    attempt_cleanup(
        failures,
        "managed cgroup forced termination",
        hard_kill_cgroup,
        authority,
    )
    attempt_cleanup(
        failures,
        "managed launcher termination and reap",
        terminate_and_reap_unacquired_launcher,
        process,
    )
    attempt_cleanup(
        failures,
        "managed cgroup authority close",
        close_cgroup_authority,
        authority,
    )
    deadline = time.monotonic() + MANAGED_UNIT_COLLECTION_SECONDS
    try:
        while True:
            properties = systemd_unit_properties(unit, environment)
            if properties["LoadState"] == "not-found":
                break
            if properties["InvocationID"] != invocation:
                raise VerificationError("managed-command unit was replaced during collection")
            if time.monotonic() >= deadline:
                raise VerificationError("managed-command unit survived its collection deadline")
            time.sleep(0.01)
    except BaseException as error:
        failures.append(("managed unit collection", error))
    try:
        if os.path.lexists(control_group_path):
            raise VerificationError("managed-command cgroup pathname survived collection")
    except BaseException as error:
        failures.append(("managed cgroup pathname absence", error))
    report_cleanup_failures(
        None,
        "managed-command unit finalization failed",
        failures,
    )


def close_private_descriptors(descriptors):
    failures = []
    while descriptors:
        descriptor = descriptors.pop()
        try:
            os.close(descriptor)
        except OSError as exc:
            failures.append(exc)
    if failures:
        raise VerificationError("managed private descriptors could not be closed") from failures[0]


def acquire_private_descriptors(descriptors):
    acquired = []
    try:
        for descriptor in descriptors:
            duplicate = os.dup(descriptor)
            os.set_inheritable(duplicate, False)
            os.fstat(duplicate)
            acquired.append(duplicate)
        return acquired
    except BaseException as primary_error:
        try:
            close_private_descriptors(acquired)
        except VerificationError as cleanup_error:
            raise VerificationError(
                f"{primary_error}; managed private descriptor acquisition cleanup failed: {cleanup_error}"
            ) from primary_error
        raise


def run_managed_command(
    command,
    cwd,
    env=None,
    timeout_seconds=300,
    cleanup_grace_seconds=120,
    kill_grace_seconds=10,
    max_output_bytes=32 * 1024 * 1024,
    inherited_fds=(),
):
    if not command or not os.path.isabs(os.fspath(command[0])):
        raise VerificationError("managed command executable is not absolute")
    target_environment = dict(os.environ if env is None else env)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in target_environment.items()):
        raise VerificationError("managed command environment is not textual")
    if not isinstance(inherited_fds, (tuple, list)):
        raise VerificationError("managed command inherited descriptor allowlist is malformed")
    if len(inherited_fds) > 64:
        raise VerificationError("managed command inherited descriptor allowlist exceeds its bound")
    normalized_fds = []
    for descriptor in inherited_fds:
        if (
            isinstance(descriptor, bool)
            or not isinstance(descriptor, int)
            or descriptor < 3
            or descriptor > 1048575
        ):
            raise VerificationError("managed command inherited descriptor is invalid")
        normalized_fds.append(descriptor)
    if len(set(normalized_fds)) != len(normalized_fds):
        raise VerificationError("managed command inherited descriptor allowlist has duplicates")
    normalized_fds = tuple(sorted(normalized_fds))
    descriptor_authority = acquire_private_descriptors(normalized_fds)
    try:
        for tool in ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/python3"):
            require_system_tool(tool)
        control_environment = systemd_control_environment()
        token = os.urandom(32).hex()
        nonce = os.urandom(32).hex()
        unit = f"rustdesk-verifier-{token}.scope"
        description = f"rustdesk-verifier:{nonce}"
        if not unit_is_absent(unit, control_environment):
            raise VerificationError("managed-command transient unit name is already loaded")
        runtime_limit = max(
            1, int(timeout_seconds + cleanup_grace_seconds + kill_grace_seconds + 60)
        )
        stop_limit = max(1, int(cleanup_grace_seconds))
    except BaseException as primary_error:
        try:
            close_private_descriptors(descriptor_authority)
        except VerificationError as cleanup_error:
            raise VerificationError(
                f"{primary_error}; managed private descriptor setup cleanup failed: {cleanup_error}"
            ) from primary_error
        raise
    launcher = [
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "--collect",
        "--no-ask-password",
        "--expand-environment=no",
        f"--unit={unit}",
        f"--description={description}",
        "--slice=app.slice",
        "--property=Delegate=no",
        "--property=KillMode=control-group",
        "--property=KillSignal=SIGTERM",
        "--property=FinalKillSignal=SIGKILL",
        "--property=SendSIGKILL=yes",
        f"--property=TimeoutStopSec={stop_limit}s",
        f"--property=RuntimeMaxSec={runtime_limit}s",
        "--",
        "/usr/bin/python3",
        "-I",
        "-S",
        "-c",
        MANAGED_GATE_HELPER,
        token,
        *[os.fspath(argument) for argument in command],
    ]
    process = None
    authority = None
    target_pidfd = None
    selector = None
    signal_scope = None
    control_socket = None
    child_socket = None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    completed = False
    acquisition_active = False
    try:
        control_socket, child_socket = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC,
        )
        signal_scope = enter_managed_signal_scope()
        activate_managed_signal_scope(signal_scope)
        begin_managed_process_acquisition()
        acquisition_active = True
        process = spawn_exact_process(
            launcher,
            cwd,
            control_environment,
            child_socket.fileno(),
        )
        child_socket.close()
        child_socket = None
        if process.stdout is None or process.stderr is None:
            raise VerificationError("managed command has no output streams")
        acquisition_deadline = time.monotonic() + min(30, timeout_seconds)
        target_pid = read_managed_ready(process, token, acquisition_deadline, output, max_output_bytes)
        target_pidfd = os.pidfd_open(target_pid, 0)
        authority = authenticate_managed_unit(
            unit,
            description,
            token,
            target_pid,
            control_environment,
            stop_limit,
            runtime_limit,
        )
        acquisition_active = False
        pending_signum = finish_managed_process_acquisition()
        if pending_signum is not None:
            raise ManagedSignal(pending_signum)
        frame = json.dumps(
            {
                "token": token,
                "environment": target_environment,
                "descriptors": list(normalized_fds),
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii") + b"\n"
        if len(frame) > 1024 * 1024:
            raise VerificationError("managed command environment exceeds its byte bound")
        controls = []
        if normalized_fds:
            controls.append(
                (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptor_authority))
            )
        if control_socket.sendmsg([frame], controls) != len(frame):
            raise VerificationError("managed command descriptor handoff was incomplete")
        control_socket.close()
        control_socket = None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        selector.register(target_pidfd, selectors.EVENT_READ, "target")
        timed_out = False
        lingering = False
        target_exit_observed = None
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None or any(
            key.data in ("stdout", "stderr") for key in selector.get_map().values()
        ):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            wait_seconds = remaining
            if target_exit_observed is not None:
                wait_seconds = min(
                    wait_seconds,
                    max(0.0, 0.1 - (time.monotonic() - target_exit_observed)),
                )
            events = selector.select(wait_seconds)
            if not events:
                if target_exit_observed is not None and cgroup_is_populated(authority):
                    lingering = True
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                continue
            for key, _ in events:
                if key.data == "target":
                    selector.unregister(target_pidfd)
                    target_exit_observed = time.monotonic()
                    continue
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(output["stdout"]) + len(output["stderr"]) + len(chunk) > max_output_bytes:
                    raise VerificationError("managed command output exceeds its bound")
                output[key.data].extend(chunk)
            if (
                target_exit_observed is not None
                and time.monotonic() - target_exit_observed >= 0.1
                and cgroup_is_populated(authority)
            ):
                lingering = True
                break

        if timed_out:
            gracefully_stop_managed_unit(
                authority,
                control_environment,
                cleanup_grace_seconds,
            )
        elif lingering:
            hard_kill_cgroup(authority)
        elif cgroup_is_populated(authority):
            if process.poll() is not None:
                lingering = True
                hard_kill_cgroup(authority)
            else:
                raise VerificationError("managed command stopped producing output while still active")
        if timed_out or lingering:
            remaining_budget = max_output_bytes - len(output["stdout"]) - len(output["stderr"])
            try:
                remaining_stdout, remaining_stderr = process.communicate(
                    timeout=kill_grace_seconds,
                    max_output_bytes=remaining_budget,
                )
            except subprocess.TimeoutExpired as exc:
                remaining_stdout = exc.output or b""
                remaining_stderr = exc.stderr or b""
            if (
                len(output["stdout"])
                + len(output["stderr"])
                + len(remaining_stdout)
                + len(remaining_stderr)
                > max_output_bytes
            ):
                raise VerificationError("managed command output exceeds its bound during cleanup")
            output["stdout"].extend(remaining_stdout)
            output["stderr"].extend(remaining_stderr)
        close_process_pipes(process)
        owned_authority = authority
        authority = None
        finalize_managed_unit(
            process, owned_authority, control_environment
        )
        completed = True

        stdout = output["stdout"].decode("utf-8", errors="surrogateescape")
        stderr = output["stderr"].decode("utf-8", errors="surrogateescape")
        if timed_out:
            stderr += "\nmanaged command exceeded its deadline"
        if lingering:
            raise VerificationError("managed command exited while cgroup descendants remained")
        return subprocess.CompletedProcess(command, 124 if timed_out else process.returncode, stdout, stderr)
    finally:
        primary_exception = sys.exc_info()[1]
        cleanup_failures = []
        pending_signum = None
        finalization_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        if authority is not None:
            owned_authority = authority
            authority = None
            attempt_cleanup(
                cleanup_failures,
                "managed process pipe close before shutdown",
                close_process_pipes,
                process,
            )
            attempt_cleanup(
                cleanup_failures,
                "managed unit graceful shutdown",
                gracefully_stop_managed_unit,
                owned_authority,
                control_environment,
                cleanup_grace_seconds,
            )
            attempt_cleanup(
                cleanup_failures,
                "managed unit forced finalization",
                finalize_managed_unit,
                process,
                owned_authority,
                control_environment,
            )
        elif process is not None and not completed:
            attempt_cleanup(
                cleanup_failures,
                "unacquired managed unit resolution",
                resolve_unacquired_unit,
                process,
                target_pidfd,
                unit,
                description,
                control_environment,
            )
        if control_socket is not None:
            owned_socket = control_socket
            control_socket = None
            attempt_cleanup(
                cleanup_failures,
                "managed control socket close",
                owned_socket.close,
            )
        if child_socket is not None:
            owned_socket = child_socket
            child_socket = None
            attempt_cleanup(
                cleanup_failures,
                "managed child socket close",
                owned_socket.close,
            )
        if selector is not None:
            attempt_cleanup(
                cleanup_failures,
                "managed selector close",
                selector.close,
            )
            selector = None
        if target_pidfd is not None:
            owned_pidfd = target_pidfd
            target_pidfd = None
            attempt_cleanup(
                cleanup_failures,
                "managed target pidfd close",
                os.close,
                owned_pidfd,
            )
        if process is not None:
            attempt_cleanup(
                cleanup_failures,
                "managed process pipe close",
                close_process_pipes,
                process,
            )
        attempt_cleanup(
            cleanup_failures,
            "managed private descriptor close",
            close_private_descriptors,
            descriptor_authority,
        )
        if acquisition_active:
            acquisition_active = False
            try:
                pending_signum = finish_managed_process_acquisition()
            except BaseException as error:
                cleanup_failures.append(("managed process acquisition finish", error))
        if signal_scope is not None:
            attempt_cleanup(
                cleanup_failures,
                "managed signal-scope release",
                leave_managed_signal_scope,
                signal_scope,
                finalization_mask,
            )
        else:
            attempt_cleanup(
                cleanup_failures,
                "managed signal-mask restoration",
                signal.pthread_sigmask,
                signal.SIG_SETMASK,
                finalization_mask,
            )
        report_cleanup_failures(
            primary_exception,
            "managed-command finalization failed",
            cleanup_failures,
        )
        if pending_signum is not None:
            if primary_exception is None:
                raise ManagedSignal(pending_signum)
            primary_exception.add_note(
                f"managed signal {pending_signum} was deferred until admission cleanup completed"
            )


class StatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("seconds", ctypes.c_int64),
        ("nanoseconds", ctypes.c_uint32),
        ("reserved", ctypes.c_int32),
    ]


class Statx(ctypes.Structure):
    _fields_ = [
        ("mask", ctypes.c_uint32),
        ("block_size", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64),
        ("link_count", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
        ("spare0", ctypes.c_uint16),
        ("inode", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64),
        ("attributes_mask", ctypes.c_uint64),
        ("access_time", StatxTimestamp),
        ("birth_time", StatxTimestamp),
        ("change_time", StatxTimestamp),
        ("modify_time", StatxTimestamp),
        ("rdev_major", ctypes.c_uint32),
        ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32),
        ("dev_minor", ctypes.c_uint32),
        ("mount_id", ctypes.c_uint64),
        ("dio_memory_alignment", ctypes.c_uint32),
        ("dio_offset_alignment", ctypes.c_uint32),
        ("spare3", ctypes.c_uint64 * 12),
    ]


STATX_BASIC_STATS = 0x000007FF
STATX_BTIME = 0x00000800
STATX_MNT_ID = 0x00001000
AT_EMPTY_PATH = 0x1000
AT_NO_AUTOMOUNT = 0x800
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_FSGETXATTR = 0x801C581F
PUBLICATION_ENTRY_LIMIT = 128
PUBLICATION_DEPTH_LIMIT = 16
PUBLICATION_CONTENT_LIMIT = 2 * 1024 * 1024 * 1024
PUBLICATION_XATTR_VALUE_LIMIT = 64 * 1024
PUBLICATION_XATTR_NAME_LIMIT = 64 * 1024
PUBLICATION_XATTR_TOTAL_LIMIT = 16 * 1024 * 1024
PUBLICATION_XATTR_PER_INODE_COUNT_LIMIT = 1024
PUBLICATION_XATTR_TOTAL_COUNT_LIMIT = 65536
PUBLICATION_REPOSITORY_ENTRY_LIMIT = 4096
PUBLICATION_REPOSITORY_BYTE_LIMIT = 1024 * 1024
PUBLICATION_NAMESPACE_LIMIT = 17
PUBLICATION_SERIALIZED_RESULT_LIMIT = 16 * 1024 * 1024
PUBLICATION_OUTPUT_LIMIT = 16 * 1024 * 1024
PUBLICATION_DEADLINE_SECONDS = 120


def descriptor_statx(descriptor):
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.statx
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(Statx),
    ]
    function.restype = ctypes.c_int
    result = Statx()
    requested = STATX_BASIC_STATS | STATX_BTIME | STATX_MNT_ID
    if function(descriptor, b"", AT_EMPTY_PATH | AT_NO_AUTOMOUNT, requested, ctypes.byref(result)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if result.mask & (STATX_BASIC_STATS | STATX_MNT_ID) != STATX_BASIC_STATS | STATX_MNT_ID:
        raise VerificationError("publication statx result omitted required basic or mount identity")
    birth = None
    if result.mask & STATX_BTIME:
        birth = (result.birth_time.seconds, result.birth_time.nanoseconds)
    return (
        result.mask,
        result.block_size,
        result.attributes,
        result.attributes_mask,
        result.link_count,
        result.uid,
        result.gid,
        result.mode,
        result.inode,
        result.size,
        result.blocks,
        (result.change_time.seconds, result.change_time.nanoseconds),
        (result.modify_time.seconds, result.modify_time.nanoseconds),
        birth,
        result.rdev_major,
        result.rdev_minor,
        result.dev_major,
        result.dev_minor,
        result.mount_id,
    )


def publication_ioctl_state(descriptor, request, size, label):
    value = bytearray(size)
    try:
        fcntl.ioctl(descriptor, request, value, True)
    except OSError as exc:
        if exc.errno in (errno.ENOTTY, errno.EOPNOTSUPP):
            return ("unsupported", exc.errno)
        raise VerificationError(f"cannot inspect publication {label}: {exc}") from exc
    return ("supported", value.hex())


def publication_security_state(descriptor, budget):
    metadata = os.fstat(descriptor)
    ordinary = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_blocks,
        metadata.st_rdev,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    names = sorted(os.listxattr(descriptor), key=os.fsencode)
    encoded_names = [os.fsencode(name) for name in names]
    if len(names) > PUBLICATION_XATTR_PER_INODE_COUNT_LIMIT:
        raise VerificationError("canonical publication state exceeds the xattr-count bound")
    if sum(len(name) + 1 for name in encoded_names) > PUBLICATION_XATTR_NAME_LIMIT:
        raise VerificationError("canonical publication state exceeds the xattr-name bound")
    xattrs = []
    by_name = {}
    for name, encoded in zip(names, encoded_names):
        value = os.getxattr(descriptor, name)
        if len(value) > PUBLICATION_XATTR_VALUE_LIMIT:
            raise VerificationError("canonical publication state exceeds the per-xattr byte bound")
        budget["xattr_bytes"] += len(value)
        budget["xattr_count"] += 1
        if budget["xattr_bytes"] > PUBLICATION_XATTR_TOTAL_LIMIT:
            raise VerificationError("canonical publication state exceeds the xattr byte bound")
        if budget["xattr_count"] > PUBLICATION_XATTR_TOTAL_COUNT_LIMIT:
            raise VerificationError("canonical publication state exceeds the shared xattr-count bound")
        record = (encoded.hex(), len(value), hashlib.sha256(value).hexdigest())
        xattrs.append(record)
        by_name[encoded] = record
    explicit = []
    for encoded in (
        b"system.posix_acl_access",
        b"system.posix_acl_default",
        b"security.capability",
    ):
        try:
            value = os.getxattr(descriptor, encoded)
        except OSError as exc:
            if exc.errno == errno.ENODATA:
                explicit.append((encoded.hex(), "absent"))
                continue
            if exc.errno == errno.EOPNOTSUPP:
                explicit.append((encoded.hex(), "unsupported"))
                continue
            raise VerificationError(f"cannot inspect publication security xattr {encoded!r}: {exc}") from exc
        record = (encoded.hex(), len(value), hashlib.sha256(value).hexdigest())
        if by_name.get(encoded) != record:
            raise VerificationError("publication security xattr enumeration is inconsistent")
        explicit.append(record)
    filesystem = os.fstatvfs(descriptor)
    return (
        ordinary,
        descriptor_statx(descriptor),
        filesystem.f_flag,
        publication_ioctl_state(descriptor, FS_IOC_GETFLAGS, 4, "inode flags"),
        publication_ioctl_state(descriptor, FS_IOC_FSGETXATTR, 28, "extended inode flags"),
        tuple(xattrs),
        tuple(explicit),
    )


def publication_directory_inventory(descriptor, budget, repository_root=False):
    inventory_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
    try:
        entry_limit = (
            PUBLICATION_REPOSITORY_ENTRY_LIMIT
            if repository_root
            else max(0, PUBLICATION_ENTRY_LIMIT - budget["entries"])
        )
        names = []
        name_bytes = 0
        with os.scandir(inventory_fd) as entries:
            for entry in entries:
                if len(names) >= entry_limit:
                    if repository_root:
                        raise VerificationError(
                            "canonical publication repository inventory exceeds its entry bound"
                        )
                    raise VerificationError("canonical publication state exceeds the entry bound")
                encoded_size = len(os.fsencode(entry.name)) + 1
                if (
                    repository_root
                    and name_bytes + encoded_size > PUBLICATION_REPOSITORY_BYTE_LIMIT
                ):
                    raise VerificationError(
                        "canonical publication repository inventory exceeds its byte bound"
                    )
                names.append(entry.name)
                name_bytes += encoded_size
    finally:
        os.close(inventory_fd)
    return sorted(names, key=os.fsencode)


def publication_path_snapshot(parent_fd, name, root_device, budget):
    records = []

    def visit(directory_fd, entry_name, relative, depth):
        if depth > PUBLICATION_DEPTH_LIMIT:
            raise VerificationError("canonical publication state exceeds the depth bound")
        if budget["entries"] >= PUBLICATION_ENTRY_LIMIT:
            raise VerificationError("canonical publication state exceeds the entry bound")
        try:
            edge = os.stat(entry_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            records.append((relative, "absent"))
            budget["entries"] += 1
            return
        if edge.st_dev != root_device:
            raise VerificationError("canonical publication state crosses a filesystem boundary")
        if stat.S_ISREG(edge.st_mode):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        elif stat.S_ISDIR(edge.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        else:
            raise VerificationError("canonical publication state contains a link or special entry")
        descriptor = os.open(entry_name, flags, dir_fd=directory_fd)
        try:
            opened = os.fstat(descriptor)
            if filesystem_identity(opened) != filesystem_identity(edge):
                raise VerificationError("canonical publication entry changed during open")
            before = publication_security_state(descriptor, budget)
            budget["entries"] += 1
            if stat.S_ISREG(opened.st_mode):
                if opened.st_size > budget["content_remaining"]:
                    raise VerificationError("canonical publication state exceeds the content byte bound")
                digest = hashlib.sha256()
                offset = 0
                while offset < opened.st_size:
                    chunk = os.pread(descriptor, min(1024 * 1024, opened.st_size - offset), offset)
                    if not chunk:
                        raise VerificationError("canonical publication file ended before its recorded size")
                    digest.update(chunk)
                    offset += len(chunk)
                if os.pread(descriptor, 1, opened.st_size):
                    raise VerificationError("canonical publication file exceeds its recorded size")
                budget["content_remaining"] -= opened.st_size
                after = publication_security_state(descriptor, budget)
                if after != before:
                    raise VerificationError("canonical publication file changed during snapshot")
                records.append((relative, "file", before, digest.hexdigest()))
            else:
                first_inventory = publication_directory_inventory(descriptor, budget)
                records.append((relative, "directory", before, tuple(first_inventory)))
                for child_name in first_inventory:
                    visit(descriptor, child_name, os.path.join(relative, child_name), depth + 1)
                second_inventory = publication_directory_inventory(descriptor, budget)
                after = publication_security_state(descriptor, budget)
                if second_inventory != first_inventory or after != before:
                    raise VerificationError("canonical publication directory changed during snapshot")
            final_edge = os.stat(entry_name, dir_fd=directory_fd, follow_symlinks=False)
            if filesystem_identity(final_edge) != filesystem_identity(opened):
                raise VerificationError("canonical publication parent edge changed during snapshot")
        finally:
            os.close(descriptor)

    visit(parent_fd, name, name, 0)
    return tuple(records)


def publication_snapshot_worker(repo, test_gate_fd=None):
    if test_gate_fd is not None:
        os.read(test_gate_fd, 1)
    descriptor_match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", os.fspath(repo))
    if descriptor_match is None:
        repository_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    else:
        inherited_fd = int(descriptor_match.group(1))
        repository_fd = os.dup(inherited_fd)
        if not stat.S_ISDIR(os.fstat(repository_fd).st_mode):
            os.close(repository_fd)
            raise VerificationError("publication repository descriptor is not a directory")
    try:
        repository_metadata = os.fstat(repository_fd)
        budget = {
            "entries": 0,
            "content_remaining": PUBLICATION_CONTENT_LIMIT,
            "xattr_bytes": 0,
            "xattr_count": 0,
        }
        before = publication_security_state(repository_fd, budget)
        first_inventory = publication_directory_inventory(repository_fd, budget, repository_root=True)
        names = ["dist"]
        for name in first_inventory:
            if name.startswith(".dist-release-"):
                names.append(name)
        names = sorted(set(names), key=os.fsencode)
        if len(names) > PUBLICATION_NAMESPACE_LIMIT:
            raise VerificationError("canonical publication namespace exceeds the path bound")
        snapshot = tuple(
            (
                name,
                publication_path_snapshot(repository_fd, name, repository_metadata.st_dev, budget),
            )
            for name in names
        )
        second_inventory = publication_directory_inventory(repository_fd, budget, repository_root=True)
        after = publication_security_state(repository_fd, budget)
        if second_inventory != first_inventory or after != before:
            raise VerificationError("repository root changed during publication-state snapshot")
        return snapshot
    finally:
        os.close(repository_fd)


def encode_publication_worker_result(message):
    payload = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(payload) <= PUBLICATION_SERIALIZED_RESULT_LIMIT:
        return payload
    fallback = b'{"ok":false,"error":"publication snapshot result exceeds its byte bound"}'
    if len(fallback) > PUBLICATION_SERIALIZED_RESULT_LIMIT:
        raise VerificationError("publication result bound cannot contain its failure result")
    return fallback


def append_publication_worker_output(payload, diagnostics, target, chunk):
    if len(payload) + len(diagnostics) + len(chunk) > PUBLICATION_OUTPUT_LIMIT:
        raise VerificationError("publication snapshot worker output exceeds its byte bound")
    target.extend(chunk)


def run_publication_snapshot_worker(repository_fd, test_gate_fd):
    try:
        state = publication_snapshot_worker(
            f"/proc/self/fd/{repository_fd}", test_gate_fd=test_gate_fd
        )
        message = {"ok": True, "state": state}
    except BaseException as exc:
        message = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    payload = encode_publication_worker_result(message)
    offset = 0
    while offset < len(payload):
        offset += os.write(1, payload[offset:])
    return 0


def acquire_verifier_program(repo):
    repository_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    scripts_fd = None
    source_fd = None
    sealed_fd = None
    try:
        scripts_fd = os.open(
            "scripts",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=repository_fd,
        )
        source_fd = os.open(
            "verify-verifier-workspace.py",
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=scripts_fd,
        )
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > VERIFIER_PROGRAM_LIMIT:
            raise VerificationError("verifier program source is not a bounded regular file")
        content = bytearray()
        while len(content) <= VERIFIER_PROGRAM_LIMIT:
            chunk = os.read(source_fd, min(65536, VERIFIER_PROGRAM_LIMIT + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > VERIFIER_PROGRAM_LIMIT or len(content) != before.st_size:
            raise VerificationError("verifier program source exceeds its byte bound")
        after = os.fstat(source_fd)
        edge = os.stat(
            "verify-verifier-workspace.py",
            dir_fd=scripts_fd,
            follow_symlinks=False,
        )
        if (
            stable_file_metadata(after) != stable_file_metadata(before)
            or filesystem_identity(edge) != filesystem_identity(before)
        ):
            raise VerificationError("verifier program source changed during acquisition")
        source = bytes(content).decode("utf-8")
        sealed_fd = os.memfd_create(
            "rustdesk-verifier-program",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        offset = 0
        while offset < len(content):
            offset += os.write(sealed_fd, content[offset:])
        os.lseek(sealed_fd, 0, os.SEEK_SET)
        fcntl.fcntl(sealed_fd, fcntl.F_ADD_SEALS, VERIFIER_PROGRAM_SEALS)
        if fcntl.fcntl(sealed_fd, fcntl.F_GET_SEALS) != VERIFIER_PROGRAM_SEALS:
            raise VerificationError("verifier program authority is not immutably sealed")
        result_fd = sealed_fd
        sealed_fd = None
        return source, result_fd
    finally:
        failures = []
        for label, descriptor in (
            ("sealed verifier program", sealed_fd),
            ("verifier source", source_fd),
            ("verifier scripts directory", scripts_fd),
            ("verifier repository", repository_fd),
        ):
            if descriptor is not None:
                attempt_cleanup(failures, f"{label} close", os.close, descriptor)
        report_cleanup_failures(
            sys.exc_info()[1],
            "verifier program acquisition cleanup failed",
            failures,
        )


def canonical_publication_state(repo, timeout_seconds=PUBLICATION_DEADLINE_SECONDS, test_gate_fd=None):
    if _VERIFIER_PROGRAM_FD is None:
        raise VerificationError("publication snapshot worker program authority is unavailable")
    descriptor_match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", os.fspath(repo))
    if descriptor_match is None:
        repository_fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    else:
        repository_fd = os.dup(int(descriptor_match.group(1)))
    if not stat.S_ISDIR(os.fstat(repository_fd).st_mode):
        os.close(repository_fd)
        raise VerificationError("publication repository descriptor is not a directory")
    try:
        worker_fd = os.dup(_VERIFIER_PROGRAM_FD)
    except BaseException:
        os.close(repository_fd)
        raise
    try:
        if (
            not stat.S_ISREG(os.fstat(worker_fd).st_mode)
            or fcntl.fcntl(worker_fd, fcntl.F_GET_SEALS) != VERIFIER_PROGRAM_SEALS
        ):
            raise VerificationError("publication snapshot worker program is not immutably sealed")
    except BaseException:
        os.close(worker_fd)
        os.close(repository_fd)
        raise
    command = [
        "/usr/bin/python3",
        "-I",
        "-S",
        f"/proc/self/fd/{worker_fd}",
        "--publication-worker-fd",
        str(repository_fd),
    ]
    inherited = [repository_fd, worker_fd]
    if test_gate_fd is not None:
        command.extend(("--publication-worker-gate-fd", str(test_gate_fd)))
        inherited.append(test_gate_fd)
    process = None
    pidfd = None
    signal_scope = None
    selector = selectors.DefaultSelector()
    payload = bytearray()
    diagnostics = bytearray()
    exited = False
    reaped = False
    timed_out = False
    stdin_fd = None
    deadline = time.monotonic() + timeout_seconds
    try:
        signal_scope = enter_managed_signal_scope()
        activate_managed_signal_scope(signal_scope)
        begin_managed_process_acquisition()
        try:
            stdin_fd = os.open("/dev/null", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            process = spawn_exact_process(
                command,
                "/",
                {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"},
                stdin_fd,
                tuple(inherited),
            )
        finally:
            acquisition_error = sys.exc_info()[1]
            acquisition_failures = []
            if stdin_fd is not None:
                attempt_cleanup(
                    acquisition_failures,
                    "publication worker stdin close",
                    os.close,
                    stdin_fd,
                )
                stdin_fd = None
            pending_signum = None
            try:
                pending_signum = finish_managed_process_acquisition()
            except BaseException as error:
                acquisition_failures.append(("publication worker acquisition finish", error))
            deferred_signal = None
            if pending_signum is not None:
                if acquisition_error is None:
                    deferred_signal = pending_signum
                else:
                    acquisition_error.add_note(
                        f"managed signal {pending_signum} was deferred until publication-worker cleanup"
                    )
            report_cleanup_failures(
                acquisition_error,
                "publication worker acquisition cleanup failed",
                acquisition_failures,
            )
            if deferred_signal is not None:
                raise ManagedSignal(deferred_signal)
        os.close(repository_fd)
        repository_fd = -1
        os.close(worker_fd)
        worker_fd = -1
        if process.stdout is None or process.stderr is None:
            raise VerificationError("publication snapshot worker has no output streams")
        pidfd = os.pidfd_open(process.pid, 0)
        selector.register(process.stdout, selectors.EVENT_READ, "result")
        selector.register(process.stderr, selectors.EVENT_READ, "diagnostic")
        selector.register(pidfd, selectors.EVENT_READ, "pidfd")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                break
            for key, _ in events:
                if key.data == "pidfd":
                    exited = True
                    selector.unregister(pidfd)
                    continue
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = payload if key.data == "result" else diagnostics
                append_publication_worker_output(payload, diagnostics, target, chunk)
        if timed_out:
            process.kill()
            process.wait()
            reaped = True
            exited = True
            raise VerificationError("canonical publication state snapshot exceeded its deadline")
        if not exited:
            status = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT)
            exited = status is not None
        if not exited:
            raise VerificationError("publication snapshot worker status is unavailable")
        process.wait()
        reaped = True
        if process.returncode != 0:
            raise VerificationError(
                "publication snapshot worker exited unsuccessfully: "
                + diagnostics.decode("utf-8", errors="surrogateescape")
            )
        if diagnostics:
            raise VerificationError(
                "publication snapshot worker emitted diagnostics: "
                + diagnostics.decode("utf-8", errors="surrogateescape")
            )
        message = json.loads(payload.decode("ascii"))
        if not isinstance(message, dict) or set(message) not in ({"ok", "state"}, {"ok", "error"}):
            raise VerificationError("publication snapshot worker returned a malformed result")
        if message.get("ok") is not True:
            raise VerificationError(f"publication snapshot worker failed: {message.get('error')}")
        return message["state"]
    finally:
        primary_error = sys.exc_info()[1]
        cleanup_failures = []
        finalization_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        try:
            if process is not None and not reaped:
                terminated = attempt_cleanup(
                    cleanup_failures,
                    "publication worker termination",
                    process.kill,
                )
                if terminated and attempt_cleanup(
                    cleanup_failures,
                    "publication worker reap",
                    process.wait,
                ):
                    reaped = True
                    exited = True
            if process is not None:
                attempt_cleanup(
                    cleanup_failures,
                    "publication worker stream close",
                    close_process_pipes,
                    process,
                )
            attempt_cleanup(
                cleanup_failures,
                "publication worker selector close",
                selector.close,
            )
            if repository_fd >= 0:
                attempt_cleanup(
                    cleanup_failures,
                    "publication repository descriptor close",
                    os.close,
                    repository_fd,
                )
                repository_fd = -1
            if worker_fd >= 0:
                attempt_cleanup(
                    cleanup_failures,
                    "publication program descriptor close",
                    os.close,
                    worker_fd,
                )
                worker_fd = -1
            if pidfd is not None:
                attempt_cleanup(
                    cleanup_failures,
                    "publication worker observation pidfd close",
                    os.close,
                    pidfd,
                )
                pidfd = None
        finally:
            if signal_scope is not None:
                attempt_cleanup(
                    cleanup_failures,
                    "publication worker signal-scope release",
                    leave_managed_signal_scope,
                    signal_scope,
                    finalization_mask,
                )
            else:
                attempt_cleanup(
                    cleanup_failures,
                    "publication worker signal-mask restoration",
                    signal.pthread_sigmask,
                    signal.SIG_SETMASK,
                    finalization_mask,
                )
        report_cleanup_failures(
            primary_error,
            "publication worker finalization failed",
            cleanup_failures,
        )


def expect_publication_rejection(function, diagnostic, label):
    try:
        function()
    except VerificationError as exc:
        if diagnostic not in str(exc):
            raise VerificationError(f"{label} failed for the wrong reason: {exc}") from exc
        return
    raise VerificationError(f"{label} accepted input above its bound")


def exercise_publication_limit(constant, temporary_value, function, diagnostic, label):
    original = globals()[constant]
    globals()[constant] = temporary_value
    try:
        expect_publication_rejection(function, diagnostic, label)
    finally:
        globals()[constant] = original


def exercise_canonical_publication_snapshot(scratch):
    with scratch.directory("publication-state-") as repository:
        destination = repository / "dist"
        destination.mkdir(mode=0o700)
        artifact = destination / "artifact"
        artifact.write_bytes(b"original")
        external = repository / "external"
        external.write_bytes(b"outside-a")
        external_link = destination / "external-link"
        external_link.symlink_to(external)
        try:
            canonical_publication_state(repository)
        except VerificationError:
            pass
        else:
            raise VerificationError("canonical publication snapshot accepted a symlink")
        external_link.unlink()
        before = canonical_publication_state(repository)
        artifact_metadata = artifact.stat()
        artifact.write_bytes(b"mutated!")
        os.utime(artifact, ns=(artifact_metadata.st_atime_ns, artifact_metadata.st_mtime_ns))
        if canonical_publication_state(repository) == before:
            raise VerificationError("canonical publication snapshot omitted same-size content mutation")
        artifact.write_bytes(b"original")
        os.utime(artifact, ns=(artifact_metadata.st_atime_ns, artifact_metadata.st_mtime_ns))
        restored = canonical_publication_state(repository)
        external.write_bytes(b"outside-b")
        if canonical_publication_state(repository) != restored:
            raise VerificationError("canonical publication snapshot included noncanonical repository content")
        os.setxattr(artifact, b"user.rustdesk-verifier", b"original")
        xattr_before = canonical_publication_state(repository)
        os.setxattr(artifact, b"user.rustdesk-verifier", b"mutated!")
        if canonical_publication_state(repository) == xattr_before:
            raise VerificationError("canonical publication snapshot omitted visible xattr mutation")
        artifact_fd = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            def security_state(xattr_bytes=0, xattr_count=0):
                return publication_security_state(
                    artifact_fd,
                    {
                        "xattr_bytes": xattr_bytes,
                        "xattr_count": xattr_count,
                    },
                )

            exercise_publication_limit(
                "PUBLICATION_XATTR_VALUE_LIMIT",
                0,
                security_state,
                "per-xattr byte bound",
                "publication per-xattr behavioral fixture",
            )
            exercise_publication_limit(
                "PUBLICATION_XATTR_NAME_LIMIT",
                0,
                security_state,
                "xattr-name bound",
                "publication xattr-name behavioral fixture",
            )
            exercise_publication_limit(
                "PUBLICATION_XATTR_PER_INODE_COUNT_LIMIT",
                0,
                security_state,
                "xattr-count bound",
                "publication per-inode xattr-count behavioral fixture",
            )
            expect_publication_rejection(
                lambda: security_state(xattr_bytes=PUBLICATION_XATTR_TOTAL_LIMIT),
                "xattr byte bound",
                "publication aggregate-xattr behavioral fixture",
            )
            expect_publication_rejection(
                lambda: security_state(xattr_count=PUBLICATION_XATTR_TOTAL_COUNT_LIMIT),
                "shared xattr-count bound",
                "publication shared-xattr-count behavioral fixture",
            )
        finally:
            os.close(artifact_fd)
        os.removexattr(artifact, b"user.rustdesk-verifier")
        ctime_before = canonical_publication_state(repository)
        original_mode = stat.S_IMODE(artifact.stat().st_mode)
        artifact.chmod(0o600)
        artifact.chmod(original_mode)
        if canonical_publication_state(repository) == ctime_before:
            raise VerificationError("canonical publication snapshot omitted ctime-only mutation")

        repository_fd = os.dup(repository.fd)
        try:
            exercise_publication_limit(
                "PUBLICATION_REPOSITORY_ENTRY_LIMIT",
                0,
                lambda: publication_directory_inventory(repository_fd, {}, repository_root=True),
                "repository inventory exceeds its entry bound",
                "publication repository-entry behavioral fixture",
            )
            exercise_publication_limit(
                "PUBLICATION_REPOSITORY_BYTE_LIMIT",
                0,
                lambda: publication_directory_inventory(repository_fd, {}, repository_root=True),
                "repository inventory exceeds its byte bound",
                "publication repository-byte behavioral fixture",
            )
        finally:
            os.close(repository_fd)
        exercise_publication_limit(
            "PUBLICATION_NAMESPACE_LIMIT",
            0,
            lambda: publication_snapshot_worker(repository),
            "namespace exceeds the path bound",
            "publication namespace behavioral fixture",
        )

        original_result_limit = globals()["PUBLICATION_SERIALIZED_RESULT_LIMIT"]
        globals()["PUBLICATION_SERIALIZED_RESULT_LIMIT"] = 128
        try:
            encoded = encode_publication_worker_result({"ok": True, "state": "x" * 1024})
            if encoded != b'{"ok":false,"error":"publication snapshot result exceeds its byte bound"}':
                raise VerificationError("publication serialized-result behavioral fixture missed its fallback")
        finally:
            globals()["PUBLICATION_SERIALIZED_RESULT_LIMIT"] = original_result_limit
        original_output_limit = globals()["PUBLICATION_OUTPUT_LIMIT"]
        globals()["PUBLICATION_OUTPUT_LIMIT"] = 128
        try:
            expect_publication_rejection(
                lambda: append_publication_worker_output(bytearray(), bytearray(), bytearray(), b"x" * 129),
                "worker output exceeds its byte bound",
                "publication aggregate-output behavioral fixture",
            )
        finally:
            globals()["PUBLICATION_OUTPUT_LIMIT"] = original_output_limit

        oversized = destination / "oversized"
        with oversized.open("wb") as output:
            output.truncate(PUBLICATION_CONTENT_LIMIT + 1)
        expect_publication_rejection(
            lambda: canonical_publication_state(repository),
            "content byte bound",
            "canonical publication snapshot content fixture",
        )
        oversized.unlink()

        bounded_entries = []
        for index in range(PUBLICATION_ENTRY_LIMIT):
            path = destination / f"entry-{index:03d}"
            path.write_bytes(b"")
            bounded_entries.append(path)
        expect_publication_rejection(
            lambda: canonical_publication_state(repository),
            "entry bound",
            "canonical publication snapshot entry fixture",
        )
        for path in bounded_entries:
            path.unlink()

        depth_root = destination / "depth-root"
        depth_root.mkdir()
        depth_cursor = depth_root
        for index in range(PUBLICATION_DEPTH_LIMIT + 1):
            depth_cursor = depth_cursor / f"level-{index:02d}"
            depth_cursor.mkdir()
        try:
            expect_publication_rejection(
                lambda: canonical_publication_state(repository),
                "depth bound",
                "publication depth behavioral fixture",
            )
        finally:
            for path in reversed(list(depth_root.rglob("*"))):
                path.rmdir()
            depth_root.rmdir()

        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        try:
            try:
                canonical_publication_state(repository, timeout_seconds=0.05, test_gate_fd=gate_read)
            except VerificationError as exc:
                if "exceeded its deadline" not in str(exc):
                    raise
            else:
                raise VerificationError("canonical publication snapshot worker ignored its deadline")
        finally:
            os.close(gate_read)
            os.close(gate_write)

        real_spawn = spawn_exact_process
        pre_assignment_workers = []

        def signal_before_publication_spawn_return(*arguments, **keywords):
            worker = real_spawn(*arguments, **keywords)
            command = arguments[0]
            if "--publication-worker-fd" in command:
                pre_assignment_workers.append(worker)
                handle_managed_signal(signal.SIGTERM, None)
            return worker

        gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
        globals()["spawn_exact_process"] = signal_before_publication_spawn_return
        try:
            try:
                canonical_publication_state(repository, timeout_seconds=5, test_gate_fd=gate_read)
            except ManagedSignal as exc:
                if exc.signum != signal.SIGTERM:
                    raise
            else:
                raise VerificationError(
                    "publication snapshot pre-assignment signal fixture did not raise"
                )
        finally:
            globals()["spawn_exact_process"] = real_spawn
            os.close(gate_read)
            os.close(gate_write)
        if len(pre_assignment_workers) != 1:
            raise VerificationError(
                "publication snapshot pre-assignment signal fixture did not capture one worker"
            )
        assert_process_absent(
            pre_assignment_workers[0].pid,
            "publication snapshot pre-assignment signal worker",
        )


def reserved_release_state(repo):
    directory_pattern = re.compile(r"\Arustdesk-release\.[A-Za-z0-9]{10}\Z")
    directories = {}
    with os.scandir("/tmp") as entries:
        for entry in entries:
            if not directory_pattern.match(entry.name):
                continue
            metadata = entry.stat(follow_symlinks=False)
            directories[entry.path] = (metadata.st_dev, metadata.st_ino, metadata.st_mode)
    return directories, canonical_publication_state(repo)


def assert_reserved_release_state_unchanged(before, cwd, execution_error=None):
    after = reserved_release_state(cwd)
    if after != before:
        before_directories, before_publication = before
        after_directories, after_publication = after
        detail = {
            "new_directories": sorted(set(after_directories) - set(before_directories)),
            "missing_directories": sorted(set(before_directories) - set(after_directories)),
            "changed_directories": sorted(
                path
                for path in set(before_directories) & set(after_directories)
                if before_directories[path] != after_directories[path]
            ),
            "canonical_publication_changed": before_publication != after_publication,
        }
        state_error = VerificationError(f"stateful fixture changed reserved release state: {detail}")
        if execution_error is not None:
            raise state_error from execution_error
        raise state_error


def run_stateful_command(
    command,
    cwd,
    env=None,
    timeout_seconds=300,
    cleanup_grace_seconds=120,
    kill_grace_seconds=10,
    inherited_fds=(),
):
    signal_scope = None
    before = None
    result = None
    execution_error = None
    try:
        signal_scope = enter_managed_signal_scope()
        activate_managed_signal_scope(signal_scope)
        before = reserved_release_state(cwd)
        try:
            result = run_managed_command(
                command,
                cwd,
                env,
                timeout_seconds,
                cleanup_grace_seconds,
                kill_grace_seconds,
                inherited_fds=inherited_fds,
            )
        except BaseException as exc:
            execution_error = exc
        assert_reserved_release_state_unchanged(before, cwd, execution_error)
        if execution_error is not None:
            raise execution_error
        if result is None:
            raise VerificationError("stateful command produced no result")
        return result
    except ManagedSignal:
        if before is not None:
            assert_reserved_release_state_unchanged(before, cwd)
        raise
    finally:
        finalization_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        if signal_scope is not None:
            leave_managed_signal_scope(signal_scope, finalization_mask)
        else:
            signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask)


def assert_process_absent(pid, label):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    except PermissionError as exc:
        raise VerificationError(f"{label} process ownership cannot be inspected") from exc
    raise VerificationError(f"{label} process remains after cgroup cleanup: {pid}")


def run_stateful_timeout_fixtures(repo, scratch):
    finalization_events = []

    def injected_finalization_failure(label):
        def fail(*_arguments):
            finalization_events.append(label)
            raise OSError(errno.EIO, label)

        return fail

    finalization_functions = (
        "hard_kill_cgroup",
        "terminate_and_reap_unacquired_launcher",
        "close_cgroup_authority",
        "systemd_unit_properties",
    )
    original_finalization_functions = {
        name: globals()[name] for name in finalization_functions
    }
    original_lexists = os.path.lexists
    expected_finalization_events = [
        "forced termination",
        "launcher reap",
        "authority close",
        "unit collection",
        "pathname absence",
    ]
    try:
        for name, label in zip(
            finalization_functions, expected_finalization_events[:4]
        ):
            globals()[name] = injected_finalization_failure(label)

        def fail_finalization_pathname(_path):
            finalization_events.append(expected_finalization_events[4])
            raise OSError(errno.EIO, expected_finalization_events[4])

        os.path.lexists = fail_finalization_pathname
        try:
            finalize_managed_unit(
                object(),
                {
                    "path": "/injected-managed-finalization",
                    "unit": "injected.service",
                    "invocation": "0" * 32,
                },
                {},
            )
        except VerificationError as exc:
            diagnostic = str(exc)
            if not all(label in diagnostic for label in expected_finalization_events):
                raise VerificationError(
                    "managed finalization accumulator fixture lost a cleanup failure"
                ) from exc
        else:
            raise VerificationError(
                "managed finalization accumulator fixture accepted cleanup failures"
            )
    finally:
        for name, function in original_finalization_functions.items():
            globals()[name] = function
        os.path.lexists = original_lexists
    if finalization_events != expected_finalization_events:
        raise VerificationError(
            "managed finalization accumulator fixture did not exhaust cleanup"
        )

    descriptor_inventory = live_descriptor_inventory()
    descriptors = []
    try:
        for _ in range(4):
            descriptors.append(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise
    authority = dict(zip(("events", "kill", "processes", "directory"), descriptors))
    attempted = []
    real_close = os.close

    def fail_first_cgroup_close(descriptor):
        attempted.append(descriptor)
        if descriptor == descriptors[0]:
            raise OSError(errno.EIO, "injected cgroup descriptor close failure")
        real_close(descriptor)

    os.close = fail_first_cgroup_close
    try:
        try:
            close_cgroup_authority(authority)
        except VerificationError as exc:
            if "cgroup descriptors could not be closed: events" not in str(exc):
                raise
        else:
            raise VerificationError("cgroup descriptor close fixture accepted an injected failure")
    finally:
        os.close = real_close
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                real_close(descriptor)
    if attempted != descriptors or any(authority[name] is not None for name in authority):
        raise VerificationError("cgroup descriptor close fixture did not exhaust its authority")
    if live_descriptor_inventory() != descriptor_inventory:
        raise VerificationError("cgroup descriptor close fixture leaked a descriptor")

    control_environment = systemd_control_environment()
    injected_processes = []
    injected_units = []

    real_spawn = spawn_exact_process
    real_authenticate = authenticate_managed_unit
    admission_launchers = []
    admission_targets = []
    admission_units = []

    def capture_admission_launcher(*arguments, **keywords):
        process = real_spawn(*arguments, **keywords)
        if arguments and arguments[0] and arguments[0][0] == "/usr/bin/systemd-run":
            admission_launchers.append(process.pid)
        return process

    def reject_managed_unit_authentication(*arguments, **keywords):
        authority = real_authenticate(*arguments, **keywords)
        admission_units.append(arguments[0])
        admission_targets.append(arguments[3])
        close_cgroup_authority(authority)
        raise RuntimeError("STATEFUL-UNACQUIRED-CLEANUP")

    globals()["spawn_exact_process"] = capture_admission_launcher
    globals()["authenticate_managed_unit"] = reject_managed_unit_authentication
    try:
        try:
            run_managed_command(
                ["/usr/bin/bash", "--noprofile", "--norc", "-c", "trap '' TERM; sleep 60"],
                repo,
                timeout_seconds=30,
                cleanup_grace_seconds=0.1,
                kill_grace_seconds=2,
            )
        except RuntimeError as exc:
            if str(exc) != "STATEFUL-UNACQUIRED-CLEANUP":
                raise
        else:
            raise VerificationError("unacquired managed-command fixture did not inject its failure")
    finally:
        globals()["authenticate_managed_unit"] = real_authenticate
        globals()["spawn_exact_process"] = real_spawn
    if len(admission_launchers) != 1 or len(admission_targets) != 1 or len(admission_units) != 1:
        raise VerificationError("unacquired managed-command fixture did not capture exact ownership")
    assert_process_absent(admission_launchers[0], "unacquired managed-command launcher")
    assert_process_absent(admission_targets[0], "unacquired managed-command gate")
    if not unit_is_absent(admission_units[0], control_environment):
        raise VerificationError("unacquired managed-command fixture retained its transient unit")

    with scratch.directory("descriptor-reuse-") as descriptor_fixture:
        descriptor_inventory = live_descriptor_inventory()
        original_path = descriptor_fixture / "original"
        replacement_path = descriptor_fixture / "replacement"
        original_path.write_bytes(b"original-authority\n")
        replacement_path.write_bytes(b"replacement-authority\n")
        target_fd = None
        replacement_fd = None

        def replace_caller_descriptor(*arguments, **keywords):
            authority = real_authenticate(*arguments, **keywords)
            os.dup2(replacement_fd, target_fd, inheritable=False)
            return authority

        try:
            target_fd = os.open(original_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            replacement_fd = os.open(
                replacement_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            globals()["authenticate_managed_unit"] = replace_caller_descriptor
            descriptor_result = run_managed_command(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-c",
                    "import os,sys; os.write(1, os.read(int(sys.argv[1]), 64))",
                    str(target_fd),
                ],
                repo,
                timeout_seconds=5,
                cleanup_grace_seconds=1,
                kill_grace_seconds=2,
                inherited_fds=(target_fd,),
            )
        finally:
            globals()["authenticate_managed_unit"] = real_authenticate
            if replacement_fd is not None:
                os.close(replacement_fd)
            if target_fd is not None:
                os.close(target_fd)
        if live_descriptor_inventory() != descriptor_inventory:
            raise VerificationError("managed descriptor handoff leaked a private descriptor")
        if descriptor_result.returncode != 0 or descriptor_result.stdout != "original-authority\n":
            raise VerificationError("managed descriptor handoff followed a reused caller descriptor number")

    entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    try:
        blocked_signal_result = run_managed_command(
            [
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                "trap 'echo STATEFUL-UNBLOCKED-TERM; exit 143' TERM; while :; do sleep 1; done",
            ],
            repo,
            timeout_seconds=0.1,
            cleanup_grace_seconds=5,
            kill_grace_seconds=2,
        )
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, entry_mask)
    if (
        blocked_signal_result.returncode != 124
        or "STATEFUL-UNBLOCKED-TERM" not in blocked_signal_result.stdout
    ):
        raise VerificationError("managed target inherited the verifier's blocked SIGTERM state")

    def inject_after_spawn(frame, event, argument):
        del argument
        if event == "line" and frame.f_code is run_managed_command.__code__:
            process = frame.f_locals.get("process")
            state = _MANAGED_SIGNAL_STATE
            if (
                isinstance(process, ExactChildProcess)
                and state is not None
                and not state["acquiring_process"]
                and frame.f_locals.get("authority") is not None
            ):
                injected_processes.append(process.pid)
                injected_units.append(frame.f_locals["unit"])
                raise RuntimeError("STATEFUL-POST-SPAWN-CLEANUP")
        return inject_after_spawn

    previous_trace = sys.gettrace()
    try:
        sys.settrace(inject_after_spawn)
        run_managed_command(
            ["/usr/bin/bash", "--noprofile", "--norc", "-c", "trap '' TERM; sleep 60"],
            repo,
            timeout_seconds=30,
            cleanup_grace_seconds=0.1,
            kill_grace_seconds=2,
        )
    except RuntimeError as exc:
        if str(exc) != "STATEFUL-POST-SPAWN-CLEANUP":
            raise
    else:
        raise VerificationError("stateful post-spawn exception fixture did not inject its failure")
    finally:
        sys.settrace(previous_trace)
    if len(injected_processes) != 1 or len(injected_units) != 1:
        raise VerificationError("stateful post-spawn exception fixture did not capture one process")
    assert_process_absent(injected_processes[0], "stateful post-spawn exception")
    if not unit_is_absent(injected_units[0], control_environment):
        raise VerificationError("stateful post-spawn exception retained its transient unit")

    pre_assignment_processes = []
    pre_assignment_units = []

    def signal_before_spawn_return(*arguments, **keywords):
        process = real_spawn(*arguments, **keywords)
        if not arguments or not arguments[0] or arguments[0][0] != "/usr/bin/systemd-run":
            return process
        pre_assignment_processes.append(process)
        for argument in arguments[0]:
            if argument.startswith("--unit="):
                pre_assignment_units.append(argument.split("=", 1)[1])
        handle_managed_signal(signal.SIGTERM, None)
        return process

    globals()["spawn_exact_process"] = signal_before_spawn_return
    try:
        try:
            run_managed_command(
                ["/usr/bin/bash", "--noprofile", "--norc", "-c", "trap '' TERM; sleep 60"],
                repo,
                timeout_seconds=30,
                cleanup_grace_seconds=0.1,
                kill_grace_seconds=2,
            )
        except ManagedSignal as exc:
            if exc.signum != signal.SIGTERM:
                raise
        else:
            raise VerificationError("pre-assignment managed signal fixture did not raise its recorded signal")
    finally:
        globals()["spawn_exact_process"] = real_spawn
    if len(pre_assignment_processes) != 1 or len(pre_assignment_units) != 1:
        raise VerificationError("pre-assignment managed signal fixture did not capture one process")
    pre_assignment_process = pre_assignment_processes[0]
    assert_process_absent(pre_assignment_process.pid, "pre-assignment managed signal")
    if not unit_is_absent(pre_assignment_units[0], control_environment):
        raise VerificationError("pre-assignment managed signal retained its transient unit")

    with scratch.directory("stateful-signal-") as fixture_root:
        leader_file = fixture_root / "leader"
        descendant_file = fixture_root / "descendant"
        cleanup_file = fixture_root / "cleanup"
        verifier_pid = os.getpid()
        sender_pid = os.fork()
        if sender_pid == 0:
            try:
                time.sleep(1)
                os.kill(verifier_pid, signal.SIGTERM)
                os._exit(0)
            except BaseException:
                os._exit(1)
        try:
            run_stateful_command(
                [
                    "/usr/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    "trap 'printf cleaned >\"$3\"; kill -TERM \"$child\" 2>/dev/null || true; "
                    "wait \"$child\" 2>/dev/null || true; exit 143' TERM; "
                    "printf '%s' \"$$\" >\"$1\"; setsid sleep 60 & child=$!; "
                    "printf '%s' \"$child\" >\"$2\"; wait \"$child\"",
                    "_",
                    str(leader_file),
                    str(descendant_file),
                    str(cleanup_file),
                ],
                repo,
                timeout_seconds=30,
                cleanup_grace_seconds=5,
                kill_grace_seconds=2,
                inherited_fds=fixture_root.inherited_fds,
            )
        except ManagedSignal as exc:
            if exc.signum != signal.SIGTERM:
                raise
        else:
            raise VerificationError("stateful parent-signal fixture did not raise its signal")
        finally:
            waited_sender, sender_status = os.waitpid(sender_pid, 0)
        if waited_sender != sender_pid or os.waitstatus_to_exitcode(sender_status) != 0:
            raise VerificationError("stateful parent-signal sender failed")
        leader_pid = int(leader_file.read_text(encoding="ascii"))
        descendant_pid = int(descendant_file.read_text(encoding="ascii"))
        if cleanup_file.read_text(encoding="ascii") != "cleaned":
            raise VerificationError("stateful parent-signal fixture skipped graceful target cleanup")
        assert_process_absent(leader_pid, "stateful parent-signal leader")
        assert_process_absent(descendant_pid, "stateful parent-signal descendant")

    graceful = run_stateful_command(
        [
            "/usr/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            "trap 'kill -TERM \"$child\" 2>/dev/null || true; wait \"$child\" 2>/dev/null || true; "
            "echo STATEFUL-GRACEFUL-CLEANUP; exit 143' TERM; "
            "sleep 60 & child=$!; echo STATEFUL-CHILD:$child; wait \"$child\"",
        ],
        repo,
        timeout_seconds=0.1,
        cleanup_grace_seconds=5,
        kill_grace_seconds=2,
    )
    graceful_output = graceful.stdout + graceful.stderr
    match = re.search(r"STATEFUL-CHILD:(\d+)", graceful_output)
    if graceful.returncode != 124 or "STATEFUL-GRACEFUL-CLEANUP" not in graceful_output or match is None:
        raise VerificationError("stateful graceful-timeout fixture did not execute its cleanup trap")
    assert_process_absent(int(match.group(1)), "stateful graceful-timeout descendant")

    resistant = run_stateful_command(
        [
            "/usr/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            "trap '' TERM; /usr/bin/bash --noprofile --norc -c "
            "'trap \"\" TERM; setsid sleep 60' & child=$!; echo STATEFUL-RESISTANT-CHILD:$child; wait \"$child\"",
        ],
        repo,
        timeout_seconds=0.1,
        cleanup_grace_seconds=0.1,
        kill_grace_seconds=2,
    )
    resistant_output = resistant.stdout + resistant.stderr
    match = re.search(r"STATEFUL-RESISTANT-CHILD:(\d+)", resistant_output)
    if resistant.returncode != 124 or match is None:
        raise VerificationError("stateful hard-timeout fixture did not reach its resistant descendant")
    assert_process_absent(int(match.group(1)), "stateful hard-timeout descendant")

    try:
        run_stateful_command(
            [
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                "setsid /usr/bin/bash --noprofile --norc -c 'sleep 60' & "
                "echo STATEFUL-LINGERING-CHILD:$!; exit 0",
            ],
            repo,
            timeout_seconds=5,
            cleanup_grace_seconds=1,
            kill_grace_seconds=2,
        )
    except VerificationError as exc:
        if "cgroup descendants remained" not in str(exc):
            raise
    else:
        raise VerificationError("stateful normal-exit fixture accepted a lingering setsid descendant")

    with scratch.directory("double-fork-") as fixture_root:
        descendant_file = fixture_root / "grandchild"
        program = (
            "import os,time,sys\n"
            "pid=os.fork()\n"
            "if pid: raise SystemExit(0)\n"
            "os.setsid()\n"
            "pid=os.fork()\n"
            "if pid: raise SystemExit(0)\n"
            "open(sys.argv[1],'w',encoding='ascii').write(str(os.getpid()))\n"
            "os.close(0); os.close(1); os.close(2); time.sleep(60)\n"
        )
        try:
            result = run_stateful_command(
                ["/usr/bin/python3", "-I", "-S", "-c", program, str(descendant_file)],
                repo,
                timeout_seconds=5,
                cleanup_grace_seconds=1,
                kill_grace_seconds=2,
                inherited_fds=fixture_root.inherited_fds,
            )
        except VerificationError as exc:
            if "cgroup descendants remained" not in str(exc):
                raise
        else:
            raise VerificationError(
                "stateful double-fork fixture accepted a daemonized descendant: "
                f"{result.returncode}: {(result.stdout + result.stderr)[-2000:]}: "
                f"recorded={descendant_file.exists()}"
            )
        deadline = time.monotonic() + 2
        while not descendant_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not descendant_file.exists():
            raise VerificationError("stateful double-fork fixture did not record its grandchild")
        assert_process_absent(
            int(descendant_file.read_text(encoding="ascii")),
            "stateful double-fork grandchild",
        )


def require_success(result, label, marker):
    output = result.stdout + result.stderr
    if result.returncode != 0 or marker not in output:
        raise VerificationError(f"{label} failed ({result.returncode}): {output[-2000:]}")


def run_transaction_fixtures(repo):
    poison = dict(os.environ)
    poison.update(
        {
            "GIT_CONFIG": "/hostile/git-config",
            "PYTHONPATH": "/hostile/python",
            "DOCKER_HOST": "tcp://hostile.invalid:2376",
            "HARNESS_PREFIX": "hostile",
            "OUT_DIR": "/hostile/out",
        }
    )
    for relative, marker, label in (
        ("scripts/build-release.sh", "build-release self-test: OK", "release transaction fixture"),
        (
            "scripts/build-release.sh",
            "build-release root-owned reset self-test: OK",
            "root-owned reset transaction fixture",
        ),
        (
            "scripts/publish-github-release.sh",
            "publish-github-release self-test: OK",
            "publisher transaction fixture",
        ),
    ):
        path = repo / relative
        mode = "--self-test-reset" if "root-owned reset" in label else "--self-test"
        result = run_stateful_command([str(path), mode], repo, poison)
        require_success(result, label, marker)
        bypass = run_stateful_command(
            ["/usr/bin/bash", "--noprofile", "--norc", str(path), mode],
            repo,
            poison,
        )
        if bypass.returncode == 0 or "forbidden inherited environment variable" not in (bypass.stdout + bypass.stderr):
            raise VerificationError(f"{label} accepted a poisoned environment through an explicit Bash bypass")


def run_target_contract_fixtures(sources, scratch):
    commit = "a" * 40
    image_ids = {
        "debian": "sha256:" + "d" * 64,
        "android": "sha256:" + "a" * 64,
    }
    roles = {"debian": "deb-builder", "android": "android-builder"}
    pin_names = {"debian": "DEB_BUILDER_IMAGE_ID", "android": "ANDROID_BUILDER_IMAGE_ID"}
    with scratch.directory("target-contract-") as root_authority:
        root = root_authority.canonical_path()
        scripts = root / "scripts"
        tools = root / "bin"
        scripts.mkdir(mode=0o700)
        tools.mkdir(mode=0o700)
        for target in ("debian", "android"):
            path = scripts / f"build-{target}.sh"
            path.write_text(sources[target], encoding="utf-8")
            path.chmod(0o700)
        (scripts / "lib.sh").write_text(
            r'''set -euo pipefail
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/.." && pwd)"
ONLINE_DIR="$REPO_ROOT/online"
DEFAULT_ANDROID_KEYSTORE="$REPO_ROOT/private/key.jks"
DEFAULT_ANDROID_KEYSTORE_PASS_FILE="$REPO_ROOT/private/pass"
SHA_PENDING="__PENDING_R_B12__"
die() { printf 'fixture:FATAL: %s\n' "$*" >&2; exit 1; }
log() { :; }
load_pins() {
    SOURCE_DATE_EPOCH_PIN=1700000000
    RUST_VERSION=1.75
    FLUTTER_VERSION=3.24.5
    LLVM_VERSION=15.0.6
    ANDROID_NDK_VERSION=r28c
    ANDROID_BUILD_TOOLS=34.0.0
    ANDROID_MIN_SDK=24
    SHA256_RUST_1_75=1
    SHA256_RUST_STD_ANDROID_1_75=2
    SHA256_FLUTTER_3_24_5=3
    SHA256_LLVM_15_0_6=4
    SHA256_ANDROID_NDK_R28C=5
    SHA256_ANDROID_CMDLINE_TOOLS=6
    SHA256_BASEIMAGE_UBUNTU_1804=sha256:7
    SHA256_BASEIMAGE_UBUNTU_2404=sha256:8
    ANDROID_SIGNING_CERT_SHA256=9
    DEB_BUILDER_IMAGE_ID="sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    ANDROID_BUILDER_IMAGE_ID="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    if [ "${FIXTURE_MISSING_IMAGE_PIN:-0}" = 1 ]; then
        DEB_BUILDER_IMAGE_ID=""
        ANDROID_BUILDER_IMAGE_ID=""
    fi
}
require_cmd() { :; }
assert_repo_state() { :; }
assert_clean_worktree() { :; }
assert_source_date_epoch() { [ "${SOURCE_DATE_EPOCH:-}" = 1700000000 ] || die "bad epoch"; }
require_online_complete() {
    [ "$(cat "$ONLINE_DIR/closure" 2>/dev/null)" = pinned ] || die "canonical online closure mismatch"
}
verify_online_shas() { :; }
require_pinned_builder_image() {
    local role="$1" image_id="$2" expected="" pin=""
    case "$role" in
        deb-builder) expected="$DEB_BUILDER_IMAGE_ID"; pin=DEB_BUILDER_IMAGE_ID ;;
        android-builder) expected="$ANDROID_BUILDER_IMAGE_ID"; pin=ANDROID_BUILDER_IMAGE_ID ;;
        *) die "unexpected builder role: $role" ;;
    esac
    [ -n "$expected" ] || die "pins.env is missing $pin"
    [ "$image_id" = "$expected" ] || die "builder image ID differs from $pin"
    printf '%s|%s\n' "$role" "$image_id" >> "$FIXTURE_LOG"
}
verify_private_online_snapshot() {
    [ "$(cat "$1/online/closure" 2>/dev/null)" = pinned ] || die "private online closure mismatch"
}
create_private_online_snapshot() {
    [ ! -e "$1" ] || die "snapshot destination exists"
    mkdir -m 0700 "$1"
    mkdir -m 0700 "$1/online"
    cp "$ONLINE_DIR/closure" "$1/online/closure"
    chmod 0400 "$1/online/closure"
    chmod 0500 "$1/online"
    verify_private_online_snapshot "$1"
}
''',
            encoding="utf-8",
        )
        (tools / "git").write_text(
            f"#!/usr/bin/env bash\nprintf '%s\\n' '{commit}'\n",
            encoding="utf-8",
        )
        (tools / "git").chmod(0o700)
        (tools / "docker").write_text(
            """#!/usr/bin/python3
import json
import os
import sys
with open(os.environ["FIXTURE_DOCKER_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("FIXTURE_MUTATE_ONLINE") == "1":
    mounts = [value for value in sys.argv[1:] if value.endswith(":/online:ro")]
    if len(mounts) != 1:
        raise SystemExit(18)
    closure = os.path.join(mounts[0][:-len(":/online:ro")], "closure")
    os.chmod(closure, 0o600)
    with open(closure, "w", encoding="ascii") as stream:
        stream.write("consumer mutation\\n")
    os.chmod(closure, 0o400)
raise SystemExit(17)
""",
            encoding="utf-8",
        )
        (tools / "docker").chmod(0o700)

        online = root / "online"
        online.mkdir(mode=0o700)
        (online / "closure").write_text("pinned\n", encoding="ascii")
        snapshot = root / "release-online"
        snapshot.mkdir(mode=0o700)
        snapshot_online = snapshot / "online"
        snapshot_online.mkdir(mode=0o700)
        (snapshot_online / "closure").write_text("pinned\n", encoding="ascii")
        (snapshot_online / "closure").chmod(0o400)
        snapshot_online.chmod(0o500)
        docker_config = root / "docker-config"
        docker_config.mkdir(mode=0o700)
        (docker_config / "config.json").write_text("{}\n", encoding="ascii")
        (docker_config / "config.json").chmod(0o600)
        home = root / "home"
        home.mkdir(mode=0o700)
        apk = root / "app.apk"
        apk.write_bytes(b"fixture apk")
        output = root / "out"
        output.mkdir(mode=0o700)
        helper_log = root / "helper.log"
        docker_log = root / "docker.log"

        def invoke(target, *, release=True, supplied_snapshot=snapshot, extra_env=None):
            root_authority.assert_bound()
            helper_log.write_text("", encoding="ascii")
            docker_log.write_text("", encoding="ascii")
            environment = {
                "HOME": str(home),
                "PATH": f"{tools}:/usr/bin:/bin",
                "LC_ALL": "C",
                "LANG": "C",
                "SOURCE_DATE_EPOCH": "1700000000",
                "DOCKER_HOST": "unix:///var/run/docker.sock",
                "FIXTURE_LOG": str(helper_log),
                "FIXTURE_DOCKER_LOG": str(docker_log),
                "OUT_DIR": str(output),
                "DOUBLE_BUILD": "0",
            }
            if release:
                environment.update(
                    {
                        "RELEASE_SRC_COMMIT": commit,
                        "RELEASE_DOCKER_IMAGE_ID": image_ids[target],
                        "DOCKER_CONFIG": str(docker_config),
                    }
                )
                if supplied_snapshot is not None:
                    environment["RUSTDESK_RELEASE_ONLINE_SNAPSHOT"] = str(supplied_snapshot)
            if extra_env:
                environment.update(extra_env)
            command = ["/usr/bin/bash", str(scripts / f"build-{target}.sh")]
            if target == "android":
                command.extend(("--verify-apk", str(apk)))
            try:
                return run_managed_command(
                    command,
                    root,
                    environment,
                    timeout_seconds=90,
                    cleanup_grace_seconds=5,
                    kill_grace_seconds=2,
                )
            finally:
                root_authority.assert_bound()

        def output_of(result):
            return result.stdout + result.stderr

        for target in ("debian", "android"):
            result = invoke(target)
            if result.returncode == 0:
                raise VerificationError(f"{target} target fixture unexpectedly completed a platform build")
            helper_lines = helper_log.read_text(encoding="ascii").splitlines()
            expected_helper = f"{roles[target]}|{image_ids[target]}"
            if helper_lines != [expected_helper]:
                raise VerificationError(
                    f"{target} did not verify exactly its pinned builder image: {helper_lines}: "
                    f"{output_of(result)[-2000:]}"
                )
            docker_lines = docker_log.read_text(encoding="ascii").splitlines()
            if len(docker_lines) != 1:
                raise VerificationError(f"{target} did not make exactly one fixture Docker invocation")
            docker_arguments = json.loads(docker_lines[0])
            if image_ids[target] not in docker_arguments:
                raise VerificationError(f"{target} Docker invocation did not use the immutable image ID")
            mutable_images = {
                "rustdesk-fork-harness-deb-builder",
                "rustdesk-fork-harness-android-builder",
            }
            if any(argument in mutable_images for argument in docker_arguments):
                raise VerificationError(f"{target} Docker invocation retained a mutable image tag")
            expected_mount = f"{snapshot_online}:/online:ro"
            if expected_mount not in docker_arguments:
                raise VerificationError(f"{target} release child did not mount the supplied private snapshot")

            result = invoke(target, extra_env={"FIXTURE_MUTATE_ONLINE": "1"})
            (snapshot_online / "closure").chmod(0o600)
            (snapshot_online / "closure").write_text("pinned\n", encoding="ascii")
            (snapshot_online / "closure").chmod(0o400)
            if "private online closure mismatch" not in output_of(result):
                raise VerificationError(f"{target} did not verify the snapshot after a consuming Docker run")

            result = invoke(target, supplied_snapshot=None)
            if "release child requires RUSTDESK_RELEASE_ONLINE_SNAPSHOT" not in output_of(result):
                raise VerificationError(f"{target} release child fell back to the canonical online tree")
            if docker_log.read_text(encoding="ascii"):
                raise VerificationError(f"{target} reached Docker without a release snapshot")

            snapshot.chmod(0o755)
            result = invoke(target)
            snapshot.chmod(0o700)
            if "current-UID mode-0700 directory" not in output_of(result):
                raise VerificationError(f"{target} accepted a non-private snapshot parent")

            (docker_config / "config.json").write_text('{"currentContext":"hostile"}\n', encoding="ascii")
            result = invoke(target)
            (docker_config / "config.json").write_text("{}\n", encoding="ascii")
            if "empty canonical configuration" not in output_of(result):
                raise VerificationError(f"{target} accepted mutable Docker configuration bytes")

            (snapshot_online / "closure").chmod(0o600)
            (snapshot_online / "closure").write_text("mutated\n", encoding="ascii")
            (snapshot_online / "closure").chmod(0o400)
            result = invoke(target)
            (snapshot_online / "closure").chmod(0o600)
            (snapshot_online / "closure").write_text("pinned\n", encoding="ascii")
            (snapshot_online / "closure").chmod(0o400)
            if "private online closure mismatch" not in output_of(result):
                raise VerificationError(f"{target} accepted a snapshot with the wrong pinned closure")

            snapshot_link = root / f"{target}-snapshot-link"
            snapshot_link.symlink_to(snapshot, target_is_directory=True)
            result = invoke(target, supplied_snapshot=snapshot_link)
            snapshot_link.unlink()
            if "must be a real directory" not in output_of(result):
                raise VerificationError(f"{target} accepted a symlinked release snapshot")

            result = invoke(target, extra_env={"FIXTURE_MISSING_IMAGE_PIN": "1"})
            expected_missing = f"pins.env is missing {pin_names[target]}"
            if expected_missing not in output_of(result):
                raise VerificationError(f"{target} did not fail precisely for a missing builder image pin")

            result = invoke(target, release=False, extra_env={"ONLINE_DIR": str(online)})
            if "ONLINE_DIR is not an operator override" not in output_of(result):
                raise VerificationError(f"{target} accepted an ambient online path override")

            result = invoke(target, release=False)
            if result.returncode == 0:
                raise VerificationError(f"{target} direct fixture unexpectedly completed a platform build")
            docker_lines = docker_log.read_text(encoding="ascii").splitlines()
            if len(docker_lines) != 1:
                raise VerificationError(f"{target} direct invocation did not reach one Docker consumer")
            docker_arguments = json.loads(docker_lines[0])
            online_mounts = [argument for argument in docker_arguments if argument.endswith(":/online:ro")]
            if len(online_mounts) != 1 or online_mounts[0] == f"{online}:/online:ro":
                raise VerificationError(f"{target} direct invocation consumed the mutable canonical online tree")


def run_fork_version_fixture(version_source, fork_version, changelog, scratch, cargo="1.4.7", expected=True):
    with scratch.directory("version-fixture-") as root:
        (root / "scripts").mkdir()
        (root / "scripts/fork-version.sh").write_text(version_source, encoding="utf-8")
        (root / "Cargo.toml").write_text(
            f'[package]\nname = "fixture"\nversion = "{cargo}"\n', encoding="utf-8"
        )
        (root / "FORK_VERSION").write_text(fork_version, encoding="utf-8")
        (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        result = run_managed_command(
            ["/usr/bin/bash", str(root / "scripts/fork-version.sh")],
            root,
            timeout_seconds=90,
            cleanup_grace_seconds=5,
            kill_grace_seconds=2,
            inherited_fds=root.inherited_fds,
        )
        if (result.returncode == 0) != expected:
            raise VerificationError(
                f"fork-version fixture expected success={expected}, got {result.returncode}: {result.stderr.strip()}"
            )


def run_hostile_fork_version_fixture(scratch):
    with scratch.directory("version-descendant-") as root:
        script = root / "fork-version.sh"
        descendant = root / "descendant"
        script.write_text(
            "#!/usr/bin/bash\n"
            "set -euo pipefail\n"
            "setsid /usr/bin/bash --noprofile --norc -c 'trap \"\" TERM; sleep 60' &\n"
            "printf '%s' \"$!\" > \"$1\"\n",
            encoding="utf-8",
        )
        script.chmod(0o700)
        try:
            run_managed_command(
                [str(script), str(descendant)],
                root,
                timeout_seconds=5,
                cleanup_grace_seconds=1,
                kill_grace_seconds=2,
                inherited_fds=root.inherited_fds,
            )
        except VerificationError as exc:
            if "cgroup descendants remained" not in str(exc):
                raise
        else:
            raise VerificationError("fork-version fixture accepted a daemonized descendant")
        if not descendant.exists():
            raise VerificationError("fork-version descendant fixture did not record its process")
        assert_process_absent(
            int(descendant.read_text(encoding="ascii")),
            "fork-version fixture descendant",
        )


def run_version_fixtures(version_source, scratch):
    valid = (
        "# Changelog\n\n"
        "## 1.4.7-hardened.6 - 2026-07-13\n\n"
        "## 1.4.7-hardened.5 — 2026-07-11\n\n"
        "## 1.4.7-hardened.4 - 2026-07-08\n"
    )
    run_fork_version_fixture(version_source, "1.4.7-hardened.6\n", valid, scratch)
    invalid = (
        ("1.4.7-hardened.6", valid, "1.4.7"),
        ("1.4.7-hardened.6\n", valid.replace("2026-07-13", "2026-02-30"), "1.4.7"),
        ("1.4.7-hardened.6\n", valid.replace("hardened.5 —", "hardened.5 /"), "1.4.7"),
        ("1.4.7-hardened.7\n", valid.replace("hardened.6", "hardened.7"), "1.4.7"),
        ("1.4.7-hardened.6\n", valid + "\n## 1.4.7-hardened.6 - 2026-01-01\n", "1.4.7"),
        ("1.4.7-hardened.6\n", valid.replace("2026-07-11", "2026-07-14"), "1.4.7"),
        ("1.4.7-hardened.06\n", valid, "1.4.7"),
    )
    for fork_version, changelog, cargo in invalid:
        run_fork_version_fixture(version_source, fork_version, changelog, scratch, cargo, expected=False)
    transition = (
        "# Changelog\n\n"
        "## 1.4.8-hardened.1 - 2026-07-14\n\n"
        "## 1.4.7-hardened.6 - 2026-07-13\n"
    )
    run_fork_version_fixture(version_source, "1.4.8-hardened.1\n", transition, scratch, "1.4.8")
    run_fork_version_fixture(
        version_source,
        "1.4.8-hardened.2\n",
        transition.replace("1.4.8-hardened.1", "1.4.8-hardened.2"),
        scratch,
        "1.4.8",
        expected=False,
    )
    run_hostile_fork_version_fixture(scratch)


def expect_workspace_rejection(lines, expected):
    try:
        validate_verify_workspace("\n".join(lines) + "\n")
    except VerificationError as exc:
        if expected not in str(exc):
            raise VerificationError(f"workspace mutation rejected for {exc}, expected {expected}") from exc
        return
    raise VerificationError(f"workspace mutation was accepted: {expected}")


def run_workspace_mutations(lines, positions):
    for label, block in WORKSPACE_BLOCKS:
        start = positions[label]
        for offset, line in enumerate(block):
            if not line:
                continue
            mutated = list(lines)
            del mutated[start + offset]
            expect_workspace_rejection(mutated, label)
    expect_workspace_rejection(lines + ["printf x >/tmp/verify-probe"], "direct public-/tmp redirection")
    expect_workspace_rejection(lines + ["printf x >/tmp/rd_verify_probe.$$"], "predictable public scratch prefix")
    expect_workspace_rejection(
        lines + ["grep -qF 'readonly VERIFY_TMP' scripts/verify.sh"],
        "fixed-string self-inspection",
    )


def mutation_offsets(source, needle):
    offsets = []
    cursor = 0
    while True:
        offset = source.find(needle, cursor)
        if offset < 0:
            return offsets
        offsets.append(offset)
        cursor = offset + len(needle)


def python_mutation_scopes(source, offsets):
    module = ast.parse(source)

    def node_span(node):
        return python_ast_span(source, node)

    excluded = []
    named = []
    for node in module.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        start, end = node_span(node)
        named.append((start, end, node.name))
        if node.name.startswith("validate_") or node.name == "run_source_mutations":
            excluded.append((start, end))
    result = []
    for offset in offsets:
        if any(start <= offset < end for start, end in excluded):
            continue
        owners = [
            (end - start, name)
            for start, end, name in named
            if start <= offset < end
        ]
        scope = min(owners)[1] if owners else "<module>"
        result.append((offset, scope))
    return result


def run_source_mutations(sources):
    mutations = (
        (
            "build",
            "run_child() {\n    assert_release_docker_config\n    /usr/bin/env -i",
            "run_child() {\n    assert_release_docker_config\n    /usr/bin/env",
            "child environment allowlist",
        ),
        ("build", 'create_snapshot B "$SOURCE_B"', 'true # snapshot B removed', "snapshot B creation"),
        (
            "build",
            'git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source"',
            'git_closed clone --quiet --no-checkout --reject-shallow "$REPO_ROOT" "$source"',
            "independent complete-history snapshot clone",
        ),
        (
            "build",
            'git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source"',
            'git_closed worktree add --quiet --detach "$source" "$PINNED_HEAD"',
            "release build retains production Git worktree add authority",
        ),
        (
            "build",
            'git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$source"',
            'git_closed clone --quiet --no-hardlinks --no-checkout "$REPO_ROOT" "$source"',
            "independent complete-history snapshot clone",
        ),
        (
            "build",
            'git_closed clone --quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$fixture_repo"',
            'git_closed clone --quiet --no-hardlinks --no-checkout "$REPO_ROOT" "$fixture_repo"',
            "reset fixture complete-history Git clone",
        ),
        (
            "build",
            'git_closed -C "$source" checkout --quiet --detach "$PINNED_HEAD"',
            'git_closed -C "$source" checkout --quiet master',
            "detached pinned-commit snapshot checkout",
        ),
        (
            "build",
            'assert_git_object_authority "$source"',
            'true # snapshot object substitution proof removed',
            "snapshot object-authority rejection",
        ),
        (
            "build",
            '[ "$(git_closed -C "$repository" rev-parse --is-shallow-repository 2>/dev/null)" = false ]',
            'true # shallow Git authority proof removed',
            "Git shallow-state query",
        ),
        (
            "build",
            '"$expected:$(id -u):$(id -g):700" ] \\\n        || die "$phase: snapshot root identity/owner/mode differs after normalization"',
            '"$expected:$(id -u):$(id -g):711" ] \\\n        || die "$phase: snapshot root identity/owner/mode differs after normalization"',
            "snapshot root metadata proof",
        ),
        (
            "build",
            'run_private_tree_closure_from_descriptor --inode-root "$source"',
            'true # snapshot inode-link closure removed',
            "snapshot inode-link closure",
        ),
        (
            "build",
            'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
            'true # online snapshot removed',
            "exactly one private online snapshot",
        ),
        (
            "build",
            'assert_release_online_snapshot "before final dist installation"',
            'true # final online proof removed',
            "pre-publication online snapshot proof",
        ),
        (
            "build",
            "require_cmd cmp git docker python3 sha256sum stat readlink install find date flock /usr/bin/grep",
            "require_cmd cmp git docker python3 sha256sum stat readlink install find date /usr/bin/grep",
            "release host-tool preflight",
        ),
        (
            "build",
            'run_child /usr/bin/bash --noprofile --norc "$REPO_ROOT/scripts/verify-release.sh" --preflight',
            "true # release source-gate preflight removed",
            "release source-gate preflight",
        ),
        (
            "build",
            'normalize_snapshot_access "$source" "$label"',
            'true # snapshot normalization removed',
            "snapshot-scoped ownership reset",
        ),
        (
            "build",
            'normalize_snapshot_access "$source" "$label"',
            'normalize_snapshot_access "$WORKSPACE" "$label"',
            "snapshot-scoped ownership reset",
        ),
        (
            "build",
            "docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n            --cap-drop=ALL --cap-add=DAC_READ_SEARCH",
            "docker_local run --interactive --rm --pull=never --network=bridge --read-only --user 0:0 \\\n            --cap-drop=ALL --cap-add=DAC_READ_SEARCH",
            "descriptor-bound private-tree normalizer",
        ),
        (
            "build",
            "--cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=CHOWN \\",
            "--cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=CHOWN --cap-add=FOWNER \\",
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            "--cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=CHOWN \\",
            "--cap-drop=ALL --cap-add=CHOWN \\",
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            "            --ulimit nofile=524544:524544 \\",
            "            --ulimit nofile=1024:1024 \\",
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            '            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled"',
            '            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled,readonly"',
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            '            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled"',
            '            --mount "type=bind,src=$path,dst=/cleanup"',
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            '"$DEBIAN_IMAGE_ID" /usr/bin/python3 -I -S -c "$PRIVATE_TREE_CLOSURE_EXECUTOR" \\\n            "$PRIVATE_TREE_CLOSURE_HASH" \\\n            --normalize-root /cleanup',
            '"$DEBIAN_IMAGE_ID" /bin/sh -ceu \'/usr/bin/find /cleanup\' -- \\\n            --normalize-root /cleanup',
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            '--normalize-root /cleanup --expected-identity "$expected_identity"',
            '--normalize-root /cleanup',
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            '            --owner "$uid" --group "$gid" < "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"',
            '            --owner 0 --group 0 < "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"',
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            "docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n"
            "            --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=CHOWN \\",
            "docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n"
            "            --cap-drop=ALL --cap-add=DAC_READ_SEARCH \\\n"
            "            --security-opt no-new-privileges \\\n"
            '            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled,readonly" \\\n'
            '            "$DEBIAN_IMAGE_ID" /usr/bin/python3 -I -S -c "$PRIVATE_TREE_CLOSURE_EXECUTOR" "$PRIVATE_TREE_CLOSURE_HASH" --inode-root /cleanup\n'
            "        docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n"
            "            --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=CHOWN \\",
            "single descriptor-bound normalizer container",
        ),
        (
            "build",
            'offline_remove_exact_tree_contents "$WORKSPACE" "$WORKSPACE_ID" \\\n                    "release workspace" || cleanup_failed=1',
            'true # descriptor-bound terminal removal removed',
            "descriptor-bound terminal workspace cleanup ordering",
        ),
        (
            "build",
            'offline_remove_exact_tree_contents "$WORKSPACE" "$WORKSPACE_ID" \\\n                    "release workspace" || cleanup_failed=1',
            'offline_normalize_exact_tree "$WORKSPACE" "$WORKSPACE_ID" \\\n                "release workspace" || cleanup_failed=1',
            "descriptor-bound terminal workspace cleanup ordering",
        ),
        (
            "build",
            'verify_private_tree_cleanup_preflight \\\n        || die "release preflight cannot establish the complete terminal cleanup authority"\n    create_release_online_snapshot',
            'create_release_online_snapshot # capacity preflight removed',
            "release preflight ordering",
        ),
        (
            "build",
            '--check-exact-descriptor-budget',
            '--check-descriptor-budget',
            "container exact retained-authority capacity proof",
        ),
        (
            "build",
            'exec {PRIVATE_TREE_CLOSURE_FD}< "$PRIVATE_TREE_CLOSURE_PROBE"',
            'PRIVATE_TREE_CLOSURE_FD=0 # helper execution authority removed',
            "open helper execution authority",
        ),
        (
            "build",
            '[ "$observed_hash" = "$PRIVATE_TREE_CLOSURE_HASH" ]',
            'true # helper committed-content equality removed',
            "helper committed-content equality",
        ),
        (
            "build",
            '--remove-tree-contents /cleanup --expected-identity "$expected_identity" \\\n        --owner "$uid" --group "$gid" < "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"',
            '--remove-tree-contents /cleanup --expected-identity "$expected_identity" \\\n        --owner "$uid" --group "$gid" < "$PRIVATE_TREE_CLOSURE_PROBE"',
            "private-tree terminal remover command is not the exact authority allowlist",
        ),
        (
            "build",
            '--normalize-root /cleanup --expected-identity "$expected_identity" \\\n            --owner "$uid" --group "$gid" < "/proc/self/fd/$PRIVATE_TREE_CLOSURE_FD"',
            '--normalize-root /cleanup --expected-identity "$expected_identity" \\\n            --owner "$uid" --group "$gid" < "$PRIVATE_TREE_CLOSURE_PROBE"',
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            'sys.stdin.buffer.read(1048577)',
            'sys.stdin.buffer.read()',
            "bounded terminal-removal helper input",
        ),
        (
            "build",
            'docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n        --cap-drop=ALL --cap-add=DAC_OVERRIDE --cap-add=FOWNER \\',
            'docker_local run --interactive --rm --pull=never --network=none --read-only --user 0:0 \\\n        --cap-drop=ALL --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=CHOWN \\',
            "private-tree terminal remover command is not the exact authority allowlist",
        ),
        (
            "build",
            '--remove-tree-contents /cleanup --expected-identity "$expected_identity"',
            '--inode-root /cleanup',
            "private-tree terminal remover command is not the exact authority allowlist",
        ),
        (
            "build",
            'close_private_tree_closure_execution || cleanup_failed=1',
            'true # helper execution authority close removed',
            "descriptor-bound terminal workspace cleanup ordering",
        ),
        (
            "build",
            '[ -z "$PRIVATE_TREE_CLOSURE_FD" ] || return 1',
            '[ -n "$PRIVATE_TREE_CLOSURE_FD" ] && return 0',
            "duplicate helper-authority rejection",
        ),
        (
            "build",
            '[ "$path_state" = "$(stat -c \'%d:%i\' -- "$PRIVATE_TREE_CLOSURE_PROBE"):$(id -u):$(id -g):500:1:regular file" ]',
            'true # helper pathname metadata proof removed',
            "helper pathname metadata proof",
        ),
        (
            "build",
            'hashlib.sha256(source).hexdigest() == expected or sys.exit(126)',
            'True # helper digest proof removed',
            "in-memory helper digest proof",
        ),
        (
            "build",
            'exec {PRIVATE_TREE_CLOSURE_FD}<&- || return 1',
            'true # helper descriptor close removed',
            "helper descriptor close",
        ),
        (
            "build",
            'exec {PRIVATE_TREE_CLOSURE_FD}<&- || return 1\n    PRIVATE_TREE_CLOSURE_FD=""',
            'exec {PRIVATE_TREE_CLOSURE_FD}<&- || return 1\n    true # helper descriptor retirement removed',
            "helper descriptor retirement",
        ),
        (
            "build",
            '--remove-empty-private-root "$WORKSPACE"',
            '--remove-private-root "$WORKSPACE"',
            "descriptor-bound terminal workspace cleanup ordering",
        ),
        (
            "build",
            'verify_private_tree_removal_capability || status=1',
            'true # terminal-removal capability proof removed',
            "complete terminal-cleanup preflight ordering",
        ),
        (
            "build",
            '    acquire_private_tree_closure_execution \\\n        || die "cannot acquire the committed private-tree helper authority"',
            '    true # workspace helper descriptor acquisition removed',
            "private release-helper installation",
        ),
        (
            "build",
            'DEBIAN_IMAGE_ID="${DEB_BUILDER_IMAGE_ID:-}"\n    create_workspace',
            'create_workspace # cleanup image initialization removed',
            "production cleanup image initialization",
        ),
        (
            "build",
            "production cleanup lacks the pinned terminal-removal image; retained path",
            "production cleanup will use recursive host fallback",
            "missing production cleanup image rejection",
        ),
        (
            "build",
            '    verify_private_tree_cleanup_preflight \\\n        || die "reset self-test cannot establish the complete terminal cleanup authority"',
            '    true # reset terminal-cleanup preflight removed',
            "reset fixture complete terminal-cleanup preflight",
        ),
        (
            "build",
            'chmod 0000 /capability/locked',
            'chmod 0700 /capability/locked',
            "capability fixture inaccessible root-owned directory",
        ),
        (
            "build",
            'docker_local run --rm --pull=never --network=none --read-only --user 0:0 \\\n        --cap-drop=ALL --cap-add=DAC_OVERRIDE --cap-add=FOWNER \\',
            'docker_local run --rm --pull=never --network=none --read-only --user 0:0 \\\n        --cap-drop=ALL --cap-add=DAC_READ_SEARCH --cap-add=DAC_OVERRIDE --cap-add=FOWNER \\',
            "capability fixture exact capability set",
        ),
        (
            "build",
            'trap cleanup_release_workspace EXIT\n    trap \'exit 129\' HUP',
            'true # workspace cleanup trap delayed\n    trap \'exit 129\' HUP',
            "workspace trap installation",
        ),
        (
            "build",
            '--mount "type=bind,src=$SOURCE_A,dst=/fixture,bind-recursive=disabled"',
            '--mount "type=bind,src=$SOURCE_A,dst=/fixture"',
            "reset fixture recursive-bind exclusion",
        ),
        (
            "build",
            'elif [ ! -e "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ]; then',
            'elif false; then',
            "missing workspace detection",
        ),
        (
            "build",
            'if [ "$SELF_TEST" -eq 0 ]; then',
            'if [ "$SELF_TEST" -eq 0 ] && [ "$SELF_TEST_RESET" -eq 0 ]; then',
            "reset fixture pinned closure-probe provenance",
        ),
        (
            "build",
            "trap - EXIT\n    trap '' HUP INT TERM",
            "trap - EXIT\n    trap - HUP INT TERM",
            "cleanup signal exclusion",
        ),
        (
            "build",
            '[ "$status" -ne 0 ] || status=1',
            "status=1 # original failure discarded",
            "cleanup original-status preservation",
        ),
        (
            "build",
            'reset_snapshot_build_state "$source" "$label before verification"',
            'true # pre-verification reset removed',
            "verification reset envelope",
        ),
        (
            "build",
            'reset_snapshot_build_state "$source" "$label after verification"',
            'assert_snapshot_exact "$source" "$label after verification"',
            "verification reset envelope",
        ),
        (
            "build",
            'reset_snapshot_build_state "$source" "$label after $target"',
            'assert_snapshot_exact "$source" "$label after $target"',
            "post-target reset ordering",
        ),
        (
            "build",
            '{ [ ! -e "$output" ] && [ ! -L "$output" ]; } \\\n'
            '        || die "$label: $target output path must be absent before target publication"',
            'mkdir -p "$output" # target publication path precreated',
            "release orchestrator precreates a target publication path",
        ),
        (
            "build",
            'windows_state="$(dirname "$source")/windows-state"',
            'windows_state="$output/windows-state"',
            "absent target publication and output-disjoint Windows state",
        ),
        (
            "build",
            "        printf '[ ! -e \"$OUT_DIR\" ] && [ ! -L \"$OUT_DIR\" ]\\n'",
            "        printf 'true # target output absence proof removed\\n'",
            "fixture target-output absence proof",
        ),
        (
            "build",
            "            printf 'case \"$state_path/\" in \"$output_path/\"*) exit 1 ;; esac\\n'",
            "            printf 'true # Windows state descendant rejection removed\\n'",
            "fixture Windows-state descendant rejection",
        ),
        (
            "build",
            "            printf 'case \"$output_path/\" in \"$state_path/\"*) exit 1 ;; esac\\n'",
            "            printf 'true # Windows state ancestor rejection removed\\n'",
            "fixture Windows-state ancestor rejection",
        ),
        (
            "build",
            "            printf '[ ! -e \"$fixture_output\" ] && [ ! -L \"$fixture_output\" ]\\n'",
            "            printf 'true # post-state output absence proof removed\\n'",
            "fixture post-state Windows-output absence proof",
        ),
        (
            "build",
            "            printf 'mv -T --no-clobber -- \"$OUT_DIR\" \"$fixture_output\"\\n'",
            "            printf 'mv -T -- \"$OUT_DIR\" \"$fixture_output\"\\n'",
            "fixture atomic Windows publication",
        ),
        (
            "build",
            'ignored="$(git_closed -C "$source" clean -nffdx 2>/dev/null)" \\\n'
            '        || die "$label: cannot prove generated-state removal"',
            'ignored="" # generated-state proof removed',
            "generated-state reset ordering",
        ),
        (
            "build",
            '            --mount "type=bind,src=$path,dst=/cleanup,bind-recursive=disabled"',
            '            --mount "type=bind,src=$WORKSPACE,dst=/cleanup,bind-recursive=disabled"',
            "private-tree normalizer command is not the exact authority allowlist",
        ),
        (
            "build",
            'offline_normalize_exact_tree "$source" "$expected" "$phase snapshot"',
            'offline_normalize_exact_tree "$WORKSPACE" "$expected" "$phase snapshot"',
            "snapshot normalizer exact-tree call",
        ),
        (
            "build",
            '[ "$observed" = "$expected_identity" ] \\\n'
            '        || { warn "$role identity changed: $path"; return 1; }',
            'true # pre-normalization identity proof removed',
            "normalizer identity stages",
        ),
        (
            "build",
            'if ! (verify_release_builder_image deb-builder "$DEBIAN_IMAGE_ID"); then\n'
            '        warn "$role normalization image failed provenance verification"',
            'if false; then\n'
            '        warn "$role normalization image failed provenance verification"',
            "normalizer live image provenance",
        ),
        (
            "build",
            'if git_closed -C "$SOURCE_A" clean -ffdx >/dev/null 2>"$WORKSPACE/negative-clean.log"; then',
            'if false && git_closed -C "$SOURCE_A" clean -ffdx >/dev/null 2>"$WORKSPACE/negative-clean.log"; then',
            "reset fixture live negative control",
        ),
        (
            "build",
            'metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0',
            'False',
            "reset fixture live hostile-mode predicate",
        ),
        (
            "build",
            'if [ "$SELF_TEST_RESET" -eq 1 ]; then\n        run_reset_self_test',
            'if [ "$SELF_TEST_RESET" -eq 1 ]; then\n        return 0 # reset fixture bypassed',
            "reset fixture main dispatch",
        ),
        (
            "faillo",
            'scripts/build-release.sh --self-test-reset',
            '/bin/true',
            "root-owned reset exact command",
        ),
        (
            "closure",
            "for expected, count in linked.values():\n        if count != expected:",
            "for expected, count in linked.values():\n        if False:",
            "external hardlink rejection",
        ),
        (
            "closure",
            "    require_retained_descriptor_budget()\n    require_protected_hardlinks()",
            "    require_protected_hardlinks() # descriptor budget removed",
            "normalization authority dispatch",
        ),
        (
            "closure",
            "RETAINED_DESCRIPTOR_RESERVE = 256",
            "RETAINED_DESCRIPTOR_RESERVE = 0",
            "retained-authority descriptor reserve",
        ),
        (
            "closure",
            "TREE_ENTRY_LIMIT = 524288",
            "TREE_ENTRY_LIMIT = 131072",
            "retained-authority exact entry bound",
        ),
        (
            "closure",
            "MAX_DIRECTORY_DEPTH = 128",
            "MAX_DIRECTORY_DEPTH = 1024",
            "retained-authority directory-depth bound",
        ),
        (
            "closure",
            "if len(live_descriptor_inventory()) > MAX_PREEXISTING_DESCRIPTORS:",
            "if False: # pre-existing descriptor rejection removed",
            "pre-existing descriptor rejection",
        ),
        (
            "closure",
            "if depth >= MAX_DIRECTORY_DEPTH:",
            "if False: # directory-depth rejection removed",
            "directory-depth enforcement",
        ),
        (
            "closure",
            'raise ClosureError("tree contains a special filesystem object")',
            'pass # special filesystem object accepted',
            "special-object rejection",
        ),
        (
            "closure",
            'if observed_soft != RETAINED_DESCRIPTOR_LIMIT:\n        raise ClosureError("retained-authority descriptor budget differs after establishment")',
            'if observed_soft < RETAINED_DESCRIPTOR_LIMIT:\n        raise ClosureError("retained-authority descriptor budget differs after establishment")',
            "retained-authority exact soft-limit reproof",
        ),
        (
            "closure",
            "if exact_hard_limit and observed_hard != RETAINED_DESCRIPTOR_LIMIT:",
            "if False: # exact hard-limit reproof removed",
            "retained-authority exact hard-limit reproof",
        ),
        (
            "closure",
            "                exercise_authority_bounds(scratch)",
            "                pass # retained-authority bound fixture removed",
            "retained-authority bound fixture dispatch",
        ),
        (
            "closure",
            "                scratch.remove_tree_contents(expected)",
            "                scratch.assert_bound() # terminal removal removed",
            "terminal tree-contents removal dispatch",
        ),
        (
            "closure",
            "                scratch.remove_empty_root((int(match.group(1)), int(match.group(2))))",
            "                scratch.remove_root((int(match.group(1)), int(match.group(2))))",
            "terminal empty-root identity dispatch",
        ),
        (
            "closure",
            "        if not directory_is_empty(self.fd):\n            raise ClosureError(\"empty private-root removal found retained contents\")",
            "        if False:\n            raise ClosureError(\"empty private-root removal found retained contents\")",
            "terminal empty-root exact removal",
        ),
        (
            "closure",
            '                    "uid": root.st_uid,',
            '                    "uid": 0,',
            "normalization root owner acquisition",
        ),
        (
            "closure",
            '                            "gid": metadata.st_gid,',
            '                            "gid": 0,',
            "normalization child group acquisition",
        ),
        (
            "closure",
            "        self.assert_bound(owner, group)",
            "        self.assert_bound() # normalized metadata reproof removed",
            "retained-authority normalization ordering",
        ),
        (
            "closure",
            '            print("verify-private-tree-closure: DETAIL: {}".format(note), file=sys.stderr)',
            "            pass # concrete close-failure detail removed",
            "concrete cleanup-error diagnostics",
        ),
        (
            "closure",
            "        require_retained_descriptor_budget()\n        linked = {}",
            "        linked = {} # retained inode descriptor budget removed",
            "retained inode-closure descriptor budget",
        ),
        (
            "closure",
            "    require_protected_hardlinks()\n    authority = TreeNormalizationAuthority(path, expected_identity)",
            "    authority = TreeNormalizationAuthority(path, expected_identity) # hardlink prerequisite removed",
            "normalization authority dispatch",
        ),
        (
            "closure",
            "        authority.normalize(owner, group)",
            "        authority.assert_bound() # normalization mutation removed",
            "normalization authority dispatch",
        ),
        (
            "closure",
            '                if authority["internal"] != authority["nlink"]:',
            "                if False: # initial external-hardlink rejection removed",
            "initial external-hardlink rejection",
        ),
        (
            "closure",
            "            if current.st_uid != owner or current.st_gid != group:",
            "            if False: # normalized inode ownership postcondition removed",
            "normalized inode ownership postcondition",
        ),
        (
            "closure",
            "    for descriptor in descriptors:",
            "    for descriptor in list(descriptors)[:1]:",
            "complete descriptor close iteration",
        ),
        (
            "closure",
            "            primary.add_note(note)",
            "            pass # cleanup failures discarded",
            "primary cleanup-error annotation",
        ),
        (
            "build",
            'reset_snapshot_build_state "$SOURCE_A" "root-owned reset self-test"',
            'git_closed -C "$SOURCE_A" clean -ffdx',
            "reset fixture production-call proof",
        ),
        (
            "build",
            'install -m 0500 "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"',
            'cp "$PRIVATE_TREE_CLOSURE_SOURCE" "$PRIVATE_TREE_CLOSURE_PROBE"',
            "private closure-probe installation",
        ),
        (
            "build",
            'flock -n "$PUBLICATION_LOCK_FD"',
            "true # publication lock removed",
            "exclusive publication lock",
        ),
        (
            "build",
            'RELEASE_SUCCESS_MESSAGE="RELEASE OK:',
            'log "RELEASE OK:',
            "a build-release success marker bypasses final cleanup",
        ),
        (
            "verify",
            'VERIFY_SUCCESS_MESSAGE="VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
            'echo "VERIFY: all required source, behavior, compile, policy, inventory, and excision gates green"',
            "deferred verify completion marker",
        ),
        (
            "verify",
            'native_watch_log=$(mktemp "$VERIFY_TMP/native-watch.XXXXXXXXXX")',
            'native_watch_log=$(mktemp)',
            "native watch log workspace ownership",
        ),
        (
            "verify",
            'echo "verify workspace missing self-test: REACHED" >&2',
            'true # verify missing-workspace reached marker removed',
            "verify missing-workspace reached marker",
        ),
        (
            "build",
            "printf 'build-release cleanup-missing self-test: REACHED\\n' >&2",
            'true # release missing-workspace reached marker removed',
            "release missing-workspace reached marker",
        ),
        (
            "faillo",
            '[ "$observed" = "$probe_id" ] || cleanup_failed=1',
            'true # dirty-probe identity verification removed',
            "dirty-probe identity verification",
        ),
        (
            "faillo",
            'ONLINE_DIR="$fixture" bash -c',
            'ONLINE_DIR="$REPO_ROOT/online" bash -c',
            "fixture-local online directory",
        ),
        (
            "faillo",
            '--remove-private-root "$fixture" --expected-identity "$fixture_id"',
            '--remove-private-root "$fixture"',
            "wrong-SHA descriptor-bound cleanup",
        ),
        (
            "faillo",
            'run_script_die "verify_online_shas wrong SHA" "SHA-256 mismatch for " run_wrong_online_sha_probe',
            'run_die "verify_online_shas wrong SHA" "SHA-256 mismatch for " \'verify_online_shas missing 0\'',
            "independent wrong-SHA dispatch",
        ),
        (
            "faillo",
            '--quiet --no-hardlinks --no-checkout --reject-shallow "$REPO_ROOT" "$fixture_repo"',
            '--quiet --no-checkout --reject-shallow "$REPO_ROOT" "$fixture_repo"',
            "production fixture independent complete clone",
        ),
        (
            "faillo",
            'checkout --quiet -B master "$EXPECTED_SOURCE_COMMIT"',
            'checkout --quiet --detach "$EXPECTED_SOURCE_COMMIT"',
            "production fixture attached exact master",
        ),
        (
            "faillo",
            'symbolic-ref --quiet --short HEAD',
            'rev-parse --abbrev-ref HEAD',
            "production fixture attached-branch proof",
        ),
        (
            "faillo",
            'status --porcelain=v1 --untracked-files=all',
            'status --porcelain=v1 --untracked-files=no',
            "production fixture clean baseline proof",
        ),
        (
            "faillo",
            '--remove-private-root "$fixture_root" --expected-identity "$fixture_id"',
            '--inode-root "$fixture_root"',
            "production fixture descriptor-bound cleanup",
        ),
        (
            "faillo",
            'DIRTY_PROBE_PARENT="$fixture_repo" run_with_dirty_probe doctor',
            'DIRTY_PROBE_PARENT="$REPO_ROOT/scripts" run_with_dirty_probe doctor',
            "production fixture sole dirty mutation",
        ),
        (
            "faillo",
            "  cleanup_production_fixture() {\n    status=$?\n    local cleanup_failed=0",
            "  cleanup_production_fixture() {\n    status=0 # original production-fixture status discarded\n    local cleanup_failed=0",
            "production fixture original-status capture",
        ),
        (
            "faillo",
            "      printf 'BUILD-FAILLO: PRODUCTION-FIXTURE-CLEANUP-FAILURE: %s\\n' \"$fixture_root\" >&2\n      status=125\n    fi\n    exit \"$status\"",
            "      printf 'BUILD-FAILLO: PRODUCTION-FIXTURE-CLEANUP-FAILURE: %s\\n' \"$fixture_root\" >&2\n      status=125\n    fi\n    exit 0 # production-fixture status discarded",
            "production fixture final-status propagation",
        ),
        (
            "faillo",
            '  run_production_dirty_probe',
            '  run_with_dirty_probe doctor "${CLEAN_SCRIPT_ENV[@]}" scripts/build-release.sh --doctor',
            "production release-source fixture dispatch",
        ),
        (
            "faillo",
            'rm -f -- "$probe" || cleanup_failed=1',
            'true # dirty-probe removal removed',
            "dirty-probe exact removal",
        ),
        (
            "faillo",
            '[ ! -e "$probe" ] && [ ! -L "$probe" ] || cleanup_failed=1',
            'true # dirty-probe absence proof removed',
            "dirty-probe absence postcondition",
        ),
        (
            "faillo",
            "&& ! printf '%s' \"$out\" | grep -qF 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE:'",
            "&& /bin/false # dirty-probe cleanup rejection removed",
            "dirty-probe cleanup rejection",
        ),
        (
            "faillo",
            "printf 'BUILD-FAILLO: DIRTY-PROBE-CLEANUP-FAILURE: %s\\n' \"$probe\" >&2",
            "true # dirty-probe cleanup marker emission removed",
            "dirty-probe cleanup failure marker emission",
        ),
        (
            "faillo",
            '[ "$rc" -ne 125 ]',
            'true # dirty-probe cleanup status accepted',
            "dirty-probe cleanup status rejection",
        ),
        (
            "faillo",
            "printf 'BUILD-FAILLO: DIRTY-PROBE-READY: %s\\n' \"$probe\" >&2",
            "true # dirty-probe reached-state marker removed",
            "dirty-probe reached-state marker",
        ),
        (
            "faillo",
            'grep -qF "$expected"',
            "grep -qiE 'FATAL|FAIL'",
            "fail-loud suite accepts a broad unrelated failure diagnostic",
        ),
        (
            "faillo",
            '[ "$rc" -ne 0 ] || return 1',
            'true # reached-state status check removed',
            "reached-state failure classification",
        ),
        (
            "faillo",
            '[ "$rc" -ne 0 ] || return 1\n  printf \'%s\\n\' "$out" | grep -qF "$reached"',
            '[ "$rc" -ne 0 ] || return 1\n  true # reached-state marker check removed',
            "reached-state failure classification",
        ),
        (
            "faillo",
            'printf \'%s\\n\' "$out" | grep -qF "$expected"',
            'true # reached-state diagnostic check removed',
            "reached-state failure classification",
        ),
        (
            "faillo",
            '! printf \'%s\\n\' "$out" | grep -qF "$marker"',
            'true # forbidden success marker check removed',
            "reached-state failure classification",
        ),
        (
            "workspace_verifier",
            "if threading.current_thread() is not threading.main_thread():",
            "if False:",
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            "MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)",
            "MANAGED_SIGNALS = (signal.SIGINT, signal.SIGTERM)",
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            'state["caught"] = True\n    if state["acquiring_process"]:',
            'state["caught"] = True\n    if False:',
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            "signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)\n    raise ManagedSignal(signum)",
            "raise ManagedSignal(signum) # repeated managed signals remain unblocked",
            "managed command signal ownership",
        ),
        (
            "workspace_verifier",
            "control_socket, child_socket = socket.socketpair(\n            socket.AF_UNIX,\n            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC,\n        )\n        signal_scope = enter_managed_signal_scope()\n        activate_managed_signal_scope(signal_scope)",
            "control_socket, child_socket = socket.socketpair(\n            socket.AF_UNIX,\n            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC,\n        )\n        signal_scope = None # managed signal handlers removed",
            "managed command cgroup ownership",
        ),
        (
            "workspace_verifier",
            "begin_managed_process_acquisition()\n        acquisition_active = True\n        process = spawn_exact_process(",
            "acquisition_active = True\n        process = spawn_exact_process(",
            "managed command cgroup ownership",
        ),
        (
            "workspace_verifier",
            "acquisition_active = False\n        pending_signum = finish_managed_process_acquisition()",
            "acquisition_active = False\n        pending_signum = None # process acquisition handoff removed",
            "managed command cgroup ownership",
        ),
        (
            "workspace_verifier",
            '        "managed-command unit finalization failed",\n        failures,\n    )',
            '        "managed-command unit finalization failed",\n        [],\n    )',
            "managed cleanup accumulator does not report the complete failure list",
        ),
        (
            "workspace_verifier",
            "if signal_scope is not None:\n            leave_managed_signal_scope(signal_scope, finalization_mask)\n        else:\n            signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask)",
            "signal.pthread_sigmask(signal.SIG_SETMASK, finalization_mask) # managed scope restoration removed",
            "stateful release-state proof",
        ),
        (
            "workspace_verifier",
            "signal_scope = enter_managed_signal_scope()\n        activate_managed_signal_scope(signal_scope)\n        before = reserved_release_state(cwd)",
            "signal_scope = None # state transaction signal scope removed\n        before = reserved_release_state(cwd)",
            "stateful release-state proof",
        ),
        (
            "workspace_verifier",
            'globals()["spawn_exact_process"] = signal_before_spawn_return\n    try:',
            'globals()["spawn_exact_process"] = real_spawn # pre-assignment fixture removed\n    try:',
            "pre-assignment managed signal fixture",
        ),
        (
            "workspace_verifier",
            'assert_process_absent(descendant_pid, "stateful parent-signal descendant")',
            'assert_process_absent(descendant_pid, "stateful parent-signal cleanup unproven")',
            "external parent-signal cleanup fixture",
        ),
        (
            "workspace_verifier",
            'except ManagedSignal as exc:\n        failure = (128 + exc.signum, f"interrupted by signal {exc.signum}")',
            'except Exception as exc:\n        failure = (128 + exc.signum, f"interrupted by signal {exc.signum}")',
            "managed signal main classification",
        ),
        (
            "workspace_verifier",
            '"--scope",',
            '"--service",',
            "transient scope execution",
        ),
        (
            "workspace_verifier",
            '"descriptors": list(normalized_fds)',
            '"descriptors": []',
            "managed descriptor allowlist frame",
        ),
        (
            "workspace_verifier",
            "if control_socket.sendmsg([frame], controls) != len(frame):",
            "if control_socket.send(frame) != len(frame): # descriptor rights omitted",
            "managed descriptor handoff",
        ),
        (
            "workspace_verifier",
            "target_pidfd = os.pidfd_open(target_pid, 0)",
            "target_pidfd = None # target identity authority removed",
            "managed command cgroup ownership",
        ),
        (
            "workspace_verifier",
            'parse_systemd_second_duration(properties["RuntimeMaxUSec"]) != runtime_limit',
            "False # runtime backstop authentication removed",
            "exact runtime-duration policy",
        ),
        (
            "workspace_verifier",
            "authority = authenticate_managed_unit(\n            unit,\n            description,\n            token,\n            target_pid,\n            control_environment,\n            stop_limit,\n            runtime_limit,\n        )",
            "authority = None # managed unit authentication removed",
            "managed command cgroup ownership",
        ),
        (
            "workspace_verifier",
            'os.write(authority["kill"], b"1")',
            'os.write(authority["kill"], b"")',
            "exact cgroup.kill operation",
        ),
        (
            "workspace_verifier",
            "def hard_kill_cgroup(authority):\n    if cgroup_is_populated(authority):\n        os.write(authority[\"kill\"], b\"1\")\n    wait_cgroup_empty(authority)",
            "def hard_kill_cgroup(authority):\n    if cgroup_is_populated(authority):\n        os.write(authority[\"kill\"], b\"1\")\n    pass # recursive cgroup emptiness proof removed",
            "recursive cgroup emptiness proof",
        ),
        (
            "workspace_verifier",
            '"unacquired managed unit resolution",\n                resolve_unacquired_unit,',
            '"unacquired managed unit resolution",\n                lambda *ignored: None,',
            "unacquired gate retained through cgroup reacquisition",
        ),
        (
            "workspace_verifier",
            "hard_kill_cgroup(authority)\n        terminate_and_reap_unacquired_launcher(process)",
            "hard_kill_cgroup(authority)\n        pass # primary unacquired launcher reap removed",
            "unacquired launcher cleanup ordering",
        ),
        (
            "workspace_verifier",
            '"unacquired launcher termination and reap",\n                terminate_and_reap_unacquired_launcher,',
            '"unacquired launcher termination and reap",\n                lambda ignored: None,',
            "unacquired launcher cleanup ordering",
        ),
        (
            "workspace_verifier",
            "authority = authenticate_unacquired_unit(unit, description, environment)",
            "authority = None # unacquired authority reacquisition removed",
            "unacquired launcher cleanup ordering",
        ),
        (
            "workspace_verifier",
            '"managed unit graceful shutdown",\n                gracefully_stop_managed_unit,',
            '"managed unit graceful shutdown",\n                hard_kill_cgroup,',
            "graceful exceptional managed cleanup",
        ),
        (
            "workspace_verifier",
            "while process.poll() is None or any(\n            key.data in (\"stdout\", \"stderr\") for key in selector.get_map().values()\n        ):\n            remaining = deadline - time.monotonic()",
            "while process.poll() is None or any(\n            key.data in (\"stdout\", \"stderr\") for key in selector.get_map().values()\n        ):\n            if process.poll() is not None:\n                process.stdout.read(max_output_bytes + 1)\n            remaining = deadline - time.monotonic()",
            "managed command performs an unbounded post-exit pipe read",
        ),
        (
            "workspace_verifier",
            "owned_authority = authority",
            "owned_authority = None # finalization ownership handoff removed",
            "managed finalization authority handoff",
        ),
        (
            "workspace_verifier",
            "after = reserved_release_state(cwd)\n    if after != before:",
            "after = reserved_release_state(cwd)\n    if False:",
            "stateful release-state proof",
        ),
        (
            "workspace_verifier",
            "result = run_stateful_command([str(path), mode], repo, poison)",
            "result = run_command([str(path), mode], repo, poison)",
            "transaction fixtures use the stateful runner",
        ),
        (
            "workspace_verifier",
            '            run_fixture_stage("managed lifecycle fixture", run_stateful_timeout_fixtures, repo, scratch)\n'
            '            run_fixture_stage("transaction fixture", run_transaction_fixtures, repo)',
            '            run_fixture_stage("transaction fixture", run_transaction_fixtures, repo) # stateful timeout fixtures removed',
            "stateful timeout fixture dispatch",
        ),
        (
            "build",
            'run_snapshot_consumer "final APK certificate proof"',
            'compare_snapshots\n    run_snapshot_consumer "final APK certificate proof"',
            "release transaction",
        ),
        (
            "build",
            'run_publication_reconciliation_self_test "$SET_A"',
            'true # publication reconciliation fixture removed',
            "publication reconciliation fixture dispatch",
        ),
        (
            "build",
            "for point in staging prepared rollback-record exchange cleanup-record payload-removal; do",
            "for point in prepared exchange payload-removal; do",
            "complete publication restart matrix",
        ),
        (
            "build",
            "pre-exchange recovery at $point",
            "prepared recovery",
            "state-accurate pre-exchange recovery diagnostics",
        ),
        (
            "build",
            "publication recovery did not reject a canonical wrong-token payload",
            "wrong-token payload fixture removed",
            "wrong-token payload ownership fixture",
        ),
        (
            "build",
            "publication recovery did not reject a canonical wrong-token next record",
            "wrong-token next-record fixture removed",
            "wrong-token next-record ownership fixture",
        ),
        (
            "build",
            'install -d -m 0770 "$writable"',
            'install -d -m 0700 "$writable"',
            "group-writable parent rejection fixture",
        ),
        (
            "finalizer",
            'SUPPORTED_FILESYSTEMS = {\n    0xEF53: "ext4",\n}',
            'SUPPORTED_FILESYSTEMS = {\n    0xEF53: "ext4",\n    0x58465342: "xfs",\n}',
            "final release publisher filesystem allowlist",
        ),
        (
            "finalizer",
            '("initializing", "staging", "prepared", "rollback", "cleanup")',
            '("initializing", "prepared", "rollback", "cleanup")',
            "final release publisher durable staging and terminal states",
        ),
        (
            "finalizer",
            '("initializing", "staging"),',
            '("initializing", "prepared"),',
            "final release publisher exact crash-state transitions",
        ),
        (
            "finalizer",
            "observed = mount_filesystem_type(mount_id)",
            'observed = "ext4" # mount-table type proof removed',
            "ext4 versus ext2/ext3 discrimination",
        ),
        (
            "finalizer",
            "fcntl.ioctl(descriptor, FS_IOC_GETFSUUID, filesystem_uuid, True)",
            "filesystem_uuid[1:] = bytes.fromhex('01' * 16) # filesystem UUID ioctl removed",
            "descriptor-bound filesystem UUID",
        ),
        (
            "finalizer",
            '                "handle": persistent_handle(descriptor),',
            '                "handle": "", # path object handle removed',
            "publication path persistent object handle",
        ),
        (
            "finalizer",
            "name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd",
            "name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd",
            "nonblocking descriptor-bound regular-file acquisition",
        ),
        (
            "finalizer",
            "os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC,",
            "os.O_RDONLY | os.O_CLOEXEC,",
            "nonblocking descriptor-bound regular-file acquisition",
        ),
        (
            "finalizer",
            '        "filesystem": parent.filesystem,',
            '        "filesystem": "", # initial filesystem authority removed',
            "initial durable record filesystem binding",
        ),
        (
            "finalizer",
            'current["state"] == "initializing" and following["state"] == "staging"',
            "False",
            "payload-handle binding transition",
        ),
        (
            "finalizer",
            "os.mkdir(payload_name, 0o700, dir_fd=parent.fd)\n    os.fsync(parent.fd)",
            "os.mkdir(payload_name, 0o700, dir_fd=parent.fd) # payload parent fsync removed",
            "durable empty payload authority before handle commit",
        ),
        (
            "finalizer",
            'if record["state"] == "staging":\n        finish_rollback(parent, record_name, record, record_identity)',
            'if False: # staging rollback removed\n        finish_rollback(parent, record_name, record, record_identity)',
            "unbound initialization rejection and bound staging rollback",
        ),
        (
            "finalizer",
            'if record["state"] == "initializing":\n        verify_prior_release(parent, old_handle)\n        if payload is not None:',
            'if record["state"] == "initializing":\n        verify_prior_release(parent, old_handle)\n        if False: # unbound payload accepted',
            "unbound initialization rejection and bound staging rollback",
        ),
        (
            "finalizer",
            "        if next_token != token:",
            "        if False: # next-record transaction ownership removed",
            "next-record transaction ownership",
        ),
        (
            "finalizer",
            '    if found["payload"] and found["payload"][0] != (record["payload"], token):',
            "    if False: # payload transaction ownership removed",
            "payload transaction ownership",
        ),
        (
            "finalizer",
            'record_identity = update_record(parent, record_name, token, record_identity, staging)',
            "record_identity = record_identity # staging record durability removed",
            "failure-atomic publication state machine",
        ),
        (
            "finalizer",
            "if any(record_names(parent).values()):",
            "if False: # quiescent publication-state proof removed",
            "non-repairing quiescent publication verification",
        ),
        (
            "finalizer",
            'ACL_XATTRS = {"system.posix_acl_access", "system.posix_acl_default"}',
            'ACL_XATTRS = {"system.posix_acl_access"}',
            "final release publisher complete POSIX ACL rejection",
        ),
        (
            "finalizer",
            "or destination in (\".\", \"..\")",
            "or False # dot destinations accepted",
            "dot-destination rejection",
        ),
        (
            "finalizer",
            "fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)",
            "True # publication parent lock removed",
            "exclusive parent lock",
        ),
        (
            "finalizer",
            "if self.metadata.st_mode & 0o022:",
            "if False: # publication parent writer rejection removed",
            "publication parent writer rejection",
        ),
        (
            "finalizer",
            "or self.metadata.st_gid != self.gid",
            "or False # publication parent group proof removed",
            "publication parent group proof",
        ),
        (
            "finalizer",
            "or metadata.st_gid != self.gid",
            "or False # live publication parent group proof removed",
            "live publication parent group proof",
        ),
        (
            "finalizer",
            '        "parent_handle": parent.handle,',
            '        "parent_id": parent.handle,',
            "initial durable record parent binding",
        ),
        (
            "finalizer",
            "parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC",
            "parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC",
            "no-follow parent descriptor",
        ),
        (
            "finalizer",
            "if names:\n        raise PublicationError(f\"{label} has filesystem extended attributes\")",
            "if False:\n        raise PublicationError(f\"{label} has filesystem extended attributes\")",
            "publication xattr rejection",
        ),
        (
            "finalizer",
            "DEADLINE_SECONDS = 180",
            "DEADLINE_SECONDS = 0",
            "final release publisher exact DEADLINE_SECONDS bound",
        ),
        (
            "finalizer",
            "os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC",
            "os.O_RDWR | os.O_CREAT | os.O_CLOEXEC",
            "durable unnamed publication record commit",
        ),
        (
            "finalizer",
            "os.fsync(descriptor)\n        link_unnamed_file(descriptor, parent.fd, name)",
            "link_unnamed_file(descriptor, parent.fd, name) # record fsync removed",
            "durable unnamed publication record commit",
        ),
        (
            "finalizer",
            "os.replace(next_name, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)",
            "os.rename(next_name, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)",
            "durable publication record transition",
        ),
        (
            "finalizer",
            "if name.startswith(reserved_prefix):",
            "if False: # unknown reserved names accepted",
            "unknown reserved-name rejection",
        ),
        (
            "finalizer",
            "match = pattern.fullmatch(name)",
            "match = pattern.match(name)",
            "exact reserved-name classification",
        ),
        (
            "finalizer",
            "renameat2(parent.fd, record[\"payload\"], parent.destination, RENAME_NOREPLACE)",
            "renameat2(parent.fd, record[\"payload\"], parent.destination, 0)",
            "first-publication kernel no-clobber",
        ),
        (
            "finalizer",
            "renameat2(parent.fd, record[\"payload\"], parent.destination, RENAME_EXCHANGE)",
            "renameat2(parent.fd, record[\"payload\"], parent.destination, 0)",
            "existing-publication atomic exchange",
        ),
        (
            "finalizer",
            "parent.assert_bound()\n    os.fsync(parent.fd)\n    if (\n        parent.path_authority(parent.destination) != post_destination",
            "parent.assert_bound()\n    if (\n        parent.path_authority(parent.destination) != post_destination",
            "failure-atomic publication state machine",
        ),
        (
            "finalizer",
            "os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC",
            "os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC",
            "unnamed staged files",
        ),
        (
            "finalizer",
            'report_cleanup_failures(primary, "publication parent descriptor close", failures)',
            "pass # publication parent close failures discarded",
            "publication parent cleanup failure preservation",
        ),
        (
            "scan",
            'if [ "$status" -eq 1 ]; then',
            'if [ "$status" -eq 2 ]; then',
            "scanner no-match status",
        ),
        (
            "scan",
            'else\n    status=$?\n  fi',
            'else\n    status=0\n  fi',
            "scanner status capture",
        ),
        (
            "release",
            "verify_scan_preflight || exit 1",
            "true # scanner preflight removed",
            "release scanner preflight",
        ),
        (
            "verify",
            "source scripts/verify-scan.sh",
            "source scripts/verify-scan.sh\nrg -n forbidden src",
            "undeclared ripgrep dependency",
        ),
        (
            "verify",
            "^[[:space:]]*virtual_display[[:space:]]*=",
            "virtual_display =",
            "anchored IDD dependency scan",
        ),
        (
            "verify",
            "smoke_nonroot_stage=$(awk '/^  password-nonroot\\)/{capture=1}",
            "smoke_nonroot_stage=$(awk '/^run_stage out2c /{capture=1}",
            "verify non-root smoke extraction follows the mounted stage form",
        ),
        (
            "smoke_stage",
            'cd "$HOME"',
            "cd /work",
            "non-root smoke runner retains forbidden source/process authority",
        ),
        (
            "smoke_stage",
            'install -o root -g "$gid" -m 0550 target/debug/examples/probe_client "$fixture/bin/probe_client"',
            "true # probe client fixture removed",
            "probe client fixture",
        ),
        (
            "smoke_stage",
            "chmod 0755 target/debug/rustdesk",
            "chmod 0700 target/debug/rustdesk",
            "installed-mode lifecycle executable",
        ),
        (
            "smoke_stage",
            '"$bin/smoke-ready.sh" --terminate-server "$SRV" "$SRV_START" "$HOME/srv2c.log"',
            'pkill -TERM -x rustdesk || true',
            "mounted smoke stage retains broad or raw signal authority",
        ),
        (
            "smoke_stage",
            '$READY --wait-user-server "$SRV" "$SRV_START" /tmp/srv.log /work/target/debug/examples/smoke_readiness 0',
            'true # root IPC readiness proof removed',
            "root user-owned IPC readiness proof",
        ),
        (
            "smoke_stage",
            '$READY --hold-running "$SRV" "$SRV_START" /tmp/srv.log 64 "limiter-decay interval"',
            'sleep 6',
            "identity-monitored limiter-decay interval",
        ),
        (
            "service_lifecycle",
            'signal.pidfd_send_signal(pidfd_file.fileno(), signals[signal_name], None, 0)',
            'os.kill(pid, signals[signal_name])',
            "pidfd-only lifecycle signaling",
        ),
        (
            "service_lifecycle",
            '[b"rd-smoke-server", b"--server", b""]',
            '[b"rd-smoke-server", b"--server", b"--service-owned-server", b""]',
            "portable role isolation",
        ),
        (
            "service_lifecycle",
            're.fullmatch(rb"/proc/self/fd/[0-9]+", argv[0])',
            're.fullmatch(rb"/proc/self/exe", argv[0])',
            "descriptor-bound non-root role proof",
        ),
        (
            "service_lifecycle",
            'for capability_set in ("CapInh", "CapPrm", "CapEff", "CapAmb"):',
            'for capability_set in ("CapInh", "CapPrm", "CapAmb"):',
            "non-root capability clearing proof",
        ),
        (
            "service_lifecycle",
            'os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC',
            'os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC',
            "exclusive no-follow hostile-record fixture",
        ),
        (
            "service_lifecycle",
            'if [ "$service_status" -ne 1 ]; then',
            'if [ "$service_status" -ne 0 ]; then',
            "hostile-record exact failure status",
        ),
        (
            "service_lifecycle",
            '[ "$after_identity" = "$before_identity" ]',
            'true # hostile-record metadata preservation removed',
            "hostile-record metadata preservation",
        ),
        (
            "service_lifecycle",
            '  assert_decoy_alive\n  assert_portable_alive',
            '  true # hostile-record sentinel survival removed',
            "hostile-record sentinel survival",
        ),
        (
            "service_lifecycle",
            'SERVICE_LIFECYCLE_HOSTILE_RECORDS=pass cases=malformed,metadata,reused-start,executable,uid,generation,portable-role',
            'SERVICE_LIFECYCLE_HOSTILE_RECORDS=pass cases=malformed,metadata',
            "hostile-record lifecycle result",
        ),
        (
            "service_lifecycle",
            'RD_SERVICE_SMOKE_FORCE_PRE_PIDFD=1',
            'true # pre-pidfd runtime exercise removed',
            "forced pre-pidfd runtime exercise",
        ),
        (
            "service_lifecycle",
            'SERVICE_LIFECYCLE_PRE_PIDFD_RECOVERY=pass prior_generation=',
            'SERVICE_LIFECYCLE_PRE_PIDFD_SKIPPED=pass prior_generation=',
            "pre-pidfd runtime result",
        ),
        (
            "linux_source",
            'require_service_child_identity_match(record, "pre-pidfd kill fallback")',
            'true; // pre-pidfd signal revalidation removed',
            "pre-pidfd signal revalidation",
        ),
        (
            "linux_source",
            'wait_revalidated_service_child_pid_exit(record, SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT)',
            'service_child_pid_exists(record.pid)',
            "pre-pidfd graceful wait revalidation",
        ),
        (
            "linux_source",
            'wait_revalidated_service_child_pid_exit(record, SERVICE_CHILD_FORCED_STOP_TIMEOUT)',
            'service_child_pid_exists(record.pid)',
            "pre-pidfd forced wait revalidation",
        ),
        (
            "linux_source",
            'const SERVICE_CHILD_FORCE_PRE_PIDFD_FOR_SMOKE_ENV: &str = "RD_SERVICE_SMOKE_FORCE_PRE_PIDFD";',
            'const SERVICE_CHILD_FORCE_PRE_PIDFD_FOR_SMOKE_ENV: &str = "RD_SERVICE_SMOKE_FORCE_PRE_PIDFD_DISABLED";',
            "debug-only pre-pidfd smoke force constant",
        ),
        (
            "linux_source",
            '#[cfg(not(debug_assertions))]\n    {\n        false\n    }\n}\n\nfn open_service_child_pidfd',
            '#[cfg(not(debug_assertions))]\n    {\n        true\n    }\n}\n\nfn open_service_child_pidfd',
            "pre-pidfd smoke force release-disabled result",
        ),
        (
            "linux_source",
            'if service_child_pidfd_open_is_forced_unsupported_for_smoke() {',
            'if false { // pre-pidfd smoke force dispatch removed',
            "pre-pidfd smoke force dispatch",
        ),
        (
            "linux_source",
            'runtime.recover_previous_child()?;',
            'true; // hostile-record recovery removed',
            "hostile-record recovery precedes signal and listener authority",
        ),
        (
            "smoke_ready",
            "  exit 1\n}\n\nmonotonic_millis",
            "  return 1\n}\n\nmonotonic_millis",
            "terminal smoke readiness failure",
        ),
        (
            "loginctl_fixture",
            'exit 64',
            'exit 0',
            "loginctl unexpected-argv rejection",
        ),
        (
            "loginctl_fixture",
            "uid=4001",
            "uid=0 # non-root seat removed",
            "loginctl non-root seat uid",
        ),
        (
            "smoke",
            "LIFECYCLE_RUN=(docker run --rm --network none --cap-add SYS_PTRACE",
            "LIFECYCLE_RUN=(docker run --rm --network none",
            "network-isolated lifecycle procfs authority",
        ),
        (
            "smoke",
            'docker run -d --name "$SIBLING_NAME" --network none',
            'docker run -d --name "$SIBLING_NAME"',
            "sibling Docker network isolation",
        ),
        (
            "smoke",
            'docker run -d --name "$SIBLING_NAME" --network none',
            'docker run -d --name "$SIBLING_NAME" --network none --pid=container:service',
            "sibling Docker must not share a host or container PID namespace",
        ),
        (
            "smoke",
            'record_stage_status R-S11c-27j',
            'true # sibling Docker survival status removed',
            "sibling Docker stage status preservation",
        ),
        (
            "smoke",
            'record_stage_status R-S11c-27k',
            'true # pre-pidfd fallback status removed',
            "pre-pidfd fallback stage status preservation",
        ),
        (
            "smoke",
            'record_stage_status R-S11c-27l',
            'true # Debian SysV lifecycle status removed',
            "Debian SysV stage status preservation",
        ),
        (
            "smoke",
            'record_stage_status R-S11c-27n',
            'true # cross-container identity status removed',
            "cross-container identity stage status preservation",
        ),
        (
            "smoke",
            '&& [ "$main_executable" != "$sibling_executable" ]',
            '&& [ "$main_executable" = "$sibling_executable" ]',
            "cross-container executable-object separation",
        ),
        (
            "smoke",
            '&& [ "$main_pid_namespace" != "$sibling_pid_namespace" ]',
            '&& [ "$main_pid_namespace" = "$sibling_pid_namespace" ]',
            "cross-container PID-namespace separation",
        ),
        (
            "smoke",
            '&& [ "$main_mount_namespace" != "$sibling_mount_namespace" ]',
            '&& [ "$main_mount_namespace" = "$sibling_mount_namespace" ]',
            "cross-container mount-namespace separation",
        ),
        (
            "smoke_stage",
            '"$SERVER_LAUNCHER" "$installed_server" --service-owned-server',
            '"$SERVER_LAUNCHER" "$installed_server"',
            "sibling exact service-owned role",
        ),
        (
            "service_lifecycle",
            'readonly BINARY=/usr/bin/rustdesk',
            'readonly BINARY=/work/target/debug/rustdesk',
            "manual lifecycle identical installed path",
        ),
        (
            "smoke_process_guard",
            '[NEUTRAL_ARGV0, SERVER_ROLE, SERVICE_OWNED_ROLE]',
            '[NEUTRAL_ARGV0, SERVER_ROLE]',
            "exact service-owned sibling argv",
        ),
        (
            "smoke_launcher",
            'server_argv[2] = (char *)SERVICE_OWNED_ROLE;',
            'server_argv[2] = NULL;',
            "launcher service-owned role forwarding",
        ),
        (
            "verify",
            "grep -qF 'R-S11c-27n — cross-container executable identity' HARDENING_STATUS.md",
            "true # cross-container hardening ledger gate removed",
            "cross-container hardening ledger gate",
        ),
        (
            "smoke_stage",
            'debian-sysv-installed-lifecycle)',
            'debian-sysv-installed-lifecycle-disabled)',
            "Debian SysV dispatch",
        ),
        (
            "debian_sysv_lifecycle",
            "assert_wrong_executable_alive() {",
            "assert_wrong_executable_alive_removed() {",
            "Debian SysV wrong-executable survival proof",
        ),
        (
            "debian_sysv_lifecycle",
            'printf \'%s\\n\' "$WRONG_PID" >/run/rustdesk.pid',
            'true # stale PID record fixture removed',
            "Debian SysV stale PID record fixture",
        ),
        (
            "debian_sysv_lifecycle",
            'dpkg -r "$PACKAGE"',
            'true # package removal removed',
            "Debian SysV package removal",
        ),
        (
            "debian_sysv_lifecycle",
            'DEBIAN_SYSV_INSTALLED_LIFECYCLE=pass os=debian-%s portable_uid=%s stale_wrong_exec=survived',
            'DEBIAN_SYSV_INSTALLED_LIFECYCLE=skipped',
            "Debian SysV installed lifecycle result",
        ),
        (
            "systemd_smoke_host",
            "-nic none",
            "-nic user",
            "systemd VM host network isolation",
        ),
        (
            "systemd_smoke_host",
            "--cap-drop ALL --security-opt no-new-privileges",
            "--security-opt no-new-privileges",
            "systemd VM dependency staging confinement",
        ),
        (
            "systemd_smoke_guest",
            'cmp -s "$UNIT_SOURCE" /usr/lib/systemd/system/rustdesk.service',
            'true # installed unit identity proof removed',
            "installed systemd exact production unit",
        ),
        (
            "systemd_smoke_guest",
            'not main_cgroup.endswith("/system.slice/rustdesk.service")',
            "False",
            "installed systemd service cgroup identity",
        ),
        (
            "systemd_smoke_guest",
            'systemctl kill --kill-whom=main --signal=KILL "$UNIT"',
            'kill -KILL "$precrash_main"',
            "installed systemd unit-scoped crash",
        ),
        (
            "systemd_smoke_guest",
            "assert_portable_alive\ncrash_generation=$LAST_GENERATION",
            "true # crash-time portable survival removed\ncrash_generation=$LAST_GENERATION",
            "installed systemd crash/restart transaction",
        ),
        (
            "systemd_smoke_loginctl",
            "exit 64",
            "exit 0",
            "systemd VM loginctl unexpected-argv rejection",
        ),
        (
            "release",
            "smoke-debian-systemd-lifecycle.sh|installed Debian systemd stop/restart/crash recovery + portable noninterference",
            "smoke-debian-systemd-lifecycle.sh|systemd smoke skipped",
            "installed systemd release gate",
        ),
        (
            "pins",
            'SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE="6c2607f1846ee86040830c87d0b723f0967da3e884ea4673d9db4aa8eee13a4b7c663524bfa42082c16fc6919f3aa1bf425c004d07ff06c53a319ad0c42647bb"',
            'SHA512_DEBIAN_SYSTEMD_SMOKE_IMAGE="unverified"',
            "systemd VM publisher hash pin",
        ),
        (
            "online_fetch",
            "fetch_debian_systemd_smoke_image()",
            "fetch_debian_systemd_smoke_image_disabled()",
            "systemd VM sole fetch mode",
        ),
        (
            "online_fetch",
            '[ -d "$harness_state" ] && [ ! -L "$harness_state" ]',
            '[ -d "$harness_state" ]',
            "systemd VM private state root",
        ),
        (
            "smoke",
            'if stop_sibling_docker >"$sibling_out_file" 2>&1; then',
            'if sibling_out=$(stop_sibling_docker 2>&1); then',
            "sibling Docker stop runs in parent shell",
        ),
        (
            "smoke_stage",
            'SIBLING_DOCKER_SURVIVED=pass pid=%s start=%s',
            'SIBLING_DOCKER_SKIPPED=pass pid=%s start=%s',
            "sibling Docker survival marker",
        ),
        (
            "smoke",
            "STAGE_STATUS=$?",
            "STAGE_STATUS=0",
            "isolated command failure status preservation",
        ),
        (
            "smoke_stage",
            'timeout --signal=TERM --kill-after=5s "$((RECOVERY_SECONDS + 60))"',
            'timeout "$((RECOVERY_SECONDS + 60))"',
            "every password watchdog must derive from recovery and have a forced-kill ceiling",
        ),
        (
            "smoke_stage",
            'wait "$TCPD"',
            'wait "$TCPD" 2>/dev/null || true',
            "capture exit-status proof",
        ),
        (
            "smoke",
            '"$HOST_GUARD" record "$HOST_GUARD_ROOT/baseline.json"',
            'true # host selector baseline removed',
            "pre-smoke host selector baseline",
        ),
        (
            "smoke",
            'bash --noprofile --norc /work/scripts/smoke-server-stage.sh parked',
            'bash -c "/work/target/debug/rustdesk --server"',
            "exact mounted stage dispatch",
        ),
        (
            "linux_source",
            'format!("/proc/self/fd/{}", executable.as_raw_fd())',
            '"/proc/self/exe".to_owned()',
            "service executable descriptor path",
        ),
        (
            "smoke_stage",
            'LD_PRELOAD="$BIND_SHIM" "$SERVER_LAUNCHER" "$executable"',
            'LD_PRELOAD="$BIND_SHIM" "$executable" --server',
            "neutral server launcher use",
        ),
        (
            "smoke_process_guard",
            'return argv == expected_argv',
            'return argv[-1:] == expected_argv[-1:]',
            "generic exact argv proof",
        ),
        (
            "smoke_process_guard",
            'violations = new_matches(baseline, current)',
            'violations = [] # new matches accepted',
            "new-match rejection",
        ),
        (
            "smoke_launcher",
            'fexecve(executable_fd, server_argv, environ);',
            'execve(argv[1], server_argv, environ);',
            "descriptor-bound exact executable launch",
        ),
        (
            "core_main",
            '        if i > 0 {',
            '        if i >= 0 {',
            "Rust argv0 exclusion",
        ),
        (
            "smoke_ready",
            "readonly READY_WAIT_SECONDS=60",
            "readonly READY_WAIT_SECONDS=0",
            "fixed 60-second readiness bound",
        ),
        (
            "smoke_ready",
            '[ "$start" = "$expected_start" ] || return 2',
            'true # pid start identity accepted',
            "pid start identity enforcement",
        ),
        (
            "smoke_ready",
            '[ "$now" -le "$deadline" ] && pid_is_same_and_running "$pid" "$expected_start"',
            'true # post-observation identity and deadline accepted',
            "post-observation PID identity and deadline enforcement",
        ),
        (
            "smoke_ready",
            '[ "$(stat -c %u:%a -- "$socket")" = "$uid:600" ]',
            '[ "$(stat -c %u:%a -- "$socket")" = "$uid:666" ]',
            "IPC socket ownership and mode",
        ),
        (
            "smoke_ready",
            'SELF_TEST_IPC_PARENT_ID=$(path_identity "$parent")',
            'SELF_TEST_IPC_PARENT_ID=assumed',
            "self-test IPC root inode retention",
        ),
        (
            "smoke_ready",
            'typed_ipc_ready "$probe" "$expected" "$pid" "$expected_start" "$deadline" || return 1',
            'true # typed IPC transaction removed',
            "successful typed IPC readiness transaction",
        ),
        (
            "smoke_ready",
            '[ "$output" = "SMOKE_TYPED_IPC_READY state=$expected" ]',
            "true # typed IPC output accepted",
            "exact typed IPC output comparison",
        ),
        (
            "smoke_ready",
            '$4 == "00010000" && $5 == "0001" && $6 == "01"',
            '$5 == "0001" && $6 == "01"',
            "Unix stream listening-state proof",
        ),
        (
            "smoke_ready",
            'pid_owns_unix_listener "$pid" "$socket" || return 1',
            "true # IPC socket process ownership accepted",
            "both IPC paths bound to the exact process",
        ),
        (
            "smoke_ready",
            "signal.pidfd_send_signal(pidfd, signals[signal_name], None, 0)",
            "os.kill(pid, signals[signal_name])",
            "pidfd signal delivery",
        ),
        (
            "smoke_typed_probe",
            "ipc::get_main_readiness_snapshot_for_process(",
            "async { Ok(Default::default()) }",
            "typed process-bound main-IPC readiness transaction",
        ),
        (
            "smoke_typed_probe",
            "if actual_values.0 != expected_values.0",
            "if true",
            "individual readiness fact comparison",
        ),
        (
            "session_probe",
            'mode != "filetransfer" || file_transfer_ok',
            'mode != "filetransfer" || true',
            "file-transfer semantic pass condition",
        ),
        (
            "session_probe",
            "let login_bytes = match msg.write_to_bytes()",
            "let login_bytes = msg.write_to_bytes().unwrap_or_default(); // serialization result discarded",
            "file-transfer login serialization result",
        ),
        (
            "session_probe",
            "if !peer_username_nonempty || !readdir_send_ok",
            "if !readdir_send_ok",
            "missing/empty PeerInfo failure",
        ),
        (
            "ipc_source",
            "std::time::Duration::from_secs(PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS)",
            "std::time::Duration::from_secs(600)",
            "password recovery duration derivation",
        ),
        (
            "ipc_source",
            "if peer_pid != expected_pid",
            "if false",
            "SO_PEERCRED peer-pid binding",
        ),
        (
            "ipc_source",
            "tokio::time::timeout_at(deadline, async {",
            "async {",
            "one hard readiness transaction deadline",
        ),
        ("build", "git --no-replace-objects", "git", "Git replacement-object suppression"),
        (
            "build",
            '--verify-apk "$SET_A/rustdesk-arm64.apk"',
            '--verify-apk "$FINAL_OUT_DIR/rustdesk-arm64.apk"',
            "staged final APK certificate proof",
        ),
        (
            "debian",
            'require_pinned_builder_image deb-builder "$IMAGE_ID"',
            "true # builder proof removed",
            "Debian builder provenance verification",
        ),
        (
            "android",
            'create_private_online_snapshot "$ONLINE_SNAPSHOT_PARENT"',
            "true # direct snapshot removed",
            "Android direct snapshot",
        ),
        (
            "publish",
            "EXPECTED_REPO_ID=1268555599",
            "EXPECTED_REPO_ID=1",
            "numeric GitHub repository identity pin",
        ),
        (
            "publish",
            'gh_api "repos/$REPO_SLUG/releases/$RELEASE_ID" --method PATCH',
            'gh_api "repos/$REPO_SLUG/releases/$TAG" --method PATCH',
            "numeric-ID publication",
        ),
        (
            "publish",
            'strict_release_inventory "$RELEASE_ID" 1',
            "true # barrier inventory removed",
            "barrier release inventory",
        ),
        (
            "publish",
            'assert_immutable_release_policy "final pre-publication barrier"',
            "true # immutable-release policy removed",
            "barrier immutable-release policy",
        ),
        (
            "publish",
            "parse_constant=reject_nonfinite",
            "parse_constant=None",
            "non-finite JSON rejection",
        ),
        (
            "publish",
            "GitHub release asset server digest differs",
            "GitHub release asset digest omitted",
            "server digest proof",
        ),
        (
            "publish",
            "--no-replace-objects -c core.hooksPath=/dev/null",
            "-c core.hooksPath=/dev/null",
            "publisher Git replacement suppression",
        ),
        (
            "closure",
            'os.mkdir(name, 0o700, dir_fd=self.fd)',
            'os.mkdir(os.path.join("/tmp", name), 0o700)',
            "closure descriptor-relative fixture creation",
        ),
        (
            "closure",
            '                    if identity(current) != child_identity:\n                        raise ClosureError("self-test fixture edge changed before cleanup")',
            '                    if False:\n                        raise ClosureError("self-test fixture edge changed before cleanup")',
            "closure retained-authority cleanup gate",
        ),
        (
            "closure",
            'or descriptor_mount_id(authority_fd) != self.mount_id',
            'or False # closure entry mount proof removed',
            "mount-boundary proof",
        ),
        (
            "closure",
            'if descriptor_mount_id(self.fd) != self.mount_id:',
            'if False: # closure root mount proof removed',
            "closure scratch live mount authority",
        ),
        (
            "closure",
            "def bounded_directory_names(descriptor, limit):\n    names = []\n    with os.scandir(f\"/proc/self/fd/{descriptor}\") as entries:",
            "def bounded_directory_names(descriptor, limit):\n    names = []\n    with contextlib.nullcontext(os.listdir(descriptor)) as entries:",
            "closure descriptor-bound streamed cleanup inventory",
        ),
        (
            "closure",
            "                exercise_scratch_acquisition_failures(scratch)",
            "                pass # scratch acquisition fixture removed",
            "closure scratch acquisition fixture dispatch",
        ),
        (
            "closure",
            "                exercise_scratch_external_link_rejection(scratch)",
            "                pass # scratch hardlink fixture removed",
            "closure scratch hardlink fixture dispatch",
        ),
        (
            "closure",
            "                exercise_scratch_root_removal(scratch)",
            "                pass # scratch root-removal fixture removed",
            "closure scratch root-removal fixture dispatch",
        ),
        (
            "workspace_verifier",
            "stat.S_IMODE(mode) in (0o700, 0o755)",
            "stat.S_IMODE(mode) == 0o755",
            "private release-snapshot readiness executable mode",
        ),
        (
            "workspace_verifier",
            "metadata.st_blocks,\n        metadata.st_rdev,\n        metadata.st_mtime_ns,\n        metadata.st_ctime_ns,",
            "metadata.st_blocks,\n        metadata.st_rdev,\n        metadata.st_mtime_ns,\n        metadata.st_mtime_ns, # publication ctime omitted",
            "publication ctime metadata",
        ),
        (
            "workspace_verifier",
            'publication_ioctl_state(descriptor, FS_IOC_GETFLAGS, 4, "inode flags")',
            '("omitted",), # inode flags omitted',
            "publication inode flags",
        ),
        (
            "workspace_verifier",
            'publication_ioctl_state(descriptor, FS_IOC_FSGETXATTR, 28, "extended inode flags")',
            '("omitted",), # extended inode flags omitted',
            "publication extended inode flags",
        ),
        (
            "workspace_verifier",
            'if depth > PUBLICATION_DEPTH_LIMIT:',
            'if False: # publication depth bound removed',
            "publication depth bound enforcement",
        ),
        (
            "workspace_verifier",
            'if budget["entries"] >= PUBLICATION_ENTRY_LIMIT:',
            'if False: # publication entry bound removed',
            "publication entry bound enforcement",
        ),
        (
            "workspace_verifier",
            'if opened.st_size > budget["content_remaining"]:',
            'if False: # publication content bound removed',
            "publication content bound enforcement",
        ),
        (
            "workspace_verifier",
            'if len(value) > PUBLICATION_XATTR_VALUE_LIMIT:',
            'if False: # publication per-xattr bound removed',
            "publication per-xattr value bound enforcement",
        ),
        (
            "workspace_verifier",
            'if sum(len(name) + 1 for name in encoded_names) > PUBLICATION_XATTR_NAME_LIMIT:',
            'if False: # publication xattr-name bound removed',
            "publication xattr names bound enforcement",
        ),
        (
            "workspace_verifier",
            'if len(names) > PUBLICATION_XATTR_PER_INODE_COUNT_LIMIT:',
            'if False: # publication per-inode xattr-count bound removed',
            "publication per-inode xattr count bound enforcement",
        ),
        (
            "workspace_verifier",
            'if budget["xattr_bytes"] > PUBLICATION_XATTR_TOTAL_LIMIT:',
            'if False: # publication xattr byte bound removed',
            "publication aggregate xattr bytes bound enforcement",
        ),
        (
            "workspace_verifier",
            'if budget["xattr_count"] > PUBLICATION_XATTR_TOTAL_COUNT_LIMIT:',
            'if False: # publication xattr count bound removed',
            "publication aggregate xattr count bound enforcement",
        ),
        (
            "workspace_verifier",
            'if len(names) >= entry_limit:',
            'if False: # publication streamed entry bound removed',
            "publication repository entries bound enforcement",
        ),
        (
            "workspace_verifier",
            'and name_bytes + encoded_size > PUBLICATION_REPOSITORY_BYTE_LIMIT',
            'and False # publication streamed repository-byte bound removed',
            "publication repository name bytes bound enforcement",
        ),
        (
            "workspace_verifier",
            "with os.scandir(inventory_fd) as entries:",
            "with contextlib.nullcontext(os.listdir(inventory_fd)) as entries:",
            "publication streamed directory inventory",
        ),
        (
            "workspace_verifier",
            'if len(names) > PUBLICATION_NAMESPACE_LIMIT:',
            'if False: # publication namespace bound removed',
            "publication canonical namespace bound enforcement",
        ),
        (
            "workspace_verifier",
            'if len(payload) <= PUBLICATION_SERIALIZED_RESULT_LIMIT:',
            'if True: # publication serialized-result bound removed',
            "publication serialized worker result bound enforcement",
        ),
        (
            "workspace_verifier",
            'if len(payload) + len(diagnostics) + len(chunk) > PUBLICATION_OUTPUT_LIMIT:',
            'if False: # publication aggregate-output bound removed',
            "publication aggregate worker output bound enforcement",
        ),
        (
            "workspace_verifier",
            "while selector.get_map():\n            remaining = deadline - time.monotonic()\n            if remaining <= 0:\n                timed_out = True",
            "while selector.get_map():\n            remaining = deadline - time.monotonic()\n            if False:\n                timed_out = True",
            "publication worker deadline bound enforcement",
        ),
        (
            "workspace_verifier",
            "if timed_out:\n            process.kill()",
            "if timed_out:\n            process.send_signal(0)",
            "publication worker exact timeout kill",
        ),
        (
            "workspace_verifier",
            "pending_signum = None\n            try:\n                pending_signum = finish_managed_process_acquisition()\n            except BaseException as error:\n                acquisition_failures.append((\"publication worker acquisition finish\", error))",
            "pending_signum = None\n            try:\n                pending_signum = None # publication worker acquisition handoff removed\n            except BaseException as error:\n                acquisition_failures.append((\"publication worker acquisition finish\", error))",
            "publication worker acquisition handoff",
        ),
        (
            "workspace_verifier",
            "if filesystem_identity(edge) != self.identity:\n            raise VerificationError(\"verifier fixture scratch pathname was replaced\")",
            "if False:\n            raise VerificationError(\"verifier fixture scratch pathname was replaced\")",
            "fixture scratch edge authority",
        ),
        (
            "workspace_verifier",
            "if filesystem_identity(edge) != child_identity:\n                        raise VerificationError(\"fixture directory edge changed before cleanup\")",
            "if False:\n                        raise VerificationError(\"fixture directory edge changed before cleanup\")",
            "live fixture edge cleanup gate",
        ),
        (
            "workspace_verifier",
            'or descriptor_mount_id(authority_fd) != self.mount_id',
            'or False # fixture entry mount proof removed',
            "mount-boundary proof",
        ),
        (
            "workspace_verifier",
            'if descriptor_mount_id(self.fd) != self.mount_id:',
            'if False: # fixture root mount proof removed',
            "fixture scratch mount authority",
        ),
        (
            "workspace_verifier",
            "if len(inherited_fds) > 64:",
            "if False: # inherited descriptor count bound removed",
            "managed descriptor count bound",
        ),
        (
            "workspace_verifier",
            "or descriptor > 1048575",
            "or False # inherited descriptor-number bound removed",
            "managed descriptor number bound",
        ),
        (
            "workspace_verifier",
            "if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(data) % descriptor_size:",
            "if False: # descriptor control validation removed",
            "managed descriptor control validation",
        ),
        (
            "workspace_verifier",
            "if len(received) != len(payload[\"descriptors\"]):",
            "if False: # exact received descriptor count removed",
            "managed descriptor count equality",
        ),
        (
            "workspace_verifier",
            "socket.MSG_CMSG_CLOEXEC,",
            "0, # received descriptor close-on-exec removed",
            "managed descriptor receive close-on-exec",
        ),
        (
            "workspace_verifier",
            "duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)\n                if duplicate in targets:",
            "duplicate = descriptor # descriptor collision isolation removed\n                if duplicate in targets:",
            "managed descriptor collision isolation",
        ),
        (
            "workspace_verifier",
            "os.dup2(descriptor, target, inheritable=True)",
            "os.dup2(descriptor, target, inheritable=False)",
            "managed descriptor inheritance restoration",
        ),
        (
            "workspace_verifier",
            "digest.update(chunk)\n                    offset += len(chunk)",
            "offset += len(chunk) # publication digest update removed",
            "publication content digest update",
        ),
        (
            "workspace_verifier",
            "return directories, canonical_publication_state(repo)",
            "return directories, ()",
            "canonical publication state inclusion",
        ),
        (
            "workspace_verifier",
            "bypass = run_stateful_command(\n            [\"/usr/bin/bash\", \"--noprofile\", \"--norc\", str(path), mode]",
            "bypass = run_command(\n            [\"/usr/bin/bash\", \"--noprofile\", \"--norc\", str(path), mode]",
            "explicit-Bash transaction fixtures use the stateful runner",
        ),
        (
            "workspace_verifier",
            'os.mkdir(child_name, 0o700, dir_fd=self.fd)',
            'os.mkdir(child_name, 0o700)',
            "descriptor-relative fixture creation",
        ),
        (
            "workspace_verifier",
            "def bounded_directory_names(descriptor, limit, diagnostic):\n    names = []\n    with os.scandir(descriptor) as entries:",
            "def bounded_directory_names(descriptor, limit, diagnostic):\n    names = []\n    with contextlib.nullcontext(os.listdir(descriptor)) as entries:",
            "fixture streamed bounded cleanup inventory",
        ),
        (
            "workspace_verifier",
            'run_fixture_stage("publication snapshot fixture", exercise_canonical_publication_snapshot, scratch)\n'
            '            run_fixture_stage("workspace mutation fixture", run_workspace_mutations, lines, positions)',
            'run_fixture_stage("workspace mutation fixture", run_workspace_mutations, lines, positions)',
            "canonical publication snapshot fixture dispatch",
        ),
        (
            "workspace_verifier",
            'run_fixture_stage("scratch acquisition fixture", exercise_scratch_acquisition_failures, scratch)',
            'run_fixture_stage("scratch acquisition fixture", lambda ignored: None, scratch)',
            "scratch acquisition fixture dispatch",
        ),
        (
            "workspace_verifier",
            "descriptor_mount_id = reject_constructor_mount",
            "descriptor_mount_id = original # constructor failure injection removed",
            "scratch constructor acquisition fixture",
        ),
        (
            "workspace_verifier",
            "child_owned = True\n            yield ScratchDirectory(self, child_fd, child_name, child_identity)",
            "child_owned = False\n            yield ScratchDirectory(self, child_fd, child_name, child_identity)",
            "fixture child acquisition authority",
        ),
        (
            "workspace_verifier",
            '"--scratch-fd",\n                    str(scratch.fd),',
            '"--scratch-omitted",',
            "closure fixture scratch descriptor dispatch",
        ),
        (
            "workspace_verifier",
            "if not directory_is_empty(self.fd):\n                raise VerificationError(\"verifier fixture scratch retained state after self-test\")",
            "if False:\n                raise VerificationError(\"verifier fixture scratch retained state after self-test\")",
            "fixture scratch final emptiness proof",
        ),
        (
            "verify",
            'readonly VERIFIER_FIXTURE_TMP="$VERIFY_TMP/verifier-fixtures"',
            'VERIFIER_FIXTURE_TMP="$VERIFY_TMP/verifier-fixtures"',
            "verifier fixture scratch ownership",
        ),
        (
            "verify",
            '--remove-private-root "$VERIFY_TMP" --expected-identity "$VERIFY_TMP_ID"',
            '--remove-private-root "$VERIFY_TMP"',
            "identity-bound workspace removal",
        ),
        (
            "build_rs",
            'let version = env::var("CARGO_PKG_VERSION")?;',
            'let version = env::var("RUSTDESK_VERSION")?;',
            "Cargo package version authority",
        ),
        (
            "build_rs",
            'generate_version(&version)?;',
            'generate_version("1.4.7")?;',
            "fallible version-metadata generation",
        ),
        (
            "build_rs",
            'emit_fork_version(&version)?;',
            'let _ = emit_fork_version(&version);',
            "fallible fork-version generation",
        ),
        (
            "build_rs",
            'fs::symlink_metadata("FORK_VERSION")?.file_type().is_file()',
            'fs::metadata("FORK_VERSION")?.file_type().is_file()',
            "regular fork-version file",
        ),
        (
            "build_rs",
            'let contents = fs::read_to_string("FORK_VERSION")?;',
            'let contents = fs::read_to_string("FORK_VERSION").unwrap_or_default();',
            "fallible fork-version read",
        ),
        (
            "build_rs",
            'strip_prefix(&format!("{version}-hardened."))',
            'strip_prefix("hardened.")',
            "fork-version package-base equality",
        ),
        (
            "build_rs",
            'PathBuf::from(out_dir).join("version.rs")',
            'PathBuf::from(out_dir).join("../src/version.rs")',
            "Cargo OUT_DIR output path",
        ),
        (
            "build_rs",
            '!raw.bytes().all(|byte| byte.is_ascii_digit())',
            'raw.bytes().all(|byte| byte.is_ascii_digit())',
            "explicit malformed epoch rejection",
        ),
        (
            "build_rs",
            'raw.parse::<i64>().map_err',
            'raw.parse::<i64>().unwrap_or_else',
            "explicit integer-overflow epoch rejection",
        ),
        (
            "build_rs",
            'DateTime::<chrono::Utc>::from_timestamp(epoch, 0).ok_or_else',
            'DateTime::<chrono::Utc>::from_timestamp(epoch, 0).or_else',
            "explicit chrono-range epoch rejection",
        ),
        (
            "root_lib",
            'include!(concat!(env!("OUT_DIR"), "/version.rs"));',
            'include!("version.rs");',
            "root OUT_DIR version include",
        ),
        (
            "hbb_common_lib",
            "pub mod compress;\n",
            "pub fn gen_version() {}\npub mod compress;\n",
            "common source version writer absence",
        ),
        (
            "root_cargo",
            '[build-dependencies]\ncc = "1.0"\nchrono = "0.4"',
            '[build-dependencies]\ncc = "1.0"\nhbb_common = { path = "libs/hbb_common" }',
            "root Cargo build dependencies",
        ),
        (
            "verify",
            'RUN=(docker run --rm\n  -v "$PWD:/work:ro"',
            'RUN=(docker run --rm\n  -v "$PWD:/work:rw"',
            "verifier read-only Cargo source bind",
        ),
        (
            "core_main",
            'println!("{}", env!("RUSTDESK_FORK_VERSION"));',
            'println!("{}", option_env!("RUSTDESK_FORK_VERSION").unwrap_or(crate::VERSION));',
            "required fork-version compile-time environment",
        ),
        (
            "verify",
            '"${RUN[@]}" cargo clean -p rustdesk',
            'true # Cargo package clean removed',
            "version-metadata Cargo clean",
        ),
        (
            "verify",
            'if ! "${RUN[@]}" bash scripts/version-metadata-check.sh; then',
            'if ! "${RUN[@]}" true; then',
            "version-metadata behavioral checker invocation",
        ),
        (
            "verify",
            "done < <(git ls-files -z --cached -- ':(glob)build.rs' ':(glob)**/build.rs')",
            "done < <(git ls-files -z --cached -- ':(glob)build.rs')",
            "indexed Cargo build-script scan",
        ),
        (
            "verify",
            "git check-ignore --no-index -q -- src/version.rs\nversion_ignore_status=$?",
            "grep -qF src/version.rs .gitignore\nversion_ignore_status=$?",
            "Git ignore matching for source version output",
        ),
        (
            "version_metadata_checker",
            "find /build/debug/build -path '/build/debug/build/rustdesk-*/out/version.rs'",
            "find /work -path '/work/src/version.rs'",
            "checker Cargo OUT_DIR output discovery",
        ),
        (
            "version_metadata_checker",
            "for value in '' -1 +1 abc 01700000000 9223372036854775808 9223372036854775807; do",
            "for value in '' -1 +1 abc 01700000000; do",
            "checker malformed and out-of-range epochs",
        ),
        (
            "version_metadata_checker",
            "for value in '' 1.4 1.04.7 1.4.7-beta; do",
            "for value in ''; do",
            "checker invalid package-version fixtures",
        ),
        (
            "version_metadata_checker",
            'run_invalid_fork "$build_script" missing',
            'true # missing FORK_VERSION fixture removed',
            "checker missing fork-version fixture",
        ),
        (
            "version_metadata_checker",
            'run_invalid_epoch() {\n  local build_script="$1" value="$2" out\n  out="$(mktemp -d "$tmp/epoch.XXXXXXXXXX")"\n  if env \\',
            'run_invalid_epoch() {\n  local build_script="$1" value="$2" out\n  out="$(mktemp -d "$tmp/epoch.XXXXXXXXXX")"\n  if ! env \\',
            "checker invalid epoch must fail",
        ),
        (
            "gitignore",
            ".claude/\n",
            ".claude/\nsrc/version.rs\n",
            "Git ignore matching permits src/version.rs",
        ),
        (
            "android_rust",
            '--user "$(id -u):$(id -g)"',
            '--user "0:0"',
            "Android target non-root user",
        ),
        (
            "docs",
            "required ext4 publication filesystem",
            "supported publication filesystem",
            "versioning transaction documentation",
        ),
        (
            "docs",
            "immediately before installation",
            "again after installation",
            "versioning transaction documentation",
        ),
        (
            "requirements",
            "FS_IOC_GETFSUUID",
            "f_fsid",
            "requirements release authority",
        ),
        (
            "requirements",
            "refuses any late content instead of traversing it",
            "recursively removes any late content",
            "requirements release authority",
        ),
        (
            "hardening",
            "Current `.6` source verdict (2026-07-14)",
            "Current `.6` source verdict (2026-07-13)",
            "hardening-status current release authority",
        ),
        (
            "changelog",
            "terminal privileged deletion instead of whole-workspace ownership normalization",
            "whole-workspace ownership normalization before deletion",
            "changelog current release authority",
        ),
        (
            "hardening",
            "hashes the complete bytes in memory",
            "executes the retained descriptor without re-authentication",
            "hardening-status current release authority",
        ),
        (
            "changelog",
            "host refuses late content before removing only the exact",
            "host recursively removes late content before deleting the",
            "changelog current release authority",
        ),
        (
            "requirements",
            "This is a current-release harness defect",
            "This is deferred upcoming-release lifecycle work",
            "requirements release authority",
        ),
        (
            "hardening",
            "does not close or advance the upcoming-release",
            "also closes the upcoming-release",
            "hardening-status current release authority",
        ),
        (
            "changelog",
            "installed service or close the separately tracked upcoming Linux service-child lifecycle redesign",
            "installed service and close the Linux service-child lifecycle redesign",
            "changelog current release authority",
        ),
        (
            "native_watch",
            "Requirements hash:",
            "Requirements digest:",
            "native-codec requirements hash is stale",
        ),
        ("version", "fork_version_real_date() {", "fork_version_date() {", "real calendar validation"),
    )
    for key, old, new, expected in mutations:
        offsets = mutation_offsets(sources[key], old)
        if not offsets:
            raise VerificationError(f"mutation fixture target is absent: {old}")
        if key in ("workspace_verifier", "finalizer"):
            candidates = python_mutation_scopes(sources[key], offsets)
        else:
            candidates = [(offset, f"line {sources[key].count(chr(10), 0, offset) + 1}") for offset in offsets]
        if not candidates:
            raise VerificationError(f"mutation fixture has no runtime target: {expected}")
        effective = []
        outcomes = []
        for offset, scope in candidates:
            changed = sources[key][:offset] + new + sources[key][offset + len(old):]
            mutated = dict(sources)
            mutated[key] = changed
            try:
                validate_sources(mutated)
            except VerificationError as exc:
                outcome = str(exc)
                outcomes.append((scope, outcome))
                if expected in outcome:
                    effective.append((offset, scope))
            else:
                outcomes.append((scope, "accepted"))
        if len(effective) != len(candidates):
            summary = "; ".join(f"{scope}: {outcome}" for scope, outcome in outcomes[:8])
            raise VerificationError(
                f"mutation fixture has {len(effective)} of {len(candidates)} effective runtime targets "
                f"for {expected} at {old[:120]!r}: {summary}"
            )


def validate_fixture_scratch(path):
    return ScratchRoot(path)


def run_fixture_stage(label, function, *arguments):
    try:
        return function(*arguments)
    except (OSError, UnicodeError, subprocess.TimeoutExpired, VerificationError) as exc:
        raise VerificationError(f"{label}: {exc}") from exc


def live_descriptor_inventory():
    descriptors = set()
    for name in os.listdir("/proc/self/fd"):
        if re.fullmatch(r"[0-9]+", name) is None:
            raise VerificationError("process descriptor inventory is malformed")
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            descriptors.add(descriptor)
    return descriptors


def exercise_scratch_acquisition_failures(scratch):
    global descriptor_mount_id
    with scratch.directory("constructor-failure-") as directory:
        path = directory.canonical_path()
        before = live_descriptor_inventory()
        original = descriptor_mount_id

        def reject_constructor_mount(descriptor):
            del descriptor
            raise VerificationError("injected scratch constructor mount failure")

        descriptor_mount_id = reject_constructor_mount
        try:
            try:
                ScratchRoot(path)
            except VerificationError as exc:
                if "injected scratch constructor mount failure" not in str(exc):
                    raise
            else:
                raise VerificationError("scratch constructor accepted a missing mount authority")
        finally:
            descriptor_mount_id = original
        if live_descriptor_inventory() != before:
            raise VerificationError("scratch constructor leaked a descriptor after acquisition failure")

    prefix = "child-acquisition-failure-"
    before = live_descriptor_inventory()
    original = descriptor_mount_id

    def reject_child_mount(descriptor):
        if descriptor == scratch.fd:
            return original(descriptor)
        raise VerificationError("injected scratch child mount failure")

    descriptor_mount_id = reject_child_mount
    try:
        try:
            with scratch.directory("child-acquisition-failure-"):
                pass
        except VerificationError as exc:
            if "injected scratch child mount failure" not in str(exc):
                raise
        else:
            raise VerificationError("scratch child accepted a missing mount authority")
    finally:
        descriptor_mount_id = original
    if live_descriptor_inventory() != before:
        raise VerificationError("scratch child leaked a descriptor after acquisition failure")
    retained = [name for name in os.listdir(scratch.fd) if name.startswith(prefix)]
    if len(retained) != 1:
        raise VerificationError("scratch child acquisition failure did not preserve one ambiguous edge")
    name = retained[0]
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=scratch.fd)
    try:
        metadata = os.fstat(child)
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or descriptor_mount_id(child) != scratch.mount_id
            or os.listdir(child)
        ):
            raise VerificationError("preserved scratch child acquisition state is not exact")
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=scratch.fd)
    scratch.assert_bound()


def exercise_scratch_external_link_rejection(scratch):
    external_name = f"external-link-{os.urandom(16).hex()}"
    try:
        try:
            with scratch.directory("external-link-rejection-") as directory:
                descriptor = os.open(
                    "payload",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory.fd,
                )
                try:
                    os.write(descriptor, b"retained\n")
                finally:
                    os.close(descriptor)
                os.link(
                    "payload",
                    external_name,
                    src_dir_fd=directory.fd,
                    dst_dir_fd=scratch.fd,
                    follow_symlinks=False,
                )
        except VerificationError as exc:
            if "linked outside its boundary" not in str(exc):
                raise
        else:
            raise VerificationError("scratch cleanup accepted an externally linked fixture inode")
        retained = [
            name for name in os.listdir(scratch.fd) if name.startswith("external-link-rejection-")
        ]
        if len(retained) != 1:
            raise VerificationError("scratch external-link fixture did not preserve its directory")
        child_name = retained[0]
        child_fd = os.open(
            child_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=scratch.fd,
        )
        try:
            payload = os.stat("payload", dir_fd=child_fd, follow_symlinks=False)
            external = os.stat(external_name, dir_fd=scratch.fd, follow_symlinks=False)
            if filesystem_identity(payload) != filesystem_identity(external) or payload.st_nlink != 2:
                raise VerificationError("scratch external-link fixture did not preserve exact inode state")
            os.unlink(external_name, dir_fd=scratch.fd)
            external_name = None
            scratch._assert_inode_closure(child_fd)
            scratch._remove_contents(child_fd, [131072])
        finally:
            os.close(child_fd)
        os.rmdir(child_name, dir_fd=scratch.fd)
    finally:
        if external_name is not None:
            try:
                os.unlink(external_name, dir_fd=scratch.fd)
            except FileNotFoundError:
                pass
    scratch.assert_bound()


def exercise_scratch_path_replacement(scratch):
    scratch.assert_bound()
    suffix = os.urandom(16).hex()
    live_name = None
    live_moved = None
    live_identity = None
    replacement_identity = None
    try:
        with scratch.directory("live-edge-") as directory:
            live_name = directory.name
            live_moved = f".{live_name}.moved-{suffix}"
            os.rename(live_name, live_moved, src_dir_fd=scratch.fd, dst_dir_fd=scratch.fd)
            live_identity = filesystem_identity(
                os.stat(live_moved, dir_fd=scratch.fd, follow_symlinks=False)
            )
            os.mkdir(live_name, 0o700, dir_fd=scratch.fd)
            replacement_identity = filesystem_identity(
                os.stat(live_name, dir_fd=scratch.fd, follow_symlinks=False)
            )
            result = run_managed_command(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-c",
                    "open(__import__('sys').argv[1], 'wb').write(b'descriptor-owned\\n')",
                    str(directory / "consumer-write"),
                ],
                Path("/"),
                timeout_seconds=5,
                cleanup_grace_seconds=1,
                kill_grace_seconds=2,
                inherited_fds=directory.inherited_fds,
            )
            if result.returncode != 0:
                raise VerificationError("scratch replacement fixture consumer command failed")
    except VerificationError as exc:
        if "fixture directory edge changed before cleanup" not in str(exc):
            raise
    else:
        raise VerificationError("scratch replacement fixture accepted a replaced live fixture edge")
    if live_name is None or live_moved is None or live_identity is None or replacement_identity is None:
        raise VerificationError("scratch replacement fixture did not establish live edge authority")
    replacement = os.stat(live_name, dir_fd=scratch.fd, follow_symlinks=False)
    displaced = os.stat(live_moved, dir_fd=scratch.fd, follow_symlinks=False)
    if (
        filesystem_identity(replacement) != replacement_identity
        or filesystem_identity(displaced) != live_identity
    ):
        raise VerificationError("scratch replacement fixture changed a rejected live directory")
    replacement_fd = os.open(
        live_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=scratch.fd
    )
    displaced_fd = os.open(
        live_moved, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=scratch.fd
    )
    try:
        if os.listdir(replacement_fd):
            raise VerificationError("scratch replacement fixture modified the replacement directory")
        if os.listdir(displaced_fd) != ["consumer-write"]:
            raise VerificationError("scratch replacement fixture missed the descriptor-owned directory")
        payload_fd = os.open("consumer-write", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=displaced_fd)
        try:
            if os.read(payload_fd, 64) != b"descriptor-owned\n" or os.read(payload_fd, 1):
                raise VerificationError("scratch replacement fixture consumer bytes differ")
        finally:
            os.close(payload_fd)
        os.unlink("consumer-write", dir_fd=displaced_fd)
    finally:
        os.close(displaced_fd)
        os.close(replacement_fd)
    os.rmdir(live_name, dir_fd=scratch.fd)
    os.rename(live_moved, live_name, src_dir_fd=scratch.fd, dst_dir_fd=scratch.fd)
    os.rmdir(live_name, dir_fd=scratch.fd)

    moved = f".{scratch.basename}.moved-{suffix}"
    external = f".{scratch.basename}.external-{suffix}"
    moved_identity = None
    external_identity = None
    try:
        os.rename(scratch.basename, moved, src_dir_fd=scratch.parent_fd, dst_dir_fd=scratch.parent_fd)
        moved_identity = filesystem_identity(
            os.stat(moved, dir_fd=scratch.parent_fd, follow_symlinks=False)
        )
        if moved_identity != scratch.identity:
            raise VerificationError("scratch replacement fixture moved the wrong inode")
        os.mkdir(external, 0o700, dir_fd=scratch.parent_fd)
        external_identity = filesystem_identity(
            os.stat(external, dir_fd=scratch.parent_fd, follow_symlinks=False)
        )
        os.symlink(external, scratch.basename, dir_fd=scratch.parent_fd)
        try:
            with scratch.directory("replacement-proof-"):
                pass
        except VerificationError:
            pass
        else:
            raise VerificationError("scratch replacement fixture accepted a replaced pathname edge")
        external_fd = os.open(
            external,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=scratch.parent_fd,
        )
        try:
            if os.listdir(external_fd):
                raise VerificationError("scratch replacement fixture wrote through the replacement symlink")
        finally:
            os.close(external_fd)
        os.unlink(scratch.basename, dir_fd=scratch.parent_fd)
        os.rename(moved, scratch.basename, src_dir_fd=scratch.parent_fd, dst_dir_fd=scratch.parent_fd)
        moved_identity = None
        os.rmdir(external, dir_fd=scratch.parent_fd)
        external_identity = None
        with scratch.directory("replacement-proof-") as directory:
            (directory / "descriptor-bound").write_bytes(b"bound\n")
    finally:
        try:
            current = os.stat(scratch.basename, dir_fd=scratch.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and stat.S_ISLNK(current.st_mode):
            os.unlink(scratch.basename, dir_fd=scratch.parent_fd)
            current = None
        if moved_identity is not None:
            moved_current = os.stat(moved, dir_fd=scratch.parent_fd, follow_symlinks=False)
            if filesystem_identity(moved_current) != moved_identity or current is not None:
                raise VerificationError("scratch replacement fixture cannot restore its recorded root")
            os.rename(moved, scratch.basename, src_dir_fd=scratch.parent_fd, dst_dir_fd=scratch.parent_fd)
        if external_identity is not None:
            external_current = os.stat(external, dir_fd=scratch.parent_fd, follow_symlinks=False)
            if filesystem_identity(external_current) != external_identity:
                raise VerificationError("scratch replacement fixture external identity changed")
            external_fd = os.open(
                external,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=scratch.parent_fd,
            )
            try:
                if os.listdir(external_fd):
                    raise VerificationError("scratch replacement fixture external directory is not empty")
            finally:
                os.close(external_fd)
            os.rmdir(external, dir_fd=scratch.parent_fd)
        scratch.assert_bound()


def main():
    global _VERIFIER_PROGRAM_FD
    parser = argparse.ArgumentParser(description="Verify private workspace and release transactions.")
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="run executable and mutation fixtures")
    parser.add_argument("--scratch", help="preallocated private fixture scratch directory")
    parser.add_argument("--publication-worker-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--publication-worker-gate-fd", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.publication_worker_fd is not None:
        if args.self_test or args.scratch is not None or args.repo != ".":
            parser.error("publication worker mode cannot be combined with verifier options")
        return run_publication_snapshot_worker(
            args.publication_worker_fd, args.publication_worker_gate_fd
        )
    if args.publication_worker_gate_fd is not None:
        parser.error("publication worker gate requires publication worker mode")
    scratch = None
    verifier_program_fd = None
    failure = None
    try:
        repo = Path(args.repo).resolve()
        verifier_program_source, verifier_program_fd = acquire_verifier_program(repo)
        _VERIFIER_PROGRAM_FD = verifier_program_fd
        if args.self_test:
            if args.scratch is None:
                raise VerificationError("verifier self-test requires an owned --scratch directory")
            scratch = validate_fixture_scratch(Path(args.scratch))
        elif args.scratch is not None:
            raise VerificationError("--scratch is valid only with --self-test")
        lines, positions = validate_verify_workspace((repo / "scripts/verify.sh").read_text(encoding="utf-8"))
        sources = {
            "build": (repo / "scripts/build-release.sh").read_text(encoding="utf-8"),
            "scan": (repo / "scripts/verify-scan.sh").read_text(encoding="utf-8"),
            "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
            "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
            "release": (repo / "scripts/verify-release.sh").read_text(encoding="utf-8"),
            "smoke": (repo / "scripts/smoke-server.sh").read_text(encoding="utf-8"),
            "smoke_stage": (repo / "scripts/smoke-server-stage.sh").read_text(encoding="utf-8"),
            "smoke_stage_mode": os.lstat(repo / "scripts/smoke-server-stage.sh").st_mode,
            "service_lifecycle": (repo / "scripts/smoke-service-lifecycle.sh").read_text(encoding="utf-8"),
            "service_lifecycle_mode": os.lstat(repo / "scripts/smoke-service-lifecycle.sh").st_mode,
            "debian_sysv_lifecycle": (repo / "scripts/smoke-debian-sysv-lifecycle.sh").read_text(encoding="utf-8"),
            "debian_sysv_lifecycle_mode": os.lstat(repo / "scripts/smoke-debian-sysv-lifecycle.sh").st_mode,
            "systemd_smoke_host": (repo / "scripts/smoke-debian-systemd-lifecycle.sh").read_text(encoding="utf-8"),
            "systemd_smoke_host_mode": os.lstat(repo / "scripts/smoke-debian-systemd-lifecycle.sh").st_mode,
            "systemd_smoke_guest": (repo / "scripts/smoke-debian-systemd-lifecycle-guest.sh").read_text(encoding="utf-8"),
            "systemd_smoke_guest_mode": os.lstat(repo / "scripts/smoke-debian-systemd-lifecycle-guest.sh").st_mode,
            "systemd_smoke_loginctl": (repo / "scripts/smoke-debian-systemd-loginctl.sh").read_text(encoding="utf-8"),
            "systemd_smoke_loginctl_mode": os.lstat(repo / "scripts/smoke-debian-systemd-loginctl.sh").st_mode,
            "online_fetch": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
            "loginctl_fixture": (repo / "scripts/smoke-service-loginctl.sh").read_text(encoding="utf-8"),
            "loginctl_fixture_mode": os.lstat(repo / "scripts/smoke-service-loginctl.sh").st_mode,
            "smoke_process_guard": (repo / "scripts/smoke-process-guard.py").read_text(encoding="utf-8"),
            "smoke_process_guard_mode": os.lstat(repo / "scripts/smoke-process-guard.py").st_mode,
            "smoke_launcher": (repo / "scripts/smoke-server-launcher.c").read_text(encoding="utf-8"),
            "smoke_ready": (repo / "scripts/smoke-ready.sh").read_text(encoding="utf-8"),
            "smoke_ready_mode": os.lstat(repo / "scripts/smoke-ready.sh").st_mode,
            "smoke_typed_probe": (repo / "examples/smoke_readiness.rs").read_text(encoding="utf-8"),
            "session_probe": (repo / "examples/probe_client.rs").read_text(encoding="utf-8"),
            "ipc_source": (repo / "src/ipc.rs").read_text(encoding="utf-8"),
            "faillo": (repo / "scripts/test-build-faillo.sh").read_text(encoding="utf-8"),
            "closure": (repo / "scripts/verify-private-tree-closure.py").read_text(encoding="utf-8"),
            "finalizer": (repo / "scripts/finalize-release-set.py").read_text(encoding="utf-8"),
            "publish": (repo / "scripts/publish-github-release.sh").read_text(encoding="utf-8"),
            "version": (repo / "scripts/fork-version.sh").read_text(encoding="utf-8"),
            "build_rs": (repo / "build.rs").read_text(encoding="utf-8"),
            "root_cargo": (repo / "Cargo.toml").read_text(encoding="utf-8"),
            "root_lib": (repo / "src/lib.rs").read_text(encoding="utf-8"),
            "hbb_common_lib": (repo / "libs/hbb_common/src/lib.rs").read_text(encoding="utf-8"),
            "core_main": (repo / "src/core_main.rs").read_text(encoding="utf-8"),
            "common_source": (repo / "src/common.rs").read_text(encoding="utf-8"),
            "linux_source": (repo / "src/platform/linux.rs").read_text(encoding="utf-8"),
            "gitignore": (repo / ".gitignore").read_text(encoding="utf-8"),
            "android_rust": (repo / "scripts/android-rust-check.sh").read_text(encoding="utf-8"),
            "version_metadata_checker": (repo / "scripts/version-metadata-check.sh").read_text(encoding="utf-8"),
            "version_metadata_checker_mode": os.lstat(repo / "scripts/version-metadata-check.sh").st_mode,
            "debian": (repo / "scripts/build-debian.sh").read_text(encoding="utf-8"),
            "android": (repo / "scripts/build-android.sh").read_text(encoding="utf-8"),
            "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
            "docs": (repo / "docs/VERSIONING.md").read_text(encoding="utf-8"),
            "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
            "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
            "changelog": (repo / "CHANGELOG.md").read_text(encoding="utf-8"),
            "native_watch": (repo / "docs/NATIVE-CODEC-WATCH.md").read_text(encoding="utf-8"),
            "workspace_verifier": verifier_program_source,
        }
        validate_sources(sources)
        if args.self_test:
            run_fixture_stage("scratch acquisition fixture", exercise_scratch_acquisition_failures, scratch)
            run_fixture_stage("scratch hardlink fixture", exercise_scratch_external_link_rejection, scratch)
            run_fixture_stage("scratch replacement fixture", exercise_scratch_path_replacement, scratch)
            run_fixture_stage("publication snapshot fixture", exercise_canonical_publication_snapshot, scratch)
            run_fixture_stage("workspace mutation fixture", run_workspace_mutations, lines, positions)
            run_fixture_stage("source mutation fixture", run_source_mutations, sources)
            run_fixture_stage("version fixture", run_version_fixtures, sources["version"], scratch)
            run_fixture_stage("target-contract fixture", run_target_contract_fixtures, sources, scratch)
            run_fixture_stage("managed lifecycle fixture", run_stateful_timeout_fixtures, repo, scratch)
            run_fixture_stage("transaction fixture", run_transaction_fixtures, repo)
            closure = run_managed_command(
                [
                    "/usr/bin/python3",
                    str(repo / "scripts/verify-private-tree-closure.py"),
                    "--self-test",
                    "--scratch-fd",
                    str(scratch.fd),
                ],
                repo,
                timeout_seconds=90,
                cleanup_grace_seconds=5,
                kill_grace_seconds=2,
                inherited_fds=(scratch.fd,),
            )
            require_success(closure, "private-tree closure fixture", "")
    except ManagedSignal as exc:
        failure = (128 + exc.signum, f"interrupted by signal {exc.signum}")
    except (OSError, UnicodeError, subprocess.TimeoutExpired, VerificationError) as exc:
        failure = (1, f"FAIL: {exc}")
    finally:
        if verifier_program_fd is not None:
            descriptor = verifier_program_fd
            verifier_program_fd = None
            _VERIFIER_PROGRAM_FD = None
            try:
                os.close(descriptor)
            except OSError as exc:
                if failure is None:
                    failure = (1, f"FAIL: {exc}")
                else:
                    failure = (failure[0], f"{failure[1]}; verifier program cleanup failed: {exc}")
        if scratch is not None:
            try:
                scratch.close()
            except (OSError, VerificationError) as exc:
                if failure is None:
                    failure = (1, f"FAIL: {exc}")
                else:
                    failure = (failure[0], f"{failure[1]}; scratch cleanup failed: {exc}")
    if failure is not None:
        print(f"verify-verifier-workspace: {failure[1]}", file=sys.stderr)
        return failure[0]
    print("verify-verifier-workspace: ok")
    return 0


def validate_workspace_verifier_self_contract(source):
    try:
        module = ast.parse(source)
    except SyntaxError as exc:
        raise VerificationError(f"managed command signal ownership: Python source does not parse: {exc}") from exc
    readiness_mode_validator = extract_python_definition(
        source,
        module,
        "smoke_readiness_mode_is_valid",
        "private release-snapshot readiness executable mode",
    )
    require_text(
        readiness_mode_validator,
        "stat.S_IMODE(mode) in (0o700, 0o755)",
        "private release-snapshot readiness executable mode",
    )
    signal_assignments = [
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "MANAGED_SIGNALS" for target in node.targets)
    ]
    expected_signals = ast.parse(
        "MANAGED_SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)"
    ).body[0].value
    if len(signal_assignments) != 1 or ast.dump(signal_assignments[0].value) != ast.dump(expected_signals):
        raise VerificationError("managed command signal ownership: exact managed signal set is absent")
    temporary_directories = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "tempfile"
        and node.func.attr == "TemporaryDirectory"
    ]
    tempfile_imports = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Import)
        and any(alias.name == "tempfile" for alias in node.names)
    ]
    if temporary_directories or tempfile_imports:
        raise VerificationError("verifier retains pathname temporary-directory authority")
    scratch_directories = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "scratch"
        and node.func.attr == "directory"
    ]
    if not scratch_directories:
        raise VerificationError("verifier has no descriptor-owned scratch allocation")
    for call in scratch_directories:
        if (
            len(call.args) != 1
            or call.keywords
            or not isinstance(call.args[0], ast.Constant)
            or not isinstance(call.args[0].value, str)
            or re.fullmatch(r"[a-z0-9-]+", call.args[0].value) is None
        ):
            raise VerificationError("verifier fixture scratch allocation is not a literal bounded prefix")
    parents = {}
    for parent in ast.walk(module):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def enclosing_function(node):
        current = parents.get(node)
        while current is not None and not isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current = parents.get(current)
        return None if current is None else current.name

    allowed_subprocess_calls = {
        ("run_systemd_control", "run"),
    }
    for node in ast.walk(module):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr in ("run", "Popen")
        ):
            continue
        owner = enclosing_function(node)
        if (owner, node.func.attr) not in allowed_subprocess_calls:
            raise VerificationError(
                f"unmanaged subprocess execution remains in {owner or '<module>'}"
            )
    systemd_control_owners = [
        enclosing_function(node)
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_systemd_control"
    ]
    if systemd_control_owners != ["systemd_unit_properties"]:
        raise VerificationError("name-based systemd destructive action exclusion")
    if any(isinstance(node, ast.FunctionDef) and node.name == "run_command" for node in module.body):
        raise VerificationError("verifier retains an unmanaged fixture command runner")
    signal_boundary = extract_between(
        source,
        "def handle_managed_signal(",
        "\n\ndef close_process_pipes(",
        "managed verifier signal boundary",
    )
    managed_support = extract_between(
        source,
        "def close_process_pipes(",
        "\n\ndef run_managed_command(",
        "managed verifier cgroup authority",
    )
    managed = extract_between(
        source,
        "def run_managed_command(",
        "\n\nclass StatxTimestamp(",
        "managed verifier command runner",
    )
    publication_state = extract_between(
        source,
        "class StatxTimestamp(",
        "\n\ndef reserved_release_state(",
        "canonical publication-state snapshot",
    )
    reserved_state = extract_between(
        source,
        "def reserved_release_state(",
        "\n\ndef assert_reserved_release_state_unchanged(",
        "reserved release-state snapshot",
    )
    state_proof = extract_between(
        source,
        "def assert_reserved_release_state_unchanged(",
        "\n\ndef run_stateful_command(",
        "stateful reserved release-state proof",
    )
    stateful = extract_between(
        source,
        "def run_stateful_command(",
        "\n\ndef assert_process_absent(",
        "stateful verifier command runner",
    )
    transactions = extract_between(
        source,
        "def run_transaction_fixtures(repo):",
        "\n\ndef run_version_fixtures(",
        "stateful transaction fixture dispatch",
    )
    timeout_fixtures = extract_between(
        source,
        "def run_stateful_timeout_fixtures(repo, scratch):",
        "\n\ndef require_success(",
        "stateful timeout behavioral fixtures",
    )
    target_contract_fixtures = extract_python_definition(
        source,
        module,
        "run_target_contract_fixtures",
        "target-contract behavioral fixtures",
    )
    version_fixtures = "\n".join(
        extract_python_definition(source, module, name, "fork-version behavioral fixtures")
        for name in (
            "run_fork_version_fixture",
            "run_hostile_fork_version_fixture",
            "run_version_fixtures",
        )
    )
    scratch_acquisition_fixtures = extract_python_definition(
        source,
        module,
        "exercise_scratch_acquisition_failures",
        "scratch acquisition behavioral fixtures",
    )
    scratch_replacement_fixtures = extract_python_definition(
        source,
        module,
        "exercise_scratch_path_replacement",
        "scratch replacement behavioral fixtures",
    )
    main = extract_python_definition(
        source, module, "main", "verifier main dispatch"
    )
    scratch_validator = "\n".join(
        extract_python_definition(
            source, module, name, "verifier descriptor-bound scratch authority"
        )
        for name in (
            "directory_is_empty",
            "bounded_directory_names",
            "ScratchDirectory",
            "ScratchRoot",
            "validate_fixture_scratch",
        )
    )
    scratch_cleanup = extract_python_method(
        source, module, "ScratchRoot", "_remove_contents", "fixture cleanup traversal"
    )
    scratch_inode_closure = extract_python_method(
        source,
        module,
        "ScratchRoot",
        "_collect_inode_links",
        "fixture inode-closure traversal",
    )
    for method, label in (
        (scratch_cleanup, "fixture cleanup mount-boundary proof"),
        (scratch_inode_closure, "fixture inode-closure mount-boundary proof"),
    ):
        require_text(method, "descriptor_mount_id(authority_fd) != self.mount_id", label)
    bounded_cleanup_inventory = extract_python_definition(
        source,
        module,
        "bounded_directory_names",
        "fixture bounded cleanup inventory",
    )
    require_order(
        signal_boundary,
        (
            'state["caught"] = True',
            'if state["acquiring_process"]:',
            'state["pending_signum"] = signum',
            "return",
            "signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            "raise ManagedSignal(signum)",
            "def enter_managed_signal_scope():",
            "if threading.current_thread() is not threading.main_thread():",
            "entry_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            'return {"entry_mask": entry_mask, "outer": False}',
            "signal.signal(signum, handle_managed_signal)",
            "_MANAGED_SIGNAL_STATE = state",
            "def activate_managed_signal_scope(scope):",
            'signal.pthread_sigmask(signal.SIG_SETMASK, scope["entry_mask"])',
            "def begin_managed_process_acquisition():",
            'state["acquiring_process"] = True',
            "def finish_managed_process_acquisition():",
            "previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            'state["acquiring_process"] = False',
            'pending_signum = state["pending_signum"]',
            "return pending_signum",
            "def leave_managed_signal_scope(scope, finalization_mask):",
            'if state["caught"]:',
            "signal.signal(signum, signal.SIG_IGN)",
            "signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)",
            "signal.signal(signum, handler)",
            "_MANAGED_SIGNAL_STATE = None",
            "signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)",
        ),
        "managed command signal ownership",
    )
    managed_functions = [
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_managed_command"
    ]
    if len(managed_functions) != 1:
        raise VerificationError("managed command cgroup ownership: expected one runner")
    managed_function = managed_functions[0]
    unacquired_cleanup = extract_python_definition(
        source,
        module,
        "resolve_unacquired_unit",
        "unacquired launcher cleanup ordering",
    )
    unacquired_authentication = extract_python_definition(
        source,
        module,
        "authenticate_unacquired_unit",
        "unacquired authority cleanup",
    )
    target_backstop = extract_python_definition(
        source, module, "kill_observed_target", "unacquired target pidfd backstop"
    )
    launcher_cleanup = extract_python_definition(
        source,
        module,
        "terminate_and_reap_unacquired_launcher",
        "unacquired launcher cleanup",
    )
    managed_finalization = extract_python_definition(
        source, module, "finalize_managed_unit", "managed cleanup accumulator"
    )
    managed_finalization_functions = [
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "finalize_managed_unit"
    ]
    if len(managed_finalization_functions) != 1:
        raise VerificationError("managed cleanup accumulator: expected one finalizer")
    finalization_reports = [
        node
        for node in ast.walk(managed_finalization_functions[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "report_cleanup_failures"
    ]
    if (
        len(finalization_reports) != 1
        or len(finalization_reports[0].args) != 3
        or finalization_reports[0].keywords
        or not isinstance(finalization_reports[0].args[0], ast.Constant)
        or finalization_reports[0].args[0].value is not None
        or not isinstance(finalization_reports[0].args[1], ast.Constant)
        or finalization_reports[0].args[1].value
        != "managed-command unit finalization failed"
        or not isinstance(finalization_reports[0].args[2], ast.Name)
        or finalization_reports[0].args[2].id != "failures"
    ):
        raise VerificationError(
            "managed cleanup accumulator does not report the complete failure list"
        )
    require_order(
        unacquired_cleanup,
        (
            "authority = authenticate_unacquired_unit(unit, description, environment)",
            "hard_kill_cgroup(authority)",
            "terminate_and_reap_unacquired_launcher(process)",
            "while True:",
            "if invocation is None:",
            "authority = authenticate_unacquired_unit(unit, description, environment)",
            "hard_kill_cgroup(authority)",
            "finally:",
            '"unacquired cgroup authority close"',
            "close_cgroup_authority",
            '"unacquired target termination"',
            "kill_observed_target",
            "if not launcher_reaped:",
            '"unacquired launcher termination and reap"',
            "terminate_and_reap_unacquired_launcher",
            "report_cleanup_failures(",
        ),
        "unacquired launcher cleanup ordering",
    )
    for text, label in (
        ("except BaseException as primary_error:", "unacquired authentication primary-error preservation"),
        ("attempt_cleanup(", "unacquired authentication cleanup accumulator"),
        ("close_cgroup_authority", "unacquired authentication authority close"),
        ("report_cleanup_failures(", "unacquired authentication cleanup reporting"),
    ):
        require_text(unacquired_authentication, text, label)
    require_text(
        target_backstop,
        "signal.pidfd_send_signal(target_pidfd, signal.SIGKILL)",
        "unacquired target pidfd backstop",
    )
    require_order(
        launcher_cleanup,
        (
            "process.terminate()",
            "process.wait(timeout=1)",
            "process.kill()",
            "process.wait()",
            "if process.returncode is None:",
            "report_cleanup_failures(",
        ),
        "unacquired launcher exact reap",
    )
    require_order(
        managed_finalization,
        (
            '"managed cgroup forced termination"',
            "hard_kill_cgroup",
            '"managed launcher termination and reap"',
            "terminate_and_reap_unacquired_launcher",
            '"managed cgroup authority close"',
            "close_cgroup_authority",
            "while True:",
            '"managed unit collection"',
            "os.path.lexists(control_group_path)",
            '"managed cgroup pathname absence"',
            "report_cleanup_failures(",
        ),
        "managed cleanup accumulator",
    )
    require_text(
        timeout_fixtures,
        "managed finalization accumulator fixture did not exhaust cleanup",
        "managed finalization accumulator behavioral fixture",
    )
    exact_spawn_calls = [
        node
        for node in ast.walk(managed_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "spawn_exact_process"
    ]
    if len(exact_spawn_calls) != 1 or not any(
        isinstance(node, ast.Try) for node in managed_function.body
    ):
        raise VerificationError("managed command cgroup ownership: launcher escapes its teardown try")
    managed_contract = managed_support + managed
    if ".read(max_output_bytes + 1)" in managed:
        raise VerificationError("managed command performs an unbounded post-exit pipe read")
    require_exact_count(
        managed,
        "owned_authority = authority",
        2,
        "managed finalization authority handoff",
    )
    for text, label in (
        ('"/usr/bin/systemd-run"', "fixed systemd-run authority"),
        ('"/usr/bin/systemctl"', "fixed systemctl authority"),
        ('"--scope"', "transient scope execution"),
        ('"--collect"', "transient scope collection"),
        ('"--expand-environment=no"', "systemd environment expansion exclusion"),
        ('"--property=Delegate=no"', "cgroup delegation exclusion"),
        ('"--property=KillMode=control-group"', "whole-cgroup systemd signaling"),
        ('"--property=FinalKillSignal=SIGKILL"', "systemd hard-kill backstop"),
        ('"--property=RuntimeMaxSec={runtime_limit}s"', "parent-death runtime backstop"),
        ('"TimeoutStopUSec"', "authenticated stop-duration property"),
        ('"RuntimeMaxUSec"', "authenticated runtime-duration property"),
        ('parse_systemd_second_duration(properties["TimeoutStopUSec"]) != stop_limit', "exact stop-duration policy"),
        ('parse_systemd_second_duration(properties["RuntimeMaxUSec"]) != runtime_limit', "exact runtime-duration policy"),
        ('pwd.getpwuid(os.geteuid()).pw_dir', "fixed current-principal control HOME"),
        ('os.O_DIRECTORY | os.O_NOFOLLOW', "descriptor cgroup walk"),
        ('os.open("cgroup.events"', "retained cgroup population authority"),
        ('os.open("cgroup.kill"', "retained cgroup kill authority"),
        ('os.open("cgroup.procs"', "retained cgroup process inventory authority"),
        ('cgroup_type != b"domain\\n"', "domain cgroup proof"),
        ('process_cgroup != f"0::{properties[\'ControlGroup\']}\\n"', "gated process cgroup membership"),
        ('repeated["InvocationID"] != properties["InvocationID"]', "unit acquisition identity stability"),
        ('os.write(authority["kill"], b"1")', "exact cgroup.kill operation"),
        ('wait_cgroup_empty(authority)', "unbounded recursive cgroup emptiness proof"),
        ('if os.path.lexists(control_group_path):', "collected cgroup pathname absence"),
        ('properties["InvocationID"] != invocation', "collected unit replacement rejection"),
        ('def resolve_unacquired_unit(', "synchronous unacquired-unit resolution"),
        ('authority = authenticate_unacquired_unit(unit, description, environment)', "unacquired cgroup authority reacquisition"),
        ('kill_observed_target(target_pidfd)', "unacquired target pidfd backstop dispatch"),
        ('terminate_and_reap_unacquired_launcher(process)', "unacquired launcher reap"),
        ('unacquired managed-command unit was replaced during cleanup', "unacquired unit replacement rejection"),
        ('signal.pidfd_send_signal(pidfd, numeric_signal)', "pidfd-bound graceful signaling"),
        ('"managed unit graceful shutdown"', "graceful exceptional managed cleanup"),
        ('socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC', "managed descriptor control channel"),
        ('socket.SCM_RIGHTS', "managed descriptor rights transfer"),
        ('"descriptors": list(normalized_fds)', "managed descriptor allowlist frame"),
        ('os.dup2(descriptor, target, inheritable=True)', "managed descriptor inheritance restoration"),
        ('control_socket.sendmsg([frame], controls)', "managed descriptor handoff"),
    ):
        require_text(managed_contract, text, label)
    require_text(managed, "if len(inherited_fds) > 64:", "managed descriptor count bound")
    require_text(managed, "or descriptor > 1048575", "managed descriptor number bound")
    private_descriptor_acquisition = extract_python_definition(
        source, module, "acquire_private_descriptors", "private managed descriptor acquisition"
    )
    require_text(
        private_descriptor_acquisition,
        "duplicate = os.dup(descriptor)",
        "private managed descriptor duplication",
    )
    require_text(
        managed,
        '"unacquired managed unit resolution",\n                resolve_unacquired_unit,',
        "unacquired gate retained through cgroup reacquisition",
    )
    require_text(
        managed,
        '"managed unit graceful shutdown",\n                gracefully_stop_managed_unit,',
        "graceful exceptional managed cleanup",
    )
    require_order(
        managed,
        (
            "descriptor_authority = acquire_private_descriptors(normalized_fds)",
            'for tool in ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/python3"):',
            "process = None",
            "authority = None",
            "try:",
            "signal_scope = enter_managed_signal_scope()",
            "activate_managed_signal_scope(signal_scope)",
            "begin_managed_process_acquisition()",
            "acquisition_active = True",
            "process = spawn_exact_process(",
            "child_socket.fileno()",
            "target_pid = read_managed_ready(",
            "target_pidfd = os.pidfd_open(target_pid, 0)",
            "authority = authenticate_managed_unit(",
            "acquisition_active = False",
            "finish_managed_process_acquisition()",
            "control_socket.sendmsg([frame], controls)",
            'selector.register(target_pidfd, selectors.EVENT_READ, "target")',
            "gracefully_stop_managed_unit(",
            "hard_kill_cgroup(authority)",
            "process, owned_authority, control_environment",
            "finally:",
            '"managed process pipe close before shutdown"',
            '"managed unit graceful shutdown"',
            '"managed unit forced finalization"',
            '"unacquired managed unit resolution"',
            '"managed control socket close"',
            '"managed child socket close"',
            '"managed selector close"',
            '"managed target pidfd close"',
            '"managed process pipe close"',
            '"managed private descriptor close"',
            "if acquisition_active:",
            '"managed process acquisition finish"',
            '"managed signal-scope release"',
            '"managed signal-mask restoration"',
            "report_cleanup_failures(",
        ),
        "managed command cgroup ownership",
    )
    gate_helper = extract_between(
        managed_support,
        "MANAGED_GATE_HELPER = r'''",
        "\n'''\n\n\ndef require_system_tool(",
        "managed descriptor gate helper",
    )
    cgroup_close = extract_python_definition(
        source, module, "close_cgroup_authority", "managed cgroup descriptor finalizer"
    )
    cgroup_open = extract_python_definition(
        source, module, "open_cgroup_authority", "managed cgroup authority acquisition"
    )
    hard_kill = extract_python_definition(
        source, module, "hard_kill_cgroup", "recursive cgroup emptiness proof"
    )
    require_text(
        hard_kill,
        "wait_cgroup_empty(authority)",
        "recursive cgroup emptiness proof",
    )
    require_text(
        cgroup_close,
        'for name in ("events", "kill", "processes", "directory"):',
        "exhaustive cgroup descriptor close",
    )
    for text, label in (
        ('os.open("cgroup.controllers"', "cgroup-v2 controller authority"),
        ('os.open("cgroup.type"', "cgroup type authority"),
        ('"cgroup type descriptor"', "cgroup type descriptor cleanup"),
        ('"cgroup controller descriptor"', "cgroup controller descriptor cleanup"),
        ('"cgroup processes descriptor"', "cgroup process descriptor cleanup"),
        ('"cgroup kill descriptor"', "cgroup kill descriptor cleanup"),
        ('"cgroup events descriptor"', "cgroup event descriptor cleanup"),
        ('"cgroup directory descriptor"', "cgroup directory descriptor cleanup"),
        ("attempt_cleanup(", "cgroup acquisition cleanup accumulator"),
        ("report_cleanup_failures(", "cgroup acquisition cleanup reporting"),
    ):
        require_text(cgroup_open, text, label)
    process_cgroup_reader = extract_python_definition(
        source, module, "read_process_cgroup", "managed process cgroup reader"
    )
    for text, label in (
        ("os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC", "no-follow process cgroup read"),
        ("content = os.read(descriptor, 4097)", "bounded process cgroup read"),
        ("if len(content) > 4096:", "process cgroup overflow rejection"),
    ):
        require_text(process_cgroup_reader, text, label)
    require_exact_count(
        managed_support,
        "read_process_cgroup(",
        3,
        "descriptor-bound process cgroup inspection",
    )
    if 'Path(f"/proc/{' in managed_support:
        raise VerificationError("managed process cgroup inspection retains an unbounded pathname read")
    exact_spawn = extract_python_definition(
        source, module, "spawn_exact_process", "exact child process creation"
    )
    for text, label in (
        ("threading.active_count() != 1", "single-threaded exact fork boundary"),
        ("require_single_native_thread()", "native single-threaded exact fork boundary"),
        ("signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)", "pre-fork signal exclusion"),
        ("pid = os.fork()", "immediate child PID authority"),
        ("set_child_parent_death_signal(parent_pid)", "exact child parent-death backstop"),
        ("signal.signal(signum, signal.SIG_DFL)", "exact child default signal disposition"),
        ("os.setsid()", "exact child process session ownership"),
        ("close_unlisted_child_descriptors(inherited, inherited_identities)", "post-fork exact child descriptor closure"),
        ("target_mask = set(previous_mask) - set(MANAGED_SIGNALS)", "exact child managed-signal unblocking"),
        ("os.execve(command[0], command, environment)", "exact child executable boundary"),
        ('state["acquiring_process_object"] = process', "pre-return child authority publication"),
    ):
        require_text(exact_spawn, text, label)
    for text, label in (
        ("or descriptor > 1048575", "managed descriptor number bound"),
        (
            "signal.pthread_sigmask(signal.SIG_UNBLOCK, (signal.SIGHUP, signal.SIGINT, signal.SIGTERM))",
            "managed target signal-mask reset",
        ),
        (
            "if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(data) % descriptor_size:",
            "managed descriptor control validation",
        ),
        (
            'if len(received) != len(payload["descriptors"]):',
            "managed descriptor count equality",
        ),
        ("socket.MSG_CMSG_CLOEXEC", "managed descriptor receive close-on-exec"),
        (
            "duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)",
            "managed descriptor collision isolation",
        ),
        (
            "os.dup2(descriptor, target, inheritable=True)",
            "managed descriptor inheritance restoration",
        ),
    ):
        require_text(gate_helper, text, label)
    require_order(
        gate_helper,
        (
            "descriptor_capacity = 64",
            "channel.recvmsg(",
            "socket.CMSG_SPACE(descriptor_capacity * descriptor_size)",
            "socket.MSG_CMSG_CLOEXEC",
            "flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)",
            'set(payload) != {"token", "environment", "descriptors"}',
            'len(payload["descriptors"]) > descriptor_capacity',
            "or descriptor > 1048575",
            'len(set(payload["descriptors"])) != len(payload["descriptors"])',
            "for level, kind, data in controls:",
            "level != socket.SOL_SOCKET",
            "kind != socket.SCM_RIGHTS",
            'len(received) != len(payload["descriptors"])',
            'targets = set(payload["descriptors"])',
            "for descriptor in received:",
            "duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)",
            "if duplicate in targets:",
            "reservations.append(duplicate)",
            "temporary.append(duplicate)",
            "os.close(descriptor)",
            "for descriptor in reservations:",
            'for descriptor, target in zip(temporary, payload["descriptors"]):',
            "os.dup2(descriptor, target, inheritable=True)",
            "channel.close()",
            'os.execve(command[0], command, environment)',
        ),
        "managed descriptor gate contract",
    )
    require_order(
        stateful,
        (
            "signal_scope = None",
            "try:",
            "signal_scope = enter_managed_signal_scope()",
            "activate_managed_signal_scope(signal_scope)",
            "before = reserved_release_state(cwd)",
            "try:",
            "result = run_managed_command(",
            "except BaseException as exc:",
            "assert_reserved_release_state_unchanged(before, cwd, execution_error)",
            "except ManagedSignal:",
            "assert_reserved_release_state_unchanged(before, cwd)",
            "finally:",
            "leave_managed_signal_scope(signal_scope, finalization_mask)",
        ),
        "stateful release-state proof",
    )
    require_order(
        state_proof,
        (
            "after = reserved_release_state(cwd)",
            "if after != before:",
            '"new_directories"',
            '"changed_directories"',
            '"canonical_publication_changed"',
            "raise state_error",
        ),
        "stateful release-state proof",
    )
    for text, label in (
        ("stateful fixture changed reserved release state", "stateful reserved-state mismatch rejection"),
        ("managed command output exceeds its bound", "managed command output bound"),
        ("managed command exited while cgroup descendants remained", "normal-exit descendant rejection"),
        ("wait_cgroup_empty(authority)", "unbounded managed cgroup drain"),
    ):
        require_text(source, text, label)
    require_text(
        transactions,
        "result = run_stateful_command([str(path), mode], repo, poison)",
        "transaction fixtures use the stateful runner",
    )
    require_text(
        transactions,
        "bypass = run_stateful_command(",
        "explicit-Bash transaction fixtures use the stateful runner",
    )
    for text, label in (
        (
            "cgroup descriptor close fixture did not exhaust its authority",
            "cgroup descriptor close fixture",
        ),
        (
            "managed descriptor handoff leaked a private descriptor",
            "managed descriptor leak fixture",
        ),
        ("STATEFUL-POST-SPAWN-CLEANUP", "post-spawn exception cleanup fixture"),
        ("def signal_before_spawn_return", "pre-assignment managed signal fixture"),
        ('globals()["spawn_exact_process"] = signal_before_spawn_return', "pre-assignment managed signal fixture"),
        (
            "handle_managed_signal(signal.SIGTERM, None)",
            "pre-assignment managed signal injection",
        ),
        ("pre-assignment managed signal retained", "pre-assignment cgroup absence proof"),
        ('assert_process_absent(descendant_pid, "stateful parent-signal descendant")', "external parent-signal cleanup fixture"),
        ("stateful parent-signal fixture skipped graceful target cleanup", "external-signal graceful cleanup proof"),
        ("STATEFUL-GRACEFUL-CLEANUP", "graceful cgroup cleanup fixture"),
        ("STATEFUL-RESISTANT-CHILD", "hard-kill cgroup cleanup fixture"),
        ("STATEFUL-LINGERING-CHILD", "normal-exit lingering cgroup fixture"),
        ('with scratch.directory("double-fork-")', "double-fork cgroup fixture"),
        ("stateful double-fork fixture accepted a daemonized descendant", "double-fork descendant rejection"),
        ("assert_process_absent", "timeout descendant absence proof"),
    ):
        require_text(timeout_fixtures, text, label)
    for text, label in (
        ('parser.add_argument("--scratch"', "verifier fixture scratch option"),
        ('scratch = validate_fixture_scratch(Path(args.scratch))', "verifier fixture scratch validation dispatch"),
        ('elif args.scratch is not None:', "verifier non-self-test scratch rejection"),
        ('run_fixture_stage("publication snapshot fixture", exercise_canonical_publication_snapshot, scratch)', "canonical publication snapshot fixture dispatch"),
        ('run_fixture_stage("scratch acquisition fixture", exercise_scratch_acquisition_failures, scratch)', "scratch acquisition fixture dispatch"),
        ('run_fixture_stage("scratch replacement fixture", exercise_scratch_path_replacement, scratch)', "scratch replacement fixture dispatch"),
        ('run_fixture_stage("managed lifecycle fixture", run_stateful_timeout_fixtures, repo, scratch)', "stateful timeout fixture dispatch"),
        ('run_fixture_stage("version fixture", run_version_fixtures, sources["version"], scratch)', "fork-version fixture dispatch"),
        ('run_fixture_stage("target-contract fixture", run_target_contract_fixtures, sources, scratch)', "target fixture scratch dispatch"),
        ('"--scratch-fd",\n                    str(scratch.fd)', "closure fixture scratch descriptor dispatch"),
        ('failure = (failure[0], f"{failure[1]}; scratch cleanup failed: {exc}")', "scratch cleanup failure preservation"),
    ):
        require_text(main, text, label)
    for text, label in (
        ("os.path.isabs(rendered)", "fixture scratch absolute-path proof"),
        ("os.path.normpath(rendered) != rendered", "fixture scratch normalized-path proof"),
        (
            "def bounded_directory_names(descriptor, limit, diagnostic):",
            "fixture bounded cleanup inventory",
        ),
        ("os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW", "fixture scratch descriptor walk"),
        ("dir_fd=current_fd", "fixture scratch component-relative acquisition"),
        ("metadata.st_uid != os.geteuid()", "fixture scratch owner proof"),
        ("metadata.st_gid != os.getegid()", "fixture scratch group proof"),
        ("stat.S_IMODE(metadata.st_mode) != 0o700", "fixture scratch mode proof"),
        ("if not directory_is_empty(current_fd):", "fixture scratch initial emptiness proof"),
        ("descriptor_mount_id(self.fd) != self.mount_id", "fixture scratch mount authority"),
        ('return Path(f"/proc/self/fd/{self.fd}")', "unresolved fixture descriptor path"),
        ("return (self.fd,)", "fixture descriptor inheritance allowlist"),
        ("os.mkdir(child_name, 0o700, dir_fd=self.fd)", "descriptor-relative fixture creation"),
        ("descriptor_mount_id(child_fd) != self.mount_id", "fixture child mount authority"),
        ("yield ScratchDirectory(self, child_fd, child_name, child_identity)", "fixture child authority handoff"),
        ("os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC", "fixture cleanup entry authority"),
        ("descriptor_mount_id(authority_fd) != self.mount_id", "fixture cleanup mount-boundary proof"),
        ("os.rmdir(child_name, dir_fd=self.fd)", "descriptor-relative fixture removal"),
        ("if not directory_is_empty(self.fd):", "fixture scratch final emptiness proof"),
        ("scratch pathname was replaced", "fixture scratch edge replacement rejection"),
        ("fixture directory edge changed before cleanup", "live fixture edge cleanup gate"),
    ):
        require_text(scratch_validator, text, label)
    require_text(
        bounded_cleanup_inventory,
        "with os.scandir(descriptor) as entries:",
        "fixture streamed bounded cleanup inventory",
    )
    for text, label in (
        ("descriptor_mount_id = reject_constructor_mount", "scratch constructor acquisition fixture"),
        ("scratch constructor leaked a descriptor after acquisition failure", "scratch constructor descriptor inventory proof"),
        ("descriptor_mount_id = reject_child_mount", "scratch child acquisition fixture"),
        ("scratch child leaked a descriptor after acquisition failure", "scratch child descriptor inventory proof"),
        ("scratch child acquisition failure did not preserve one ambiguous edge", "scratch ambiguous-edge preservation proof"),
        ("preserved scratch child acquisition state is not exact", "scratch preserved-edge metadata proof"),
    ):
        require_text(scratch_acquisition_fixtures, text, label)
    for text, label in (
        ("wrote through the replacement symlink", "scratch replacement non-traversal proof"),
        ("modified the replacement directory", "live fixture replacement preservation proof"),
        ("descriptor-owned\\n", "descriptor-bound consumer-write fixture"),
        ("inherited_fds=directory.inherited_fds", "exact consumer descriptor inheritance"),
    ):
        require_text(scratch_replacement_fixtures, text, label)
    for text, label in (
        ("fork-version fixture accepted a daemonized descendant", "fork-version descendant fixture"),
        ("inherited_fds=root.inherited_fds", "fork-version exact descriptor inheritance"),
    ):
        require_text(version_fixtures, text, label)
    for text, label in (
        ("root = root_authority.canonical_path()", "canonical-path target-contract exception"),
        ("root_authority.assert_bound()", "target-contract edge authority proof"),
    ):
        require_text(target_contract_fixtures, text, label)
    require_order(
        scratch_validator,
        (
            "def assert_bound(self):",
            "metadata = os.fstat(self.fd)",
            "edge = os.stat(self.basename, dir_fd=self.parent_fd, follow_symlinks=False)",
            "if filesystem_identity(edge) != self.identity:",
            'raise VerificationError("verifier fixture scratch pathname was replaced")',
        ),
        "fixture scratch edge authority",
    )
    require_text(
        scratch_validator,
        "child_owned = True\n            yield ScratchDirectory(self, child_fd, child_name, child_identity)",
        "fixture child acquisition authority",
    )
    require_order(
        scratch_validator,
        (
            "child_owned = False",
            "child_fd = os.open(",
            "if descriptor_mount_id(child_fd) != self.mount_id:",
            "child_owned = True",
            "yield ScratchDirectory(self, child_fd, child_name, child_identity)",
            "edge = os.stat(child_name, dir_fd=self.fd, follow_symlinks=False)",
            "if filesystem_identity(edge) != child_identity:",
            'raise VerificationError("fixture directory edge changed before cleanup")',
            "self._remove_contents(child_fd, [131072])",
        ),
        "live fixture edge cleanup gate",
    )
    for text, label in (
        ("os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW", "publication snapshot no-follow directory descriptors"),
        ("dir_fd=directory_fd", "publication snapshot descriptor-relative traversal"),
        ("with os.scandir(inventory_fd) as entries:", "publication streamed directory inventory"),
        ("canonical publication directory changed during snapshot", "publication directory stability proof"),
        ("canonical publication file changed during snapshot", "publication file stability proof"),
        ("canonical publication state contains a link or special entry", "publication alias and special-entry rejection"),
        ("metadata.st_ctime_ns", "publication ctime metadata"),
        ("descriptor_statx(descriptor)", "publication statx metadata"),
        ("result.mount_id", "publication mount identity"),
        ("os.fstatvfs(descriptor)", "publication mount-policy metadata"),
        ("os.listxattr(descriptor)", "publication visible xattr inventory"),
        ("system.posix_acl_access", "publication ACL probe"),
        ("security.capability", "publication capability probe"),
        ('publication_ioctl_state(descriptor, FS_IOC_GETFLAGS, 4, "inode flags")', "publication inode flags"),
        ('publication_ioctl_state(descriptor, FS_IOC_FSGETXATTR, 28, "extended inode flags")', "publication extended inode flags"),
        ("second_inventory = publication_directory_inventory", "publication second directory inventory"),
        ("canonical publication parent edge changed during snapshot", "publication final parent-edge proof"),
        ("hashlib.sha256()", "publication content digest"),
        ("digest.update(chunk)", "publication content digest update"),
        ('names = ["dist"]', "canonical dist state"),
        ('name.startswith(".dist-release-")', "complete reserved publication state"),
        ('"--publication-worker-fd"', "publication isolated worker mode"),
        ("process = spawn_exact_process(", "publication exact worker process"),
        ("worker_fd = os.dup(_VERIFIER_PROGRAM_FD)", "publication worker program descriptor"),
        ("fcntl.fcntl(worker_fd, fcntl.F_GET_SEALS) != VERIFIER_PROGRAM_SEALS", "publication sealed worker program"),
        ('f"/proc/self/fd/{worker_fd}"', "publication descriptor-bound worker program"),
        ("tuple(inherited)", "publication worker descriptor inheritance"),
        ("begin_managed_process_acquisition()", "publication worker signal-safe acquisition"),
        ("finish_managed_process_acquisition()", "publication worker acquisition handoff"),
        ("pidfd = os.pidfd_open(process.pid, 0)", "publication worker pidfd authority"),
        ("process.kill()", "publication worker exact timeout kill"),
        ("os.waitid(os.P_PIDFD, pidfd", "publication worker deadline observation"),
        ("same-size content mutation", "publication content mutation fixture"),
        ("omitted visible xattr mutation", "publication xattr mutation fixture"),
        ("omitted ctime-only mutation", "publication ctime mutation fixture"),
        ("accepted a symlink", "publication symlink rejection fixture"),
        ("canonical publication snapshot content fixture", "publication content-bound fixture"),
        ("canonical publication snapshot entry fixture", "publication entry-bound fixture"),
        ("worker ignored its deadline", "publication deadline fixture"),
        ("signal_before_publication_spawn_return", "publication pre-assignment signal fixture"),
        ("publication snapshot pre-assignment signal worker", "publication pre-assignment worker absence proof"),
    ):
        require_text(publication_state, text, label)
    publication_bound_matrix = (
        (
            "PUBLICATION_ENTRY_LIMIT = 128",
            'if budget["entries"] >= PUBLICATION_ENTRY_LIMIT:',
            "canonical publication snapshot entry fixture",
            "entry",
        ),
        (
            "PUBLICATION_DEPTH_LIMIT = 16",
            "if depth > PUBLICATION_DEPTH_LIMIT:",
            "publication depth behavioral fixture",
            "depth",
        ),
        (
            "PUBLICATION_CONTENT_LIMIT = 2 * 1024 * 1024 * 1024",
            'if opened.st_size > budget["content_remaining"]:',
            "canonical publication snapshot content fixture",
            "content",
        ),
        (
            "PUBLICATION_XATTR_VALUE_LIMIT = 64 * 1024",
            "if len(value) > PUBLICATION_XATTR_VALUE_LIMIT:",
            "publication per-xattr behavioral fixture",
            "per-xattr value",
        ),
        (
            "PUBLICATION_XATTR_NAME_LIMIT = 64 * 1024",
            "if sum(len(name) + 1 for name in encoded_names) > PUBLICATION_XATTR_NAME_LIMIT:",
            "publication xattr-name behavioral fixture",
            "xattr names",
        ),
        (
            "PUBLICATION_XATTR_TOTAL_LIMIT = 16 * 1024 * 1024",
            'if budget["xattr_bytes"] > PUBLICATION_XATTR_TOTAL_LIMIT:',
            "publication aggregate-xattr behavioral fixture",
            "aggregate xattr bytes",
        ),
        (
            "PUBLICATION_XATTR_PER_INODE_COUNT_LIMIT = 1024",
            "if len(names) > PUBLICATION_XATTR_PER_INODE_COUNT_LIMIT:",
            "publication per-inode xattr-count behavioral fixture",
            "per-inode xattr count",
        ),
        (
            "PUBLICATION_XATTR_TOTAL_COUNT_LIMIT = 65536",
            'if budget["xattr_count"] > PUBLICATION_XATTR_TOTAL_COUNT_LIMIT:',
            "publication shared-xattr-count behavioral fixture",
            "aggregate xattr count",
        ),
        (
            "PUBLICATION_REPOSITORY_ENTRY_LIMIT = 4096",
            "if len(names) >= entry_limit:",
            "publication repository-entry behavioral fixture",
            "repository entries",
        ),
        (
            "PUBLICATION_REPOSITORY_BYTE_LIMIT = 1024 * 1024",
            "and name_bytes + encoded_size > PUBLICATION_REPOSITORY_BYTE_LIMIT",
            "publication repository-byte behavioral fixture",
            "repository name bytes",
        ),
        (
            "PUBLICATION_NAMESPACE_LIMIT = 17",
            "if len(names) > PUBLICATION_NAMESPACE_LIMIT:",
            "publication namespace behavioral fixture",
            "canonical namespace",
        ),
        (
            "PUBLICATION_SERIALIZED_RESULT_LIMIT = 16 * 1024 * 1024",
            "if len(payload) <= PUBLICATION_SERIALIZED_RESULT_LIMIT:",
            "serialized-result behavioral fixture",
            "serialized worker result",
        ),
        (
            "PUBLICATION_OUTPUT_LIMIT = 16 * 1024 * 1024",
            "if len(payload) + len(diagnostics) + len(chunk) > PUBLICATION_OUTPUT_LIMIT:",
            "aggregate-output behavioral fixture",
            "aggregate worker output",
        ),
        (
            "PUBLICATION_DEADLINE_SECONDS = 120",
            "while selector.get_map():\n            remaining = deadline - time.monotonic()\n            if remaining <= 0:\n                timed_out = True",
            "worker ignored its deadline",
            "worker deadline",
        ),
    )
    for constant, predicate, fixture, label in publication_bound_matrix:
        require_text(publication_state, constant, f"publication {label} bound")
        require_text(publication_state, predicate, f"publication {label} bound enforcement")
        require_text(publication_state, fixture, f"publication {label} behavioral fixture")
    require_exact_count(
        publication_state,
        "process.kill",
        2,
        "publication worker exact timeout kill",
    )
    require_text(
        reserved_state,
        "return directories, canonical_publication_state(repo)",
        "canonical publication state inclusion",
    )
    require_text(main, "except ManagedSignal as exc:", "managed signal main classification")
    require_text(main, "failure = (128 + exc.signum", "managed signal exit status")
    require_text(main, "return failure[0]", "managed failure status return")


if __name__ == "__main__":
    raise SystemExit(main())
