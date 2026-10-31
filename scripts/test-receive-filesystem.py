#!/usr/bin/env python3
"""Bounded Linux primitive experiment, only inside the owned zero-NIC verifier VM."""

import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import tempfile
import time


ROOT = Path("/var/tmp/rustdesk-verifier-authority")
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_char_p]
LIBC.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
LIBC.unshare.argtypes = [ctypes.c_int]
LIBC.statx.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_uint, ctypes.c_void_p]
LIBC.name_to_handle_at.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_int), ctypes.c_int]
LIBC.open_by_handle_at.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
LIBC.unlinkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]


class Handle(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint), ("kind", ctypes.c_int),
                ("bytes", ctypes.c_ubyte * 128)]


def checked(result):
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def directory(path):
    return os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def observe(fd):
    metadata = os.fstat(fd)
    fields = Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines()
    mount_ids = [int(line.split()[1]) for line in fields if line.startswith("mnt_id:")]
    assert len(mount_ids) == 1
    mount_id = mount_ids[0]
    mounts = [line.split(" - ", 1)[1].split()[0]
              for line in Path("/proc/self/mountinfo").read_text().splitlines()
              if int(line.split()[0]) == mount_id]
    assert len(mounts) == 1
    # Linux v6.1 UAPI stat.h: fixed 256-byte ABI; inode at 0x20, btime at
    # 0x50 and mount ID at 0x90. Read only fields present in the returned mask.
    extended = ctypes.create_string_buffer(256)
    checked(LIBC.statx(fd, b"", 0x1000, 0x1fff, extended))
    mask = struct.unpack_from("=I", extended.raw, 0)[0]
    if mask & 0x100:
        assert struct.unpack_from("=Q", extended.raw, 32)[0] == metadata.st_ino
    if mask & 0x1000:
        assert struct.unpack_from("=Q", extended.raw, 144)[0] == mount_id
    birth = list(struct.unpack_from("=qI", extended.raw, 80)) if mask & 0x800 else None
    handle = Handle(length=128)
    handle_mount = ctypes.c_int()
    status = LIBC.name_to_handle_at(fd, b"", ctypes.byref(handle),
                                    ctypes.byref(handle_mount), 0x1000)
    failure = ctypes.get_errno() if status < 0 else 0
    token = None
    if status == 0:
        assert 0 < handle.length <= 128 and handle_mount.value == mount_id
        token = [handle.kind, bytes(handle.bytes[:handle.length]).hex()]
    return {"device": metadata.st_dev, "inode": metadata.st_ino,
            "mount_id": mount_id, "filesystem": mounts[0], "statx_mask": mask,
            "birth_time": birth, "handle": token, "handle_errno": failure}, handle


def identity_case(base):
    selected = base / "object"
    selected.mkdir()
    fd = directory(selected)
    try:
        before, handle = observe(fd)
        renamed = base / "renamed"
        selected.rename(renamed)
        after, _ = observe(fd)
        assert before == after
        reopened = directory(renamed)
        try:
            by_name, _ = observe(reopened)
            assert before == by_name
        finally:
            os.close(reopened)
        by_handle_errno = None
        if before["handle"] is not None:
            # Linux 6.1 resolves this argument with fdget(), which excludes
            # O_PATH descriptors. The owned fixture permits a readable open.
            mount_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                opened = LIBC.open_by_handle_at(mount_fd, ctypes.byref(handle),
                                               os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                by_handle_errno = ctypes.get_errno() if opened < 0 else 0
                if opened >= 0:
                    try:
                        assert (os.fstat(opened).st_dev, os.fstat(opened).st_ino) == (
                            before["device"], before["inode"])
                    finally:
                        os.close(opened)
                assert by_handle_errno == (0 if os.geteuid() == 0 else errno.EPERM)
            finally:
                os.close(mount_fd)
        renamed.rmdir()
        deleted, _ = observe(fd)
        selected.mkdir()
        replacement_fd = directory(selected)
        try:
            replacement, _ = observe(replacement_fd)
        finally:
            os.close(replacement_fd)
        assert (replacement["device"], replacement["inode"]) != (before["device"], before["inode"])
        if before["handle"] is not None and replacement["handle"] is not None:
            assert before["handle"] != replacement["handle"]
        selected.rmdir()
    finally:
        os.close(fd)
    reused = None
    for attempt in range(64):
        selected.mkdir()
        candidate_fd = directory(selected)
        try:
            candidate, _ = observe(candidate_fd)
        finally:
            os.close(candidate_fd)
        selected.rmdir()
        if (candidate["device"], candidate["inode"]) == (before["device"], before["inode"]):
            reused = {"attempt": attempt + 1, "identity": candidate}
            if before["handle"] is not None and candidate["handle"] is not None:
                assert before["handle"] != candidate["handle"]
            break
    return {"before": before, "rename_stable": True, "deleted": deleted,
            "replacement": replacement, "open_by_handle_errno": by_handle_errno,
            "inode_reuse": reused, "reuse_attempt_bound": 64}


def principal_case(base, uid, parent_pid, operation=None):
    if uid:
        os.setgroups([])
        os.setresgid(uid, uid, uid)
        os.setresuid(uid, uid, uid)
    checked(LIBC.prctl(38, 1, 0, 0, 0))  # PR_SET_NO_NEW_PRIVS
    checked(LIBC.prctl(1, 9, 0, 0, 0))  # PR_SET_PDEATHSIG, after credential changes.
    assert os.getppid() == parent_pid
    status = Path("/proc/self/status").read_text().splitlines()
    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
    assert fields["Uid"].split() == [str(uid)] * 4
    assert fields["Gid"].split() == [str(uid)] * 4 and fields["NoNewPrivs"] == "1"
    if uid:
        assert not fields["Groups"]
        assert all(int(fields[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
    if operation is not None:
        return {"uid": uid, "no_new_privileges": True,
                "effective_capabilities": fields["CapEff"], "result": operation(base)}
    result = identity_case(base)
    anchor = base.parent / f"anchor-{uid}"
    try:
        anchor.mkdir(mode=0o700)
    except OSError as error:
        anchor_errno = error.errno
    else:
        anchor_errno = 0
        anchor.rmdir()
    return {"uid": uid, "no_new_privileges": True, "effective_capabilities": fields["CapEff"],
            "identity": result, "staging_parent_mkdir_errno": anchor_errno}


def joined_principal(base, uid, operation=None):
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    parent_pid = os.getpid()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            # A foreign actor must not inherit the observer's retained directory handles.
            for entry in os.listdir("/proc/self/fd"):
                fd = int(entry)
                if fd > 2 and fd != write_fd:
                    try:
                        os.close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
            message = {"result": principal_case(base, uid, parent_pid, operation)}
        except BaseException as error:
            message = {"error": repr(error)}
        encoded = json.dumps(message, sort_keys=True).encode()
        if len(encoded) > 4096:
            os._exit(2)
        assert os.write(write_fd, encoded) == len(encoded)
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    deadline = time.monotonic() + 5
    joined = 0
    try:
        while True:
            joined, status = os.waitpid(pid, os.WNOHANG)
            if joined:
                break
            if time.monotonic() >= deadline:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
                joined = pid
                raise RuntimeError("filesystem principal deadline; child killed and joined")
            time.sleep(0.01)
        assert os.waitstatus_to_exitcode(status) == 0
        encoded = os.read(read_fd, 4097)
        assert len(encoded) <= 4096 and not os.read(read_fd, 1)
        message = json.loads(encoded)
        assert "error" not in message, message
        return message["result"]
    finally:
        if not joined:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        os.close(read_fd)


def failure(operation):
    try:
        operation()
    except OSError as error:
        return error.errno
    return 0


def retirement_cases(root):
    observations = []
    for label, owner, mode, admitted in (("protected", 0, 0o755, False),
            ("public", 0, 0o777, True), ("sticky-root", 0, 0o1777, False),
            ("sticky-actor", 4001, 0o1777, True)):
        base = root / label
        base.mkdir()
        os.chown(base, owner, owner)
        base.chmod(mode)
        (base / "stage").mkdir(mode=0o700)
        (base / "root-empty").mkdir(mode=0o700)
        fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            def actor(path):
                return {"rename_errno": failure(lambda: (path / "stage").rename(path / "held")),
                        "rmdir_errno": failure(lambda: (path / "root-empty").rmdir())}
            result = joined_principal(base, 4001, actor)
            errors = result["result"]
            assert all(value == 0 if admitted else value in (errno.EACCES, errno.EPERM)
                       for value in errors.values()), errors
            assert (base / "held").exists() == admitted
            assert (base / "root-empty").exists() != admitted
            observations.append({"case": "directory-parent-authority", "layout": label,
                                 "parent_owner": owner, "parent_mode": oct(mode),
                                 "parent_flock": "exclusive", **result})
        finally:
            os.close(fd)
            shutil.rmtree(base)

    for kind in ("empty", "nonempty", "regular", "symlink"):
        base = root / ("replacement-" + kind)
        base.mkdir()
        base.chmod(0o777)
        stage = base / "stage"
        replacement = base / "replacement"
        stage.mkdir(mode=0o700)
        if kind in ("empty", "nonempty"):
            replacement.mkdir(mode=0o700)
            if kind == "nonempty":
                (replacement / "guard").write_bytes(b"root-private-guard")
        elif kind == "regular":
            replacement.write_bytes(b"root-private-file")
            replacement.chmod(0o600)
        else:
            replacement.symlink_to("../symlink-guard")
        (base / "root-empty-control").mkdir(mode=0o700)
        original = directory(stage)
        substituted = os.open(replacement, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            def substitute(path):
                (path / "stage").rename(path / "held")
                (path / "replacement").rename(path / "stage")
                # Calibrate the actor's existing removal authority on an equivalent
                # root-owned empty directory, before the receiver uses root authority.
                (path / "root-empty-control").rmdir()
                return {"substitution": True, "empty_root_control_removed": True}
            actor = joined_principal(base, 4001, substitute)
            result = failure(stage.rmdir)
            assert result == {"empty": 0, "nonempty": errno.ENOTEMPTY,
                              "regular": errno.ENOTDIR, "symlink": errno.ENOTDIR}[kind]
            assert os.fstat(original).st_ino == (base / "held").stat().st_ino
            assert os.fstat(original).st_nlink > 0
            assert (os.fstat(substituted).st_nlink == 0) == (kind == "empty")
            if kind == "nonempty":
                assert (stage / "guard").read_bytes() == b"root-private-guard"
            elif kind == "regular":
                assert stage.read_bytes() == b"root-private-file"
            elif kind == "symlink":
                assert stage.is_symlink() and os.readlink(stage) == "../symlink-guard"
            observations.append({"case": "directory-removal-substitution", "replacement": kind,
                                 "receiver_uid": 0, "rmdir_errno": result,
                                 "original_retained": True, "replacement_removed": kind == "empty",
                                 "actor": actor})
        finally:
            os.close(substituted)
            os.close(original)
            shutil.rmtree(base)

    base = root / "descriptor-removal"
    base.mkdir()
    fd = directory(base)
    try:
        empty_path = failure(lambda: checked(LIBC.unlinkat(fd, b"", 0x1000 | 0x200)))
        dot = failure(lambda: checked(LIBC.unlinkat(fd, b".", 0x200)))
        assert empty_path == errno.EINVAL and dot == errno.EINVAL and base.is_dir()
        base.rmdir()
        assert os.fstat(fd).st_nlink == 0
        def create_after_removal():
            created = os.open("payload", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
            os.close(created)
        create = failure(create_after_removal)
        assert create == errno.ENOENT
        observations.append({"case": "directory-descriptor-removal", "empty_path_errno": empty_path,
                             "dot_errno": dot, "create_after_removal_errno": create})
    finally:
        os.close(fd)
    return observations


def shared_mount_case(root, receiver_uid):
    base = root / "shared-mount"
    protected = root / f"protected-{receiver_uid}"
    protected.mkdir(mode=0o700)
    os.chown(protected, receiver_uid, receiver_uid)
    stage = f"stage-{receiver_uid}"
    held = f"held-{receiver_uid}"
    try:
        def receive(path):
            final = path / f"final-{receiver_uid}"
            final.write_bytes(b"authorized-output")
            final.unlink()
            container = path / stage
            container.mkdir(mode=0o700)
            (container / "identity").write_bytes(b"private-marker")
            (path / f"empty-{receiver_uid}").mkdir(mode=0o700)
            source = protected / "payload"
            source.write_bytes(b"protected-source")
            result = failure(lambda: source.rename(path / f"published-{receiver_uid}"))
            assert result == errno.EXDEV and source.read_bytes() == b"protected-source"
            source.unlink()
            return {"ordinary_write": True, "protected_publication_errno": result}
        receiver = joined_principal(base, receiver_uid, receive)

        def move(path):
            same = failure(lambda: (path / stage).rename(path / held))
            cross = failure(lambda: (path / held).rename(path / "other" / held))
            read = failure(lambda: (path / held / "identity").read_bytes())
            nonempty = failure(lambda: (path / held).rmdir())
            empty = failure(lambda: (path / f"empty-{receiver_uid}").rmdir())
            control = path / f"actor-control-{receiver_uid}"
            control.mkdir(mode=0o700)
            control.rename(path / "other" / control.name)
            (path / "other" / control.name).rmdir()
            return {"same_parent_errno": same, "cross_parent_errno": cross,
                    "read_errno": read, "nonempty_rmdir_errno": nonempty,
                    "empty_rmdir_errno": empty, "own_cross_parent_control": True}
        actor = joined_principal(base, 4001, move)
        assert actor["result"] == {"same_parent_errno": 0, "cross_parent_errno": errno.EACCES,
                                   "read_errno": errno.EACCES, "nonempty_rmdir_errno": errno.ENOTEMPTY,
                                   "empty_rmdir_errno": 0, "own_cross_parent_control": True}
        assert (base / held / "identity").read_bytes() == b"private-marker"
        assert (base / held).stat().st_uid == receiver_uid
        assert not (base / "other" / held).exists()
        inside, outside = directory(base), directory(protected)
        try:
            admitted, _ = observe(inside)
            external, _ = observe(outside)
            assert admitted["device"] == external["device"]
            assert admitted["mount_id"] != external["mount_id"]
        finally:
            os.close(inside)
            os.close(outside)
        return {"case": "shared-mount-root", "mount_owner": 4001, "mount_mode": "0o777",
                "same_device": True, "distinct_mounts": True, "receiver": receiver,
                "actor": actor, "private_marker_preserved": True}
    finally:
        for candidate in (base / held, base / stage):
            if candidate.exists():
                shutil.rmtree(candidate)
        shutil.rmtree(protected)


def main():
    assert os.geteuid() == 0 and platform.machine() == "x86_64"
    assert "rustdesk.verifier_vm=1" in Path("/proc/cmdline").read_text().split()
    assert sorted(p.name for p in Path("/sys/class/net").iterdir()) == ["lo"]
    assert Path(__file__).resolve().parent.parent == ROOT / "focused-rust-test-source"
    assert (ROOT.stat().st_uid, stat.S_IMODE(ROOT.stat().st_mode)) == (0, 0o755)
    checked(LIBC.unshare(0x20000))  # CLONE_NEWNS; never alter the guest supervisor's mounts.
    checked(LIBC.mount(None, b"/", None, (1 << 18) | 16384, None))  # MS_PRIVATE | MS_REC
    root = Path(tempfile.mkdtemp(prefix="rustdesk-receive-filesystem-", dir="/tmp"))
    root.chmod(0o755)
    mounted = []
    observations = []
    try:
        guard = root / "symlink-guard"
        guard.mkdir(mode=0o700)
        (guard / "data").write_bytes(b"unchanged-guard")
        observations.extend(retirement_cases(root))
        assert (guard / "data").read_bytes() == b"unchanged-guard"
        shutil.rmtree(guard)
        for name in ("native", "tmpfs", "bind", "readonly", "lower", "upper", "work", "overlay",
                     "shared-source", "shared-mount"):
            (root / name).mkdir(mode=0o755)
            (root / name).chmod(0o755)
        def mount(source, target, kind, flags=0, data=None):
            checked(LIBC.mount(os.fsencode(source) if source is not None else None,
                               os.fsencode(root / target), kind, flags, data))
            mounted.append(root / target)
        mount("tmpfs", "tmpfs", b"tmpfs", data=b"size=8388608,mode=0755")
        mount(root / "native", "bind", None, 4096)
        mount(root / "native", "readonly", None, 4096)
        checked(LIBC.mount(None, os.fsencode(root / "readonly"), None, 4096 | 32 | 1, None))
        overlay_options = f"lowerdir={root}/lower,upperdir={root}/upper,workdir={root}/work"
        mount("overlay", "overlay", b"overlay", data=overlay_options.encode())
        os.chown(root / "shared-source", 4001, 4001)
        (root / "shared-source").chmod(0o777)
        mount(root / "shared-source", "shared-mount", None, 4096)
        (root / "shared-mount" / "other").mkdir(mode=0o700)
        os.chown(root / "shared-mount" / "other", 4001, 4001)
        for receiver_uid in (0, 4002):
            observations.append(shared_mount_case(root, receiver_uid))
        (root / "shared-mount" / "other").rmdir()
        for kind in ("native", "tmpfs", "bind", "overlay"):
            for uid in (0, 4001):
                base = root / kind / f"principal-{kind}-{uid}"
                base.mkdir(mode=0o700)
                os.chown(base, uid, uid)
                observations.append({"case": "identity", "topology": kind,
                                     **joined_principal(base, uid)})
                base.rmdir()
        for index, (source, destination) in enumerate((
                ("native", "native"), ("tmpfs", "tmpfs"), ("overlay", "overlay"),
                ("native", "tmpfs"), ("native", "bind"), ("native", "readonly"))):
            old = root / source / f"source-{index}"
            new = root / destination / f"destination-{index}"
            old.write_bytes(b"exact")
            try:
                old.rename(new)
            except OSError as error:
                result = error.errno
                assert old.read_bytes() == b"exact" and not new.exists()
                old.unlink()
            else:
                result = 0
                assert new.read_bytes() == b"exact" and not old.exists()
                new.unlink()
            assert result == 0 if source == destination else result in (errno.EXDEV, errno.EROFS)
            observations.append({"case": "publication", "source": source,
                                 "destination": destination, "errno": result})
    finally:
        # No lazy unmount and no recursive deletion through a still-mounted filesystem.
        while mounted:
            checked(LIBC.umount2(os.fsencode(mounted[-1]), 0))
            mounted.pop()
        shutil.rmtree(root)
        assert not root.exists()
    assert len(observations) == 25
    for observation in observations:
        print("RECEIVE_FILESYSTEM_CASE=" + json.dumps(observation, sort_keys=True))
    print("RECEIVE_FILESYSTEM=observed cases=25 principals=0,4001,4002 children=joined mounts=retired "
          "fixture=retired product=unexecuted kernel=" + platform.release()
          + " source_sha256=" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
