#!/usr/bin/env python3
"""Installed-layout Linux receiver behavior in the owned zero-NIC systemd VM."""

import ctypes
import errno
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import pty
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import termios
import time
import tomllib
import uuid


MEDIA = Path("/mnt/rustdesk-verifier-inputs")
WORK = Path("/var/tmp/rustdesk-linux-service-receiver")
PRIMARY = Path("/usr/share/rustdesk/rustdesk")
CHILD = PRIMARY.with_name("rustdesk-service-child")
PROBE = WORK / "probe_client"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
ADMIN_PASSWORD = "Receiver-admin-PAM-2026!"
INVALID_ADMIN_PASSWORD = "Receiver-invalid-PAM-2026!"
AUTH_TIMEOUT_ROOT_PASSWORD = "Receiver-timeout-root-2026!"
OPENRC_PACKAGES = {"openrc": "0.45.2-2+deb12u1", "librc1": "0.45.2-2+deb12u1",
                   "libeinfo1": "0.45.2-2+deb12u1", "insserv": "1.24.0-1"}


def guard():
    authority = Path("/run/rustdesk-verifier-vm").lstat()
    if (os.geteuid() != 0 or authority.st_uid != 0
            or not stat.S_ISDIR(authority.st_mode)
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or sorted(p.name for p in Path("/sys/class/net").iterdir()) != ["lo"]
            or Path(__file__).resolve() != MEDIA / "repo/scripts" / Path(__file__).name):
        raise RuntimeError("native receiver fixture requires the owned zero-NIC systemd VM")


def run(argv, timeout=15, input=None, allowed=(0,), env=ENV):
    result = subprocess.run(argv, env=env, input=input, capture_output=True,
                            text=True, timeout=timeout)
    if len(result.stdout) + len(result.stderr) > 131072:
        raise RuntimeError("native fixture output exceeded its bound")
    if result.returncode not in allowed:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}: "
                           f"{result.stdout[-4096:]} {result.stderr[-4096:]}")
    return result


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pam_module():
    path = MEDIA / "repo/scripts/test-linux-logind-session-selection.py"
    spec = importlib.util.spec_from_file_location("rustdesk_owned_pam", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare_container(openrc=False):
    if os.getuid() != 1000 or not Path("/.dockerenv").is_file():
        raise RuntimeError("runtime preparation requires the isolated ordinary builder")
    built = run(["/usr/bin/python3", "-I", "-S", "/native/build.py",
                 "--output", "/out/libxdo.so.3"], timeout=40)
    print(built.stdout, end="", flush=True)
    source = Path("/usr/share/X11/xkb")
    if not source.is_dir() or source.is_symlink():
        raise RuntimeError("pinned verifier image lacks XKB runtime data")
    shutil.copytree(source, "/out/xkb", symlinks=True)
    libraries = Path("/out/x11-libraries")
    libraries.mkdir(mode=0o700)
    for name in ("Xvfb", "xkbcomp"):
        listing = run(["/usr/bin/ldd", "/xvfb-root/usr/bin/" + name],
                      env={**ENV, "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}).stdout
        if "not found" in listing:
            raise RuntimeError(f"X11 runtime dependency is missing: {listing}")
        for line in listing.splitlines():
            match = re.search(r"(?:=>\s+|^\s*)(/\S+)\s+\(", line)
            if match is None:
                continue
            source = Path(match[1])
            destination = libraries / source.name
            if destination.exists():
                if digest(destination) != digest(source):
                    raise RuntimeError("X11 dependency basename collision")
            else:
                shutil.copyfile(source, destination)
    count = len(list(libraries.iterdir()))
    if not 5 <= count <= 64:
        raise RuntimeError("X11 dependency closure count differs")
    print(f"LINUX_RECEIVER_PREPARE=pass xdo=checked-in xkb=pinned-image x11_libraries={count}", flush=True)
    if openrc:
        prepare_openrc()


def openrc_runtime_path(path):
    return (path in {"/etc/rc.conf", "/etc/insserv.conf", "/sbin/openrc", "/sbin/openrc-run",
                     "/sbin/rc-service", "/sbin/rc-status", "/sbin/rc-update"}
            or path.startswith("/lib/rc/")
            or re.fullmatch(r"/lib/x86_64-linux-gnu/lib(?:rc|einfo)\.so\.[0-9.]+", path) is not None)


def prepare_openrc():
    versions = run(["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\n",
                    *OPENRC_PACKAGES]).stdout
    expected = OPENRC_PACKAGES
    if dict(line.split("\t", 1) for line in versions.splitlines()) != expected:
        raise RuntimeError("pinned OpenRC runtime package versions differ")
    listing = run(["/usr/bin/dpkg-query", "--listfiles", *expected]).stdout.splitlines()
    target = Path("/out/openrc")
    target.mkdir(mode=0o700)
    files = {}
    total = 0
    for name in sorted(set(listing)):
        if not openrc_runtime_path(name) or not Path(name).is_file():
            continue
        source = Path(name)
        size = source.stat().st_size
        total += size
        if size > 2097152 or total > 16777216 or len(files) >= 256:
            raise RuntimeError("OpenRC runtime exceeds its fixture bound")
        destination = target / name.lstrip("/")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
        files[name] = {"bytes": size, "sha256": digest(destination), "mode": mode}
        if digest(source) != files[name]["sha256"]:
            raise RuntimeError("OpenRC runtime copy differs")
    if not {"/etc/rc.conf", "/etc/insserv.conf", "/sbin/openrc", "/sbin/openrc-run", "/sbin/rc-service"} <= files.keys():
        raise RuntimeError("OpenRC runtime entrypoints are absent")
    directory = Path("/etc/insserv.conf.d")
    if (str(directory) not in listing or directory.is_symlink() or not directory.is_dir()
            or list(directory.iterdir())):
        raise RuntimeError("pinned insserv configuration directory differs")
    (target / "manifest.json").write_text(json.dumps(
        {"versions": expected, "files": files, "directories": [str(directory)]}, sort_keys=True))
    print(f"LINUX_OPENRC_PREPARE=pass version=0.45.2-2+deb12u1 files={len(files)} bytes={total}", flush=True)


def install_openrc():
    guard()
    source = WORK / "prepared/openrc"
    manifest = source / "manifest.json"
    if manifest.stat().st_size > 65536:
        raise RuntimeError("OpenRC runtime manifest exceeds its bound")
    description = json.loads(manifest.read_text())
    if description["versions"] != OPENRC_PACKAGES:
        raise RuntimeError("OpenRC runtime version receipt differs")
    if description["directories"] != ["/etc/insserv.conf.d"] or os.path.lexists("/etc/insserv.conf.d"):
        raise RuntimeError("OpenRC configuration directory inventory differs")
    files = description["files"]
    if not 4 <= len(files) <= 256:
        raise RuntimeError("OpenRC runtime inventory differs")
    for name, spec in files.items():
        path = source / name.lstrip("/")
        metadata = path.lstat()
        if (not openrc_runtime_path(name) or ".." in Path(name).parts
                or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or (metadata.st_uid, metadata.st_gid) != (1000, 1000)
                or metadata.st_size != spec["bytes"] or metadata.st_size > 2097152
                or spec["mode"] not in (0o644, 0o755) or digest(path) != spec["sha256"]):
            raise RuntimeError("OpenRC staged runtime identity differs")
        if os.path.lexists(name):
            raise RuntimeError("OpenRC fixture would replace an existing runtime file")
    Path("/etc/insserv.conf.d").mkdir(mode=0o755)
    for name, spec in files.items():
        destination = Path(name)
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(source / name.lstrip("/"), destination)
        destination.chmod(spec["mode"])
        if digest(destination) != spec["sha256"]:
            raise RuntimeError("installed OpenRC runtime bytes differ")
    run(["/usr/sbin/ldconfig"])
    version = run(["/sbin/openrc", "--version"]).stdout
    if "0.45.2" not in version:
        raise RuntimeError("installed OpenRC runtime did not execute")
    print(f"LINUX_OPENRC_RUNTIME=pass version=0.45.2-2+deb12u1 manifest_sha256={digest(manifest)} "
          f"files={len(files)} source=pinned-devcheck", flush=True)


def install_polkit(archive_sha, manifest_sha):
    archive = MEDIA / "polkit-runtime-candidate.tar.gz"
    if digest(archive) != archive_sha:
        raise RuntimeError("signed runtime archive pin differs")
    output = WORK / "polkit-packages"
    output.mkdir(mode=0o700)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if (len(names) != 84 or len(set(names)) != 84
                or any(not m.isfile() or m.uid != 0 or m.gid != 0
                       or m.mode != 0o400 or m.size > 33554432 for m in members)):
            raise RuntimeError("polkit archive inventory differs")
        manifest = tar.extractfile("manifest.tsv").read()
        if hashlib.sha256(manifest).hexdigest() != manifest_sha:
            raise RuntimeError("signed runtime manifest pin differs")
        rows = [line.split("\t") for line in manifest.decode().splitlines()]
        packages = []
        for row in rows:
            if len(row) != 6:
                raise RuntimeError("polkit package manifest grammar differs")
            package, version, architecture, filename, size, sha = row
            name = "packages/" + filename
            if not re.fullmatch(r"packages/[a-zA-Z0-9.+_~%-]+\.deb", name):
                raise RuntimeError("polkit package name differs")
            data = tar.extractfile(name).read()
            if len(data) != int(size) or hashlib.sha256(data).hexdigest() != sha:
                raise RuntimeError("signed package bytes differ")
            path = output / Path(name).name
            with path.open("xb") as stream:
                stream.write(data)
            packages.append(str(path))
        if len(packages) != 82 or set(names) != {"contract", "manifest.tsv", *["packages/" + r[3] for r in rows]}:
            raise RuntimeError("polkit package closure differs")
    # All installation and maintainer scripts run only in this disposable guest.
    run(["/usr/bin/dpkg", "--install", *packages], timeout=90,
        env={**ENV, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND": "noninteractive"})
    run(["/usr/bin/systemctl", "start", "systemd-logind.service", "polkit.service"])
    run(["/usr/bin/systemctl", "is-active", "systemd-logind.service", "polkit.service"])
    shutil.copyfile(MEDIA / "repo/res/com.carriez.RustDesk.policy",
                    "/usr/share/polkit-1/actions/com.carriez.RustDesk.policy")
    os.chmod("/usr/share/polkit-1/actions/com.carriez.RustDesk.policy", 0o644)
    run(["/usr/bin/systemctl", "restart", "polkit.service"])
    versions = run(["/usr/bin/dpkg-query", "--show", "--showformat=${Package}\t${Version}\n",
                    "polkitd", "libc6", "libpam-systemd"]).stdout
    expected = {"polkitd": "122-3", "libc6": "2.36-9+deb12u14",
                "libpam-systemd": "252.39-1~deb12u2"}
    if dict(line.split("\t", 1) for line in versions.splitlines()) != expected:
        raise RuntimeError("installed OS authorization runtime versions differ")
    print("LINUX_RECEIVER_OS_RUNTIME=installed polkitd=122-3 libc6=2.36-9+deb12u14 "
          "libpam-systemd=252.39-1~deb12u2 packages=82", flush=True)


def child_record(supervisor=None, uid=4001):
    main = supervisor if supervisor is not None else int(run(
        ["/usr/bin/systemctl", "show", "rustdesk.service",
         "--property=MainPID", "--value"]).stdout.strip())
    if main <= 1:
        raise RuntimeError("installed supervisor is absent")
    path = Path("/run/rustdesk/service-child.record")
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (0, 0, 0o600)
            or not 0 < metadata.st_size <= 1024):
        raise RuntimeError("child record authority differs")
    raw = path.read_bytes()
    matched = re.fullmatch(rb"version=1\npid=([1-9][0-9]*)\nstart_time=([1-9][0-9]*)\n"
                           rb"boot_id=([0-9a-f-]{36})\nexe_dev=([0-9]+)\nexe_ino=([1-9][0-9]*)\n"
                           rb"uid=" + str(uid).encode() + rb"\ngeneration=([0-9a-f-]{36})\n"
                           rb"role=--server\+--service-owned-server\n", raw)
    if matched is None:
        raise RuntimeError("child record grammar or selected UID differs")
    pid, start, boot, dev, ino, generation = [v.decode() for v in matched.groups()]
    if boot != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        raise RuntimeError("child boot identity differs")
    if str(uuid.UUID(generation)) != generation:
        raise RuntimeError("child generation is noncanonical")
    proc = Path("/proc") / pid
    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
    if fields[0] in (b"Z", b"X") or int(fields[19]) != int(start):
        raise RuntimeError("child start identity differs")
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
    if status["PPid"].strip() != str(main) or status["Uid"].split() != [str(uid)] * 4:
        raise RuntimeError("child principal or direct parent differs")
    if any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")):
        raise RuntimeError("child retained capabilities")
    if status["NoNewPrivs"].strip() != "1":
        raise RuntimeError("child no-new-privileges is absent")
    executable = (proc / "exe").stat()
    expected = CHILD.stat()
    if (executable.st_dev, executable.st_ino) != (int(dev), int(ino)) or (int(dev), int(ino)) != (expected.st_dev, expected.st_ino):
        raise RuntimeError("child executable is not the retained installed child object")
    argv = (proc / "cmdline").read_bytes().split(b"\0")
    if re.fullmatch(rb"/proc/self/fd/[0-9]+", argv[0]) is None or argv[1:] != [b"--server", b"--service-owned-server", b""]:
        raise RuntimeError("child exact executable role differs")
    if (proc / "cgroup").read_text() != Path(f"/proc/{main}/cgroup").read_text():
        raise RuntimeError("child is outside its supervisor's systemd cgroup")
    return {"supervisor": main, "pid": int(pid), "start": int(start), "generation": generation}


def ready(previous=None, child_replacement=False, uid=4001):
    deadline = time.monotonic() + 25
    last = ""
    while time.monotonic() < deadline:
        try:
            record = child_record(uid=uid)
            changed = previous is None
            if previous is not None and child_replacement:
                changed = (record["supervisor"] == previous["supervisor"]
                           and record["generation"] == previous["generation"]
                           and (record["pid"], record["start"]) != (previous["pid"], previous["start"]))
            elif previous is not None:
                changed = (record["supervisor"] != previous["supervisor"]
                           and record["generation"] != previous["generation"])
            if changed:
                return record
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            last = str(error)
        time.sleep(0.1)
    journal = run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "-n", "40"]).stdout
    raise RuntimeError(f"installed service child never became ready: {last}\n{journal}")


def credential():
    path = Path("/root/.config/rustdesk/RustDesk.toml")
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > 65536):
        raise RuntimeError("durable credential file authority differs")
    values = tomllib.loads(path.read_text())
    fields = [values.get(key, "") for key in ("password", "password_prs", "salt")]
    if not all(isinstance(value, str) and value for value in fields):
        raise RuntimeError("durable root credential is incomplete")
    return hashlib.sha256(json.dumps(fields).encode()).hexdigest()


def change(uid, value, admitted):
    argv = [str(PRIMARY), "--password-stdin"]
    if uid:
        argv = ["/usr/bin/setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs", *argv]
    try:
        result = run(argv, input=value + "\n", timeout=20, allowed=(0, 1))
    except subprocess.TimeoutExpired as error:
        evidence = {"uid": uid, "timeout_seconds": error.timeout,
                    "outcome": "unknown", "cli": "killed-and-reaped"}
        for name in ("stdout", "stderr"):
            output = getattr(error, name) or b""
            evidence[name] = output[-4096:].decode("utf-8", errors="replace")
        print("LINUX_RECEIVER_TIMEOUT=" + json.dumps(evidence, sort_keys=True), flush=True)
        journal = run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager",
                       "-n", "40"], timeout=5).stdout
        print("LINUX_RECEIVER_SERVICE_JOURNAL=" + json.dumps(journal[-8192:]), flush=True)
        raise RuntimeError(f"UID {uid} password CLI had no final outcome within 20 seconds") from error
    if admitted != (result.returncode == 0 and result.stdout.strip() == "Done!"):
        raise RuntimeError(f"password result differs for UID {uid}: exit {result.returncode}")
    if not admitted and result.returncode != 1:
        raise RuntimeError("denied password operation did not report failure")


def pending_admin_helper(requester_pid, start, record, wait_seconds=0):
    expected = [b"/usr/bin/pkcheck", b"--action-id",
                b"com.carriez.RustDesk.set-unattended-password", b"--process",
                f"{requester_pid},{start},4001".encode(), b"--allow-user-interaction", b""]
    deadline = time.monotonic() + wait_seconds
    while True:
        helpers = []
        for proc in Path("/proc").iterdir():
            if not proc.name.isdecimal():
                continue
            try:
                fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                if int(fields[1]) != record["supervisor"]:
                    continue
                if (proc / "cmdline").read_bytes().split(b"\0") == expected:
                    helpers.append((proc, int(fields[19])))
            except (FileNotFoundError, ProcessLookupError):
                continue
        if helpers or time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    if len(helpers) != 1:
        raise RuntimeError(f"pending administrator request has {len(helpers)} matching service-owned pkcheck processes")
    proc, helper_start = helpers[0]
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
    if (status["Uid"].split() != ["0"] * 4
            or not (proc / "exe").samefile("/usr/bin/pkcheck")):
        raise RuntimeError("pending pkcheck has the wrong principal or image")
    return proc, helper_start


def observe_admin_authorization_timeout(client, agent, terminal, start, record, before, listener):
    proc, helper_start = pending_admin_helper(client.pid, start, record)
    pidfd = os.pidfd_open(int(proc.name))
    faulted = False
    try:
        fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        if (int(fields[19]) != helper_start or fields[0] in (b"Z", b"X")
                or select.select([pidfd], [], [], 0)[0]
                or client.poll() is not None or agent.poll() is not None):
            raise RuntimeError("authorization timeout has no exact live helper/requester/agent")
        invocation = run(["/usr/bin/systemctl", "show", "rustdesk.service",
                          "--property=InvocationID", "--value"]).stdout.strip()
        if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
            raise RuntimeError("authorization timeout has no service invocation")
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        last = run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager",
                    "--output=json", "-n", "1"]).stdout
        cursor = json.loads(last)["__CURSOR"]
        began = time.monotonic()
        signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
        faulted = True
        deadline = began + 3
        while True:
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            if int(fields[19]) != helper_start or select.select([pidfd], [], [], 0)[0]:
                raise RuntimeError("authorization helper changed before stop confirmation")
            if fields[0] == b"T":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("exact authorization helper did not stop")
            time.sleep(0.01)
        helper_age_at_stop = time.clock_gettime(time.CLOCK_BOOTTIME) - helper_start / os.sysconf("SC_CLK_TCK")
        print("LINUX_RECEIVER_AUTHORIZATION_TIMEOUT_HELD=" + json.dumps(
            {**record, "requester_pid": client.pid, "requester_start": start,
             "helper_pid": int(proc.name), "helper_start": helper_start,
             "helper_age_seconds": helper_age_at_stop, "helper_state": "T",
             "agent_pid": agent.pid, "administrator_password_sent": False,
             "invocation": invocation, "journal_cursor": cursor}, sort_keys=True), flush=True)

        root_began = time.monotonic()
        change(0, AUTH_TIMEOUT_ROOT_PASSWORD, True)
        root_seconds = time.monotonic() - root_began
        root_credential = credential()
        if root_credential == before or child_record() != record or direct_listener(record) != listener:
            raise RuntimeError("parallel root request did not converge on the existing serving owner")
        probe_sha = json.loads((MEDIA / "receiver/peer-manifest.json").read_text())["files"]["probe_client"]["sha256"]
        keyed(AUTH_TIMEOUT_ROOT_PASSWORD, "authorization-pending-root", record, probe_sha)
        fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        if (int(fields[19]) != helper_start or fields[0] != b"T" or client.poll() is not None
                or select.select([pidfd], [], [], 0)[0]):
            raise RuntimeError("parallel authorized work did not overlap the exact stopped helper")
        print("LINUX_RECEIVER_AUTHORIZATION_PARALLEL=pass root=Applied helper=kernel-stopped "
              "requester=pending child=retained listener=owned", flush=True)

        deadline = began + 130
        while not select.select([pidfd], [], [], 0)[0]:
            if client.poll() is not None:
                if select.select([pidfd], [], [], 0)[0]:
                    break
                raise RuntimeError("requester completed before service-owned helper retirement")
            try:
                fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            except (FileNotFoundError, ProcessLookupError):
                if select.select([pidfd], [], [], 0)[0]:
                    break
                raise RuntimeError("authorization helper disappeared without pidfd exit proof")
            if int(fields[19]) != helper_start or fields[0] != b"T":
                if select.select([pidfd], [], [], 0)[0]:
                    break
                raise RuntimeError("stopped helper changed before the receiver's deadline")
            if time.monotonic() >= deadline:
                raise RuntimeError("receiver did not retire its stopped authorization helper")
            time.sleep(0.05)
        helper_age_at_exit = time.clock_gettime(time.CLOCK_BOOTTIME) - helper_start / os.sysconf("SC_CLK_TCK")
        stdout, stderr = client.communicate(timeout=5)
        if (client.returncode != 1 or "Done!" in stdout
                or "Password change was denied" not in stderr
                or len(stdout) + len(stderr) > 32768):
            raise RuntimeError("authorization deadline did not produce explicit terminal denial")
        try:
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            reaped = int(fields[19]) != helper_start
        except (FileNotFoundError, ProcessLookupError):
            reaped = True
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        messages = [json.loads(line) for line in run(
            ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
             "--after-cursor=" + cursor, "-n", "80"]).stdout.splitlines()]
        expected = {"_PID": str(record["supervisor"]), "_UID": "0", "_TRANSPORT": "stdout",
                    "_SYSTEMD_UNIT": "rustdesk.service", "_SYSTEMD_INVOCATION_ID": invocation,
                    "_BOOT_ID": Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")}
        refusal = "pkcheck exceeded its authorization deadline"
        matching = [message for message in messages
                    if refusal in message.get("MESSAGE", "")
                    and all(message.get(key) == value for key, value in expected.items())]
        observed = {**record, "requester_pid": client.pid, "requester_start": start,
                    "helper_pid": int(proc.name), "helper_start": helper_start,
                    "helper_age_at_stop_seconds": helper_age_at_stop,
                    "helper_age_at_exit_seconds": helper_age_at_exit,
                    "fault_elapsed_seconds": time.monotonic() - began,
                    "root_apply_seconds": root_seconds, "root_credential_digest": root_credential,
                    "helper_exited": True, "helper_reaped": reaped, "client_exit": client.returncode,
                    "client_stdout": stdout, "client_stderr": stderr,
                    "agent_pid": agent.pid, "agent_exit": agent.poll(),
                    "agent_terminal_at_fault": terminal.decode(errors="replace"),
                    "administrator_password_sent": False, "service_journal": matching,
                    "durable_matches_root": credential() == root_credential,
                    "child_unchanged": child_record() == record,
                    "listener_unchanged": direct_listener(record) == listener}
        print("LINUX_RECEIVER_AUTHORIZATION_TIMEOUT_OBSERVED=" + json.dumps(observed, sort_keys=True), flush=True)
        if (not reaped or not 119.5 <= helper_age_at_exit <= 130 or len(matching) != 1
                or not all(observed[key] for key in ("durable_matches_root", "child_unchanged", "listener_unchanged"))):
            raise RuntimeError("receiver deadline lacked exact denial, reaping or preserved root authority")
        return observed
    finally:
        # Failure cleanup cannot manufacture the accepted service-originated retirement.
        try:
            if faulted and not select.select([pidfd], [], [], 0)[0]:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                except ProcessLookupError:
                    if not select.select([pidfd], [], [], 0)[0]:
                        raise
        finally:
            os.close(pidfd)


def observe_admin_requester_exit(client, agent, terminal, start, record, before, listener):
    proc, helper_start = pending_admin_helper(client.pid, start, record)
    pidfd = os.pidfd_open(int(proc.name))
    try:
        fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        if (int(fields[19]) != helper_start or fields[0] in (b"Z", b"X")
                or select.select([pidfd], [], [], 0)[0]):
            raise RuntimeError("pkcheck identity changed before requester exit")
        began = time.monotonic()
        client.kill()
        client.communicate(timeout=5)
        if client.returncode != -signal.SIGKILL:
            raise RuntimeError("owned administrator requester was not killed and joined")
        exited = reaped = False
        while time.monotonic() - began < 5:
            if agent.poll() is not None:
                raise RuntimeError("authentication agent exited before helper retirement proof")
            exited = bool(select.select([pidfd], [], [], 0.05)[0])
            if exited:
                try:
                    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    reaped = int(fields[19]) != helper_start
                except (FileNotFoundError, ProcessLookupError):
                    reaped = True
            if reaped:
                break
        retirement_seconds = time.monotonic() - began
        unchanged = credential() == before
        retained = direct_listener(record) == listener
        agent_alive = agent.poll() is None
        print("LINUX_RECEIVER_REQUESTER_EXIT_OBSERVED=" + json.dumps(
            {**record, "listener_inode": listener, "requester_pid": client.pid,
             "requester_start": start, "requester_exit": client.returncode,
             "helper_pid": int(proc.name), "helper_start": helper_start,
             "helper_exited": exited, "helper_reaped": reaped,
             "retirement_seconds": retirement_seconds,
             "elapsed_seconds": time.monotonic() - began, "agent_pid": agent.pid,
             "agent_alive_before_cleanup": agent_alive, "administrator_password_sent": False,
             "agent_terminal": terminal.decode(errors="replace"),
             "durable_unchanged": unchanged, "listener_unchanged": retained}, sort_keys=True), flush=True)
        if not exited or not reaped or not unchanged or not retained or not agent_alive:
            raise RuntimeError("requester exit did not promptly retire pending authorization without mutation")
    finally:
        os.close(pidfd)


def observe_admin_agent_exit(client, agent, terminal, start, record, before, listener):
    helper, helper_start = pending_admin_helper(client.pid, start, record)
    pidfd = os.pidfd_open(int(helper.name))
    try:
        fields = (helper / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        agent_proc = Path("/proc") / str(agent.pid)
        agent_fields = (agent_proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        requester = Path("/proc") / str(client.pid)
        requester_fields = (requester / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        if (int(fields[19]) != helper_start or fields[0] in (b"Z", b"X")
                or select.select([pidfd], [], [], 0)[0]
                or client.poll() is not None or agent.poll() is not None
                or int(requester_fields[19]) != start or requester_fields[0] in (b"Z", b"X")
                or not (requester / "exe").samefile(PRIMARY)
                or not (agent_proc / "exe").samefile("/usr/bin/pkttyagent")
                or agent_fields[0] in (b"Z", b"X")
                or int(agent_fields[2]) != agent.pid or int(agent_fields[3]) != agent.pid):
            raise RuntimeError("agent-loss fixture lost its live requester, helper or owned agent group")
        invocation = run(["/usr/bin/systemctl", "show", "rustdesk.service",
                          "--property=InvocationID", "--value"]).stdout.strip()
        if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
            raise RuntimeError("agent-loss request has no service invocation")
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        cursor = json.loads(run(["/usr/bin/journalctl", "--unit=rustdesk.service",
                                 "--no-pager", "--output=json", "-n", "1"]).stdout)["__CURSOR"]
        if client.poll() is not None or agent.poll() is not None or select.select([pidfd], [], [], 0)[0]:
            raise RuntimeError("requester, agent or pending authorization ended before agent loss")
        requester_fields = (requester / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        current_agent = (agent_proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        if (int(requester_fields[19]) != start or requester_fields[0] in (b"Z", b"X")
                or int(requester_fields[2]) == agent.pid
                or int(current_agent[19]) != int(agent_fields[19]) or current_agent[0] in (b"Z", b"X")
                or int(current_agent[2]) != agent.pid or int(current_agent[3]) != agent.pid):
            raise RuntimeError("agent-loss process/group identity changed before the signal")
        began = time.monotonic()
        # The retained, unreaped direct child owns this private session/process group.
        os.killpg(agent.pid, signal.SIGKILL)
        if agent.wait(timeout=5) != -signal.SIGKILL:
            raise RuntimeError("owned authentication agent was not killed and joined")
        stdout, stderr = client.communicate(timeout=5)
        exited = reaped = False
        while time.monotonic() - began < 5:
            exited = bool(select.select([pidfd], [], [], 0.02)[0])
            if exited:
                try:
                    fields = (helper / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    reaped = int(fields[19]) != helper_start
                except (FileNotFoundError, ProcessLookupError):
                    reaped = True
            if reaped:
                break
        elapsed = time.monotonic() - began
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        messages = [json.loads(line) for line in run(
            ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager",
             "--output=json", "--after-cursor=" + cursor, "-n", "40"]).stdout.splitlines()]
        expected = {"_PID": str(record["supervisor"]), "_UID": "0", "_TRANSPORT": "stdout",
                    "_SYSTEMD_UNIT": "rustdesk.service", "_SYSTEMD_INVOCATION_ID": invocation,
                    "_BOOT_ID": Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")}
        refusal = ("polkit denied action=com.carriez.RustDesk.set-unattended-password, "
                   f"subject={client.pid},{start},4001, status=exit status: 1")
        refusals = [item for item in messages if all(item.get(k) == v for k, v in expected.items())
                    and refusal in item.get("MESSAGE", "")]
        unchanged = credential() == before
        retained = direct_listener(record) == listener
        print("LINUX_RECEIVER_AGENT_EXIT_OBSERVED=" + json.dumps(
            {**record, "listener_inode": listener, "requester_pid": client.pid,
             "requester_start": start, "requester_alive_before_agent_loss": True,
             "agent_pid": agent.pid, "agent_start": int(agent_fields[19]),
             "agent_exit": agent.returncode, "signal": "SIGKILL", "agent_group": "owned",
             "helper_pid": int(helper.name), "helper_start": helper_start,
             "helper_exited": exited, "helper_reaped": reaped, "elapsed_seconds": elapsed,
             "administrator_password_sent": False, "agent_terminal": terminal.decode(errors="replace"),
             "cli_exit": client.returncode, "cli_stdout": stdout[-4096:], "cli_stderr": stderr[-4096:],
             "durable_unchanged": unchanged, "listener_unchanged": retained,
             "fresh_refusals": refusals}, sort_keys=True), flush=True)
        if (client.returncode != 1 or stdout.strip() == "Done!"
                or "Password change was denied" not in stderr
                or not exited or not reaped or elapsed > 5 or not unchanged or not retained or len(refusals) != 1
                or terminal.count(b"Password:") != 1 or b"AUTHENTICATION COMPLETE" in terminal
                or ADMIN_PASSWORD.encode() in terminal):
            raise RuntimeError("agent loss lacked exact receiver denial, helper retirement or unchanged authority")
    finally:
        os.close(pidfd)


class ServiceUnitResultReference:
    def __init__(self):
        guard()
        self.systemd = ctypes.CDLL("libsystemd.so.0")
        self.systemd.sd_bus_open_system.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        self.systemd.sd_bus_open_system.restype = ctypes.c_int
        self.systemd.sd_bus_call_method.argtypes = [ctypes.c_void_p, *[ctypes.c_char_p] * 4,
                                                   ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p]
        self.systemd.sd_bus_call_method.restype = ctypes.c_int
        self.systemd.sd_bus_message_unref.argtypes = [ctypes.c_void_p]
        self.systemd.sd_bus_message_unref.restype = ctypes.c_void_p
        self.systemd.sd_bus_flush_close_unref.argtypes = [ctypes.c_void_p]
        self.systemd.sd_bus_flush_close_unref.restype = ctypes.c_void_p
        self.bus = ctypes.c_void_p()
        reply = ctypes.c_void_p()
        try:
            if self.systemd.sd_bus_open_system(ctypes.byref(self.bus)) < 0:
                raise RuntimeError("shutdown observer could not open the guest system bus")
            result = self.systemd.sd_bus_call_method(
                self.bus, b"org.freedesktop.systemd1", b"/org/freedesktop/systemd1",
                b"org.freedesktop.systemd1.Manager", b"RefUnit", None, ctypes.byref(reply), b"s", b"rustdesk.service")
            if result < 0:
                raise RuntimeError(f"shutdown observer could not retain the unit result: {result}")
        except BaseException:
            self.close()
            raise
        finally:
            if reply:
                self.systemd.sd_bus_message_unref(reply)

    def close(self):
        if self.bus:
            self.bus = ctypes.c_void_p(self.systemd.sd_bus_flush_close_unref(self.bus))


def observe_admin_supervisor_shutdown(client, agent, terminal, start, record, before, listener):
    helper, helper_start = pending_admin_helper(client.pid, start, record)
    supervisor = Path("/proc") / str(record["supervisor"])
    supervisor_start = int((supervisor / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19])
    identities = {"supervisor": (supervisor, supervisor_start),
                  "helper": (helper, helper_start),
                  "child": (Path("/proc") / str(record["pid"]), record["start"])}
    pidfds = {}
    unit_reference = ServiceUnitResultReference()
    try:
        for role, (proc, expected_start) in identities.items():
            pidfds[role] = os.pidfd_open(int(proc.name))
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            if (int(fields[19]) != expected_start or fields[0] in (b"Z", b"X")
                    or select.select([pidfds[role]], [], [], 0)[0]):
                raise RuntimeError(f"shutdown fixture lost its retained {role} identity")
        status = dict(line.split(":", 1) for line in (supervisor / "status").read_text().splitlines() if ":" in line)
        cgroup = "/system.slice/rustdesk.service"
        properties = dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=MainPID,InvocationID,ControlGroup,KillMode,Restart"]).stdout.splitlines())
        invocation = properties.get("InvocationID", "")
        if (status["Uid"].split() != ["0"] * 4 or not (supervisor / "exe").samefile(PRIMARY)
                or (supervisor / "cmdline").read_bytes().split(b"\0")[1:] != [b"--service", b""]
                or properties.get("MainPID") != str(record["supervisor"])
                or properties.get("ControlGroup") != cgroup or properties.get("KillMode") != "mixed"
                or properties.get("Restart") != "on-failure" or re.fullmatch(r"[0-9a-f]{32}", invocation) is None
                or (supervisor / "cgroup").read_text() != "0::" + cgroup + "\n"
                or (helper / "cgroup").read_text() != (supervisor / "cgroup").read_text()
                or Path(f"/proc/{client.pid}/cgroup").read_text() == (supervisor / "cgroup").read_text()
                or Path(f"/proc/{agent.pid}/cgroup").read_text() == (supervisor / "cgroup").read_text()
                or client.poll() is not None or agent.poll() is not None or direct_listener(record) != listener):
            raise RuntimeError("shutdown fixture lacks the exact installed service and independent live requester/agent")
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        cursor = json.loads(run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager",
                                "--output=json", "-n", "1"]).stdout)["__CURSOR"]
        requester_fields = Path(f"/proc/{client.pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        if (int(requester_fields[19]) != start or requester_fields[0] in (b"Z", b"X")
                or client.poll() is not None or agent.poll() is not None
                or any(select.select([fd], [], [], 0)[0] for fd in pidfds.values())):
            raise RuntimeError("shutdown identities changed before the supervisor-only signal")
        began = time.monotonic()
        # Signal only the retained supervisor; systemd does not initiate this cancellation.
        signal.pidfd_send_signal(pidfds["supervisor"], signal.SIGTERM)
        stdout, stderr = client.communicate(timeout=5)
        reply_seconds = time.monotonic() - began
        supervisor_alive_at_reply = not select.select([pidfds["supervisor"]], [], [], 0)[0]
        retired = {}
        while time.monotonic() - began < 20:
            for role, (proc, expected_start) in identities.items():
                exited = bool(select.select([pidfds[role]], [], [], 0)[0])
                try:
                    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    reaped = int(fields[19]) != expected_start
                except (FileNotFoundError, ProcessLookupError):
                    reaped = True
                retired[role] = {"exited": exited, "reaped": reaped}
            if all(item["exited"] and item["reaped"] for item in retired.values()):
                break
            time.sleep(0.02)
        outcome = dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus"]).stdout.splitlines())
        unit_reference.close()
        while Path("/sys/fs/cgroup" + cgroup).exists() and time.monotonic() - began < 20:
            time.sleep(0.02)
        elapsed = time.monotonic() - began
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        messages = [json.loads(line) for line in run(
            ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
             "--after-cursor=" + cursor, "-n", "100"]).stdout.splitlines()]
        expected = {"_PID": str(record["supervisor"]), "_UID": "0", "_TRANSPORT": "stdout",
                    "_SYSTEMD_UNIT": "rustdesk.service", "_SYSTEMD_INVOCATION_ID": invocation,
                    "_BOOT_ID": Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")}
        root_messages = [item for item in messages if all(item.get(k) == v for k, v in expected.items())]
        exits = [item for item in root_messages if item.get("MESSAGE", "").endswith("librustdesk::platform::linux] Exit")]
        listener_absent = not any(len(fields := line.split()) >= 10 and fields[3] == "0A" and fields[9] == str(listener)
                                  for line in Path("/proc/net/tcp").read_text().splitlines()[1:])
        unchanged = credential() == before
        agent_alive = agent.poll() is None
        print("LINUX_RECEIVER_SUPERVISOR_SHUTDOWN_OBSERVED=" + json.dumps(
            {**record, "supervisor_start": supervisor_start, "listener_inode": listener,
             "requester_pid": client.pid, "requester_start": start, "agent_pid": agent.pid,
             "helper_pid": int(helper.name), "helper_start": helper_start,
             "signal": "SIGTERM", "signal_target": "supervisor-pidfd-only", "retired": retired,
             "reply_seconds": reply_seconds, "elapsed_seconds": elapsed,
             "supervisor_alive_at_reply": supervisor_alive_at_reply, "agent_alive_before_cleanup": agent_alive,
             "administrator_password_sent": False, "agent_terminal": terminal.decode(errors="replace"),
             "cli_exit": client.returncode, "cli_stdout": stdout[-4096:], "cli_stderr": stderr[-4096:],
             "unit_outcome": outcome, "unit_reference_held_at_outcome": True,
             "cgroup_absent": not Path("/sys/fs/cgroup" + cgroup).exists(),
             "listener_absent": listener_absent, "durable_unchanged": unchanged,
             "root_journal": root_messages}, sort_keys=True), flush=True)
        if (client.returncode != 1 or "Password change was denied" not in stderr
                or stdout.strip() == "Done!" or reply_seconds > 5 or elapsed >= 20
                or not all(item["exited"] and item["reaped"] for item in retired.values())
                or outcome != {"ActiveState": "inactive", "SubState": "dead", "Result": "success",
                               "MainPID": "0", "ExecMainCode": "1", "ExecMainStatus": "0"}
                or Path("/sys/fs/cgroup" + cgroup).exists() or not listener_absent or not unchanged or not agent_alive
                or len(exits) != 1 or any(" ERROR " in item.get("MESSAGE", "") for item in root_messages)
                or terminal.count(b"Password:") != 1 or b"AUTHENTICATION COMPLETE" in terminal):
            raise RuntimeError("pending authorization did not reject and drain through a clean supervisor shutdown")
    finally:
        unit_reference.close()
        for fd in pidfds.values():
            os.close(fd)


class TracedChildStop:
    def __init__(self, pid):
        self.pid = pid
        self.attached = set()
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
        self.libc.ptrace.restype = ctypes.c_long
        try:
            deadline = time.monotonic() + 3
            while True:
                tids = {int(task.name) for task in Path(f"/proc/{pid}/task").iterdir()}
                if not tids or len(tids) > 512 or not self.attached.issubset(tids):
                    raise RuntimeError("retained guest child thread inventory changed or exceeded its bound")
                if not self.attached and any((Path(f"/proc/{pid}/task/{tid}/stat").read_bytes()
                        .rsplit(b") ", 1)[1].split()[0] != b"T") for tid in tids):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("retained child threads did not finish their group stop")
                    time.sleep(0.005)
                    continue
                for tid in sorted(tids - self.attached):
                    self.call(0x4206, tid)  # PTRACE_SEIZE each retained child thread.
                    self.attached.add(tid)
                    self.call(0x4207, tid)  # SIGCONT cannot release PTRACE_INTERRUPT.
                    while True:
                        waited, status = os.waitpid(tid, os.WNOHANG | 0x40000000)  # __WALL
                        if waited == tid:
                            if not os.WIFSTOPPED(status):
                                raise RuntimeError("owned tracee exited before its stop barrier")
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError("owned tracee did not enter its stop barrier")
                        time.sleep(0.005)
                if {int(task.name) for task in Path(f"/proc/{pid}/task").iterdir()} == self.attached:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("retained child threads did not settle into the stop barrier")
        except BaseException:
            self.release()
            raise

    def call(self, request, tid):
        if self.libc.ptrace(request, tid, None, None) == -1:
            raise OSError(ctypes.get_errno(), "owned guest child ptrace operation failed")

    def release(self):
        for tid in sorted(self.attached, reverse=True):
            self.call(17, tid)  # PTRACE_DETACH each exact retained tracee.
            self.attached.remove(tid)

    def reap_killed(self):
        observed = []
        deadline = time.monotonic() + 5
        for tid in sorted(self.attached, reverse=True):
            while True:
                waited, status = os.waitpid(tid, os.WNOHANG | 0x40000000)
                if waited == tid:
                    if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
                        raise RuntimeError("retained child tracee did not die from the manager's SIGKILL")
                    observed.append({"tid": tid, "signal": os.WTERMSIG(status)})
                    self.attached.remove(tid)
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("manager-killed tracee was not reaped within its bound")
                time.sleep(0.005)
        return observed


def fail_supervisor_notification(supervisor, start, pidfd):
    guard()
    if os.uname().machine != "x86_64":
        raise RuntimeError("notification fault requires the pinned Linux x86_64 syscall ABI")
    addresses = [entry.removeprefix(b"NOTIFY_SOCKET=") for entry in
                 (supervisor / "environ").read_bytes().split(b"\0") if entry.startswith(b"NOTIFY_SOCKET=")]
    if len(addresses) != 1 or not addresses[0].startswith((b"/", b"@")):
        raise RuntimeError("owned supervisor lacks one canonical manager notification address")
    address = addresses[0]
    peer = b"\0" + address[1:] if address.startswith(b"@") else address
    descriptors = sorted(int(entry.name) for entry in (supervisor / "fd").iterdir())
    if not descriptors or len(descriptors) > 8192:
        raise RuntimeError("owned supervisor descriptor inventory exceeded its bound")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    matches = []
    try:
        for fd in descriptors:
            duplicate = libc.syscall(ctypes.c_long(438), ctypes.c_int(pidfd), ctypes.c_int(fd), ctypes.c_uint(0))
            if duplicate == -1:
                error = ctypes.get_errno()
                if error == errno.EBADF:
                    continue  # An unrelated descriptor may close during this bounded inventory.
                raise OSError(error, "owned supervisor pidfd_getfd failed")
            if not stat.S_ISSOCK(os.fstat(duplicate).st_mode):
                os.close(duplicate)
                continue
            owned = socket.socket(fileno=duplicate)
            try:
                if owned.family != socket.AF_UNIX or owned.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM:
                    continue
                try:
                    connected = os.fsencode(owned.getpeername())
                except OSError as error:
                    if error.errno == errno.ENOTCONN:
                        continue
                    raise
                if connected == peer:
                    matches.append((fd, owned, os.fstat(duplicate).st_ino))
                    owned = None
            finally:
                if owned is not None:
                    owned.close()
        if (len(matches) != 1 or select.select([pidfd], [], [], 0)[0]
                or int((supervisor / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19]) != start):
            raise RuntimeError("notification fault lost its unique retained supervisor socket")
        fd, owned, inode = matches[0]
        if (supervisor / "fd" / str(fd)).readlink() != Path(f"socket:[{inode}]"):
            raise RuntimeError("owned supervisor notification descriptor identity changed")
        owned.shutdown(socket.SHUT_WR)
        try:
            owned.send(b"EXTEND_TIMEOUT_USEC=30000000")
        except OSError as error:
            if error.errno != errno.EPIPE:
                raise
        else:
            raise RuntimeError("actual notification socket did not fail after SHUT_WR")
        observed = {"supervisor_pid": int(supervisor.name), "supervisor_start": start,
                    "fd": fd, "socket_inode": inode, "notify_address": os.fsdecode(address),
                    "fault": "pidfd_getfd-same-socket-SHUT_WR", "send_errno": errno.EPIPE}
        print("LINUX_RECEIVER_NOTIFICATION_FAULT_OBSERVED=" + json.dumps(observed, sort_keys=True), flush=True)
        return observed
    finally:
        for _, owned, _ in matches:
            owned.close()


def admitted_password_shutdown(value, record, fail_convergence=False, unit_stop=False, notification_failure=False):
    listener = direct_listener(record)
    if listener is None:
        raise RuntimeError("admitted shutdown has no retained serving listener")
    before = credential()
    supervisor = Path("/proc") / str(record["supervisor"])
    child = Path("/proc") / str(record["pid"])
    supervisor_start = int((supervisor / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19])
    identities = {"supervisor": (supervisor, supervisor_start), "child": (child, record["start"])}
    pidfds = {}
    client = None
    child_stopped = False
    trace_stop = None
    stopped_state = b"t" if unit_stop else b"T"
    unit_reference = ServiceUnitResultReference()
    try:
        for role, (proc, expected_start) in identities.items():
            pidfds[role] = os.pidfd_open(int(proc.name))
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            if (int(fields[19]) != expected_start or fields[0] in (b"Z", b"X")
                    or select.select([pidfds[role]], [], [], 0)[0]):
                raise RuntimeError(f"admitted shutdown lost its retained {role}")
        status = dict(line.split(":", 1) for line in (supervisor / "status").read_text().splitlines() if ":" in line)
        properties = dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=MainPID,InvocationID,ControlGroup,ActiveState,NRestarts"]).stdout.splitlines())
        invocation = properties.get("InvocationID", "")
        cgroup = "/system.slice/rustdesk.service"
        if (properties.get("MainPID") != str(record["supervisor"]) or properties.get("ActiveState") != "active"
                or properties.get("ControlGroup") != cgroup or re.fullmatch(r"[0-9a-f]{32}", invocation) is None
                or status["Uid"].split() != ["0"] * 4 or not (supervisor / "exe").samefile(PRIMARY)
                or (supervisor / "cmdline").read_bytes().split(b"\0")[1:] != [b"--service", b""]
                or (supervisor / "cgroup").read_text() != "0::" + cgroup + "\n"
                or child_record() != record):
            raise RuntimeError("admitted shutdown lacks the exact installed authority")
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        cursor = json.loads(run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager",
                                "--output=json", "-n", "1"]).stdout)["__CURSOR"]
        signal.pidfd_send_signal(pidfds["child"], signal.SIGSTOP)
        child_stopped = True
        deadline = time.monotonic() + 3
        while (child / "stat").read_bytes().rsplit(b") ", 1)[1].split()[0] != b"T":
            if time.monotonic() >= deadline or select.select([pidfds["child"]], [], [], 0)[0]:
                raise RuntimeError("retained child did not reach the actual kernel stop barrier")
            time.sleep(0.005)
        if unit_stop:
            # Group stop keeps thread IDs alive while ptrace takes exact ownership.
            trace_stop = TracedChildStop(record["pid"])
            signal.pidfd_send_signal(pidfds["child"], signal.SIGCONT)
            if (child / "stat").read_bytes().rsplit(b") ", 1)[1].split()[0] != stopped_state:
                raise RuntimeError("group-stop release escaped the retained tracing barrier")
        client = subprocess.Popen([str(PRIMARY), "--password-stdin"], env=ENV,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        requester = Path("/proc") / str(client.pid)
        deadline = time.monotonic() + 3
        while (requester / "cmdline").read_bytes().split(b"\0") != [os.fsencode(PRIMARY), b"--password-stdin", b""]:
            if client.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("admitted root requester did not reach its exact image and role")
            time.sleep(0.005)
        requester_start = int((requester / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19])
        status = dict(line.split(":", 1) for line in (requester / "status").read_text().splitlines() if ":" in line)
        if (status["Uid"].split() != ["0"] * 4 or not (requester / "exe").samefile(PRIMARY)
                or (requester / "cgroup").read_text() == (supervisor / "cgroup").read_text()):
            raise RuntimeError("admitted requester is not independent exact-image root")
        client.stdin.write(value + "\n")
        client.stdin.close()
        client.stdin = None
        deadline = time.monotonic() + 5
        while (changed := credential()) == before:
            if client.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("actual admitted root request did not change durable credential")
            time.sleep(0.005)
        if (client.poll() is not None or child_record() != record
                or (child / "stat").read_bytes().rsplit(b") ", 1)[1].split()[0] != stopped_state
                or any(select.select([fd], [], [], 0)[0] for fd in pidfds.values())):
            raise RuntimeError("durable change lost its pending requester or stopped-child barrier")
        fault = fail_supervisor_notification(supervisor, supervisor_start, pidfds["supervisor"]) if notification_failure else None
        began = time.monotonic()
        if unit_stop:
            run(["/usr/bin/systemctl", "stop", "--no-block", "rustdesk.service"], timeout=5)
        else:
            signal.pidfd_send_signal(pidfds["supervisor"], signal.SIGTERM)
        time.sleep(0.05)
        expected = {"_PID": str(record["supervisor"]), "_UID": "0", "_TRANSPORT": "stdout",
                    "_SYSTEMD_UNIT": "rustdesk.service", "_SYSTEMD_INVOCATION_ID": invocation,
                    "_BOOT_ID": Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")}
        shutdowns = []
        while not shutdowns and time.monotonic() - began < 0.5:
            messages = [json.loads(line) for line in run(
                ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
                 "--after-cursor=" + cursor, "-n", "40"], timeout=5).stdout.splitlines()]
            shutdowns = [item for item in messages if all(item.get(k) == v for k, v in expected.items())
                         and "R-T9: graceful shutdown initiated" in item.get("MESSAGE", "")]
            if not shutdowns:
                time.sleep(0.005)
        fields = (child / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        if (client.poll() is not None or credential() != changed or int(fields[19]) != record["start"]
                or fields[0] != stopped_state or len(shutdowns) != 1
                or any(select.select([fd], [], [], 0)[0] for fd in pidfds.values())):
            raise RuntimeError("shutdown cancelled admitted work or completed before child convergence")
        if notification_failure:
            if trace_stop is None or not unit_stop:
                raise RuntimeError("notification failure requires the installed unit's retained tracing barrier")
            print("LINUX_RECEIVER_NOTIFICATION_BARRIER_OBSERVED=" + json.dumps(
                {**record, "requester_pid": client.pid, "requester_start": requester_start,
                 "durable_changed": True, "requester_alive": True, "child_state": "t",
                 "child_threads": sorted(trace_stop.attached), "supervisor_alive": True,
                 "shutdown_journal": shutdowns[0], "fault": fault}, sort_keys=True), flush=True)
            while not select.select([pidfds["supervisor"]], [], [], 0.05)[0]:
                elapsed = time.monotonic() - began
                if elapsed >= 45 or client.poll() is not None or credential() != changed:
                    raise RuntimeError("notification loss escaped its pending mutation/manager-timeout boundary")
                if elapsed < 29:
                    fields = (child / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    if fields[0] != b"t" or int(fields[19]) != record["start"]:
                        raise RuntimeError("notification-failure child escaped its held tracing barrier")
            failure_seconds = time.monotonic() - began
            trace_deaths = trace_stop.reap_killed()
            child_stopped = False
            deadline = time.monotonic() + 10
            retired = {}
            while True:
                outcome = dict(line.split("=", 1) for line in run(
                    ["/usr/bin/systemctl", "show", "rustdesk.service",
                     "--property=ActiveState,SubState,Result,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,"
                     "InvocationID,NRestarts,TimeoutStopUSec"]).stdout.splitlines())
                for role, (proc, expected_start) in identities.items():
                    exited = bool(select.select([pidfds[role]], [], [], 0)[0])
                    try:
                        reaped = int((proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19]) != expected_start
                    except (FileNotFoundError, ProcessLookupError):
                        reaped = True
                    retired[role] = {"exited": exited, "reaped": reaped}
                if (outcome.get("ActiveState") == "failed" and all(item["exited"] and item["reaped"] for item in retired.values())
                        and not Path("/sys/fs/cgroup" + cgroup).exists()):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("manager-killed service generation did not retire within its bound")
                time.sleep(0.02)
            run(["/usr/bin/journalctl", "--sync"], timeout=5)
            messages = [json.loads(line) for line in run(
                ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
                 "--output-fields=__CURSOR,__MONOTONIC_TIMESTAMP,_BOOT_ID,_PID,_UID,_TRANSPORT,"
                 "_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,INVOCATION_ID,UNIT,MESSAGE",
                 "--after-cursor=" + cursor, "-n", "100"], timeout=5).stdout.splitlines()]
            root_messages = [item for item in messages if all(item.get(k) == v for k, v in expected.items())]
            errors = [item for item in root_messages if "systemd stop extension" in item.get("MESSAGE", "")
                      and "Broken pipe (os error 32)" in item.get("MESSAGE", "")]
            manager_timeouts = [item for item in messages if item.get("_PID") == "1" and item.get("_UID") == "0"
                               and item.get("_BOOT_ID") == expected["_BOOT_ID"] and item.get("UNIT") == "rustdesk.service"
                               and "stop-sigterm" in item.get("MESSAGE", "") and "timed out" in item.get("MESSAGE", "")]
            listener_absent = not any(len(fields := line.split()) >= 10 and fields[3] == "0A" and fields[9] == str(listener)
                                      for line in Path("/proc/net/tcp").read_text().splitlines()[1:])
            observed = {**record, "supervisor_start": supervisor_start, "seconds": failure_seconds,
                        "fault": fault, "unit_outcome": outcome, "unit_reference_held_at_outcome": True,
                        "trace_deaths": trace_deaths, "retired": retired, "listener_inode": listener,
                        "listener_absent": listener_absent, "cgroup_absent": not Path("/sys/fs/cgroup" + cgroup).exists(),
                        "durable_retained": credential() == changed, "fixture_resumed_child": False,
                        "requester_pid": client.pid, "requester_start": requester_start,
                        "root_error_count": len(errors), "root_messages": errors[:1] + errors[-1:],
                        "root_normal_exit": any(item.get("MESSAGE", "").endswith("librustdesk::platform::linux] Exit")
                                                for item in root_messages), "manager_timeouts": manager_timeouts}
            print("LINUX_RECEIVER_NOTIFICATION_TIMEOUT_OBSERVED=" + json.dumps(observed, sort_keys=True), flush=True)
            if (not 29 <= failure_seconds <= 45 or outcome != {
                    "ActiveState": "failed", "SubState": "failed", "Result": "timeout", "MainPID": "0",
                    "ExecMainPID": str(record["supervisor"]), "ExecMainCode": "2", "ExecMainStatus": "9",
                    "InvocationID": invocation, "NRestarts": properties["NRestarts"], "TimeoutStopUSec": "30s"}
                    or len(errors) < 2 or len(manager_timeouts) != 1 or not listener_absent
                    or credential() != changed or client.poll() is not None
                    or any(item.get("MESSAGE", "").endswith("librustdesk::platform::linux] Exit") for item in root_messages)):
                raise RuntimeError("actual manager timeout did not prove retained notification errors and uncertain finality")
            progress_at = 60
            while True:
                elapsed = time.monotonic() - began
                if elapsed > 625 or credential() != changed:
                    raise RuntimeError("uncertain requester exceeded its recovery bound or changed durable state")
                try:
                    stdout, stderr = client.communicate(timeout=0.1)
                except subprocess.TimeoutExpired as pending:
                    if len(pending.output or b"") + len(pending.stderr or b"") > 2 * 1024 * 1024:
                        raise RuntimeError("uncertain requester output exceeded its capture bound")
                else:
                    if len(stdout.encode()) + len(stderr.encode()) > 2 * 1024 * 1024:
                        raise RuntimeError("uncertain requester output exceeded its capture bound")
                    break
                if elapsed >= progress_at:
                    print(f"LINUX_RECEIVER_NOTIFICATION_WAIT seconds={elapsed:.1f} unit=failed requester=unknown durable=retained", flush=True)
                    progress_at += 30
                time.sleep(0.05)
            print("LINUX_RECEIVER_NOTIFICATION_CLIENT_OBSERVED=" + json.dumps(
                {"requester_pid": client.pid, "requester_start": requester_start, "seconds": time.monotonic() - began,
                 "cli_exit": client.returncode, "cli_stdout": stdout[-4096:], "cli_stderr": stderr[-4096:],
                 "stdout_bytes": len(stdout.encode()), "stderr_bytes": len(stderr.encode()),
                 "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                 "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                 "durable_retained": credential() == changed}, sort_keys=True), flush=True)
            if (client.returncode != 1 or "Done!" in stdout or not 590 <= time.monotonic() - began <= 625
                    or "Password change outcome remains unknown; it may have been applied" not in stderr
                    or credential() != changed):
                raise RuntimeError("manager-killed mutation did not retain an explicit unknown client outcome")
            unit_reference.close()
            print("LINUX_RECEIVER_NOTIFICATION_FAILURE=pass uid=0 fault=same-socket-SHUT_WR errno=EPIPE "
                  "durable=changed-before-stop child=ptrace-held shutdown=systemctl timeout=30 "
                  "cli=explicit-uncertainty supervisor=SIGKILL old_child=reaped old_listener=absent "
                  "unit=timeout cgroup=absent durable=retained cleanup=client-joined", flush=True)
            return
        if unit_stop:
            while time.monotonic() - began < 40:
                fields = (child / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                status = dict(line.split(":", 1) for line in (child / "status").read_text().splitlines() if ":" in line)
                if (client.poll() is not None or credential() != changed
                        or fields[0] != stopped_state or int(fields[19]) != record["start"]
                        or int(status["TracerPid"]) != os.getpid()
                        or any(select.select([fd], [], [], 0)[0] for fd in pidfds.values())):
                    raise RuntimeError("normal systemd stop killed or cancelled admitted credential work")
                if any((Path(f"/proc/{record['pid']}/task/{tid}/stat").read_bytes()
                        .rsplit(b") ", 1)[1].split()[0] != b"t") for tid in trace_stop.attached):
                    raise RuntimeError("a retained child thread escaped the native stop barrier")
                time.sleep(0.1)
            stop_properties = dict(line.split("=", 1) for line in run(
                ["/usr/bin/systemctl", "show", "rustdesk.service",
                 "--property=MainPID,ActiveState,SubState,KillMode,Type,NotifyAccess,TimeoutStopUSec,NRestarts"]).stdout.splitlines())
            if stop_properties != {"MainPID": str(record["supervisor"]), "ActiveState": "deactivating",
                                   "SubState": "stop-sigterm", "KillMode": "mixed", "Type": "notify",
                                   "NotifyAccess": "main", "TimeoutStopUSec": "30s",
                                   "NRestarts": properties["NRestarts"]}:
                raise RuntimeError("normal stop did not retain the notified supervisor past the original timeout")
            print("LINUX_RECEIVER_UNIT_STOP_PENDING=" + json.dumps(stop_properties, sort_keys=True), flush=True)
        held_seconds = time.monotonic() - began
        barrier_name = "UNIT_STOP" if unit_stop else "CONVERGENCE" if fail_convergence else "ADMITTED"
        print(f"LINUX_RECEIVER_{barrier_name}_BARRIER_OBSERVED=" + json.dumps(
            {**record, "requester_pid": client.pid, "requester_start": requester_start,
             "durable_changed": True, "requester_alive": True, "child_state": stopped_state.decode(),
             "child_threads": sorted(trace_stop.attached) if trace_stop is not None else None,
             "supervisor_alive": True, "held_seconds": held_seconds, "shutdown_journal": shutdowns[0]},
            sort_keys=True), flush=True)
        if fail_convergence:
            progress_at = 0
            child_exit_observed = None
            while not select.select([pidfds["supervisor"]], [], [], 0)[0]:
                elapsed = time.monotonic() - began
                if elapsed >= 625:
                    raise RuntimeError("unresolved authority did not fail-stop after its full recovery window")
                if client.poll() is not None and (client.returncode != 1 or elapsed < 590):
                    raise RuntimeError("unconverged credential requester reported a premature terminal result")
                try:
                    fields = (child / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    still_stopped = int(fields[19]) == record["start"] and fields[0] == b"T"
                except (FileNotFoundError, ProcessLookupError):
                    still_stopped = False
                if not still_stopped:
                    if elapsed < 590 or not select.select([pidfds["child"]], [], [], 0.2)[0]:
                        raise RuntimeError("convergence-failure child escaped its retained kernel stop barrier")
                    if child_exit_observed is None:
                        supervisor_exited = bool(select.select([pidfds["supervisor"]], [], [], 0)[0])
                        core_dumping = None
                        if not supervisor_exited:
                            try:
                                parent_fields = (supervisor / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                                if int(parent_fields[19]) == supervisor_start:
                                    status = dict(line.split(":", 1) for line in (supervisor / "status").read_text().splitlines() if ":" in line)
                                    core_dumping = status.get("CoreDumping", "").strip()
                            except (FileNotFoundError, ProcessLookupError):
                                pass
                        child_exit_observed = {"seconds": elapsed, "child_exited": True,
                                               "supervisor_exited": supervisor_exited,
                                               "supervisor_core_dumping": core_dumping,
                                               "fixture_resumed_child": False}
                        print("LINUX_RECEIVER_CONVERGENCE_CHILD_EXIT_OBSERVED=" +
                              json.dumps(child_exit_observed, sort_keys=True), flush=True)
                if elapsed >= progress_at:
                    child_state_note = "kernel-exited" if child_exit_observed else "kernel-stopped"
                    print(f"LINUX_RECEIVER_CONVERGENCE_WAIT seconds={elapsed:.1f} child={child_state_note} "
                          "durable=changed requester=not-Applied supervisor=draining", flush=True)
                    progress_at += 30
                select.select([pidfds["supervisor"]], [], [], 0.02)
            failure_seconds = time.monotonic() - began
            deadline = time.monotonic() + 1
            while True:
                outcome = dict(line.split("=", 1) for line in run(
                    ["/usr/bin/systemctl", "show", "rustdesk.service",
                     "--property=ActiveState,SubState,Result,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,InvocationID"]
                ).stdout.splitlines())
                if (outcome.get("MainPID") == "0"
                        and outcome.get("ExecMainPID") == str(record["supervisor"])
                        and outcome.get("ExecMainStatus") == str(signal.SIGABRT)):
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.01)
            print("LINUX_RECEIVER_CONVERGENCE_EXIT_OBSERVED=" + json.dumps(
                {**record, "supervisor_start": supervisor_start, "seconds": failure_seconds,
                 "unit_outcome": outcome, "unit_reference_held_at_outcome": True,
                 "fixture_resumed_child": False, "requester_exit_at_failure": client.poll()}, sort_keys=True), flush=True)
            if (not 590 <= failure_seconds <= 625 or outcome.get("MainPID") != "0"
                    or outcome.get("ExecMainPID") != str(record["supervisor"])
                    or outcome.get("ExecMainStatus") != str(signal.SIGABRT)
                    or (outcome.get("ExecMainCode"), outcome.get("Result")) not in
                    (("2", "signal"), ("3", "core-dump"))
                    or outcome.get("InvocationID") != invocation
                    or outcome.get("ActiveState") not in ("deactivating", "activating")):
                raise RuntimeError("unresolved supervisor authority was not an exact SIGABRT unit failure")
            unit_reference.close()
            stdout, stderr = client.communicate(timeout=5)
            if (client.returncode != 1 or "Done!" in stdout
                    or "Password change outcome remains unknown; it may have been applied" not in stderr):
                raise RuntimeError("unconverged root request did not retain an explicit uncertain outcome")
            run(["/usr/bin/journalctl", "--sync"], timeout=5)
            barrier_timestamp = int(shutdowns[0]["__MONOTONIC_TIMESTAMP"])
            terminal_query = run(
                ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
                 "--output-fields=__CURSOR,__MONOTONIC_TIMESTAMP,_BOOT_ID,_PID,_UID,_TRANSPORT,"
                 "_STREAM_ID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,MESSAGE",
                 "_SYSTEMD_INVOCATION_ID=" + invocation, "-n", "40"], timeout=5)
            messages = [json.loads(line) for line in terminal_query.stdout.splitlines()]
            root_messages = [item for item in messages if all(item.get(k) == v for k, v in expected.items())
                             and isinstance(item.get("__MONOTONIC_TIMESTAMP"), str)
                             and item["__MONOTONIC_TIMESTAMP"].isdecimal()
                             and int(item["__MONOTONIC_TIMESTAMP"]) > barrier_timestamp]
            terminal_journal = {
                "replica_failed": any("Linux durable credential changed but its runtime replica did not converge"
                                      in item.get("MESSAGE", "") for item in root_messages),
                "authority_aborted": any(
                    "Linux password admission transactions drained with unresolved authority; terminating"
                    in item.get("MESSAGE", "") for item in root_messages),
                "normal_exit": any(item.get("MESSAGE", "").endswith("librustdesk::platform::linux] Exit")
                                   for item in root_messages),
            }
            print("LINUX_RECEIVER_CONVERGENCE_JOURNAL_OBSERVED=" + json.dumps(
                {"expected_authority": expected, "baseline_cursor": cursor, "unit_outcome": outcome,
                 "after_monotonic_usec": barrier_timestamp, "query_exit": terminal_query.returncode,
                 "cli_exit": client.returncode, "cli_stdout": stdout[-4096:], "cli_stderr": stderr[-4096:],
                 "checks": terminal_journal, "queried_messages": messages, "root_messages": root_messages},
                sort_keys=True), flush=True)
            if (terminal_query.returncode != 0 or not terminal_journal["replica_failed"]
                    or not terminal_journal["authority_aborted"]
                    or terminal_journal["normal_exit"]):
                diagnostic = run(
                    ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
                     "--output-fields=__CURSOR,__MONOTONIC_TIMESTAMP,_BOOT_ID,_PID,_UID,_TRANSPORT,"
                     "_STREAM_ID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,_EXE,_COMM,MESSAGE",
                     "-n", "60"], timeout=5)
                for line in diagnostic.stdout.splitlines():
                    print("LINUX_RECEIVER_CONVERGENCE_JOURNAL_DIAGNOSTIC=" +
                          json.dumps(json.loads(line), sort_keys=True), flush=True)
                raise RuntimeError("exact root journal did not prove unresolved-replica fail-stop")
            recovered = ready(record)
            deadline = time.monotonic() + 10
            while (recovered_listener := direct_listener(recovered)) is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError("automatically recovered child has no serving listener")
                time.sleep(0.05)
            recovered_unit = dict(line.split("=", 1) for line in run(
                ["/usr/bin/systemctl", "show", "rustdesk.service",
                 "--property=ActiveState,SubState,Result,MainPID,InvocationID,NRestarts"]).stdout.splitlines())
            retired = {}
            for role, (proc, expected_start) in identities.items():
                exited = bool(select.select([pidfds[role]], [], [], 0)[0])
                try:
                    reaped = int((proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19]) != expected_start
                except (FileNotFoundError, ProcessLookupError):
                    reaped = True
                retired[role] = {"exited": exited, "reaped": reaped}
            listener_absent = not any(len(fields := line.split()) >= 10 and fields[3] == "0A"
                                      and fields[9] == str(listener)
                                      for line in Path("/proc/net/tcp").read_text().splitlines()[1:])
            durable_retained = credential() == changed
            observed = {**record, "supervisor_start": supervisor_start, "listener_inode": listener,
                        "requester_pid": client.pid, "requester_start": requester_start, "requester_uid": 0,
                        "child_barrier": "pidfd-SIGSTOP/kernel-T", "fixture_resumed_child": False,
                        "shutdown_signal": "supervisor-pidfd-SIGTERM", "durable_changed_before_shutdown": True,
                        "held_after_shutdown_seconds": held_seconds, "failure_seconds": failure_seconds,
                        "elapsed_seconds": time.monotonic() - began, "unit_outcome": outcome,
                        "unit_reference_held_at_outcome": True, "cli_exit": client.returncode,
                        "cli_stdout": stdout[-4096:], "cli_stderr": stderr[-4096:], "retired": retired,
                        "listener_absent": listener_absent, "durable_retained": durable_retained,
                        "root_journal": root_messages, "recovered": recovered,
                        "child_exit_observed": child_exit_observed,
                        "recovered_unit": recovered_unit, "recovered_listener_inode": recovered_listener,
                        "restarts_before": properties["NRestarts"]}
            print("LINUX_RECEIVER_CONVERGENCE_FAILURE_OBSERVED=" + json.dumps(observed, sort_keys=True), flush=True)
            if (not all(item["exited"] and item["reaped"] for item in retired.values())
                    or not listener_absent or recovered_listener == listener or not durable_retained
                    or recovered_unit.get("ActiveState") != "active" or recovered_unit.get("SubState") != "running"
                    or recovered_unit.get("Result") != "success"
                    or recovered_unit.get("MainPID") != str(recovered["supervisor"])
                    or recovered_unit.get("InvocationID") == invocation
                    or not re.fullmatch(r"[0-9a-f]{32}", recovered_unit.get("InvocationID", ""))
                    or int(recovered_unit["NRestarts"]) != int(properties["NRestarts"]) + 1):
                raise RuntimeError("failed service generation did not retire into exactly one automatic recovery")
            print("LINUX_RECEIVER_CONVERGENCE_FAILURE=pass uid=0 durable=changed-before-stop "
                  "child=kernel-stopped shutdown=supervisor-only recovery_window=600 "
                  "cli=explicit-uncertainty supervisor=SIGABRT old_child=reaped old_listener=absent "
                  "restart=automatic-once durable=retained cleanup=client-joined", flush=True)
            return recovered
        released_at = time.monotonic()
        if trace_stop is not None:
            trace_stop.release()
        else:
            signal.pidfd_send_signal(pidfds["child"], signal.SIGCONT)
        child_stopped = False
        stdout, stderr = client.communicate(timeout=5)
        reply_seconds = time.monotonic() - released_at
        retired = {}
        while time.monotonic() - released_at < 20:
            for role, (proc, expected_start) in identities.items():
                exited = bool(select.select([pidfds[role]], [], [], 0)[0])
                try:
                    reaped = int((proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19]) != expected_start
                except (FileNotFoundError, ProcessLookupError):
                    reaped = True
                retired[role] = {"exited": exited, "reaped": reaped}
            if all(item["exited"] and item["reaped"] for item in retired.values()):
                break
            time.sleep(0.02)
        outcome = dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus"]).stdout.splitlines())
        unit_reference.close()
        while Path("/sys/fs/cgroup" + cgroup).exists() and time.monotonic() - released_at < 20:
            time.sleep(0.02)
        elapsed = time.monotonic() - began
        run(["/usr/bin/journalctl", "--sync"], timeout=5)
        messages = [json.loads(line) for line in run(
            ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
             "--after-cursor=" + cursor, "-n", "100"]).stdout.splitlines()]
        root_messages = [item for item in messages if all(item.get(k) == v for k, v in expected.items())]
        exits = [item for item in root_messages if item.get("MESSAGE", "").endswith("librustdesk::platform::linux] Exit")]
        listener_absent = not any(len(fields := line.split()) >= 10 and fields[3] == "0A" and fields[9] == str(listener)
                                  for line in Path("/proc/net/tcp").read_text().splitlines()[1:])
        retained_durable = credential() == changed
        print(f"LINUX_RECEIVER_{barrier_name}_SHUTDOWN_OBSERVED=" + json.dumps(
            {**record, "supervisor_start": supervisor_start, "listener_inode": listener,
             "requester_pid": client.pid, "requester_start": requester_start, "requester_uid": 0,
             "child_barrier": "ptrace/kernel-t" if unit_stop else "pidfd-SIGSTOP/kernel-T", "durable_changed_before_shutdown": True,
             "held_after_shutdown_seconds": held_seconds, "incomplete_while_child_stopped": True,
             "shutdown_signal": "systemctl-stop" if unit_stop else "supervisor-pidfd-SIGTERM",
             "resume_signal": "PTRACE_DETACH" if unit_stop else "child-pidfd-SIGCONT",
             "reply_seconds": reply_seconds, "elapsed_seconds": elapsed, "retired": retired,
             "cli_exit": client.returncode, "cli_stdout": stdout[-4096:], "cli_stderr": stderr[-4096:],
             "durable_retained": retained_durable, "listener_absent": listener_absent,
             "unit_outcome": outcome, "unit_reference_held_at_outcome": True,
             "cgroup_absent": not Path("/sys/fs/cgroup" + cgroup).exists(), "root_journal": root_messages},
            sort_keys=True), flush=True)
        if (client.returncode != 0 or stdout.strip() != "Done!" or stderr or reply_seconds > 5
                or time.monotonic() - released_at >= 20
                or not all(item["exited"] and item["reaped"] for item in retired.values())
                or outcome != {"ActiveState": "inactive", "SubState": "dead", "Result": "success",
                               "MainPID": "0", "ExecMainCode": "1", "ExecMainStatus": "0"}
                or not retained_durable or not listener_absent or Path("/sys/fs/cgroup" + cgroup).exists()
                or len(exits) != 1 or any(" ERROR " in item.get("MESSAGE", "") for item in root_messages)):
            raise RuntimeError("admitted credential did not converge before a clean supervisor drain")
    finally:
        try:
            if child_stopped and not select.select([pidfds["child"]], [], [], 0)[0]:
                if trace_stop is not None:
                    trace_stop.release()
                else:
                    signal.pidfd_send_signal(pidfds["child"], signal.SIGCONT)
        finally:
            try:
                if client is not None:
                    if client.poll() is None:
                        client.kill()
                        client.communicate(timeout=5)
                    for pipe in (client.stdin, client.stdout, client.stderr):
                        if pipe is not None:
                            pipe.close()
            finally:
                unit_reference.close()
                for fd in pidfds.values():
                    os.close(fd)
    print(f"LINUX_RECEIVER_{barrier_name}_SHUTDOWN=pass uid=0 durable=changed-before-stop child=kernel-stopped "
          f"shutdown={'systemctl' if unit_stop else 'supervisor-only'} admitted=retained "
          f"resume={'ptrace-detach' if unit_stop else 'pidfd'} cli=Applied supervisor=clean-exit "
          "unit=inactive cgroup=absent durable=retained cleanup=client-joined", flush=True)


def close_admin_requester_session(client, agent, start, record, actor):
    pam = pam_module()
    pam.properties(actor, "active")
    helper, helper_start = pending_admin_helper(client.pid, start, record)
    invocation = run(["/usr/bin/systemctl", "show", "rustdesk.service",
                      "--property=InvocationID", "--value"]).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        raise RuntimeError("administrator request has no exact service invocation")
    run(["/usr/bin/journalctl", "--sync"], timeout=5)
    journal = run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager",
                   "--output=json", "-n", "1"]).stdout
    cursor = json.loads(journal)["__CURSOR"]
    actor["process"].stdin.write(b"close\n")
    actor["process"].stdin.flush()
    if pam.reply(actor["process"]) != {"session": actor["session"], "phase": "closed"}:
        raise RuntimeError("PAM session did not acknowledge close")
    properties = pam.properties(actor, "closing")
    requester = Path("/proc") / str(client.pid)
    fields = (requester / "stat").read_bytes().rsplit(b") ", 1)[1].split()
    helper_fields = (helper / "stat").read_bytes().rsplit(b") ", 1)[1].split()
    if (client.poll() is not None or agent.poll() is not None or actor["process"].poll() is not None
            or fields[0] in (b"Z", b"X") or int(fields[19]) != start
            or not (requester / "exe").samefile(PRIMARY)
            or helper_fields[0] in (b"Z", b"X") or int(helper_fields[19]) != helper_start
            or not Path("/tmp/.X11-unix/X77").is_socket()):
        raise RuntimeError("session close also retired the requester, agent, helper or desktop")
    observed = {**record, "session": actor["session"], "pam_actor_pid": actor["process"].pid,
                "logind_properties": properties, "requester_pid": client.pid,
                "requester_start": start, "agent_pid": agent.pid,
                "helper_pid": int(helper.name), "helper_start": helper_start,
                "requester_alive_after_close": True, "agent_alive_after_close": True,
                "helper_alive_after_close": True, "desktop_socket_after_close": True,
                "journal_cursor": cursor, "invocation": invocation}
    print("LINUX_RECEIVER_SESSION_CLOSING_OBSERVED=" + json.dumps(observed, sort_keys=True), flush=True)
    return observed


def stopped_receiver_threads(record):
    proc = Path(f"/proc/{record['pid']}")
    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
    if int(fields[19]) != record["start"] or child_record() != record:
        raise RuntimeError("stopped receiver generation changed")
    threads = sorted(int(path.name) for path in (proc / "task").iterdir())
    if not threads or any((proc / "task" / str(tid) / "stat").read_bytes()
                          .rsplit(b") ", 1)[1].split()[0] != b"T" for tid in threads):
        return None
    return threads


def admitted_admin_requester_exit(value, record, probe_sha):
    listener = direct_listener(record)
    before = credential()
    child_fd = os.pidfd_open(record["pid"])
    stopped = False
    try:
        if child_record() != record or select.select([child_fd], [], [], 0)[0]:
            raise RuntimeError("requester-exit fixture lost its exact child")
        signal.pidfd_send_signal(child_fd, signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 3
        while stopped_receiver_threads(record) is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("requester-exit child did not reach its kernel stop barrier")
            time.sleep(0.005)
        admitted = admin_change(value, record, "committed-requester-exit")
        if (credential() == before or credential() != admitted["credential_digest"]
                or stopped_receiver_threads(record) != admitted["child_threads"]
                or Path(f"/proc/{admitted['requester_pid']}").exists()
                or direct_listener(record) != listener):
            raise RuntimeError("admitted requester exit lost durable state or its stopped receiver")
        released_at = time.monotonic()
        signal.pidfd_send_signal(child_fd, signal.SIGCONT)
        stopped = False
        # Allow the production one-second replica retry to run. Only the actual
        # peer confirmation below establishes that this same child uses the value.
        time.sleep(2)
        keyed(value, "committed-requester-exit", record, probe_sha)
        if credential() != admitted["credential_digest"]:
            raise RuntimeError("requester-independent convergence rewrote durable state")
        print("LINUX_RECEIVER_COMMITTED_EXIT_CONVERGENCE_OBSERVED=" + json.dumps(
            {**admitted, **record, "listener_inode": listener,
             "seconds_after_release": time.monotonic() - released_at,
             "same_child": True, "durable_preserved": True}, sort_keys=True), flush=True)
        print("LINUX_RECEIVER_COMMITTED_EXIT_CONVERGENCE=pass requester=exited-reaped "
              "child=same-generation credential=new-value durable=preserved", flush=True)
        return admitted["credential_digest"]
    finally:
        try:
            if stopped and not select.select([child_fd], [], [], 0)[0]:
                signal.pidfd_send_signal(child_fd, signal.SIGCONT)
        finally:
            os.close(child_fd)


def admin_change(value, record, phase="apply", actor=None):
    if phase not in ("apply", "requester-exit", "committed-requester-exit", "agent-exit", "supervisor-shutdown", "session-close", "bad-password", "authorization-timeout") or (phase == "session-close" and actor is None):
        raise RuntimeError("unknown administrator fixture phase")
    listener = direct_listener(record)
    if listener is None:
        raise RuntimeError("administrator test has no serving listener")
    before = credential()
    authorities = (("/usr/bin/pkttyagent", 0o755,
                    "820110471dd023bf8272a05dd0910d876c0d2c54f3c91ed49d6cc93598f7f814"),
                   ("/usr/lib/polkit-1/polkit-agent-helper-1", 0o4755,
                    "8eb4c2d5f21698a41a0d6cdafb49c889c4ace55cada690c2cea118073fe05bab"))
    for name, mode, sha in authorities:
        path = Path(name)
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (0, 0, mode)
                or digest(path) != sha):
            raise RuntimeError("packaged authentication agent authority differs")
    policy = Path("/usr/share/polkit-1/actions/com.carriez.RustDesk.policy")
    if digest(policy) != digest(MEDIA / "repo/res/com.carriez.RustDesk.policy"):
        raise RuntimeError("installed administrator policy differs from shipped policy")
    if "rdreceiver4003" not in grp.getgrnam("sudo").gr_mem:
        raise RuntimeError("fixture administrator lacks the packaged admin-group identity")
    client = subprocess.Popen(
        ["/usr/bin/setpriv", "--reuid=4001", "--regid=4001", "--clear-groups",
         "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
         str(PRIMARY), "--password-stdin"], env=ENV,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    agent = None
    master = slave = notify_read = notify_write = None
    terminal = bytearray()
    password_sent = identity_chosen = False
    denial = None
    denial_pidfd = None
    timeout_observation = None
    committed_exit = None
    try:
        proc = Path("/proc") / str(client.pid)
        deadline = time.monotonic() + 3
        while (proc / "cmdline").read_bytes().split(b"\0") != [os.fsencode(PRIMARY), b"--password-stdin", b""]:
            if client.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("ordinary password requester did not reach its exact image/role")
            time.sleep(0.01)
        status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
        if (not (proc / "exe").samefile(PRIMARY)
                or status["Uid"].split() != ["4001"] * 4 or status["NoNewPrivs"].strip() != "1"
                or any(int(status[k], 16) for k in ("CapInh", "CapPrm", "CapEff", "CapAmb"))):
            raise RuntimeError("administrator requester has elevated process authority")
        start = int((proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19])
        master, slave = pty.openpty()
        os.fchown(slave, 4001, 4001)
        os.fchmod(slave, 0o600)
        notify_read, notify_write = os.pipe()
        agent = subprocess.Popen(
            ["/usr/bin/python3", "-B", "-I", "-S", str(Path(__file__)), "--polkit-agent",
             f"{client.pid},{start}", str(notify_write)], env=ENV, pass_fds=(notify_write,),
            stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        slave = None
        os.close(notify_write)
        notify_write = None
        deadline = time.monotonic() + 5
        readable, _, _ = select.select([notify_read], [], [], max(0, deadline - time.monotonic()))
        if not readable or os.read(notify_read, 1) or agent.poll() is not None:
            raise RuntimeError("real polkit agent did not acknowledge registration")
        agent_proc = Path("/proc") / str(agent.pid)
        agent_status = dict(line.split(":", 1) for line in (agent_proc / "status").read_text().splitlines() if ":" in line)
        if (not (agent_proc / "exe").samefile("/usr/bin/pkttyagent")
                or agent_status["Uid"].split() != ["4001"] * 4
                or agent_status["NoNewPrivs"].strip() != "0"
                or any(int(agent_status[k], 16) for k in ("CapInh", "CapPrm", "CapEff", "CapAmb"))):
            raise RuntimeError("registered authentication agent principal or image differs")
        client.stdin.write(value + "\n")
        client.stdin.close()
        client.stdin = None
        deadline = time.monotonic() + 20
        completion = b"AUTHENTICATION FAILED" if phase == "bad-password" else b"AUTHENTICATION COMPLETE"
        while completion not in terminal:
            expected_exits = (None, 0, 1) if phase in ("session-close", "bad-password") else (None, 0)
            if agent.poll() is not None or client.poll() not in expected_exits or time.monotonic() >= deadline:
                raise RuntimeError(f"administrator challenge did not complete: {terminal[-4096:]!r}")
            readable, _, _ = select.select([master], [], [], min(0.2, max(0, deadline - time.monotonic())))
            if readable:
                data = os.read(master, 4096)
                if not data or len(terminal) + len(data) > 32768:
                    raise RuntimeError("authentication terminal closed or exceeded its bound")
                terminal.extend(data)
            if not identity_chosen and b"Choose identity to authenticate as" in terminal:
                matches = re.findall(rb"(?m)^\s*([1-9][0-9]*)\.\s+[^\r\n]*\brdreceiver4003\b[^\r\n]*", terminal)
                if len(matches) != 1:
                    raise RuntimeError("administrator identity menu is missing or ambiguous")
                os.write(master, matches[0] + b"\n")
                identity_chosen = True
            if not password_sent and b"Password:" in terminal:
                if (b"com.carriez.RustDesk.set-unattended-password" not in terminal
                        or b"rdreceiver4003" not in terminal):
                    raise RuntimeError("authentication challenge has the wrong action or administrator")
                if not termios.tcgetattr(master)[3] & termios.ECHO:
                    if phase == "authorization-timeout":
                        timeout_observation = observe_admin_authorization_timeout(
                            client, agent, terminal, start, record, before, listener)
                        break
                    if phase == "requester-exit":
                        observe_admin_requester_exit(client, agent, terminal, start,
                                                    record, before, listener)
                        break
                    if phase == "agent-exit":
                        observe_admin_agent_exit(client, agent, terminal, start,
                                                 record, before, listener)
                        break
                    if phase == "supervisor-shutdown":
                        observe_admin_supervisor_shutdown(client, agent, terminal, start,
                                                          record, before, listener)
                        break
                    if phase == "session-close":
                        denial = close_admin_requester_session(client, agent, start, record, actor)
                    if phase == "bad-password":
                        helper, helper_start = pending_admin_helper(client.pid, start, record)
                        denial_pidfd = os.pidfd_open(int(helper.name))
                        fields = (helper / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                        if (int(fields[19]) != helper_start or fields[0] in (b"Z", b"X")
                                or select.select([denial_pidfd], [], [], 0)[0]):
                            raise RuntimeError("authorization helper changed before incorrect password submission")
                        invocation = run(["/usr/bin/systemctl", "show", "rustdesk.service",
                                          "--property=InvocationID", "--value"]).stdout.strip()
                        if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
                            raise RuntimeError("incorrect-password request has no service invocation")
                        run(["/usr/bin/journalctl", "--sync"], timeout=5)
                        journal = run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager",
                                       "--output=json", "-n", "1"]).stdout
                        denial = {"helper_pid": int(helper.name), "helper_start": helper_start,
                                  "requester_pid": client.pid, "requester_start": start,
                                  "journal_cursor": json.loads(journal)["__CURSOR"],
                                  "invocation": invocation}
                    password = INVALID_ADMIN_PASSWORD if phase == "bad-password" else ADMIN_PASSWORD
                    os.write(master, (password + "\n").encode())
                    password_sent = True
        if phase == "committed-requester-exit":
            deadline = time.monotonic() + 5
            while (committed := credential()) == before:
                if client.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("authenticated requester did not reach durable commit")
                time.sleep(0.005)
            threads = stopped_receiver_threads(record)
            if (not password_sent or terminal.count(b"AUTHENTICATION COMPLETE") != 1
                    or ADMIN_PASSWORD.encode() in terminal or not threads or client.poll() is not None
                    or direct_listener(record) != listener):
                raise RuntimeError("requester exit is not after commit and before child convergence")
            requester_fd = os.pidfd_open(client.pid)
            try:
                fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                if int(fields[19]) != start or select.select([requester_fd], [], [], 0)[0]:
                    raise RuntimeError("committed requester changed before exact termination")
                signal.pidfd_send_signal(requester_fd, signal.SIGKILL)
                stdout, stderr = client.communicate(timeout=5)
                if (client.returncode != -signal.SIGKILL or stdout.strip() or stderr
                        or not select.select([requester_fd], [], [], 0)[0] or proc.exists()
                        or credential() != committed or stopped_receiver_threads(record) != threads):
                    raise RuntimeError("committed requester did not retire before receiver resumption")
            finally:
                os.close(requester_fd)
            committed_exit = {**record, "requester_pid": client.pid, "requester_start": start,
                              "requester_uid": 4001, "administrator_uid": 4003,
                              "child_threads": threads, "credential_digest": committed,
                              "cli_exit": client.returncode, "agent_terminal": terminal.decode(),
                              "policy_sha256": digest(policy)}
        elif phase not in ("requester-exit", "agent-exit", "supervisor-shutdown", "authorization-timeout"):
            try:
                stdout, stderr = client.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                if phase == "bad-password":
                    while select.select([master], [], [], 0)[0]:
                        data = os.read(master, 4096)
                        if not data or len(terminal) + len(data) > 32768:
                            raise RuntimeError("failed authentication diagnostic exceeded its terminal bound")
                        terminal.extend(data)
                    helper = Path("/proc") / str(denial["helper_pid"])
                    try:
                        fields = (helper / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                        reaped = int(fields[19]) != denial["helper_start"]
                        helper_state = fields[0].decode()
                    except (FileNotFoundError, ProcessLookupError):
                        reaped = True
                        helper_state = "absent"
                    run(["/usr/bin/journalctl", "--sync"], timeout=5)
                    messages = [json.loads(line) for line in run(
                        ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
                         "--after-cursor=" + denial["journal_cursor"], "-n", "20"]).stdout.splitlines()]
                    print("LINUX_RECEIVER_ADMIN_DENIED_TIMEOUT=" + json.dumps(
                        {**denial, **record, "agent_pid": agent.pid,
                         "agent_terminal": terminal.decode(errors="replace"),
                         "helper_exited": bool(select.select([denial_pidfd], [], [], 0)[0]),
                         "helper_reaped": reaped, "helper_state": helper_state,
                         "durable_unchanged": credential() == before,
                         "listener_unchanged": direct_listener(record) == listener,
                         "client_exit": client.poll(), "agent_exit": agent.poll(),
                         "service_journal": messages}, sort_keys=True), flush=True)
                raise
        if phase in ("session-close", "bad-password"):
            run(["/usr/bin/journalctl", "--sync"], timeout=5)
            messages = [json.loads(line) for line in run(
                ["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "--output=json",
                 "--after-cursor=" + denial["journal_cursor"]]).stdout.splitlines()]
            expected = {"_PID": str(record["supervisor"]), "_UID": "0", "_TRANSPORT": "stdout",
                        "_SYSTEMD_UNIT": "rustdesk.service", "_SYSTEMD_INVOCATION_ID": denial["invocation"],
                        "_BOOT_ID": Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")}
            refusal = ("requester changed after pkcheck authorization" if phase == "session-close" else
                       "polkit denied action=com.carriez.RustDesk.set-unattended-password, "
                       f"subject={client.pid},{start},4001, status=exit status: 1")
            refusals = [item for item in messages if all(item.get(key) == value for key, value in expected.items())
                        and refusal in item.get("MESSAGE", "")]
            helper = Path("/proc") / str(denial["helper_pid"])
            try:
                fields = (helper / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                reaped = int(fields[19]) != denial["helper_start"]
            except (FileNotFoundError, ProcessLookupError):
                reaped = True
            main = int(run(["/usr/bin/systemctl", "show", "rustdesk.service",
                            "--property=MainPID", "--value"]).stdout.strip())
            unchanged = credential() == before
            alive = agent.poll() is None
            denial.update({"agent_terminal": terminal.decode(errors="replace"),
                           "administrator_uid": 4003, "cli_exit": client.returncode,
                           "cli_stdout": stdout[-4096:], "cli_stderr": stderr[-4096:],
                           "durable_unchanged": unchanged, "helper_reaped": reaped,
                           "agent_alive_before_cleanup": alive, "supervisor_after": main,
                           "fresh_refusals": refusals})
            if phase == "bad-password":
                exited = bool(select.select([denial_pidfd], [], [], 0)[0])
                denial.update({**record, "agent_pid": agent.pid, "listener_inode": listener,
                               "helper_exited": exited, "administrator_password_correct": False,
                               "listener_unchanged": direct_listener(record) == listener})
            observed = "LINUX_RECEIVER_ADMIN_DENIED_OBSERVED=" if phase == "bad-password" else "LINUX_RECEIVER_SESSION_REVOKED_OBSERVED="
            print(observed + json.dumps(denial, sort_keys=True), flush=True)
            if (not password_sent or client.returncode != 1 or stdout.strip() == "Done!"
                    or not unchanged or not reaped or not alive or main != record["supervisor"]
                    or len(refusals) != 1 or ADMIN_PASSWORD.encode() in terminal):
                raise RuntimeError("denied administrator request changed authority or lacked exact rejection proof")
            if phase == "bad-password" and (not exited or terminal.count(b"Password:") != 1
                    or terminal.count(b"AUTHENTICATION FAILED") != 1 or b"AUTHENTICATION COMPLETE" in terminal
                    or INVALID_ADMIN_PASSWORD.encode() in terminal
                    or "Password change was denied" not in stderr):
                raise RuntimeError("incorrect administrator password did not produce actual authentication failure and helper exit")
    finally:
        try:
            if agent is not None:
                if agent.poll() is None:
                    os.killpg(agent.pid, signal.SIGTERM)
                    try:
                        agent.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(agent.pid, signal.SIGKILL)
                        agent.wait(timeout=5)
                deadline = time.monotonic() + 5
                while True:
                    try:
                        os.killpg(agent.pid, 0)
                    except ProcessLookupError:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned authentication-agent process group remains after drain")
                    time.sleep(0.02)
        finally:
            if client.poll() is None:
                client.kill()
                client.communicate(timeout=5)
            for pipe in (client.stdin, client.stdout, client.stderr):
                if pipe is not None:
                    pipe.close()
            for descriptor in (master, slave, notify_read, notify_write, denial_pidfd):
                if descriptor is not None:
                    os.close(descriptor)
    if phase == "authorization-timeout":
        if (password_sent or timeout_observation is None
                or credential() != timeout_observation["root_credential_digest"]
                or child_record() != record or direct_listener(record) != listener):
            raise RuntimeError("timed-out request changed serving authority during cleanup")
        print("LINUX_RECEIVER_AUTHORIZATION_TIMEOUT=pass uid=4001 prompt=actual password=withheld "
              "helper=kernel-stopped deadline=120 cli=explicit-denial helper_cleanup=service-reaped "
              "parallel_root=Applied durable=root-value child=retained listener=owned cleanup=agent-client-joined", flush=True)
        return
    changed = credential() != before
    if phase == "committed-requester-exit":
        if (committed_exit is None or not changed
                or credential() != committed_exit["credential_digest"]
                or stopped_receiver_threads(record) != committed_exit["child_threads"]
                or direct_listener(record) != listener):
            raise RuntimeError("committed state or child barrier changed during requester cleanup")
        print("LINUX_RECEIVER_COMMITTED_EXIT_OBSERVED=" + json.dumps(committed_exit, sort_keys=True), flush=True)
        print("LINUX_RECEIVER_COMMITTED_EXIT=pass uid=4001 administrator_uid=4003 "
              "authentication=polkit-pam durable=changed child=kernel-stopped "
              "requester=pidfd-SIGKILL-reaped cleanup=agent-client-joined", flush=True)
        return committed_exit
    if phase == "session-close":
        if changed:
            raise RuntimeError("revoked administrator request changed the durable credential during cleanup")
        print("LINUX_RECEIVER_SESSION_REVOKED=pass uid=4001 session=closing requester=alive "
              "authentication=polkit-pam authorization=fresh-denied durable=unchanged "
              "supervisor=retained helper=reaped cleanup=agent-client-joined", flush=True)
        return
    if phase == "supervisor-shutdown":
        if password_sent or changed:
            raise RuntimeError("service shutdown admitted a pending administrator request")
        print("LINUX_RECEIVER_SUPERVISOR_SHUTDOWN=pass uid=4001 prompt=actual password=withheld "
              "signal=supervisor-only cli=explicit-denial helper=reaped child=reaped supervisor=clean-exit "
              "unit=inactive cgroup=absent durable=unchanged cleanup=agent-client-joined", flush=True)
        return
    retained = direct_listener(record) == listener
    if phase == "agent-exit":
        if password_sent or changed or not retained:
            raise RuntimeError("lost authentication agent changed serving authority")
        print("LINUX_RECEIVER_AGENT_EXIT=pass uid=4001 prompt=actual password=withheld "
              "agent=group-killed requester=alive-before-loss cli=explicit-denial pkcheck=exit1 "
              "helper=service-reaped durable=unchanged listener=owned cleanup=agent-client-joined", flush=True)
        return
    if phase == "bad-password":
        if changed or not retained:
            raise RuntimeError("incorrect administrator password changed serving authority during cleanup")
        print("LINUX_RECEIVER_ADMIN_DENIED=pass uid=4001 administrator_uid=4003 password=incorrect "
              "authentication=failed pkcheck=exit1 helper=reaped agent=alive-before-cleanup "
              "durable=unchanged listener=owned cleanup=agent-client-joined", flush=True)
        return
    if phase == "requester-exit":
        if password_sent or changed or not retained:
            raise RuntimeError("abandoned administrator request changed serving authority")
        print("LINUX_RECEIVER_REQUESTER_EXIT=pass uid=4001 prompt=actual password=withheld "
              "helper=service-reaped agent=alive-before-cleanup durable=unchanged listener=owned "
              "cleanup=agent-client-joined", flush=True)
        return
    print("LINUX_RECEIVER_ADMIN_OBSERVED=" + json.dumps(
        {**record, "listener_inode": listener, "requester_pid": client.pid, "requester_start": start,
         "agent_pid": agent.pid, "requester_uid": 4001, "administrator_uid": 4003,
         "agent_terminal": terminal.decode(errors="replace"), "cli_exit": client.returncode,
         "durable_changed": changed, "listener_unchanged": retained,
         "policy_sha256": digest(policy)}, sort_keys=True), flush=True)
    if (not password_sent or client.returncode != 0 or stdout.strip() != "Done!" or stderr
            or not changed or not retained):
        raise RuntimeError("authenticated administrator change did not converge on the serving child")
    print("LINUX_RECEIVER_ADMIN=pass uid=4001 administrator_uid=4003 subject=pid-start-bound "
          "authentication=polkit-pam policy=shipped durable=changed listener=owned cleanup=agent-client-joined", flush=True)


def direct_listener(record, supervisor=None, uid=4001):
    if child_record(supervisor, uid) != record:
        raise RuntimeError("serving child changed before listener proof")
    proc = Path("/proc") / str(record["pid"])
    listeners = []
    for line in (proc / "net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            raise RuntimeError("kernel TCP socket row is incomplete")
        if fields[1].endswith(":527E") and fields[3] == "0A":
            if fields[1] != "00000000:527E" or fields[7] != str(uid):
                raise RuntimeError("direct listener address or principal differs")
            listeners.append(int(fields[9]))
    if not listeners:
        return None
    if len(listeners) != 1 or listeners[0] <= 0:
        raise RuntimeError("direct listener is absent or ambiguous")
    sockets = set()
    for descriptor in (proc / "fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            # An unrelated connection descriptor may close during inspection.
            continue
        match = re.fullmatch(r"socket:\[([1-9][0-9]*)\]", target)
        if match is not None:
            sockets.add(int(match[1]))
    if listeners[0] not in sockets or child_record(supervisor, uid) != record:
        raise RuntimeError("direct listener is not owned by the retained child")
    return listeners[0]


def keyed(value, phase, record, probe_sha):
    deadline = time.monotonic() + 10
    listener = direct_listener(record)
    while listener is None and time.monotonic() < deadline:
        time.sleep(0.1)
        listener = direct_listener(record)
    if listener is None:
        raise RuntimeError("retained child did not open its public listener")
    before = credential()
    result = run(["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                  "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                  str(PROBE), "127.0.0.1:21118", "--password-stdin", "ok"],
                 input=value + "\n", timeout=45)
    if result.stdout.splitlines() != ["probe_client: keying ok=true (expected=ok)",
                                      "probe_client: PASS"] or result.stderr:
        raise RuntimeError("network peer did not prove CPace responder confirmation")
    if credential() != before or direct_listener(record) != listener:
        raise RuntimeError("network proof changed durable state or serving listener")
    print("LINUX_RECEIVER_CPACE_OBSERVED=" + json.dumps(
        {"phase": phase, **record, "listener_inode": listener}, sort_keys=True), flush=True)
    print(f"LINUX_RECEIVER_CPACE=pass phase={phase} uid=4002 server=supervised-child "
          f"listener=owned key_confirmation=mutual probe_sha256={probe_sha}", flush=True)


def installed_file_transfer(value, record, probe_sha):
    home = Path(pwd.getpwuid(4001).pw_dir)
    destination = home / "allowed-after-login"
    if home != Path("/tmp/rd-cm-file-replay") or any(
            os.path.lexists(p) for p in (destination, home / "blocked-before-login", home / ".rustdesk-receive")):
        raise RuntimeError("installed file fixture is not fresh")
    before = credential()
    listener = direct_listener(record)
    cm_fd = None

    def probe(uid, mode, markers):
        result = run(["/usr/bin/setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                      "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                      str(PROBE), "127.0.0.1:21118", "--password-stdin", "ok", mode],
                     input=value + "\n", timeout=50, allowed=(0, 1))
        print("LINUX_RECEIVER_FILE_PROBE_OBSERVED=" + json.dumps(
            {"uid": uid, "mode": mode, "exit": result.returncode,
             "stdout": result.stdout, "stderr": result.stderr}, sort_keys=True), flush=True)
        required = ["probe_client: keying ok=true (expected=ok)", "probe_client: PASS",
                    '[FT-PEERINFO username_nonempty=true username="rdreceiver4001" platform="Linux"]',
                    '[FT-DIR-RESPONSE path="/tmp/rd-cm-file-replay" entries=', *markers]
        if (result.returncode or result.stderr or any(result.stdout.count(text) != 1 for text in required)
                or credential() != before or child_record() != record or direct_listener(record) != listener):
            raise RuntimeError("installed file peer result or stable service authority differs")
        return result.stdout

    def completed_files(expected):
        deadline = time.monotonic() + 5
        # Owner-loss cleanup is asynchronous; observe the whole destination and
        # coordinator, including hidden entries, before admitting the successor.
        while True:
            names = set(os.listdir(destination))
            coordinator = home / ".rustdesk-receive"
            if names == set(expected) and coordinator.is_dir() and not os.listdir(coordinator):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"installed receive retained unexpected entries: {sorted(names)}")
            time.sleep(0.05)
        directory = destination.lstat()
        coordinator_metadata = coordinator.lstat()
        print("LINUX_RECEIVER_FILE_DIRECTORY_OBSERVED=" + json.dumps(
            {"uid": directory.st_uid, "gid": directory.st_gid, "mode": oct(stat.S_IMODE(directory.st_mode)),
             "prelogin_exists": os.path.lexists(home / "blocked-before-login")}, sort_keys=True), flush=True)
        if (not stat.S_ISDIR(directory.st_mode)
                or (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode)) != (4001, 4001, 0o755)
                or not stat.S_ISDIR(coordinator_metadata.st_mode)
                or (coordinator_metadata.st_uid, coordinator_metadata.st_gid,
                    stat.S_IMODE(coordinator_metadata.st_mode)) != (4001, 4001, 0o700)
                or os.path.lexists(home / "blocked-before-login")):
            raise RuntimeError("installed receive directory principal or pre-login refusal differs")
        observations = []
        for name, payload in expected.items():
            path = destination / name
            metadata = path.lstat()
            if (not stat.S_ISREG(metadata.st_mode)
                    or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode), metadata.st_nlink,
                        metadata.st_size) != (4001, 4001, 0o600, 1, len(payload))
                    or path.read_bytes() != payload):
                raise RuntimeError(f"installed receive content or principal differs: {name}")
            observations.append({"name": name, "uid": metadata.st_uid, "gid": metadata.st_gid,
                                 "mode": "0600", "bytes": metadata.st_size, "sha256": digest(path)})
        print("LINUX_RECEIVER_FILE_CONTENT_OBSERVED=" + json.dumps(
            {"files": observations, "destination_entries": sorted(names), "coordination_entries": []},
            sort_keys=True), flush=True)

    try:
        probe(4002, "cmfiletransfer", [])
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(5)
            peer.connect("/tmp/RustDesk-4001/ipc_cm")
            pid, uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            cm_fd = os.pidfd_open(pid)
            proc = Path(f"/proc/{pid}")
            status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            executable = (proc / "exe").stat()
            installed = CHILD.stat()
            if ((uid, gid) != (4001, 4001) or status["Uid"].split() != ["4001"] * 4
                    or status["Gid"].split() != ["4001"] * 4 or int(status["PPid"]) != record["pid"]
                    or status["Groups"].split() not in ([], ["4001"])
                    or status["Umask"].strip() != "0022"
                    or status["NoNewPrivs"].strip() != "1"
                    or any(int(status[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapAmb"))
                    or (executable.st_dev, executable.st_ino) != (installed.st_dev, installed.st_ino)
                    or (proc / "cmdline").read_bytes() != os.fsencode(CHILD) + b"\0--cm\0"
                    or (proc / "cgroup").read_text() != Path(f"/proc/{record['pid']}/cgroup").read_text()
                    or select.select([cm_fd], [], [], 0)[0] or fields[0] in (b"Z", b"X")):
                raise RuntimeError("installed CM is not the exact unprivileged server child")
            cm = {"pid": pid, "start": int(fields[19]), "uid": uid, "gid": gid, "parent": record["pid"]}
            print("LINUX_RECEIVER_FILE_CM_OBSERVED=" + json.dumps(cm, sort_keys=True), flush=True)
        # This existing probe observes its staged private files before disconnecting;
        # run it as the receiver user. The independent-UID peers bracket that probe.
        probe(4001, "cmfileauthority", [
            "[FT-CREATE-DONE id=17002]", "[FT-PREMATURE-WRITE-REFUSED id=17003]",
            "[FT-SHORT-WRITE-REFUSED id=17014]", "[FT-WRITE-COMMITTED id=17004]",
            "[FT-MULTI-WRITE-COMMITTED id=17005 files=2 blocks=4]",
            "[FT-PEER-ERROR-REPORTED id=17006]", "[FT-CANCEL-BARRIER id=17007]",
            "[FT-OWNER-LOSS-STAGED id=17008]"])
        payloads = {"payload.txt": b"cm-file-write-finality-v1-0123456789",
                    "first.txt": b"first-file-two-blocks-0123456789",
                    "second.txt": b"second-file-two-blocks-abcdefghij"}
        completed_files(payloads)
        probe(4002, "cmfilereconnect", ["[FT-RECONNECT-WRITE-COMMITTED id=17008]"])
        payloads["orphaned.txt"] = b"new-owner-after-abrupt-loss-0123456789"
        completed_files(payloads)
        sources = home / "source-swap"
        sources.mkdir(mode=0o700)
        os.chown(sources, 4001, 4001)
        fixtures = {destination / "unreadable-source.txt": (b"unreadable-source-fixture", 0),
                    destination / "readable-source.jpg": (b"A" * 150001, 0o600),
                    sources / "a.jpg": (b"A" * 150001, 0o600),
                    sources / "b.jpg": (b"A" * 150001, 0o600)}
        for path, (payload, mode) in fixtures.items():
            with path.open("xb") as output:
                output.write(payload)
                os.fchown(output.fileno(), 4001, 4001)
                os.fchmod(output.fileno(), mode)

        def source_snapshot():
            observed = []
            for path, (payload, mode) in fixtures.items():
                metadata = path.lstat()
                if (not stat.S_ISREG(metadata.st_mode)
                        or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode),
                            metadata.st_nlink, metadata.st_size) != (4001, 4001, mode, 1, len(payload))
                        or path.read_bytes() != payload):
                    raise RuntimeError(f"installed download source changed: {path.name}")
                observed.append({"path": str(path.relative_to(home)), "device": metadata.st_dev,
                                 "inode": metadata.st_ino, "mode": oct(mode), "uid": metadata.st_uid,
                                 "gid": metadata.st_gid, "links": metadata.st_nlink,
                                 "bytes": metadata.st_size, "sha256": digest(path)})
            return observed

        sources_before = source_snapshot()
        successful_read = (r"\[FT-READ-SUCCESS id=17013 bytes=150001 blocks=(?:[2-9]|[1-9][0-9]+) "
                           r"digest=confirmed done=once barrier=passed\]")
        unreadable = probe(4002, "ftreadfailure", ["[FT-READ-ERROR-TERMINAL id=17012]"])
        # The existing source-swap probe replaces and restores one of the selected
        # user's files after enumeration, so it runs as that user inside this VM.
        replaced = probe(4001, "ftfiletype", [f"[FT-TYPE-REFUSED value={value} id=17013]"
                                              for value in (1, 2, 42, 255, -1, -2147483648, 2147483647)])
        if (len(re.findall(successful_read, unreadable)) != 1
                or len(re.findall(successful_read, replaced)) != 1
                or replaced.count("[FT-TYPE-REFUSED ") != 7
                or len(re.findall(r"\[FT-SOURCE-REFUSED id=17017 file=1 bytes=150001 "
                                  r"blocks=(?:[2-9]|[1-9][0-9]+) restored=2 barrier=passed\]", replaced)) != 1
                or source_snapshot() != sources_before
                or set(os.listdir(sources)) != {"a.jpg", "b.jpg"}
                or set(os.listdir(destination)) != set(payloads) | {"unreadable-source.txt", "readable-source.jpg"}
                or os.listdir(home / ".rustdesk-receive")):
            raise RuntimeError("installed download refusal, recovery or source preservation differs")
        print("LINUX_RECEIVER_FILE_SOURCE_OBSERVED=" + json.dumps(
            {"sources": sources_before, "after_matches_before": True}, sort_keys=True), flush=True)
        print(f"LINUX_RECEIVER_DOWNLOAD=pass peers=2 unreadable=one-error unsupported=7 "
              "source_swap=after-enumeration prefix_bytes=150001 second_file=one-error "
              "false_done=absent successful_reads=2 bytes_each=150001 done=once barriers=passed "
              f"sources=preserved probe_sha256={probe_sha}", flush=True)
        if select.select([cm_fd], [], [], 0)[0] or int(
                (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19]) != cm["start"]:
            raise RuntimeError("installed CM generation changed during file transactions")
        print(f"LINUX_RECEIVER_FILE=pass peers=3 cm_uid=4001 cross_uid=4002 prelogin=refused "
              "committed_files=4 premature=refused short=refused peer_error=reported cancel=retired "
              "owner_loss=retired reconnect=committed coordination=empty "
              f"probe_sha256={probe_sha}", flush=True)
        retained = cm_fd
        cm_fd = None
        return retained, cm
    except Exception:
        print(run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "-n", "30"]).stdout,
              flush=True)
        raise
    finally:
        if cm_fd is not None:
            os.close(cm_fd)


def rejection_journal(record, invocation, cursor=None):
    run(["/usr/bin/journalctl", "--sync"], timeout=5)
    argv = ["/usr/bin/journalctl", "--boot", "--quiet", "--no-pager", "--output=json",
            "--output-fields=__CURSOR,__MONOTONIC_TIMESTAMP,_BOOT_ID,_PID,_UID,_TRANSPORT,"
            "_STREAM_ID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,MESSAGE", "--lines=100",
            "_SYSTEMD_UNIT=rustdesk.service", "_SYSTEMD_INVOCATION_ID=" + invocation,
            "_PID=" + str(record["pid"]), "_UID=4001"]
    if cursor is not None:
        argv.append("--after-cursor=" + cursor)
    entries = [json.loads(line) for line in run(argv, timeout=5).stdout.splitlines()]
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    # Journald refreshes inherited-stream credentials from the actual sender.
    # Only the retained child can supply this receiver's rejection evidence.
    expected = {"_BOOT_ID": boot, "_PID": str(record["pid"]), "_UID": "4001",
                "_TRANSPORT": "stdout", "_SYSTEMD_UNIT": "rustdesk.service",
                "_SYSTEMD_INVOCATION_ID": invocation}
    if len(entries) > 100:
        raise RuntimeError("service journal entry count differs")
    for entry in entries:
        if (any(entry.get(key) != value for key, value in expected.items())
                or not isinstance(entry.get("MESSAGE"), str)
                or not isinstance(entry.get("__CURSOR"), str)
                or not 0 < len(entry["__CURSOR"]) <= 1024
                or re.fullmatch(r"[0-9a-f]{32}", entry.get("_STREAM_ID", "")) is None):
            observed = {key: entry.get(key) for key in expected}
            raise RuntimeError("service journal metadata is absent or ambiguous: "
                               + json.dumps(observed, sort_keys=True))
    return entries


def stale_refused(value, phase, record, probe_sha):
    listener = direct_listener(record)
    if listener is None:
        raise RuntimeError("obsolete-credential test has no serving listener")
    invocation = run(["/usr/bin/systemctl", "show", "rustdesk.service",
                      "--property=InvocationID", "--value"]).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        raise RuntimeError("installed service invocation identity is absent")
    child_stderr = Path(f"/proc/{record['pid']}/fd/2")
    parent_stderr = Path(f"/proc/{record['supervisor']}/fd/2")
    stream = os.readlink(child_stderr)
    if re.fullmatch(r"socket:\[[1-9][0-9]*\]", stream) is None or os.readlink(parent_stderr) != stream:
        raise RuntimeError("child stderr is not the inherited supervisor journal stream")
    baseline = rejection_journal(record, invocation)
    summary = "R-S10/R-T12 security summary"
    if not baseline or any(summary in entry["MESSAGE"] for entry in baseline):
        raise RuntimeError("obsolete-credential test lacks a clean journal baseline")
    previous = baseline[-1]
    before = credential()
    result = run(["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                  "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                  str(PROBE), "127.0.0.1:21118", "--password-stdin", "fail"],
                 input=value + "\n", timeout=45)
    if result.stdout.splitlines() != ["probe_client: keying ok=false (expected=fail)",
                                      "probe_client: PASS"] or result.stderr:
        raise RuntimeError("obsolete root credential completed network keying")
    entries = rejection_journal(record, invocation, previous["__CURSOR"])
    # Client failure counts only when the receiver records a tag mismatch.
    rejected = [entry for entry in entries if summary in entry["MESSAGE"]]
    if (len(rejected) != 1
            or re.search(r"R-S10/R-T12 security summary \(last 10s\): shed=0 rate_limited=0 "
                         r"key_confirmation_failures=1 recent_src=Some\(127\.0\.0\.1\)$",
                         rejected[0]["MESSAGE"]) is None
            or rejected[0]["_STREAM_ID"] != previous["_STREAM_ID"]
            or int(rejected[0]["__MONOTONIC_TIMESTAMP"]) <= int(previous["__MONOTONIC_TIMESTAMP"])):
        print("LINUX_RECEIVER_STALE_DIAGNOSTIC=" + json.dumps(
            {"phase": phase, "invocation": invocation, "summaries": rejected}, sort_keys=True), flush=True)
        raise RuntimeError("receiver did not record exactly one new confirmation mismatch")
    if (credential() != before or direct_listener(record) != listener
            or os.readlink(child_stderr) != stream or os.readlink(parent_stderr) != stream):
        raise RuntimeError("obsolete credential affected serving identity or durable state")
    print("LINUX_RECEIVER_STALE_OBSERVED=" + json.dumps(
        {"phase": phase, **record, "listener_inode": listener, "stderr_socket": stream,
         "invocation": invocation, "baseline_cursor": previous["__CURSOR"],
         "rejection": rejected[0]}, sort_keys=True), flush=True)
    print(f"LINUX_RECEIVER_STALE=pass phase={phase} uid=4002 server=supervised-child "
          f"listener=owned rejection=confirmation-mismatch journal=invocation-cursor-bound "
          f"probe_sha256={probe_sha}", flush=True)


def wire_frame(peer, allow_eof=False):
    deadline = time.monotonic() + 5

    def read(size, eof=False):
        data = b""
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("native proxy frame deadline expired")
            peer.settimeout(remaining)
            part = peer.recv(size - len(data))
            if not part:
                if eof and not data:
                    return b""
                raise RuntimeError("native proxy received a truncated frame")
            data += part
        return data

    first = read(1, allow_eof)
    if not first:
        return None
    header_size = (first[0] & 3) + 1
    header = first + read(header_size - 1)
    size = int.from_bytes(header, "little") >> 2
    if not 0 < size <= 4096 or header_size != (1 if size < 64 else 2):
        raise RuntimeError("native proxy frame is noncanonical or too large")
    return header + read(size)


def credential_race(old, new, phase, record, probe_sha):
    if phase not in ("control", "before-keys", "before-login"):
        raise RuntimeError("unknown native credential-race phase")
    listener = direct_listener(record)
    if listener is None:
        raise RuntimeError("credential-race test has no serving listener")
    before = credential()
    frames = []
    server_eof = False
    postkey_frames = 0

    def note(frame, direction, step):
        frames.append({"direction": direction, "step": step, "bytes": len(frame),
                       "sha256": hashlib.sha256(frame).hexdigest()})

    def replace():
        change(0, new, True)
        if credential() == before or direct_listener(record) != listener:
            raise RuntimeError("raced root mutation did not converge on the retained child")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.bind(("127.0.0.1", 0))
        proxy.listen(1)
        proxy.settimeout(5)
        port = proxy.getsockname()[1]
        mode = "login" if phase == "before-login" else "read"
        probe = subprocess.Popen(
            ["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
             "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
             str(PROBE), f"127.0.0.1:{port}", "--password-stdin", "ok", mode],
            env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            probe.stdin.write(old + "\n")
            probe.stdin.close()
            probe.stdin = None
            downstream, _ = proxy.accept()
            with downstream, socket.create_connection(("127.0.0.1", 21118), timeout=5) as upstream:
                for step, source, destination in (("step1", downstream, upstream),
                                                   ("step2", upstream, downstream)):
                    frame = wire_frame(source)
                    destination.sendall(frame)
                    note(frame, "c2s" if step == "step1" else "s2c", step)
                step3 = wire_frame(downstream)
                if phase == "before-keys":
                    # The real responder already snapshotted the old PRS for step2.
                    replace()
                upstream.sendall(step3)
                note(step3, "c2s", "step3")
                step4 = wire_frame(upstream)
                downstream.sendall(step4)
                note(step4, "s2c", "step4")
                if phase == "before-keys":
                    # Keep both directions open: only receiver-originated EOF counts.
                    if wire_frame(upstream, allow_eof=True) is not None:
                        raise RuntimeError("old transcript acquired a keyed application stream")
                    server_eof = True
                else:
                    login = wire_frame(downstream) if phase == "before-login" else None
                    # A server-sealed frame proves key installation before replacement.
                    barrier = wire_frame(upstream)
                    downstream.sendall(barrier)
                    note(barrier, "s2c", "postkey-barrier")
                    postkey_frames += 1
                    if phase == "before-login":
                        replace()
                        upstream.sendall(login)
                        note(login, "c2s", "held-login")
                        for _ in range(6):
                            frame = wire_frame(upstream, allow_eof=True)
                            if frame is None:
                                server_eof = True
                                break
                            downstream.sendall(frame)
                            note(frame, "s2c", "login-response")
                            postkey_frames += 1
                        else:
                            raise RuntimeError("raced login did not reach receiver EOF")
            stdout, stderr = probe.communicate(timeout=10)
        finally:
            if probe.poll() is None:
                probe.kill()
                probe.communicate(timeout=10)
            for pipe in (probe.stdin, probe.stdout, probe.stderr):
                if pipe is not None:
                    pipe.close()
    lines = stdout.splitlines()
    expected_exit = 1 if phase == "before-login" else 0
    if (probe.returncode != expected_exit or stderr or len(lines) != 3
            or lines[0] != "probe_client: keying ok=true (expected=ok)"
            or lines[-1] != ("probe_client: FAIL" if expected_exit else "probe_client: PASS")
            or not lines[1].startswith("probe_client: post-key = ")):
        raise RuntimeError(f"credential-race probe outcome differs: {stdout[-4096:]} {stderr[-4096:]}")
    postkey = lines[1].removeprefix("probe_client: post-key = ")
    if phase == "before-keys":
        valid = server_eof and postkey == "[0=TIMEOUT] " and postkey_frames == 0
    elif phase == "before-login":
        valid = (server_eof and "Some(TestDelay(" in postkey
                 and '[REMOTE-LOGIN-REJECTED Error("Permanent password changed during authorization")]' in postkey
                 and "REMOTE-LOGIN-ADMITTED" not in postkey and "PeerInfo" not in postkey)
    else:
        valid = "Some(TestDelay(" in postkey and "READ_ERR" not in postkey
    after = credential()
    listener_unchanged = direct_listener(record) == listener
    durable_changed = after != before
    print("LINUX_RECEIVER_RACE_OBSERVED=" + json.dumps(
        {"phase": phase, **record, "listener_inode": listener, "proxy_port": port,
         "transcript": frames, "server_eof": server_eof, "postkey_frames": postkey_frames,
         "listener_unchanged": listener_unchanged, "durable_changed": durable_changed,
         "probe_exit": probe.returncode, "postkey": postkey}, sort_keys=True), flush=True)
    if not valid or not listener_unchanged or durable_changed != (phase != "control"):
        raise RuntimeError(f"credential-race receiver outcome differs for {phase}: {postkey}")
    if phase == "control":
        print(f"LINUX_RECEIVER_PROXY_CONTROL=pass uid=4002 server=supervised-child "
              f"transcript=unmodified postkey=decrypted-test-delay cleanup=joined probe_sha256={probe_sha}", flush=True)
    else:
        rejection = "no-keyed-stream" if phase == "before-keys" else "generation-login-error"
        print(f"LINUX_RECEIVER_RACE=pass phase={phase} uid=4002 server=supervised-child "
              f"transcript=old-confirmed durable=changed listener=owned rejection={rejection} "
              f"cleanup=joined probe_sha256={probe_sha}", flush=True)


def network_shutdown(value, record, probe_sha):
    before = credential()
    listener = direct_listener(record)
    supervisor = Path("/proc") / str(record["supervisor"])
    supervisor_start = int((supervisor / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19])
    identities = {"supervisor": (supervisor, supervisor_start),
                  "child": (Path("/proc") / str(record["pid"]), record["start"])}
    pidfds = {}
    probe = None
    unit_reference = ServiceUnitResultReference()
    frames = []
    try:
        for role, (proc, start) in identities.items():
            pidfds[role] = os.pidfd_open(int(proc.name))
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            if int(fields[19]) != start or fields[0] in (b"Z", b"X"):
                raise RuntimeError("network shutdown lost a retained service identity")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
            proxy.bind(("127.0.0.1", 0))
            proxy.listen(1)
            proxy.settimeout(5)
            probe = subprocess.Popen(
                ["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                 "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                 str(PROBE), f"127.0.0.1:{proxy.getsockname()[1]}", "--password-stdin", "ok", "read"],
                env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            probe.stdin.write(value + "\n")
            probe.stdin.close()
            probe.stdin = None
            downstream, _ = proxy.accept()
            with downstream, socket.create_connection(("127.0.0.1", 21118), timeout=5) as keyed_peer, \
                    socket.create_connection(("127.0.0.1", 21118), timeout=5) as prekey_peer:
                for source, destination in ((downstream, keyed_peer), (keyed_peer, downstream),
                                            (downstream, keyed_peer), (keyed_peer, downstream)):
                    frame = wire_frame(source)
                    destination.sendall(frame)
                    frames.append({"bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()})
                # A sealed server frame establishes the keyed connection before shutdown.
                frame = wire_frame(keyed_peer)
                downstream.sendall(frame)
                frames.append({"bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()})
                ports = {keyed_peer.getsockname()[1], prekey_peer.getsockname()[1]}
                accepted = {}
                admission_deadline = time.monotonic() + 2
                while time.monotonic() < admission_deadline:
                    owned = set()
                    for fd in (identities["child"][0] / "fd").iterdir():
                        try:
                            target = os.readlink(fd)
                        except FileNotFoundError:
                            continue
                        match = re.fullmatch(r"socket:\[([1-9][0-9]*)\]", target)
                        if match:
                            owned.add(int(match[1]))
                    accepted = {}
                    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
                        fields = line.split()
                        if (len(fields) >= 10 and fields[1] == "0100007F:527E" and fields[3] == "01"
                                and fields[2].startswith("0100007F:") and int(fields[9]) in owned):
                            port = int(fields[2].split(":")[1], 16)
                            if port in ports:
                                accepted[port] = int(fields[9])
                    if set(accepted) == ports:
                        break
                    time.sleep(0.01)
                if (set(accepted) != ports or probe.poll() is not None or child_record() != record
                        or direct_listener(record) != listener
                        or any(select.select([fd], [], [], 0)[0] for fd in pidfds.values())):
                    raise RuntimeError("network shutdown lacks two live exact-child sockets")
                began = time.monotonic()
                run(["/usr/bin/systemctl", "stop", "--no-block", "rustdesk.service"], timeout=2)
                # Neither peer closes its write direction; only receiver-originated EOF counts.
                for _ in range(4):
                    frame = wire_frame(keyed_peer, allow_eof=True)
                    if frame is None:
                        break
                    downstream.sendall(frame)
                    frames.append({"bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()})
                else:
                    raise RuntimeError("keyed shutdown did not reach receiver EOF")
                prekey_peer.settimeout(max(0.001, 8 - (time.monotonic() - began)))
                if prekey_peer.recv(1) != b"":
                    raise RuntimeError("incomplete CPace peer received application data")
                eof_seconds = time.monotonic() - began
                stdout, stderr = probe.communicate(timeout=4)
        retired = {}
        while time.monotonic() - began < 10:
            for role, (proc, start) in identities.items():
                exited = bool(select.select([pidfds[role]], [], [], 0)[0])
                try:
                    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    reaped = int(fields[19]) != start
                except (FileNotFoundError, ProcessLookupError):
                    reaped = True
                retired[role] = {"exited": exited, "reaped": reaped}
            if all(item["exited"] and item["reaped"] for item in retired.values()):
                break
            time.sleep(0.02)
        outcome = dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,NRestarts"]).stdout.splitlines())
        unit_reference.close()
        cgroup = Path("/sys/fs/cgroup/system.slice/rustdesk.service")
        while cgroup.exists() and time.monotonic() - began < 10:
            time.sleep(0.02)
        elapsed = time.monotonic() - began
        absent = not any(len(f := line.split()) >= 10 and f[3] == "0A" and f[9] == str(listener)
                         for line in Path("/proc/net/tcp").read_text().splitlines()[1:])
        print("LINUX_RECEIVER_NETWORK_SHUTDOWN_OBSERVED=" + json.dumps(
            {**record, "supervisor_start": supervisor_start, "listener_inode": listener,
             "accepted_sockets": accepted, "frames": frames, "eof_seconds": eof_seconds,
             "elapsed_seconds": elapsed, "retired": retired, "unit_outcome": outcome,
             "unit_reference_held_at_outcome": True, "listener_absent": absent,
             "cgroup_absent": not cgroup.exists(), "durable_unchanged": credential() == before,
             "probe_exit": probe.returncode, "probe_stdout": stdout, "probe_stderr": stderr}, sort_keys=True), flush=True)
        lines = stdout.splitlines()
        if (probe.returncode != 0 or stderr or len(lines) != 3
                or lines[0] != "probe_client: keying ok=true (expected=ok)" or lines[-1] != "probe_client: PASS"
                or "Some(TestDelay(" not in lines[1] or 'CloseReason("Server is shutting down")' not in lines[1]
                or "READ_ERR" in lines[1] or eof_seconds >= 8 or elapsed >= 10
                or not all(item["exited"] and item["reaped"] for item in retired.values())
                or outcome != {"ActiveState": "inactive", "SubState": "dead", "Result": "success", "MainPID": "0",
                               "ExecMainCode": "1", "ExecMainStatus": "0", "NRestarts": "0"}
                or cgroup.exists() or not absent or credential() != before):
            raise RuntimeError("ordinary network shutdown did not close both peers and retire cleanly")
        print(f"LINUX_RECEIVER_NETWORK_SHUTDOWN=pass peers=prekey,keyed-prelogin close_reason=decrypted "
              f"eof=receiver-originated deadline=8 unit=clean process=exact-reaped durable=unchanged "
              f"cleanup=probe-joined probe_sha256={probe_sha}", flush=True)
    finally:
        if probe is not None:
            if probe.poll() is None:
                probe.kill()
                probe.communicate(timeout=5)
            for pipe in (probe.stdin, probe.stdout, probe.stderr):
                if pipe is not None:
                    pipe.close()
        unit_reference.close()
        for fd in pidfds.values():
            os.close(fd)


def installed_desktop(scenario, close_session=False, settings=False, session_controller=False):
    pam = pam_module()
    confdir = WORK / "pam"
    confdir.mkdir(mode=0o700)
    (confdir / "rustdesk-logind-fixture").write_text("session required pam_systemd.so\n")
    actor = None
    users = []
    try:
        for uid in (4001, 4002):
            try:
                pwd.getpwuid(uid)
            except KeyError:
                run(["/usr/sbin/useradd", "--uid", str(uid), "--user-group", "--create-home",
                     "--shell", "/usr/sbin/nologin", f"rdreceiver{uid}"])
                users.append(uid)
            else:
                raise RuntimeError("desktop fixture UID already exists")
        actor = subprocess.Popen(["/usr/bin/python3", "-B", "-I", "-S", str(Path(__file__)),
                                  "--settings-pam-actor" if settings else "--pam-actor"],
                                 env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        opened = pam.reply(actor)
        session = opened["session"]
        pam.properties({"process": actor, "session": session, "uid": 4001, "type": "x11"}, "active")
        deadline = time.monotonic() + 5
        while not Path("/tmp/.X11-unix/X77").is_socket():
            if actor.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("PAM-owned desktop did not start")
            time.sleep(0.05)
        if close_session or session_controller:
            scenario(actor, session, pam)
        else:
            scenario()
        if actor.poll() is not None:
            raise RuntimeError("desktop actor exited during service test")
        pam.properties({"process": actor, "session": session, "uid": 4001, "type": "x11"},
                       "closing" if close_session else "active")
    finally:
        try:
            if actor is not None:
                if actor.poll() is None:
                    actor.stdin.write(b"quit\n")
                    actor.stdin.flush()
                if actor.wait(timeout=10) != 0:
                    raise RuntimeError("desktop PAM actor cleanup failed")
                actor.stdin.close()
                actor.stdout.close()
        finally:
            for uid in users:
                run(["/usr/bin/systemctl", "stop", f"user@{uid}.service", f"user-runtime-dir@{uid}.service"])
                run(["/usr/sbin/userdel", f"rdreceiver{uid}"])
    if Path("/tmp/.X11-unix/X77").exists() or pam.sessions():
        raise RuntimeError("desktop fixture left an X11 or PAM session")
    print("LINUX_SERVICE_DESKTOP_SESSION=retired logind=actual x11=owned users=removed", flush=True)


def recovery_refusals(commit, binary_sha, probe_sha, readiness_spec):
    runtime = Path("/run/rustdesk")
    record_path = runtime / "service-child.record"
    parent = Path("/run/RustDesk-service")
    unit = Path("/etc/systemd/system/rustdesk.service")
    if any(os.path.lexists(p) for p in (runtime, parent, unit)):
        raise RuntimeError("recovery refusal fixture requires absent service state")
    readiness = WORK / "smoke_readiness"
    shutil.copyfile(MEDIA / "receiver/smoke_readiness", readiness)
    readiness.chmod(0o755)
    if readiness.stat().st_size != readiness_spec["bytes"] or digest(readiness) != readiness_spec["sha256"]:
        raise RuntimeError("retained readiness probe bytes differ")
    runtime.mkdir(mode=0o700)
    generation = str(uuid.uuid4())
    actors = []
    watch = None
    started = False

    def snapshot():
        st = record_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 1024:
            raise RuntimeError("recovery fixture record type or size differs")
        return {"identity": [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                             st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns],
                "sha256": digest(record_path)}

    def alive(actor):
        process = actor["process"]
        proc = Path("/proc") / str(process.pid)
        fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        exe = (proc / "exe").stat()
        status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
        if (process.poll() is not None or select.select([actor["pidfd"]], [], [], 0)[0]
                or fields[0] in (b"Z", b"X") or int(fields[19]) != actor["start"]
                or int(fields[1]) != os.getpid() or status["Uid"].split() != [str(actor["uid"])] * 4
                or [exe.st_dev, exe.st_ino] != actor["executable"]
                or (proc / "cmdline").read_bytes() != actor["argv"]):
            raise RuntimeError("recovery refusal changed a retained actor identity")
        argv = [str(readiness), "parked", str(process.pid), str(actor["start"]), "1000"]
        if actor["uid"]:
            argv = ["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                    "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs", *argv]
        result = run(argv, timeout=3, allowed=(0, 1))
        return result.returncode == 0 and result.stdout == "SMOKE_TYPED_IPC_READY state=parked\n" and not result.stderr

    def protected_events():
        events = []
        while select.select([watch], [], [], 0)[0]:
            data = os.read(watch, 65536)
            offset = 0
            while offset < len(data):
                _, mask, _, size = struct.unpack_from("iIII", data, offset)
                name = data[offset + 16:offset + 16 + size].rstrip(b"\0")
                offset += 16 + size
                if mask & 0x4000:
                    raise RuntimeError("recovery namespace observation overflowed")
                if name == b"RustDesk-service":
                    events.append(mask)
            if offset != len(data):
                raise RuntimeError("recovery namespace event is incomplete")
        return events

    try:
        for role, uid, args, extra in (
                ("recorded", 0, ["--server", "--service-owned-server"],
                 {"RUSTDESK_SERVICE_OWNED_SERVER_LAUNCH_PARENT": str(os.getpid()),
                  "RUSTDESK_SERVICE_OWNED_SERVER_GENERATION": generation,
                  "RD_SERVICE_SMOKE_UNSUPERVISED_RECOVERY_FIXTURE": "1", "HOME": "/root"}),
                ("portable", 4002, ["--server"], {"HOME": "/home/rdreceiver4002", "USER": "rdreceiver4002"})):
            log = WORK / ("recovery-" + role + ".log")
            stream = log.open("xb")
            argv = [str(PRIMARY), *args]
            if uid:
                argv = ["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                        "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs", *argv]
            process = subprocess.Popen(argv, env={**ENV, "RUST_LOG": "info", **extra}, cwd="/",
                                       stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT)
            stream.close()
            actor = {"process": process, "pidfd": os.pidfd_open(process.pid), "uid": uid, "role": role, "log": log}
            actors.append(actor)
            proc = Path("/proc") / str(process.pid)
            deadline = time.monotonic() + 10
            expected_argv = b"\0".join(a.encode() for a in [str(PRIMARY), *args]) + b"\0"
            while (proc / "cmdline").read_bytes() != expected_argv:
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("recovery actor did not execute the installed image")
                time.sleep(0.02)
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            exe = (proc / "exe").stat()
            if digest(proc / "exe") != binary_sha:
                raise RuntimeError("recovery actor image differs")
            actor.update(start=int(fields[19]), executable=[exe.st_dev, exe.st_ino], argv=expected_argv)
            while not alive(actor):
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"recovery actor did not become typed parked: {log.read_text()[-4096:]}")
                time.sleep(0.05)
        libc = ctypes.CDLL(None, use_errno=True)
        watch = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if watch < 0 or libc.inotify_add_watch(watch, b"/run", 0x100 | 0x200 | 0x40 | 0x80) < 0:
            raise RuntimeError("cannot observe protected namespace creation")
        cases = (("live-no-pidfd", actors[0], generation, True, "Kernel lacks required pidfd_open for live Linux service child"),
                 ("generation-pidfd", actors[0], str(uuid.uuid4()), False, "service generation is absent or duplicated"),
                 ("generation-no-pidfd", actors[0], str(uuid.uuid4()), True, "Refusing ambiguous Linux service child recovery without pidfd"),
                 ("portable-role-pidfd", actors[1], generation, False, "exact service-owned role marker is absent"),
                 ("portable-role-no-pidfd", actors[1], generation, True, "Refusing ambiguous Linux service child recovery without pidfd"))
        for label, actor, recorded_generation, unavailable, reason in cases:
            body = ("version=1\n" + f"pid={actor['process'].pid}\nstart_time={actor['start']}\n"
                    + f"boot_id={Path('/proc/sys/kernel/random/boot_id').read_text().strip()}\n"
                    + f"exe_dev={actor['executable'][0]}\nexe_ino={actor['executable'][1]}\n"
                    + f"uid={actor['uid']}\ngeneration={recorded_generation}\nrole=--server+--service-owned-server\n").encode()
            with record_path.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            before = snapshot()
            if protected_events() or parent.exists() or not all(alive(a) for a in actors):
                raise RuntimeError("recovery fixture lost its initial boundary")
            env = {**ENV, "RUST_LOG": "info"}
            if unavailable:
                env["RD_SERVICE_SMOKE_FORCE_PIDFD_UNAVAILABLE"] = "1"
            began = time.monotonic()
            result = run(["/usr/bin/rustdesk", "--service"], env=env, timeout=10, allowed=(0, 1))
            output = result.stdout + result.stderr
            events = protected_events()
            if (result.returncode != 1 or reason not in output
                    or "Linux service lifecycle authority failed closed:" not in output
                    or (unavailable and "Smoke forced pidfd_open unavailable" not in output)
                    or snapshot() != before or events or parent.exists()
                    or (runtime / "service-child.record.tmp").exists()
                    or not all(alive(a) for a in actors)):
                raise RuntimeError(f"record recovery did not refuse and preserve {label}: {output[-4096:]}")
            print("LINUX_SERVICE_RECOVERY_REFUSAL_OBSERVED=" + json.dumps(
                {"case": label, "record": before, "record_text": body.decode(), "exit": result.returncode,
                 "stdout": result.stdout, "stderr": result.stderr, "elapsed_seconds": time.monotonic() - began,
                 "namespace_events": events, "actors_parked": True, "pidfd_unavailable": unavailable,
                 "actors": [{"role": a["role"], "pid": a["process"].pid, "start": a["start"],
                             "uid": a["uid"], "executable": a["executable"]} for a in actors]}, sort_keys=True), flush=True)
            if snapshot() != before:
                raise RuntimeError("recovery record changed before exact fixture retirement")
            record_path.unlink()
            print(f"LINUX_SERVICE_RECOVERY_REFUSAL_CASE=pass case={label}", flush=True)
        for actor in actors:
            if not alive(actor):
                raise RuntimeError("recovery actor failed its final parked observation")
            signal.pidfd_send_signal(actor["pidfd"], signal.SIGTERM)
            if actor["process"].wait(timeout=10) != 0 or not select.select([actor["pidfd"]], [], [], 0)[0]:
                raise RuntimeError("recovery actor did not shut down cleanly")
        if protected_events() or parent.exists():
            raise RuntimeError("refused recovery created protected service authority")
        shutil.copyfile(MEDIA / "repo/res/rustdesk.service", unit)
        run(["/usr/bin/systemctl", "daemon-reload"])
        started = True
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        control_events = protected_events()
        if not any(mask & (0x100 | 0x80) for mask in control_events):
            raise RuntimeError("namespace observer missed the normal startup control")
        record = ready()
        value = "Receiver-recovery-control-2026!"
        change(0, value, True)
        keyed(value, "recovery-control", record, probe_sha)
        pidfds = [os.pidfd_open(record[key]) for key in ("supervisor", "pid")]
        try:
            run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
            deadline = time.monotonic() + 5
            while Path("/sys/fs/cgroup/system.slice/rustdesk.service").exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            if (any(not select.select([fd], [], [], 0)[0] for fd in pidfds)
                    or any(Path(f"/proc/{record[key]}").exists() for key in ("supervisor", "pid"))
                    or record_path.exists() or Path("/sys/fs/cgroup/system.slice/rustdesk.service").exists()):
                raise RuntimeError("normal recovery control did not retire its exact service tree")
        finally:
            for fd in pidfds:
                os.close(fd)
        print("LINUX_SERVICE_RECOVERY_CONTROL_OBSERVED=" + json.dumps(
            {"record": record, "namespace_events": control_events, "processes_reaped": True,
             "cgroup_absent": True, "record_absent": True}, sort_keys=True), flush=True)
        print(f"LINUX_SERVICE_RECOVERY_REFUSAL_NATIVE=pass cases=5 refused=5 actors=2 control=installed-cpace "
              f"source={commit} binary_sha256={binary_sha} readiness_sha256={readiness_spec['sha256']} "
              "fixture=debug-live-record namespace=inotify cleanup=joined", flush=True)
    except BaseException:
        for actor in actors:
            with actor["log"].open("rb") as stream:
                stream.seek(max(0, actor["log"].stat().st_size - 4096))
                print("LINUX_SERVICE_RECOVERY_ACTOR_DIAGNOSTIC=" + json.dumps(
                    {"role": actor["role"], "pid": actor["process"].pid,
                     "output_tail": stream.read(4096).decode("utf-8", errors="replace")}, sort_keys=True), flush=True)
        raise
    finally:
        if started:
            run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        if watch is not None and watch >= 0:
            os.close(watch)
        for actor in actors:
            process = actor["process"]
            try:
                if process.poll() is None:
                    signal.pidfd_send_signal(actor["pidfd"], signal.SIGKILL)
                process.wait(timeout=10)
                if actor["log"].stat().st_size > 131072:
                    raise RuntimeError("recovery actor log exceeded its bound")
            finally:
                os.close(actor["pidfd"])


def record_cleanup_retry(commit, binary_sha, probe_sha, actor, session, pam):
    if os.uname().machine != "x86_64":
        raise RuntimeError("record-cleanup syscall observer requires the pinned x86_64 VM")
    unit = Path("/etc/systemd/system/rustdesk.service")
    record_path = Path("/run/rustdesk/service-child.record")
    if unit.exists() or record_path.parent.exists():
        raise RuntimeError("record-cleanup fixture requires absent service state")
    shutil.copyfile(MEDIA / "repo/res/rustdesk.service", unit)
    run(["/usr/bin/systemctl", "daemon-reload"])
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    pidfds = []
    traced = paused = False
    supervisor = None
    reference = ServiceUnitResultReference()

    def trace(request, address=0, data=0):
        result = libc.ptrace(request, supervisor, address, data)
        if result == -1:
            raise OSError(ctypes.get_errno(), "record-cleanup supervisor trace failed")
        return result

    def wait_trace(deadline):
        while time.monotonic() < deadline:
            pid, status = os.waitpid(supervisor, os.WNOHANG | 0x40000000)
            if pid == supervisor:
                return status
            time.sleep(0.001)
        raise RuntimeError("record-cleanup syscall observation exceeded its deadline")

    try:
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        record = ready()
        supervisor = record["supervisor"]
        supervisor_proc = Path("/proc") / str(supervisor)
        if (digest(supervisor_proc / "exe") != binary_sha
                or (supervisor_proc / "cmdline").read_bytes() != b"/usr/bin/rustdesk\0--service\0"):
            raise RuntimeError("record-cleanup supervisor image or role differs")
        supervisor_start = int((supervisor_proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19])
        for pid in (supervisor, record["pid"]):
            pidfds.append(os.pidfd_open(pid))
        if child_record() != record or any(select.select([fd], [], [], 0)[0] for fd in pidfds):
            raise RuntimeError("record-cleanup process ownership changed")
        value = "Receiver-record-cleanup-2026!"
        change(0, value, True)
        durable = credential()
        keyed(value, "record-cleanup-control", record, probe_sha)
        raw_record = record_path.read_bytes()
        metadata = record_path.lstat()
        trace(0x4206, data=1 | 0x100000)  # SEIZE with TRACESYSGOOD and EXITKILL.
        traced = True
        trace(0x4207)  # INTERRUPT the retained supervisor's lifecycle thread only.
        status = wait_trace(time.monotonic() + 3)
        if not os.WIFSTOPPED(status) or status >> 16 != 128:
            raise RuntimeError("record-cleanup supervisor did not reach the trace barrier")
        paused = True
        actor.stdin.write(b"close\n")
        actor.stdin.flush()
        if pam.reply(actor) != {"session": session, "phase": "closed"}:
            raise RuntimeError("record-cleanup desktop did not close its PAM session")
        events = []
        active = None
        injected = False
        calls = 0
        deadline = time.monotonic() + 30
        deliver = 0
        while True:
            trace(24, data=deliver)  # SYSCALL; preserve ordinary signal delivery.
            paused = False
            status = wait_trace(deadline)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                traced = False
                if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 1:
                    raise RuntimeError("record-cleanup error did not produce the expected service failure")
                break
            if not os.WIFSTOPPED(status):
                raise RuntimeError("record-cleanup trace returned an unknown process state")
            paused = True
            stopped_signal = os.WSTOPSIG(status)
            deliver = 0
            if stopped_signal != (signal.SIGTRAP | 0x80):
                if status >> 16:
                    raise RuntimeError("record-cleanup trace reported an unexpected ptrace event")
                deliver = stopped_signal
                continue
            info = ctypes.create_string_buffer(128)
            size = trace(0x420e, ctypes.sizeof(info), ctypes.byref(info))  # GET_SYSCALL_INFO.
            data = info.raw
            if size > len(data) or size < 24 or struct.unpack_from("I", data, 4)[0] != 0xc000003e:
                raise RuntimeError("record-cleanup syscall ABI differs")
            if data[0] == 1:
                if size < 80:
                    raise RuntimeError("record-cleanup syscall entry is incomplete")
                number, *args = struct.unpack_from("7Q", data, 24)
                active = (number, args)
                calls += 1
                if calls > 10000:
                    raise RuntimeError("record-cleanup syscall count exceeded its bound")
                if number == 62 and args[:2] == [record["pid"], signal.SIGTERM]:
                    absent = not Path(f"/proc/{record['pid']}").exists()
                    if injected and (not absent or not select.select([pidfds[1]], [], [], 0)[0]):
                        raise RuntimeError("record-cleanup reaped child identity is no longer absent")
                    events.append({"event": "term-entry", "after_reap": injected, "pid_absent": absent})
            elif data[0] == 2:
                if size < 33:
                    raise RuntimeError("record-cleanup syscall exit is incomplete")
                result = struct.unpack_from("q", data, 24)[0]
                if active is not None:
                    number, args = active
                    if number == 62 and args[:2] == [record["pid"], signal.SIGTERM]:
                        events.append({"event": "term-exit", "after_reap": injected, "result": result})
                    if number == 61 and args[0] == record["pid"] and result == record["pid"]:
                        if (injected or Path(f"/proc/{record['pid']}").exists()
                                or not select.select([pidfds[1]], [], [], 0)[0]):
                            raise RuntimeError("record-cleanup wait did not reap the original child exactly once")
                        current = record_path.lstat()
                        if ((current.st_dev, current.st_ino, current.st_uid, current.st_mode, current.st_nlink)
                                != (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode, metadata.st_nlink)
                                or record_path.read_bytes() != raw_record):
                            raise RuntimeError("record changed before the exact post-reap fault")
                        record_path.unlink()
                        injected = True
                        events.append({"event": "reaped-record-unlinked", "pid": result,
                                       "record_sha256": hashlib.sha256(raw_record).hexdigest()})
                active = None
            else:
                raise RuntimeError("record-cleanup observer lacks syscall entry/exit information")
        run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        deadline = time.monotonic() + 5
        while (supervisor_proc.exists() or Path("/sys/fs/cgroup/system.slice/rustdesk.service").exists()) and time.monotonic() < deadline:
            time.sleep(0.02)
        if (not injected or supervisor_proc.exists() or not all(select.select([fd], [], [], 0)[0] for fd in pidfds)
                or Path("/sys/fs/cgroup/system.slice/rustdesk.service").exists() or credential() != durable):
            raise RuntimeError("record-cleanup fixture did not retire the exact service tree")
        before = [e for e in events if e["event"] == "term-exit" and not e["after_reap"]]
        after = [e for e in events if e["event"] == "term-exit" and e["after_reap"]]
        if before != [{"event": "term-exit", "after_reap": False, "result": 0}]:
            raise RuntimeError("record-cleanup trace lacks its real successful-signal control")
        print("LINUX_SERVICE_RECORD_CLEANUP_OBSERVED=" + json.dumps(
            {"record": record, "supervisor_start": supervisor_start, "events": events, "syscalls": calls,
             "post_reap_signals": len(after), "exit": 1, "durable_unchanged": True,
             "processes_reaped": True, "cgroup_absent": True, "fault": "exact-record-unlink-after-wait4"},
            sort_keys=True), flush=True)
        if after:
            raise RuntimeError("record-cleanup retry signalled an already reaped child")
        print(f"LINUX_SERVICE_RECORD_CLEANUP_NATIVE=pass faults=1 post_reap_signals=0 cpace=1 source={commit} "
              f"binary_sha256={binary_sha} probe_sha256={probe_sha} fixture=installed-layout "
              "trace=actual-syscalls cleanup=joined", flush=True)
    finally:
        try:
            if traced:
                if not paused:
                    trace(0x4207)
                    status = wait_trace(time.monotonic() + 3)
                    if not os.WIFSTOPPED(status):
                        raise RuntimeError("record-cleanup trace cleanup lost its stop barrier")
                trace(17)  # DETACH before requesting normal service cleanup.
            run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        finally:
            reference.close()
            for fd in pidfds:
                os.close(fd)


def stopped_child_shutdown(commit, binary_sha, probe_sha):
    unit = Path("/etc/systemd/system/rustdesk.service")
    record_path = Path("/run/rustdesk/service-child.record")
    cgroup = Path("/sys/fs/cgroup/system.slice/rustdesk.service")
    if any(os.path.lexists(p) for p in (unit, record_path.parent, cgroup)):
        raise RuntimeError("stopped-child fixture requires absent service state")
    shutil.copyfile(MEDIA / "repo/res/rustdesk.service", unit)
    run(["/usr/bin/systemctl", "daemon-reload"])
    value = "Receiver-stopped-child-2026!"
    reference = ServiceUnitResultReference()
    retained = []

    def properties():
        return dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,NRestarts,InvocationID"]).stdout.splitlines())

    def retain(record):
        identities = {}
        for role, pid in (("supervisor", record["supervisor"]), ("child", record["pid"])):
            proc = Path("/proc") / str(pid)
            fd = os.pidfd_open(pid)
            retained.append(fd)
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            if fields[0] in (b"Z", b"X") or select.select([fd], [], [], 0)[0]:
                raise RuntimeError("stopped-child fixture retained an exited process")
            if role == "child" and int(fields[19]) != record["start"]:
                raise RuntimeError("stopped-child start identity differs")
            if role == "supervisor" and (digest(proc / "exe") != binary_sha
                    or (proc / "cmdline").read_bytes() != b"/usr/bin/rustdesk\0--service\0"):
                raise RuntimeError("stopped-child supervisor image or role differs")
            identities[role] = {"pid": pid, "start": int(fields[19]), "pidfd": fd}
        if child_record() != record:
            raise RuntimeError("stopped-child fixture lost its selected child")
        return identities

    def retired(identities):
        result = {}
        for role, identity in identities.items():
            try:
                fields = Path(f"/proc/{identity['pid']}/stat").read_bytes().rsplit(b") ", 1)[1].split()
                reaped = int(fields[19]) != identity["start"]
            except (FileNotFoundError, ProcessLookupError):
                reaped = True
            result[role] = {"exited": bool(select.select([identity["pidfd"]], [], [], 0)[0]), "reaped": reaped}
        return result

    def record_snapshot():
        st = record_path.lstat()
        return {"metadata": [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                             st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns],
                "sha256": digest(record_path)}

    def stopped(record):
        proc = Path("/proc") / str(record["pid"])
        states = {p.name: (p / "stat").read_bytes().rsplit(b") ", 1)[1].split()[0].decode()
                  for p in (proc / "task").iterdir()}
        status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
        return {"threads": states, "term_pending": bool(int(status["ShdPnd"], 16) & (1 << (signal.SIGTERM - 1)))}

    def wait_retired(identities, deadline):
        while time.monotonic() < deadline:
            result = retired(identities)
            if not cgroup.exists() and all(v["exited"] and v["reaped"] for v in result.values()):
                return result
            time.sleep(0.02)
        raise RuntimeError(f"stopped-child service did not retire: {retired(identities)}")

    def clean_stop(identities, deadline, durable):
        result = wait_retired(identities, deadline)
        outcome = properties()
        while outcome["ActiveState"] == "deactivating" and time.monotonic() < deadline:
            time.sleep(0.02)
            outcome = properties()
        if (outcome["ActiveState"] != "inactive" or outcome["SubState"] != "dead"
                or outcome["Result"] != "success" or outcome["MainPID"] != "0"
                or outcome["ExecMainCode"] != "1" or outcome["ExecMainStatus"] != "0"
                or outcome["NRestarts"] != "0" or record_path.exists() or credential() != durable):
            raise RuntimeError(f"stopped-child service stop was not complete: {outcome}")
        return {"unit": outcome, "processes": result, "record_absent": True, "cgroup_absent": True}

    try:
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        old = ready()
        old_processes = retain(old)
        before = properties()
        if (before["ActiveState"], before["SubState"], before["Result"], before["NRestarts"]) != ("active", "running", "success", "0"):
            raise RuntimeError("stopped-child initial service is not ready")
        change(0, value, True)
        durable = credential()
        keyed(value, "stopped-before", old, probe_sha)
        old_listener = direct_listener(old)
        snapshot = record_snapshot()
        signal.pidfd_send_signal(old_processes["child"]["pidfd"], signal.SIGSTOP)
        deadline = time.monotonic() + 3
        while True:
            observed = stopped(old)
            if observed["threads"] and set(observed["threads"].values()) == {"T"}:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("exact child did not enter complete group stop")
            time.sleep(0.02)
        if child_record() != old or record_snapshot() != snapshot or properties() != before:
            raise RuntimeError("stopping the child changed service authority")
        print("LINUX_SERVICE_STOPPED_CHILD_INJECTION=" + json.dumps(
            {"record": old, "unit": before, "record_snapshot": snapshot, "stopped": observed,
             "listener_inode": old_listener, "signal": "SIGSTOP", "target": "child-pidfd"}, sort_keys=True), flush=True)
        began = time.monotonic()
        run(["/usr/bin/systemctl", "stop", "--no-block", "rustdesk.service"], timeout=2)
        pending = None
        samples = 0
        while pending is None or time.monotonic() - pending < 4:
            observed = stopped(old)
            current = properties()
            if (not observed["threads"] or set(observed["threads"].values()) != {"T"}
                    or any(v["exited"] or v["reaped"] for v in retired(old_processes).values())
                    or child_record() != old or record_snapshot() != snapshot or credential() != durable
                    or current["ActiveState"] not in ("active", "deactivating")
                    or (pending is not None and (current["ActiveState"] != "deactivating" or not observed["term_pending"]))
                    or current["MainPID"] != before["MainPID"]
                    or current["InvocationID"] != before["InvocationID"] or current["NRestarts"] != "0"):
                raise RuntimeError("pending stop released ownership or resumed/replaced the stopped child")
            if observed["term_pending"] and pending is None:
                pending = time.monotonic()
            if pending is None and time.monotonic() - began >= 3:
                raise RuntimeError("supervisor did not request termination of the stopped child")
            samples += 1
            time.sleep(0.1)
        print("LINUX_SERVICE_STOPPED_CHILD_HELD=" + json.dumps(
            {"record": old, "unit": current, "record_snapshot": record_snapshot(), "stopped": observed,
             "pending_observed_seconds": pending - began, "held_seconds": time.monotonic() - pending,
             "samples": samples}, sort_keys=True), flush=True)
        first_stop = clean_stop(old_processes, began + 20, durable)
        elapsed = time.monotonic() - began
        if elapsed < 8 or elapsed >= 20 or any(len(f := line.split()) >= 10 and f[3] == "0A" and f[9] == str(old_listener)
                for line in Path("/proc/net/tcp").read_text().splitlines()[1:]):
            raise RuntimeError("stopped-child termination timing or listener retirement differs")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if properties() != first_stop["unit"] or cgroup.exists() or record_path.exists():
                raise RuntimeError("explicit stop was followed by an automatic restart")
            time.sleep(0.2)
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        new = ready(old)
        new_processes = retain(new)
        after = properties()
        if (after["ActiveState"] != "active" or after["SubState"] != "running" or after["Result"] != "success"
                or after["NRestarts"] != "0" or after["InvocationID"] == before["InvocationID"] or credential() != durable):
            raise RuntimeError("fresh start after forced shutdown changed authority or failed")
        keyed(value, "stopped-recovery", new, probe_sha)
        run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        final_stop = clean_stop(new_processes, time.monotonic() + 5, durable)
        print("LINUX_SERVICE_STOPPED_CHILD_OBSERVED=" + json.dumps(
            {"old": old, "new": new, "before": before, "after": after, "first_stop": first_stop,
             "final_stop": final_stop, "forced_stop_seconds": elapsed, "old_listener": old_listener,
             "durable_unchanged": True, "automatic_restarts": 0}, sort_keys=True), flush=True)
        print(f"LINUX_SERVICE_STOPPED_CHILD_NATIVE=pass generations=2 stopped=1 held=4 restarts=0 cpace=2 "
              f"source={commit} binary_sha256={binary_sha} probe_sha256={probe_sha} fixture=installed-layout "
              "unit=shipped logind=actual signal=child-pidfd cleanup=joined", flush=True)
    except BaseException:
        print(run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "-n", "60"]).stdout, flush=True)
        raise
    finally:
        try:
            run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        finally:
            reference.close()
            for fd in retained:
                os.close(fd)


def service_session_handoff(commit, binary_sha, probe_sha):
    unit = Path("/etc/systemd/system/rustdesk.service")
    record_path = Path("/run/rustdesk/service-child.record")
    cgroup = Path("/sys/fs/cgroup/system.slice/rustdesk.service")
    pam = pam_module()
    if any(os.path.lexists(p) for p in (unit, record_path.parent, cgroup)) or pam.sessions():
        raise RuntimeError("session handoff requires absent service and desktop state")
    confdir = WORK / "pam"
    confdir.mkdir(mode=0o700)
    (confdir / "rustdesk-logind-fixture").write_text("session required pam_systemd.so\n")
    users, actors, retained, observations = [], [], [], []
    reference = None
    value = "Receiver-session-handoff-2026!"

    def properties():
        return dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,NRestarts,InvocationID,ExecMainCode,ExecMainStatus"]).stdout.splitlines())

    def endpoints(supervisor):
        result = {}
        for suffix in ("_service", "_service_password", "_service_credential"):
            path = Path("/run/RustDesk-service") / ("ipc" + suffix)
            st = path.lstat()
            if not stat.S_ISSOCK(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, 0o666):
                raise RuntimeError("handoff endpoint authority differs")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(2)
                peer.connect(str(path))
                credentials = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if credentials != (supervisor, 0, 0):
                    raise RuntimeError("handoff endpoint supervisor differs")
            result[suffix] = {"device": st.st_dev, "inode": st.st_ino, "peer": credentials}
        return result

    def start_desktop(uid, display):
        process = subprocess.Popen(["/usr/bin/python3", "-B", "-I", "-S", str(Path(__file__)),
                                    "--pam-actor" if uid == 4001 else "--handoff-actor"],
                                   env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        actor = {"process": process, "uid": uid, "type": "x11"}
        actors.append(actor)
        opened = pam.reply(process)
        if opened.get("phase") != "opened":
            raise RuntimeError("handoff desktop session did not open")
        actor["session"] = opened["session"]
        actor["desktop_pid"] = opened["desktop_pid"]
        pam.properties(actor, "active")
        deadline = time.monotonic() + 5
        while not Path(f"/tmp/.X11-unix/X{display}").is_socket():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("handoff X11 desktop did not start")
            time.sleep(0.05)
        actor["desktop_fd"] = os.pidfd_open(actor["desktop_pid"])
        retained.append(actor["desktop_fd"])
        return actor

    def close_session(actor):
        actor["process"].stdin.write(b"close\n")
        actor["process"].stdin.flush()
        if pam.reply(actor["process"]) != {"session": actor["session"], "phase": "closed"}:
            raise RuntimeError("handoff PAM close was not acknowledged")
        pam.properties(actor, "closing")

    def desktops_live():
        if any(a["process"].poll() is not None or select.select([a["desktop_fd"]], [], [], 0)[0] for a in actors):
            raise RuntimeError("handoff desktop exited instead of remaining alive")

    def child_retired(record, fd, deadline):
        while not select.select([fd], [], [], 0)[0] or Path(f"/proc/{record['pid']}").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("handoff retained the previous session child")
            time.sleep(0.02)

    def login(record, uid, display):
        deadline = time.monotonic() + 10
        listener = direct_listener(record, uid=uid)
        while listener is None and time.monotonic() < deadline:
            time.sleep(0.05)
            listener = direct_listener(record, uid=uid)
        if listener is None:
            raise RuntimeError("handoff child listener never became ready")
        environment = dict(v.split(b"=", 1) for v in Path(f"/proc/{record['pid']}/environ").read_bytes().split(b"\0") if v)
        expected = {b"HOME": f"/home/rdreceiver{uid}", b"USER": f"rdreceiver{uid}",
                    b"LOGNAME": f"rdreceiver{uid}", b"DISPLAY": f":{display}",
                    b"XDG_RUNTIME_DIR": f"/run/user/{uid}", b"XAUTHORITY": f"/run/user/{uid}/gdm/Xauthority"}
        if any(environment.get(k) != v.encode() for k, v in expected.items()):
            raise RuntimeError("handoff child retained another desktop environment")
        result = run(["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                      "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                      str(PROBE), "127.0.0.1:21118", "--password-stdin", "ok", "login"],
                     input=value + "\n", timeout=15)
        lines = result.stdout.splitlines()
        if (result.stderr or len(lines) != 3 or lines[0] != "probe_client: keying ok=true (expected=ok)"
                or lines[-1] != "probe_client: PASS" or "[REMOTE-LOGIN-ADMITTED peer-info]" not in lines[1]
                or f'username: "rdreceiver{uid}"' not in lines[1]
                or credential() != durable or child_record(uid=uid) != record
                or direct_listener(record, uid=uid) != listener):
            raise RuntimeError("handoff child authenticated login failed")
        print("LINUX_SERVICE_HANDOFF_LOGIN_OBSERVED=" + json.dumps(
            {"uid": uid, "display": display, "record": record, "listener_inode": listener,
             "environment": {k.decode(): v for k, v in expected.items()},
             "stdout": result.stdout, "stderr": result.stderr, "exit": result.returncode}, sort_keys=True), flush=True)
        print(f"LINUX_SERVICE_HANDOFF_LOGIN=pass child_uid={uid} client_uid=4002 cpace=mutual "
              f"remote=peer-info probe_sha256={probe_sha}", flush=True)
        return listener

    try:
        for uid in (4001, 4002, 4003):
            try:
                pwd.getpwuid(uid)
            except KeyError:
                run(["/usr/sbin/useradd", "--uid", str(uid), "--user-group", "--create-home",
                     "--shell", "/usr/sbin/nologin", f"rdreceiver{uid}"])
                users.append(uid)
            else:
                raise RuntimeError("handoff fixture UID already exists")
        first_actor = start_desktop(4001, 77)
        shutil.copyfile(MEDIA / "repo/res/rustdesk.service", unit)
        run(["/usr/bin/systemctl", "daemon-reload"])
        reference = ServiceUnitResultReference()
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        first = ready()
        supervisor = first["supervisor"]
        supervisor_fd = os.pidfd_open(supervisor)
        retained.append(supervisor_fd)
        supervisor_start = Path(f"/proc/{supervisor}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19]
        if digest(Path(f"/proc/{supervisor}/exe")) != binary_sha:
            raise RuntimeError("handoff supervisor image differs")
        initial = properties()
        if (initial["ActiveState"], initial["SubState"], initial["Result"], initial["NRestarts"]) != ("active", "running", "success", "0"):
            raise RuntimeError("handoff service is not stable")
        initial_endpoints = endpoints(supervisor)
        change(0, value, True)
        durable = credential()

        def stable():
            if (select.select([supervisor_fd], [], [], 0)[0] or properties() != initial
                    or Path(f"/proc/{supervisor}/stat").read_bytes().rsplit(b") ", 1)[1].split()[19] != supervisor_start
                    or endpoints(supervisor) != initial_endpoints or credential() != durable):
                raise RuntimeError("session handoff changed the supervisor or durable authority")
            desktops_live()

        first_fd = os.pidfd_open(first["pid"])
        retained.append(first_fd)
        first_listener = login(first, 4001, 77)
        began = time.monotonic()
        close_session(first_actor)
        second_actor = start_desktop(4003, 78)
        child_retired(first, first_fd, began + 15)
        second = ready(first, child_replacement=True, uid=4003)
        second_fd = os.pidfd_open(second["pid"])
        retained.append(second_fd)
        second_listener = login(second, 4003, 78)
        handoff_seconds = time.monotonic() - began
        if handoff_seconds >= 35 or first_listener == second_listener:
            raise RuntimeError("handoff did not restore a fresh serving child within its deadline")
        stable()
        observations.append({"phase": "handoff", "old": first, "new": second,
                             "old_listener": first_listener, "new_listener": second_listener,
                             "old_reaped": True, "seconds": handoff_seconds})
        began = time.monotonic()
        close_session(second_actor)
        child_retired(second, second_fd, began + 15)
        while record_path.exists():
            stable()
            if time.monotonic() >= began + 15:
                raise RuntimeError("sessionless supervisor did not retire the reaped child's record")
            time.sleep(0.02)
        deadline = time.monotonic() + 3
        samples = 0
        while time.monotonic() < deadline:
            stable()
            if record_path.exists() or any(len(f := line.split()) >= 10 and f[1].endswith(":527E") and f[3] == "0A"
                                          for line in Path("/proc/net/tcp").read_text().splitlines()[1:]):
                raise RuntimeError("closing sessions retained a child record or direct listener")
            samples += 1
            time.sleep(0.1)
        observations.append({"phase": "sessionless", "child": second, "child_reaped": True,
                             "seconds": time.monotonic() - began, "stable_samples": samples})
        run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        terminal = properties()
        if (terminal["ActiveState"], terminal["SubState"], terminal["Result"], terminal["MainPID"]) != ("inactive", "dead", "success", "0"):
            raise RuntimeError("sessionless supervisor did not stop cleanly")
        if (terminal["ExecMainCode"], terminal["ExecMainStatus"]) != ("1", "0"):
            raise RuntimeError("sessionless supervisor did not exit zero")
        if cgroup.exists() or record_path.exists() or Path(f"/proc/{supervisor}").exists() or not select.select([supervisor_fd], [], [], 0)[0]:
            raise RuntimeError("sessionless service cleanup is incomplete")
        print("LINUX_SERVICE_HANDOFF_OBSERVED=" + json.dumps(
            {"initial": initial, "terminal": terminal, "endpoints": initial_endpoints,
             "transitions": observations, "credential_unchanged": credential() == durable,
             "closing_desktops_alive": True, "supervisor_reaped": True}, sort_keys=True), flush=True)
        if credential() != durable:
            raise RuntimeError("final handoff stop changed the durable credential")
    except BaseException:
        print(run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "-n", "60"]).stdout, flush=True)
        raise
    finally:
        try:
            run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40, allowed=(0, 5))
        finally:
            try:
                for actor in actors:
                    process = actor["process"]
                    if process.poll() is None:
                        process.stdin.write(b"quit\n")
                        process.stdin.flush()
                    if process.wait(timeout=10) != 0:
                        raise RuntimeError("handoff PAM actor did not retire cleanly")
                    process.stdin.close()
                    process.stdout.close()
            finally:
                if reference is not None:
                    reference.close()
                for fd in retained:
                    os.close(fd)
                for uid in users:
                    run(["/usr/bin/systemctl", "stop", f"user@{uid}.service", f"user-runtime-dir@{uid}.service"])
                    run(["/usr/sbin/userdel", f"rdreceiver{uid}"])
    if pam.sessions() or any(Path(f"/tmp/.X11-unix/X{display}").exists() for display in (77, 78)):
        raise RuntimeError("handoff desktop sessions or X11 sockets remain")
    print(f"LINUX_SERVICE_HANDOFF_NATIVE=pass supervisors=1 children=2 handoffs=1 logins=2 source={commit} "
          f"binary_sha256={binary_sha} probe_sha256={probe_sha} fixture=installed-layout unit=shipped "
          "logind=actual seats=none credential=preserved cleanup=joined", flush=True)


def service_limiter(commit, binary_sha, probe_sha):
    unit = Path("/etc/systemd/system/rustdesk.service")
    record_path = Path("/run/rustdesk/service-child.record")
    cgroup = Path("/sys/fs/cgroup/system.slice/rustdesk.service")
    if any(os.path.lexists(p) for p in (unit, record_path.parent, cgroup)):
        raise RuntimeError("limiter fixture requires absent service state")
    shutil.copyfile(MEDIA / "repo/res/rustdesk.service", unit)
    run(["/usr/bin/systemctl", "daemon-reload"])
    reference = ServiceUnitResultReference()
    retained = []
    observations = []
    value = "Receiver-limiter-recovery-2026!"
    live = None
    live_prefix = b""

    def properties():
        return dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,NRestarts,InvocationID"]).stdout.splitlines())

    def unchanged():
        if (properties() != before or child_record() != record or credential() != durable
                or direct_listener(record) != listener
                or any(select.select([fd], [], [], 0)[0] for _, fd in retained)
                or (live is not None and live.poll() is not None)):
            raise RuntimeError("limiter observation changed service, child, listener or credential")

    def attempt(password, allowed, source, phase):
        unchanged()
        began = time.monotonic()
        expected = "ok" if allowed else "fail"
        result = run(["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                      "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                      str(PROBE), "127.0.0.1:21118", "--password-stdin", expected,
                      "login" if allowed else "", source + ":0"], input=password + "\n", timeout=15)
        lines = result.stdout.splitlines()
        if (result.stderr or len(lines) != (3 if allowed else 2)
                or lines[0] != f"probe_client: keying ok={str(allowed).lower()} (expected={expected})"
                or lines[-1] != "probe_client: PASS"
                or (allowed and "[REMOTE-LOGIN-ADMITTED peer-info]" not in lines[1])):
            raise RuntimeError(f"installed limiter outcome differs: {phase}: {result.stdout} {result.stderr}")
        unchanged()
        observations.append({"phase": phase, "source": source, "keyed": allowed,
                             "remote_peer_info": allowed, "began": began,
                             "completed": time.monotonic()})
        print("LINUX_SERVICE_LIMITER_CASE=" + json.dumps(observations[-1], sort_keys=True), flush=True)

    def wait_until(deadline):
        while time.monotonic() < deadline:
            unchanged()
            time.sleep(min(1, max(0, deadline - time.monotonic())))

    try:
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        record = ready()
        for pid in (record["supervisor"], record["pid"]):
            retained.append((pid, os.pidfd_open(pid)))
        if (digest(Path(f"/proc/{record['supervisor']}/exe")) != binary_sha
                or Path(f"/proc/{record['supervisor']}/cmdline").read_bytes() != b"/usr/bin/rustdesk\0--service\0"):
            raise RuntimeError("limiter supervisor executable or role differs")
        change(0, value, True)
        durable = credential()
        deadline = time.monotonic() + 10
        listener = direct_listener(record)
        while listener is None and time.monotonic() < deadline:
            time.sleep(0.05)
            listener = direct_listener(record)
        before = properties()
        if (listener is None or before["MainPID"] != str(record["supervisor"])
                or (before["ActiveState"], before["SubState"], before["Result"], before["NRestarts"])
                != ("active", "running", "success", "0")):
            raise RuntimeError("limiter service did not become ready")
        source, other = "127.0.0.1", "127.0.0.2"
        live_started = time.monotonic()
        live = subprocess.Popen(
            ["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
             "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
             str(PROBE), "127.0.0.1:21118", "--password-stdin", "ok", "remote-live", "127.0.0.1:0"],
            env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        live.stdin.write((value + "\n").encode())
        live.stdin.close()
        live.stdin = None
        while b"\n" not in live_prefix:
            remaining = live_started + 15 - time.monotonic()
            if remaining <= 0 or not select.select([live.stdout], [], [], remaining)[0]:
                raise RuntimeError("persistent Remote login did not become ready")
            chunk = os.read(live.stdout.fileno(), 512)
            if not chunk or len(live_prefix) + len(chunk) > 1024:
                raise RuntimeError("persistent Remote readiness output is absent or oversized")
            live_prefix += chunk
        ready_line, live_prefix = live_prefix.split(b"\n", 1)
        if ready_line != b"REMOTE_LIVE_READY=pass auth=cpace remote=peer-info source=127.0.0.1":
            raise RuntimeError(f"persistent Remote readiness differs: {ready_line!r}")
        live_ready = time.monotonic()
        print("LINUX_SERVICE_LIMITER_LIVE_READY=" + json.dumps(
            {"pid": live.pid, "ready": live_ready, "source": source, "remote_peer_info": True},
            sort_keys=True), flush=True)
        attempt(value, True, source, "initial")
        attempt(value, True, other, "initial-other")
        for index in range(1, 10):
            attempt(value + "-wrong", False, source, f"wrong-{index}")
            if index == 1:
                first = observations[-1]
        for _ in range(12):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
                peer.settimeout(5)
                peer.bind((source, 0))
                peer.connect(("127.0.0.1", 21118))
                peer.shutdown(socket.SHUT_WR)
                if peer.recv(1) != b"":
                    raise RuntimeError("pre-key EOF control did not close")
        attempt(value, True, source, "nine-failures-plus-eof")
        attempt(value + "-wrong", False, source, "wrong-10")
        for checkpoint in (0, 20, 40):
            wait_until(first["began"] + checkpoint)
            attempt(value, False, source, f"blocked-{checkpoint}")
            if observations[-1]["completed"] - first["began"] >= 55:
                raise RuntimeError("blocked observation ran too near window expiry")
            attempt(value, True, other, f"other-{checkpoint}")
        wait_until(first["completed"] + 64)
        attempt(value, True, source, "recovered")
        attempt(value, True, other, "recovered-other")
        recovery_seconds = observations[-2]["completed"] - first["completed"]
        if not 64 <= recovery_seconds < 70:
            raise RuntimeError("installed limiter recovery exceeded its observation deadline")
        if len(observations) != 21 or sum(item["remote_peer_info"] for item in observations) != 8:
            raise RuntimeError("installed limiter case inventory differs")
        live_recovery = time.monotonic()
        stdout, stderr = live.communicate(timeout=max(1, live_started + 105 - time.monotonic()))
        live_ended = time.monotonic()
        lines = (live_prefix + stdout).decode("utf-8").splitlines()
        roundtrips = []
        for line in lines[:-3]:
            matched = re.fullmatch(r"REMOTE_LIVE_ROUNDTRIP=pass seq=([0-9]+) nonce=([0-9]+) elapsed_ms=([0-9]+)", line)
            if matched is None:
                raise RuntimeError(f"persistent Remote round-trip output differs: {line}")
            sequence, nonce, elapsed = map(int, matched.groups())
            if (sequence != len(roundtrips) or nonce != 1_000_000 + sequence
                    or not sequence * 2000 <= elapsed < sequence * 2000 + 4000):
                raise RuntimeError("persistent Remote round-trip correlation or timing differs")
            roundtrips.append({"sequence": sequence, "nonce": nonce, "elapsed_ms": elapsed})
        if (live.returncode != 0 or stderr or len(roundtrips) != 45 or lines[-3:] != [
                "probe_client: keying ok=true (expected=ok)",
                "probe_client: post-key = [REMOTE-LIVE-COMPLETE roundtrips=45]", "probe_client: PASS"]):
            raise RuntimeError(f"persistent Remote session did not complete: {lines[-3:]} {stderr!r}")
        live_observed = {"pid": live.pid, "ready": live_ready, "recovery": live_recovery,
                         "ended": live_ended, "exit": live.returncode, "roundtrips": roundtrips}
        print("LINUX_SERVICE_LIMITER_LIVE_OBSERVED=" + json.dumps(live_observed, sort_keys=True), flush=True)
    except BaseException:
        print(run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "-n", "60"]).stdout, flush=True)
        raise
    finally:
        try:
            try:
                if live is not None:
                    if live.poll() is None:
                        live.kill()
                        live.communicate(timeout=5)
                    for pipe in (live.stdout, live.stderr):
                        pipe.close()
            finally:
                run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
            deadline = time.monotonic() + 5
            for pid, fd in retained:
                if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                    raise RuntimeError("limiter service process did not exit")
                while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                if Path(f"/proc/{pid}").exists():
                    raise RuntimeError("limiter service process was not reaped")
            after = properties()
            if (after["ActiveState"] != "inactive" or after["SubState"] != "dead"
                    or after["Result"] != "success" or after["MainPID"] != "0"
                    or after["ExecMainCode"] != "1" or after["ExecMainStatus"] != "0"
                    or after["NRestarts"] != "0" or record_path.exists() or cgroup.exists()):
                raise RuntimeError(f"limiter service cleanup differs: {after}")
        finally:
            reference.close()
            for _, fd in retained:
                os.close(fd)
    if credential() != durable:
        raise RuntimeError("limiter service stop changed its credential")
    print("LINUX_SERVICE_LIMITER_OBSERVED=" + json.dumps(
        {"record": record, "listener_inode": listener, "before": before, "after": after,
         "recovery_seconds": recovery_seconds, "cases": len(observations), "logins": 9,
         "live_roundtrips": 45, "live_probe_reaped": live.returncode == 0,
         "eof_controls": 12, "credential_unchanged": True, "processes_reaped": True}, sort_keys=True), flush=True)
    print(f"LINUX_SERVICE_LIMITER_NATIVE=pass cases=21 logins=9 live_roundtrips=45 eof=12 threshold=10 checkpoints=0,20,40 "
          f"recovered=64s source={commit} binary_sha256={binary_sha} probe_sha256={probe_sha} "
          "fixture=installed-layout unit=shipped logind=actual generation=unchanged credential=preserved cleanup=joined", flush=True)


def service_openrc(commit, binary_sha, probe_sha):
    unit = Path("/etc/systemd/system/rustdesk.service")
    script = Path("/etc/init.d/rustdesk")
    source = MEDIA / "repo/res/service-managers/openrc/rustdesk"
    runtime = Path("/run/openrc")
    runlevel = Path("/etc/runlevels/rustdesk-fixture")
    pidfile = Path("/run/rustdesk.pid")
    record_path = Path("/run/rustdesk/service-child.record")
    if any(os.path.lexists(path) for path in (unit, script, runtime, runlevel, pidfile, record_path.parent)):
        raise RuntimeError("OpenRC scenario requires absent manager/service state")
    manager_env = {**ENV, "PATH": "/sbin:/usr/sbin:/usr/bin:/bin"}
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0 or previous.value != 0:
        raise RuntimeError("OpenRC fixture subreaper state differs")
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot retain OpenRC-backgrounded supervisor")
    retained = []
    observations = []
    active = None
    before_children = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()

    def manager(action):
        result = run(["/sbin/rc-service", "rustdesk", action], timeout=45, env=manager_env)
        print("LINUX_OPENRC_MANAGER=" + json.dumps({"action": action, "exit": result.returncode,
              "stdout": result.stdout, "stderr": result.stderr}, sort_keys=True), flush=True)

    def capture():
        nonlocal active
        deadline = time.monotonic() + 5
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        metadata = pidfile.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != 0 or metadata.st_mode & 0o022 or not 1 <= metadata.st_size <= 32):
            raise RuntimeError("OpenRC pidfile authority differs")
        raw = pidfile.read_bytes()
        if re.fullmatch(rb"[1-9][0-9]*\n?", raw) is None:
            raise RuntimeError("OpenRC pidfile grammar differs")
        pid = int(raw)
        fd = os.pidfd_open(pid)
        retained.append(fd)
        proc = Path(f"/proc/{pid}")
        fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
        if status["PPid"].strip() != str(os.getpid()) or status["Uid"].split() != ["0"] * 4:
            raise RuntimeError("OpenRC background process parent or principal differs")
        active = {"pid": pid, "start": int(fields[19]), "fd": fd,
                  "record": None, "child_fd": None, "reaped": False}
        expected = PRIMARY.stat()
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0)[0]:
                raise RuntimeError("OpenRC background process exited before RustDesk exec")
            executable = (proc / "exe").stat()
            if (executable.st_dev, executable.st_ino) == (expected.st_dev, expected.st_ino):
                if ((proc / "cmdline").read_bytes() != b"/usr/bin/rustdesk\0--service\0"
                        or digest(proc / "exe") != binary_sha or unit.exists()):
                    raise RuntimeError("OpenRC supervisor role or image differs")
                return active
            time.sleep(0.01)
        raise RuntimeError("OpenRC background process did not exec the exact RustDesk image")

    def ready(owned):
        deadline = time.monotonic() + 25
        last = ""
        while time.monotonic() < deadline:
            if select.select([owned["fd"]], [], [], 0)[0]:
                raise RuntimeError("OpenRC supervisor exited before readiness")
            try:
                record = child_record(owned["pid"])
                for suffix in ("_service", "_service_password", "_service_credential"):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
                        endpoint.settimeout(1)
                        endpoint.connect(f"/run/RustDesk-service/ipc{suffix}")
                        peer = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if peer != (owned["pid"], 0, 0):
                            raise RuntimeError("OpenRC endpoint owner differs")
                child_fd = os.pidfd_open(record["pid"])
                retained.append(child_fd)
                owned.update(record=record, child_fd=child_fd)
                return record
            except (OSError, ValueError, RuntimeError) as error:
                last = str(error)
            time.sleep(0.05)
        raise RuntimeError(f"OpenRC service readiness failed: {last}")

    def retired(owned):
        if not select.select([owned["fd"]], [], [], 5)[0]:
            raise RuntimeError("OpenRC command returned with its supervisor alive")
        waited, status = os.waitpid(owned["pid"], 0)
        owned["reaped"] = True
        if waited != owned["pid"] or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError("OpenRC supervisor did not exit cleanly")
        if (not select.select([owned["child_fd"]], [], [], 0)[0]
                or Path(f"/proc/{owned['record']['pid']}").exists()):
            raise RuntimeError("OpenRC shutdown left its service child")

    def observe_children(owned, phase):
        observations = []
        for parent in (os.getpid(), owned["pid"], owned["record"]["pid"]):
            children = set()
            for task in Path(f"/proc/{parent}/task").iterdir():
                try:
                    children.update((task / "children").read_text().split())
                except FileNotFoundError:
                    continue
            if len(children) > 64:
                raise RuntimeError("OpenRC descendant observation exceeds its bound")
            for pid in sorted(children, key=int):
                proc = Path("/proc") / pid
                try:
                    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
                    observations.append({"parent": parent, "pid": int(pid), "state": fields[0].decode(),
                                         "start": int(fields[19]), "raw_exit": int(fields[49]),
                                         "uid": status["Uid"].split(),
                                         "comm": (proc / "comm").read_text().strip(),
                                         "argv": (proc / "cmdline").read_bytes()[:512].decode(errors="replace")})
                except FileNotFoundError:
                    observations.append({"parent": parent, "pid": int(pid), "state": "absent"})
        print("LINUX_OPENRC_CHILDREN=" + json.dumps({"phase": phase, "children": observations}, sort_keys=True), flush=True)

    try:
        shutil.copyfile(source, script)
        script.chmod(0o755)
        runlevel.mkdir(mode=0o755, parents=True)
        runtime.mkdir(mode=0o755)
        (runtime / "softlevel").write_text("rustdesk-fixture\n")
        run(["/sbin/openrc", "--no-stop", "rustdesk-fixture"], env=manager_env)
        if not (runtime / "started").is_dir() or list((runtime / "started").iterdir()):
            raise RuntimeError("OpenRC empty runlevel started another service")
        value = "Receiver-openrc-lifecycle-2026!"
        manager("start")
        for generation in (1, 2):
            active = capture()
            record = ready(active)
            observe_children(active, f"ready-{generation}")
            if generation == 1:
                change(0, value, True)
                durable = credential()
            elif credential() != durable or record["generation"] == observations[0]["record"]["generation"]:
                raise RuntimeError("OpenRC restart did not preserve credential and replace generation")
            deadline = time.monotonic() + 10
            while direct_listener(record, active["pid"]) is None and time.monotonic() < deadline:
                time.sleep(0.05)
            listener = direct_listener(record, active["pid"])
            if listener is None:
                raise RuntimeError("OpenRC child did not open its direct listener")
            login = run(["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                         "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                         str(PROBE), "127.0.0.1:21118", "--password-stdin", "ok", "login"],
                        input=value + "\n", timeout=15)
            lines = login.stdout.splitlines()
            if (login.stderr or len(lines) != 3 or lines[0] != "probe_client: keying ok=true (expected=ok)"
                    or lines[-1] != "probe_client: PASS" or "[REMOTE-LOGIN-ADMITTED peer-info]" not in lines[1]
                    or child_record(active["pid"]) != record or credential() != durable):
                raise RuntimeError("OpenRC authenticated login failed")
            print(f"LINUX_OPENRC_LOGIN=pass generation={generation} uid=4002 cpace=mutual "
                  f"remote=peer-info probe_sha256={probe_sha}", flush=True)
            manager("status")
            observe_children(active, f"before-stop-{generation}")
            began = time.monotonic()
            manager("restart" if generation == 1 else "stop")
            retired(active)
            observations.append({"generation": generation, "record": record,
                                 "supervisor_exit": 0, "child_reaped": True,
                                 "operation_seconds": time.monotonic() - began})
            active = None
            print("LINUX_OPENRC_OBSERVED=" + json.dumps(observations[-1], sort_keys=True), flush=True)
        final = {"record_present": os.path.lexists(record_path),
                 "started_services": sorted(path.name for path in (runtime / "started").iterdir()),
                 "credential_unchanged": credential() == durable,
                 "script_unchanged": digest(script) == digest(source),
                 "systemd_unit_present": os.path.lexists(unit),
                 "children_before": before_children,
                 "children_after": Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()}
        extra_children = []
        for pid in set(final["children_after"]) - set(before_children):
            proc = Path("/proc") / pid
            try:
                fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                extra_children.append({"pid": int(pid), "state": fields[0].decode(),
                                       "parent": int(fields[1]), "start": int(fields[19]),
                                       "comm": (proc / "comm").read_text().strip()})
            except FileNotFoundError:
                extra_children.append({"pid": int(pid), "state": "absent"})
        print("LINUX_OPENRC_FINAL=" + json.dumps({**final, "extra_children": extra_children}, sort_keys=True), flush=True)
        if (final["record_present"] or final["started_services"] or not final["credential_unchanged"]
                or not final["script_unchanged"] or final["systemd_unit_present"]
                or final["children_after"] != before_children):
            raise RuntimeError("OpenRC final lifecycle state differs; see LINUX_OPENRC_FINAL")
        stopped = run(["/sbin/rc-service", "rustdesk", "status"], allowed=(3,), env=manager_env)
        print("LINUX_OPENRC_STOPPED=" + json.dumps({"exit": stopped.returncode,
              "stdout": stopped.stdout, "stderr": stopped.stderr}, sort_keys=True), flush=True)
    finally:
        manager_error = None
        try:
            if script.exists() and (runtime / "started/rustdesk").exists():
                try:
                    manager("stop")
                except BaseException as error:
                    manager_error = error
            if active is not None:
                if not active["reaped"]:
                    if not select.select([active["fd"]], [], [], 5)[0]:
                        signal.pidfd_send_signal(active["fd"], signal.SIGKILL)
                    os.waitpid(active["pid"], 0)
                if active["child_fd"] is not None:
                    if not select.select([active["child_fd"]], [], [], 5)[0]:
                        raise RuntimeError("failed OpenRC scenario retained its child")
                    try:
                        os.waitpid(active["record"]["pid"], 0)
                    except ChildProcessError:
                        if Path(f"/proc/{active['record']['pid']}").exists():
                            raise RuntimeError("failed OpenRC child was not reaped")
        finally:
            for fd in retained:
                os.close(fd)
            if libc.prctl(36, 0, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "cannot restore OpenRC subreaper state")
        if manager_error is not None:
            raise manager_error
    script.unlink()
    runlevel.rmdir()
    shutil.rmtree(runtime)
    print(f"LINUX_OPENRC_NATIVE=pass generations=2 restarts=1 stops=1 logins=2 source={commit} "
          f"binary_sha256={binary_sha} probe_sha256={probe_sha} fixture=installed-layout "
          "manager=openrc script=shipped logind=actual credential=preserved cleanup=joined", flush=True)


def service_parent_death(commit, binary_sha, probe_sha):
    unit = Path("/etc/systemd/system/rustdesk.service")
    record_path = Path("/run/rustdesk/service-child.record")
    if any(os.path.lexists(p) for p in (unit, record_path.parent, Path("/run/RustDesk-service"))):
        raise RuntimeError("manual supervisor fixture requires absent service state")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0 or previous.value != 0:
        raise RuntimeError("fixture subreaper state differs")
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "cannot retain orphaned service child")
    value = "Receiver-parent-death-2026!"
    supervisor = None
    sibling = None
    retained = []
    child_pid = None
    child_fd = None
    observations = []
    try:
        sibling = subprocess.Popen(["/usr/bin/sleep", "120"], env=ENV)
        for generation in (1, 2):
            with (WORK / f"manual-supervisor-{generation}.log").open("xb") as output:
                supervisor = subprocess.Popen(["/usr/bin/rustdesk", "--service"], env=ENV,
                                              stdout=output, stderr=subprocess.STDOUT)
            supervisor_fd = os.pidfd_open(supervisor.pid)
            retained.append(supervisor_fd)
            deadline = time.monotonic() + 25
            last = ""
            while True:
                if supervisor.poll() is not None:
                    raise RuntimeError("manual supervisor exited before readiness")
                try:
                    record = child_record(supervisor.pid)
                    for suffix in ("_service", "_service_password", "_service_credential"):
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
                            endpoint.settimeout(1)
                            endpoint.connect(f"/run/RustDesk-service/ipc{suffix}")
                            peer = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                            if peer != (supervisor.pid, 0, 0):
                                raise RuntimeError("manual supervisor endpoint owner differs")
                    break
                except (OSError, ValueError, RuntimeError) as error:
                    last = str(error)
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"manual supervisor readiness failed: {last}")
                time.sleep(0.05)
            child_pid = record["pid"]
            child_fd = os.pidfd_open(child_pid)
            retained.append(child_fd)
            if (child_record(supervisor.pid) != record or unit.exists()
                    or digest(Path(f"/proc/{supervisor.pid}/exe")) != binary_sha
                    or Path(f"/proc/{supervisor.pid}/cgroup").read_bytes() != Path("/proc/self/cgroup").read_bytes()):
                raise RuntimeError("manual supervisor identity or manager isolation differs")
            if generation == 1:
                change(0, value, True)
                durable = credential()
            elif credential() != durable or record["generation"] == observations[0]["record"]["generation"]:
                raise RuntimeError("manual restart did not preserve credential and replace generation")
            deadline = time.monotonic() + 10
            while direct_listener(record, supervisor.pid) is None and time.monotonic() < deadline:
                time.sleep(0.05)
            listener = direct_listener(record, supervisor.pid)
            if listener is None:
                raise RuntimeError("manual child did not open its direct listener")
            login = run(["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                         "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                         str(PROBE), "127.0.0.1:21118", "--password-stdin", "ok", "login"],
                        input=value + "\n", timeout=15)
            lines = login.stdout.splitlines()
            if (login.stderr or len(lines) != 3 or lines[0] != "probe_client: keying ok=true (expected=ok)"
                    or lines[-1] != "probe_client: PASS" or "[REMOTE-LOGIN-ADMITTED peer-info]" not in lines[1]
                    or credential() != durable or child_record(supervisor.pid) != record):
                raise RuntimeError("manual child authenticated login failed")
            print(f"LINUX_SERVICE_PARENT_DEATH_LOGIN=pass generation={generation} uid=4002 cpace=mutual "
                  f"remote=peer-info probe_sha256={probe_sha}", flush=True)
            if generation == 1:
                before_record = record_path.read_bytes()
                began = time.monotonic()
                signal.pidfd_send_signal(supervisor_fd, signal.SIGKILL)
                if supervisor.wait(timeout=5) != -signal.SIGKILL:
                    raise RuntimeError("manual supervisor crash status differs")
                if not select.select([child_fd], [], [], max(0, 5 - (time.monotonic() - began)))[0]:
                    raise RuntimeError("service child survived its parent without manager cleanup")
                waited, status = os.waitpid(child_pid, 0)
                if waited != child_pid or not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
                    raise RuntimeError("adopted service child did not terminate by parent-death SIGKILL")
                child_pid = None
                elapsed = time.monotonic() - began
                if elapsed >= 5 or record_path.read_bytes() != before_record:
                    raise RuntimeError("parent-death retirement exceeded deadline or changed durable record")
            else:
                signal.pidfd_send_signal(supervisor_fd, signal.SIGTERM)
                if supervisor.wait(timeout=20) != 0 or not select.select([child_fd], [], [], 0)[0]:
                    raise RuntimeError("manual restarted service did not retire normally")
                if record_path.exists():
                    raise RuntimeError("normal manual shutdown retained its child record")
                child_pid = None
                elapsed = None
            if (Path(f"/proc/{record['pid']}").exists() or unit.exists() or sibling.poll() is not None
                    or credential() != durable
                    or any(len(f := line.split()) >= 10 and f[3] == "0A" and f[9] == str(listener)
                           for line in Path("/proc/net/tcp").read_text().splitlines()[1:])):
                raise RuntimeError("manual retirement left a child/listener or affected unrelated state")
            observations.append({"generation": generation, "record": record, "listener_inode": listener,
                                 "supervisor_exit": supervisor.returncode, "child_reaped": True,
                                 "parent_death_seconds": elapsed, "sibling_alive": True, "credential_unchanged": True})
            print("LINUX_SERVICE_PARENT_DEATH_OBSERVED=" + json.dumps(observations[-1], sort_keys=True), flush=True)
    except BaseException:
        for log in sorted(WORK.glob("manual-supervisor-*.log")):
            with log.open("rb") as output:
                output.seek(max(0, os.fstat(output.fileno()).st_size - 4096))
                print("LINUX_SERVICE_PARENT_DEATH_DIAGNOSTIC=" + json.dumps(
                    {"file": log.name, "tail": output.read(4096).decode(errors="replace")}), flush=True)
        raise
    finally:
        try:
            if supervisor is not None and supervisor.poll() is None:
                supervisor.terminate()
                supervisor.wait(timeout=20)
            if child_pid is not None and child_fd is not None:
                if not select.select([child_fd], [], [], 0)[0]:
                    signal.pidfd_send_signal(child_fd, signal.SIGKILL)
                if not select.select([child_fd], [], [], 5)[0]:
                    raise RuntimeError("failed manual scenario could not retire its exact child")
                try:
                    os.waitpid(child_pid, 0)
                except ChildProcessError:
                    if Path(f"/proc/{child_pid}").exists():
                        raise RuntimeError("failed manual scenario left its exact child")
        finally:
            if sibling is not None:
                if sibling.poll() is None:
                    sibling.terminate()
                sibling.wait(timeout=5)
            for fd in retained:
                os.close(fd)
            if libc.prctl(36, 0, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "cannot restore fixture subreaper state")
    print(f"LINUX_SERVICE_PARENT_DEATH_NATIVE=pass generations=2 crashes=1 logins=2 source={commit} "
          f"binary_sha256={binary_sha} probe_sha256={probe_sha} fixture=installed-layout "
          "manager=absent logind=actual child=supervised signal=supervisor-pidfd cleanup=joined", flush=True)


def service_crash(commit, binary_sha, probe_sha, child_only=False):
    prefix = "LINUX_SERVICE_CHILD_CRASH" if child_only else "LINUX_SERVICE_CRASH"
    target = "child" if child_only else "supervisor"
    unit = Path("/etc/systemd/system/rustdesk.service")
    runtime = Path("/run/rustdesk")
    parent = Path("/run/RustDesk-service")
    record_path = runtime / "service-child.record"
    cgroup = Path("/sys/fs/cgroup/system.slice/rustdesk.service")
    if any(os.path.lexists(p) for p in (unit, runtime, parent, cgroup)):
        raise RuntimeError("crash fixture requires absent service state")
    shutil.copyfile(MEDIA / "repo/res/rustdesk.service", unit)
    run(["/usr/bin/systemctl", "daemon-reload"])
    value = "Receiver-supervisor-crash-2026!"
    reference = ServiceUnitResultReference()
    retained = []

    def properties():
        return dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,NRestarts,InvocationID"]).stdout.splitlines())

    def authority(path, mode, directory=False):
        st = path.lstat()
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        if (not kind(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, mode)
                or (not directory and st.st_nlink != 1)):
            raise RuntimeError(f"crash fixture authority differs: {path}")
        return [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode]

    def retain(record):
        result = {}
        for role, pid in (("supervisor", record["supervisor"]), ("child", record["pid"])):
            proc = Path("/proc") / str(pid)
            fd = os.pidfd_open(pid)
            retained.append(fd)
            fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
            if fields[0] in (b"Z", b"X") or select.select([fd], [], [], 0)[0]:
                raise RuntimeError("crash fixture retained an exited process")
            start = int(fields[19])
            if role == "child" and start != record["start"]:
                raise RuntimeError("crash fixture child identity changed")
            if role == "supervisor" and (digest(proc / "exe") != binary_sha
                    or (proc / "cmdline").read_bytes() != b"/usr/bin/rustdesk\0--service\0"):
                raise RuntimeError("crash fixture supervisor image or role differs")
            result[role] = {"pid": pid, "start": start, "pidfd": fd}
        if child_record() != record:
            raise RuntimeError("crash fixture lost its selected child")
        return result

    def retired(identities):
        result = {}
        for role, identity in identities.items():
            try:
                fields = Path(f"/proc/{identity['pid']}/stat").read_bytes().rsplit(b") ", 1)[1].split()
                reaped = int(fields[19]) != identity["start"]
            except (FileNotFoundError, ProcessLookupError):
                reaped = True
            result[role] = {"exited": bool(select.select([identity["pidfd"]], [], [], 0)[0]), "reaped": reaped}
        return result

    def all_retired(identities):
        return all(v["exited"] and v["reaped"] for v in retired(identities).values())

    def endpoints(record):
        authority(parent, 0o711, directory=True)
        observed = {}
        for suffix in ("_service", "_service_password", "_service_credential"):
            endpoint = parent / ("ipc" + suffix)
            st = endpoint.lstat()
            if (not stat.S_ISSOCK(st.st_mode)
                    or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, 0o666)):
                raise RuntimeError("crash fixture service socket authority differs")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(3)
                peer.connect(str(endpoint))
                credentials = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if credentials != (record["supervisor"], 0, 0):
                    raise RuntimeError("crash fixture endpoint has a different owner")
            observed[suffix] = {"device": st.st_dev, "inode": st.st_ino, "peer": credentials}
        return observed

    def login(record, phase):
        deadline = time.monotonic() + 10
        listener = direct_listener(record)
        while listener is None and time.monotonic() < deadline:
            time.sleep(0.05)
            listener = direct_listener(record)
        if listener is None:
            raise RuntimeError("crash fixture child never opened its listener")
        before = credential()
        result = run(["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                      "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                      str(PROBE), "127.0.0.1:21118", "--password-stdin", "ok", "login"],
                     input=value + "\n", timeout=15)
        lines = result.stdout.splitlines()
        if (result.stderr or len(lines) != 3 or lines[0] != "probe_client: keying ok=true (expected=ok)"
                or lines[-1] != "probe_client: PASS" or "[REMOTE-LOGIN-ADMITTED peer-info]" not in lines[1]
                or "READ_ERR" in lines[1] or "REMOTE-LOGIN-REJECTED" in lines[1]
                or credential() != before or child_record() != record or direct_listener(record) != listener):
            raise RuntimeError(f"crash fixture desktop login failed: {result.stdout[-4096:]} {result.stderr[-4096:]}")
        print(prefix + "_LOGIN_OBSERVED=" + json.dumps(
            {"phase": phase, "record": record, "listener_inode": listener,
             "stdout": result.stdout, "stderr": result.stderr, "exit": result.returncode}, sort_keys=True), flush=True)
        print(f"{prefix}_LOGIN=pass phase={phase} uid=4002 cpace=mutual remote=peer-info probe_sha256={probe_sha}", flush=True)
        return listener

    try:
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        old = ready()
        old_processes = retain(old)
        before = properties()
        if (before["ActiveState"], before["SubState"], before["Result"], before["NRestarts"]) != ("active", "running", "success", "0"):
            raise RuntimeError(f"crash fixture initial service state differs: {before}")
        old_endpoints = endpoints(old)
        runtime_before = authority(runtime, 0o700, directory=True)
        lease_before = authority(runtime / "service-supervisor.lock", 0o600)
        old_record = {"identity": authority(record_path, 0o600), "sha256": digest(record_path)}
        change(0, value, True)
        durable = credential()
        old_listener = login(old, "before")
        with socket.create_connection(("127.0.0.1", 21118), timeout=5) as peer:
            port = peer.getsockname()[1]
            accepted = None
            deadline = time.monotonic() + 2
            while accepted is None and time.monotonic() < deadline:
                owned = set()
                for fd in Path(f"/proc/{old['pid']}/fd").iterdir():
                    try:
                        owned.add(os.readlink(fd))
                    except FileNotFoundError:
                        continue
                for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
                    fields = line.split()
                    if (len(fields) >= 10 and fields[1] == "0100007F:527E"
                            and fields[2] == f"0100007F:{port:04X}" and fields[3] == "01"
                            and f"socket:[{fields[9]}]" in owned):
                        accepted = int(fields[9])
                if accepted is None:
                    time.sleep(0.01)
            if accepted is None or child_record() != old or properties() != before:
                raise RuntimeError("crash fixture lacks an accepted exact-child connection")
            print(prefix + "_INJECTION=" + json.dumps(
                {"record": old, "unit": before, "accepted_socket": accepted,
                 "listener_inode": old_listener, "signal": "SIGKILL", "target": target + "-pidfd"},
                sort_keys=True), flush=True)
            began = time.monotonic()
            signal.pidfd_send_signal(old_processes[target]["pidfd"], signal.SIGKILL)
            # Recovery must occur without another fixture signal or service start/restart.
            peer.settimeout(10)
            if peer.recv(1) != b"":
                raise RuntimeError("crashed prekey connection returned application data")
            eof_seconds = time.monotonic() - began
        expected_retired = {"child": old_processes["child"]} if child_only else old_processes
        while not all_retired(expected_retired) and time.monotonic() - began < 10:
            time.sleep(0.02)
        if not all_retired(expected_retired):
            raise RuntimeError(f"crash left an old process: {retired(expected_retired)}")
        retirement_seconds = time.monotonic() - began
        recovery_retirement = retired(old_processes)
        if child_only and recovery_retirement["supervisor"] != {"exited": False, "reaped": False}:
            raise RuntimeError("child crash retired the original supervisor")
        print(prefix + "_RETIREMENT=" + json.dumps(
            {"processes": recovery_retirement, "eof_seconds": eof_seconds,
             "retirement_seconds": retirement_seconds}, sort_keys=True), flush=True)
        recovered = ready(old, child_replacement=child_only)
        new_processes = retain(recovered)
        after = properties()
        if child_only:
            if (after != before or new_processes["supervisor"]["start"] != old_processes["supervisor"]["start"]
                    or select.select([old_processes["supervisor"]["pidfd"]], [], [], 0)[0]):
                raise RuntimeError("child recovery replaced or changed the surviving supervisor")
        if (after["ActiveState"] != "active" or after["SubState"] != "running" or after["Result"] != "success"
                or (not child_only and (after["NRestarts"] != "1" or after["InvocationID"] == before["InvocationID"]))
                or authority(runtime, 0o700, directory=True) != runtime_before
                or authority(runtime / "service-supervisor.lock", 0o600) != lease_before
                or credential() != durable):
            raise RuntimeError(f"automatic crash recovery changed authority or restarted repeatedly: {after}")
        new_endpoints = endpoints(recovered)
        if child_only and (new_endpoints != old_endpoints or digest(record_path) == old_record["sha256"]):
            raise RuntimeError("child recovery changed privileged endpoints or retained the old child record")
        new_listener = login(recovered, "recovered")
        recovery_seconds = time.monotonic() - began
        if new_listener == old_listener or recovery_seconds >= 35:
            raise RuntimeError("crash recovery did not restore a fresh usable listener within 35 seconds")
        # Span more than RestartSec after the login, catching an immediately failing generation.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if properties() != after or child_record() != recovered or direct_listener(recovered) != new_listener:
                raise RuntimeError("recovered service generation was unstable")
            time.sleep(0.2)
        run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        terminal = properties()
        deadline = time.monotonic() + 5
        while (cgroup.exists() or not all_retired(new_processes)) and time.monotonic() < deadline:
            time.sleep(0.02)
        if (terminal["ActiveState"] != "inactive" or terminal["SubState"] != "dead"
                or terminal["Result"] != "success" or terminal["MainPID"] != "0"
                or terminal["ExecMainCode"] != "1" or terminal["ExecMainStatus"] != "0"
                or cgroup.exists() or record_path.exists() or not all_retired(new_processes)
                or credential() != durable):
            raise RuntimeError(f"recovered service did not stop and reap cleanly: {terminal}")
        print(prefix + "_OBSERVED=" + json.dumps(
            {"before": before, "after": after, "terminal": terminal, "old": old, "recovered": recovered,
             "old_record": old_record, "runtime_identity": runtime_before, "lease_identity": lease_before,
             "old_endpoints": old_endpoints, "new_endpoints": new_endpoints,
             "old_listener": old_listener, "new_listener": new_listener, "accepted_socket": accepted,
             "eof_seconds": eof_seconds, "retirement_seconds": retirement_seconds, "recovery_seconds": recovery_seconds,
             "old_retired": retired(old_processes), "new_retired": retired(new_processes),
             "durable_unchanged": True, "cgroup_absent": True, "record_absent": True}, sort_keys=True), flush=True)
        counts = "supervisors=1 children=2 crashes=1 restarts=0" if child_only else "generations=2 crashes=1 restarts=1"
        print(f"{prefix}_NATIVE=pass {counts} logins=2 source={commit} "
              f"binary_sha256={binary_sha} probe_sha256={probe_sha} fixture=installed-layout unit=shipped "
              f"logind=actual child=supervised signal={target}-pidfd cleanup=joined", flush=True)
    except BaseException:
        print(run(["/usr/bin/journalctl", "--unit=rustdesk.service", "--no-pager", "-n", "60"]).stdout, flush=True)
        raise
    finally:
        try:
            run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        finally:
            reference.close()
            for fd in retained:
                os.close(fd)


def login_across_duplicates(value, record, action):
    listener = direct_listener(record)
    if listener is None:
        raise RuntimeError("duplicate test requires a serving child")
    before = credential()
    probe = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
            proxy.bind(("127.0.0.1", 0))
            proxy.listen(1)
            proxy.settimeout(5)
            probe = subprocess.Popen(
                ["/usr/bin/setpriv", "--reuid=4002", "--regid=4002", "--clear-groups",
                 "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                 str(PROBE), f"127.0.0.1:{proxy.getsockname()[1]}", "--password-stdin", "ok", "login"],
                env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            probe.stdin.write(value + "\n")
            probe.stdin.close()
            probe.stdin = None
            downstream, _ = proxy.accept()
            with downstream, socket.create_connection(("127.0.0.1", 21118), timeout=5) as upstream:
                for source, destination in ((downstream, upstream), (upstream, downstream),
                                            (downstream, upstream), (upstream, downstream)):
                    destination.sendall(wire_frame(source))
                login = wire_frame(downstream)
                downstream.sendall(wire_frame(upstream))
                # The keyed stream and encrypted login exist before the duplicate launches.
                # Only release the login afterward; its decrypted response must come from
                # this same retained connection, not a fresh authentication attempt.
                if probe.poll() is not None or child_record() != record:
                    raise RuntimeError("duplicate login barrier lost its child or peer")
                duplicates = action()
                if probe.poll() is not None or child_record() != record or direct_listener(record) != listener:
                    raise RuntimeError("duplicate startup replaced the keyed connection owner")
                upstream.sendall(login)
                downstream.sendall(wire_frame(upstream))
                stdout, stderr = probe.communicate(timeout=5)
        lines = stdout.splitlines()
        if (probe.returncode != 0 or stderr or len(lines) != 3
                or lines[0] != "probe_client: keying ok=true (expected=ok)"
                or lines[-1] != "probe_client: PASS"
                or "[REMOTE-LOGIN-ADMITTED peer-info]" not in lines[1]
                or "Some(TestDelay(" not in lines[1] or "READ_ERR" in lines[1]
                or "REMOTE-LOGIN-REJECTED" in lines[1]
                or credential() != before or child_record() != record or direct_listener(record) != listener):
            raise RuntimeError(f"held connection did not admit a real desktop login: {stdout[-4096:]} {stderr[-4096:]}")
        return duplicates, {"record": record, "listener_inode": listener, "probe_pid": probe.pid,
                            "probe_exit": probe.returncode, "probe_stdout": stdout,
                            "probe_stderr": stderr, "login_released_after_duplicates": True,
                            "durable_unchanged": True}
    finally:
        if probe is not None:
            if probe.poll() is None:
                probe.kill()
                probe.communicate(timeout=5)
            for pipe in (probe.stdin, probe.stdout, probe.stderr):
                if pipe is not None:
                    pipe.close()


def startup_namespace(commit, binary_sha, incumbents=False, collisions=False, exclusive=False, desktop_probe_sha=None):
    parent = Path("/run/RustDesk-service")
    legacy = Path("/tmp/RustDesk-service")
    target = WORK / "startup-link-target"
    collision_target = WORK / "endpoint-link-target"
    unit = Path("/etc/systemd/system/rustdesk.service")
    if any(os.path.lexists(p) for p in (parent, legacy, target, collision_target, unit)):
        raise RuntimeError("startup fixture requires absent owned paths")

    def fixture(path):
        path.mkdir(mode=0o755)
        sentinel = path / "preserve"
        sentinel.write_bytes(b"service-startup-preserve\n")
        sentinel.chmod(0o644)
        os.chown(sentinel, 4002, 4002)
        os.chown(path, 4002, 4002)

    def snapshot(path):
        result = {}
        entries = [path]
        if stat.S_ISDIR(path.lstat().st_mode):
            entries.extend(sorted(path.iterdir()))
        for entry in entries:
            st = entry.lstat()
            result[entry.name] = [st.st_dev, st.st_ino, st.st_uid, st.st_gid,
                                  st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns,
                                  st.st_ctime_ns, digest(entry) if stat.S_ISREG(st.st_mode) else None,
                                  os.readlink(entry) if stat.S_ISLNK(st.st_mode) else None]
        return result

    def link_identity():
        st = parent.lstat()
        return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns, os.readlink(parent))

    def socket_identity(path):
        st = path.lstat()
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError("incumbent fixture expected a socket")
        return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                st.st_nlink, st.st_mtime_ns, st.st_ctime_ns)

    def remove_stale_socket(path):
        if os.path.lexists(path):
            old = socket_identity(path)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(1)
                try:
                    peer.connect(str(path))
                except ConnectionRefusedError:
                    pass
                else:
                    raise RuntimeError("fixture would replace a live previous service socket")
            if socket_identity(path) != old:
                raise RuntimeError("fixture stale socket changed")
            path.unlink()

    def occupy(path):
        remove_stale_socket(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(path))
            path.chmod(0o666)
            listener.listen(16)
            listener.settimeout(1)
            return listener
        except BaseException:
            listener.close()
            raise

    def observe_incumbent(listener, path):
        connections = 0
        while select.select([listener], [], [], 0)[0]:
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(1)
                pid, uid, gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if pid <= 1 or pid == os.getpid() or uid != 0 or gid != 0 or peer.recv(1) != b"":
                    raise RuntimeError("incumbent probe principal or payload differs")
            connections += 1
            if connections > 4:
                raise RuntimeError("incumbent probe count exceeded the fixture bound")
        if not connections:
            raise RuntimeError("service did not reach the occupied endpoint")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(1)
            probe.connect(str(path))
            if struct.unpack("3i", probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) != (os.getpid(), 0, 0):
                raise RuntimeError("service replaced the live incumbent")
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(1)
                probe.sendall(b"alive")
                if peer.recv(5, socket.MSG_WAITALL) != b"alive":
                    raise RuntimeError("preserved incumbent lost transport functionality")
        return connections

    def properties():
        return dict(line.split("=", 1) for line in run(
            ["/usr/bin/systemctl", "show", "rustdesk.service",
             "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus,NRestarts,ActiveEnterTimestampMonotonic,InvocationID"]).stdout.splitlines())

    def duplicate_launches(pid, pidfd, expected_unit, record=None):
        namespace = snapshot(parent)
        runtime = Path("/run/rustdesk")
        lease = runtime / "service-supervisor.lock"
        child_before = snapshot(runtime / "service-child.record") if record else None
        expected_entries = ["service-child.record", "service-supervisor.lock"] if record else ["service-supervisor.lock"]
        expected_processes = {str(pid), str(record["pid"])} if record else {str(pid)}

        def lease_identity():
            st = lease.lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                    or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, 0o600)):
                raise RuntimeError("supervisor lease authority differs")
            return [st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                    st.st_nlink, st.st_size, digest(lease)]

        lease_before = lease_identity()
        with lease.open("rb") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise RuntimeError("ready supervisor does not retain its lifecycle lease")
        outcomes = []
        for count in (1, 2):
            children = []
            began = time.monotonic()
            try:
                for _ in range(count):
                    children.append(subprocess.Popen(
                        ["/usr/bin/rustdesk", "--service"], env=ENV,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
                for child in children:
                    output, _ = child.communicate(timeout=10)
                    if (child.returncode != 1 or len(output) > 131072
                            or b"Another Linux service supervisor owns the lifecycle lease" not in output):
                        raise RuntimeError(f"duplicate did not refuse its occupied lease: {child.returncode} {output[-4096:]!r}")
                    try:
                        os.waitpid(child.pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                    else:
                        raise RuntimeError("duplicate process was not reaped")
                    outcomes.append({"pid": child.pid, "batch": count, "exit": child.returncode,
                                     "output": output.decode("utf-8", errors="strict"), "reaped": True})
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=10)
            expected = {"exited": False, "unit": expected_unit, "namespace": namespace,
                        "lease": lease_before, "entries": expected_entries,
                        "child": record, "child_record": child_before}
            actual = {"exited": bool(select.select([pidfd], [], [], 0)[0]), "unit": properties(),
                      "namespace": snapshot(parent), "lease": lease_identity(),
                      "entries": sorted(p.name for p in runtime.iterdir()),
                      "child": child_record() if record else None,
                      "child_record": snapshot(runtime / "service-child.record") if record else None}
            # Session refresh runs short-lived commands in this cgroup. Prove the
            # retained members here and require whole-cgroup retirement at stop.
            cgroup_processes = set(Path("/sys/fs/cgroup/system.slice/rustdesk.service/cgroup.procs").read_text().split())
            if actual != expected or not expected_processes <= cgroup_processes:
                processes = {}
                for candidate in cgroup_processes:
                    proc = Path("/proc") / candidate
                    try:
                        processes[candidate] = {"exe": os.readlink(proc / "exe"),
                                                "cmdline": (proc / "cmdline").read_bytes().decode("utf-8", errors="replace"),
                                                "stat": (proc / "stat").read_text()}
                    except (FileNotFoundError, ProcessLookupError):
                        processes[candidate] = {"exited_during_observation": True}
                print(prefix + "_PRESERVATION_FAILURE=" + json.dumps(
                    {"count": count, "expected": expected, "actual": actual,
                     "expected_processes": sorted(expected_processes), "cgroup_processes": sorted(cgroup_processes),
                     "process_details": processes, "outcomes": outcomes[-count:]}, sort_keys=True), flush=True)
                raise RuntimeError("duplicate launch disturbed the incumbent service generation")
            for postfix in ("_service", "_service_password", "_service_credential"):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                    peer.settimeout(5)
                    peer.connect(str(parent / ("ipc" + postfix)))
                    if struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) != (pid, 0, 0):
                        raise RuntimeError("duplicate launch replaced an incumbent endpoint")
            print(prefix + "_BATCH=" + json.dumps(
                {"count": count, "elapsed_seconds": time.monotonic() - began,
                 "incumbent": pid, "unit": expected_unit, "namespace": namespace,
                 "lease": lease_before, "outcomes": outcomes[-count:],
                 "cgroup_processes": sorted(cgroup_processes),
                 "child": record, "child_record": child_before}, sort_keys=True), flush=True)
        return outcomes

    def stop():
        run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
        deadline = time.monotonic() + 5
        cgroup = Path("/sys/fs/cgroup/system.slice/rustdesk.service")
        while cgroup.exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("startup service cgroup survived stop")
            time.sleep(0.02)
        if properties()["MainPID"] != "0" or Path("/run/rustdesk/service-child.record").exists():
            raise RuntimeError("startup service retained a process or child record")

    fixture(legacy)
    legacy_before = snapshot(legacy)
    shutil.copyfile(MEDIA / "repo/res/rustdesk.service", unit)
    run(["/usr/bin/systemctl", "daemon-reload"])
    previous = None
    previous_child = None
    desktop_credential = None
    phases = ("foreign-owner", "symlink", "fresh", "restart")
    prefix = "LINUX_SERVICE_STARTUP"
    if exclusive:
        phases = ("exclusive-first", "exclusive-restart")
        prefix = "LINUX_SERVICE_DESKTOP_EXCLUSIVE" if desktop_probe_sha else "LINUX_SERVICE_EXCLUSIVE"
    if incumbents or collisions:
        parent.mkdir(mode=0o711)
        parent.chmod(0o711)
    if incumbents:
        phases = tuple(f"{kind}-{endpoint}" for endpoint in ("service", "password", "credential")
                       for kind in ("live", "recovered"))
        prefix = "LINUX_SERVICE_INCUMBENT"
    elif collisions:
        collision_target.write_bytes(b"endpoint-target-preserve\n")
        collision_target.chmod(0o640)
        os.chown(collision_target, 4002, 4002)
        target_before = snapshot(collision_target)
        phases = tuple(f"{recovery}{kind}-{endpoint}"
                       for endpoint in ("service", "password", "credential")
                       for kind in ("file", "fifo", "directory", "symlink")
                       for recovery in ("", "recovered-"))
        prefix = "LINUX_SERVICE_COLLISION"
    try:
        for phase in phases:
            live = phase.startswith("live-")
            collision = collisions and not phase.startswith("recovered-")
            refused = phase in ("foreign-owner", "symlink") or live or collision
            listener = None
            connections = None
            duplicates = None
            network = None
            if phase == "foreign-owner":
                fixture(parent)
                before = snapshot(parent)
            elif phase == "symlink":
                fixture(target)
                parent.symlink_to(target, target_is_directory=True)
                link_before = link_identity()
                before = snapshot(target)
            elif live:
                suffix = {"service": "_service", "password": "_service_password",
                          "credential": "_service_credential"}[phase.split("-", 1)[1]]
                occupied = parent / ("ipc" + suffix)
                listener = occupy(occupied)
                before = socket_identity(occupied)
            elif collision:
                kind, endpoint_name = phase.split("-")
                suffix = {"service": "_service", "password": "_service_password",
                          "credential": "_service_credential"}[endpoint_name]
                occupied = parent / ("ipc" + suffix)
                remove_stale_socket(occupied)
                if kind == "directory":
                    fixture(occupied)
                elif kind == "symlink":
                    occupied.symlink_to(collision_target)
                elif kind == "fifo":
                    os.mkfifo(occupied, 0o644)
                else:
                    occupied.write_bytes(b"endpoint-file-preserve\n")
                    occupied.chmod(0o644)
                os.chown(occupied, 4002, 4002, follow_symlinks=False)
                before = snapshot(occupied)
            reference = ServiceUnitResultReference()
            pidfd = None
            child_pidfd = None
            try:
                previous_ready = properties()["ActiveEnterTimestampMonotonic"]
                began = time.monotonic()
                started = run(["/usr/bin/systemctl", "start", "rustdesk.service"], allowed=(0, 1))
                observed = properties()
                if refused:
                    if (started.returncode != 1 or observed["Result"] != "exit-code"
                            or observed["ExecMainCode"] != "1" or observed["ExecMainStatus"] != "1"
                            or observed["ActiveEnterTimestampMonotonic"] != previous_ready
                            or observed["MainPID"] != "0"):
                        raise RuntimeError(f"unsafe namespace reached service readiness: {observed}")
                else:
                    pid = int(observed["MainPID"])
                    if (started.returncode or pid <= 1 or observed["ActiveState"] != "active"
                            or observed["SubState"] != "running" or observed["Result"] != "success"
                            or observed["NRestarts"] != "0"):
                        raise RuntimeError(f"protected namespace did not become ready: {observed}")
                    pidfd = os.pidfd_open(pid)
                    proc = Path("/proc") / str(pid)
                    identity = [pid, int((proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()[19])]
                    if (identity == previous or digest(proc / "exe") != binary_sha
                            or (proc / "cmdline").read_bytes() != b"/usr/bin/rustdesk\x00--service\x00"):
                        raise RuntimeError("startup process identity differs")
                    previous = identity
                    st = parent.lstat()
                    if (not stat.S_ISDIR(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, 0o711)):
                        raise RuntimeError("ready service parent authority differs")
                    for postfix in ("_service", "_service_password", "_service_credential"):
                        endpoint = parent / ("ipc" + postfix)
                        st = endpoint.lstat()
                        if (not stat.S_ISSOCK(st.st_mode) or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0, 0, 0o666)):
                            raise RuntimeError("ready service socket authority differs")
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                            peer.settimeout(5)
                            peer.connect(str(endpoint))
                            credentials = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                            if credentials != (pid, 0, 0):
                                raise RuntimeError("ready endpoint belongs to a different principal or process")
                    if desktop_probe_sha:
                        current_child = ready(previous_child)
                        if current_child["supervisor"] != pid:
                            raise RuntimeError("desktop child belongs to a different supervisor")
                        previous_child = current_child
                        child_pidfd = os.pidfd_open(current_child["pid"])
                        value = "Receiver-exclusive-desktop-2026!"
                        if desktop_credential is None:
                            change(0, value, True)
                            desktop_credential = credential()
                        elif credential() != desktop_credential:
                            raise RuntimeError("desktop service restart changed its credential")
                        keyed(value, phase, current_child, desktop_probe_sha)
                        duplicates, network = login_across_duplicates(
                            value, current_child, lambda: duplicate_launches(pid, pidfd, observed, current_child))
                    elif Path("/run/rustdesk/service-child.record").exists():
                        raise RuntimeError("sessionless startup unexpectedly launched a desktop child")
                    elif exclusive:
                        duplicates = duplicate_launches(pid, pidfd, observed)
                stop()
                terminal = properties()
                if not refused and (not select.select([pidfd], [], [], 0)[0]
                                    or terminal["Result"] != "success" or terminal["ExecMainStatus"] != "0"):
                    raise RuntimeError("ready service did not stop cleanly")
                if not refused and proc.exists():
                    fields = (proc / "stat").read_bytes().rsplit(b") ", 1)[1].split()
                    if int(fields[19]) == identity[1]:
                        raise RuntimeError("stopped service process was not reaped")
                if child_pidfd is not None:
                    if (not select.select([child_pidfd], [], [], 0)[0]
                            or Path(f"/proc/{current_child['pid']}").exists()
                            or credential() != desktop_credential):
                        raise RuntimeError("desktop child did not retire or durable credential changed")
                if snapshot(legacy) != legacy_before:
                    raise RuntimeError("service changed the abandoned public namespace")
                if collisions and snapshot(collision_target) != target_before:
                    raise RuntimeError("service changed the endpoint symlink target")
                if refused:
                    actual = socket_identity(occupied) if live else snapshot(
                        occupied if collision else target if phase == "symlink" else parent)
                    if actual != before or (phase == "symlink" and link_identity() != link_before):
                        raise RuntimeError("refused service mutated a foreign namespace")
                    if live:
                        connections = observe_incumbent(listener, occupied)
                print(prefix + "_OBSERVED=" + json.dumps(
                    {"phase": phase, "start_exit": started.returncode, "ready": observed,
                     "terminal": terminal, "elapsed_seconds": time.monotonic() - began,
                     "legacy_unchanged": True, "namespace_unchanged": refused,
                     "collision_unchanged": collision,
                     "preserved_objects": before if collision else None,
                     "symlink_target_unchanged": collisions,
                     "incumbent_probes": connections,
                     "duplicates": duplicates,
                     "network": network,
                     "supervisor": previous if not refused else None}, sort_keys=True), flush=True)
                run(["/usr/bin/systemctl", "reset-failed", "rustdesk.service"])
            finally:
                reference.close()
                if pidfd is not None:
                    os.close(pidfd)
                if child_pidfd is not None:
                    os.close(child_pidfd)
                if listener is not None:
                    # Leave the exact socket pathname for production stale-socket recovery.
                    listener.close()
            if phase == "foreign-owner":
                (parent / "preserve").unlink()
                parent.rmdir()
            elif phase == "symlink":
                parent.unlink()
                (target / "preserve").unlink()
                target.rmdir()
            elif collision:
                if snapshot(occupied) != before:
                    raise RuntimeError("fixture collision changed before retirement")
                if kind == "directory":
                    (occupied / "preserve").unlink()
                    occupied.rmdir()
                else:
                    occupied.unlink()
            print(f"{prefix}_CASE=pass phase={phase}", flush=True)
    finally:
        stop()
    if exclusive:
        desktop_result = f" logind=actual child=supervised logins=2 probe_sha256={desktop_probe_sha}" if desktop_probe_sha else ""
        print(f"{prefix}_NATIVE=pass generations=2 duplicates=6 refused=6 source={commit} "
              f"binary_sha256={binary_sha} fixture=installed-layout unit=shipped legacy=unchanged cleanup=joined{desktop_result}", flush=True)
        return
    total = 24 if collisions else 6 if incumbents else 4
    print(f"{prefix}_NATIVE=pass cases={total} refusals={total // 2} starts={total // 2} source={commit} "
          f"binary_sha256={binary_sha} fixture=installed-layout unit=shipped legacy=unchanged cleanup=joined", flush=True)


def tests(args, convergence_failure=False, notification_failure=False, network_drain=False, authorization_timeout=False, committed_requester_exit=False, startup=False, incumbent=False, collisions=False, exclusive=False, desktop_exclusive=False, crash=False, recovery=False, child_crash=False, stopped_child=False, record_cleanup=False, parent_death=False, handoff=False, openrc=False, limiter=False):
    guard()
    checked = run(["/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
                   "--inh-caps=-all", "--bounding-set=-all", "--ambient-caps=-all", "--no-new-privs",
                   "/usr/bin/python3", "-B", "-I", "-S",
                   str(MEDIA / "repo/scripts/verify-linux-service-password-ipc.py"),
                   "--repo", str(MEDIA / "repo")])
    if checked.stdout.strip() != "verify-linux-service-password-ipc: source checks passed" or checked.stderr:
        raise RuntimeError("supplementary password IPC source checks returned an unexpected receipt")
    print(checked.stdout, end="", flush=True)
    commit, tree, manifest_sha, archive_sha, package_manifest_sha = args
    manifest = MEDIA / "receiver/peer-manifest.json"
    if digest(manifest) != manifest_sha:
        raise RuntimeError("production artifact manifest differs")
    description = json.loads(manifest.read_text())
    if description["context"]["source_commit"] != commit or description["context"]["source_tree"] != tree:
        raise RuntimeError("production artifact source differs")
    spec = description["files"]["rustdesk"]
    if PRIMARY.stat().st_size != spec["bytes"] or digest(PRIMARY) != spec["sha256"] or digest(CHILD) != spec["sha256"]:
        raise RuntimeError("installed primary/child bytes differ")
    probe_spec = description["files"]["probe_client"]
    metadata = PROBE.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (0, 0, 0o755)
            or metadata.st_size != probe_spec["bytes"] or digest(PROBE) != probe_spec["sha256"]):
        raise RuntimeError("installed network probe authority or bytes differ")
    if "not found" in run(["/usr/bin/ldd", str(PROBE)]).stdout:
        raise RuntimeError("network probe runtime dependency is missing")
    run(["/usr/bin/systemctl", "is-active", "systemd-logind.service", "polkit.service"])
    if limiter:
        installed_desktop(lambda: service_limiter(commit, spec["sha256"], probe_spec["sha256"]))
        return
    if openrc:
        install_openrc()
        installed_desktop(lambda: service_openrc(commit, spec["sha256"], probe_spec["sha256"]))
        return
    if handoff:
        service_session_handoff(commit, spec["sha256"], probe_spec["sha256"])
        return
    if parent_death:
        installed_desktop(lambda: service_parent_death(commit, spec["sha256"], probe_spec["sha256"]))
        return
    if record_cleanup:
        installed_desktop(lambda actor, session, pam: record_cleanup_retry(
            commit, spec["sha256"], probe_spec["sha256"], actor, session, pam), close_session=True)
        return
    if stopped_child:
        installed_desktop(lambda: stopped_child_shutdown(commit, spec["sha256"], probe_spec["sha256"]))
        return
    if recovery:
        installed_desktop(lambda: recovery_refusals(commit, spec["sha256"], probe_spec["sha256"], description["files"]["smoke_readiness"]))
        return
    if crash or child_crash:
        installed_desktop(lambda: service_crash(commit, spec["sha256"], probe_spec["sha256"], child_only=child_crash))
        return
    if desktop_exclusive:
        installed_desktop(lambda: startup_namespace(commit, spec["sha256"], exclusive=True, desktop_probe_sha=probe_spec["sha256"]))
        return
    if startup or incumbent or collisions or exclusive:
        startup_namespace(commit, spec["sha256"], incumbents=incumbent, collisions=collisions, exclusive=exclusive)
        return
    file_workflow = not any((convergence_failure, notification_failure, network_drain, authorization_timeout, committed_requester_exit))
    pam = pam_module()
    confdir = WORK / "pam"
    confdir.mkdir(mode=0o700)
    (confdir / "rustdesk-logind-fixture").write_text("session required pam_systemd.so\n")
    actor = None
    users = []
    started = False
    file_cm = None
    try:
        for uid in (4001, 4002, 4003):
            try:
                pwd.getpwuid(uid)
            except KeyError:
                groups = ["--groups", "sudo"] if uid == 4003 else []
                home_args = []
                if uid == 4001 and file_workflow:
                    if os.path.lexists("/tmp/rd-cm-file-replay"):
                        raise RuntimeError("installed file fixture home already exists")
                    home_args = ["--home-dir", "/tmp/rd-cm-file-replay"]
                shell = "/bin/bash" if uid == 4001 and file_workflow else "/usr/sbin/nologin"
                run(["/usr/sbin/useradd", "--uid", str(uid), "--user-group", "--create-home",
                     "--shell", shell, *groups, *home_args, f"rdreceiver{uid}"])
                users.append(uid)
                if home_args:
                    Path("/tmp/rd-cm-file-replay").chmod(0o700)
            else:
                raise RuntimeError("receiver fixture UID already exists")
        run(["/usr/sbin/chpasswd"], input=f"rdreceiver4003:{ADMIN_PASSWORD}\n")
        actor = subprocess.Popen(["/usr/bin/python3", "-B", "-I", "-S", str(Path(__file__)), "--pam-actor"],
                                 env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        opened = pam.reply(actor)
        session = opened["session"]
        expected = {"User": "4001", "Type": "x11", "State": "active", "Display": ":77", "Seat": ""}
        properties = run(["/usr/bin/loginctl", "show-session", "--no-pager",
                          *["--property=" + key for key in expected], "--", session]).stdout
        if dict(line.split("=", 1) for line in properties.splitlines()) != expected:
            raise RuntimeError(f"real logind desktop differs: {properties}")
        deadline = time.monotonic() + 5
        while not Path("/tmp/.X11-unix/X77").is_socket():
            if actor.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("PAM-owned Xvfb did not start")
            time.sleep(0.05)
        shutil.copyfile(MEDIA / "repo/res/rustdesk.service", "/etc/systemd/system/rustdesk.service")
        run(["/usr/bin/systemctl", "daemon-reload"])
        started = True
        run(["/usr/bin/systemctl", "start", "rustdesk.service"])
        first = ready()
        print(f"LINUX_RECEIVER_CASE=installed-child observed={json.dumps(first, sort_keys=True)}", flush=True)
        change(0, "Receiver-fixture-first-2026!", True)
        before = credential()
        if child_record() != first:
            raise RuntimeError("root mutation did not converge on the original child")
        print("LINUX_RECEIVER_CASE=root-applied durable=root convergence=Applied", flush=True)
        keyed("Receiver-fixture-first-2026!", "root-applied", first, probe_spec["sha256"])
        if committed_requester_exit:
            value = "Receiver-committed-exit-2026!"
            committed = admitted_admin_requester_exit(value, first, probe_spec["sha256"])
            stale_refused("Receiver-fixture-first-2026!", "committed-requester-exit", first, probe_spec["sha256"])
            run(["/usr/bin/systemctl", "restart", "rustdesk.service"], timeout=40)
            second = ready(first)
            if credential() != committed:
                raise RuntimeError("requester-independent credential did not persist across restart")
            keyed(value, "committed-exit-restart", second, probe_spec["sha256"])
            stale_refused("Receiver-fixture-first-2026!", "committed-exit-restart", second, probe_spec["sha256"])
            print("LINUX_RECEIVER_COMMITTED_EXIT_RESTART=pass generation=fresh "
                  "credential=preserved new=accepted old=refused", flush=True)
        elif authorization_timeout:
            admin_change("Receiver-timeout-refused-2026!", first, "authorization-timeout")
            second = first
            keyed(AUTH_TIMEOUT_ROOT_PASSWORD, "authorization-timeout-recovery", second, probe_spec["sha256"])
        elif network_drain:
            network_shutdown("Receiver-fixture-first-2026!", first, probe_spec["sha256"])
            run(["/usr/bin/systemctl", "start", "rustdesk.service"])
            second = ready(first)
            keyed("Receiver-fixture-first-2026!", "network-drain-recovery", second, probe_spec["sha256"])
        elif convergence_failure:
            second = admitted_password_shutdown("Receiver-fixture-convergence-2026!", first, fail_convergence=True)
            keyed("Receiver-fixture-convergence-2026!", "convergence-failure-recovery", second, probe_spec["sha256"])
            stale_refused("Receiver-fixture-first-2026!", "convergence-failure-recovery", second, probe_spec["sha256"])
        elif notification_failure:
            admitted_password_shutdown("Receiver-fixture-notification-2026!", first, unit_stop=True, notification_failure=True)
            run(["/usr/bin/systemctl", "start", "rustdesk.service"])
            second = ready(first)
            recovered_unit = dict(line.split("=", 1) for line in run(
                ["/usr/bin/systemctl", "show", "rustdesk.service",
                 "--property=ActiveState,SubState,Result,MainPID,InvocationID,NRestarts"]).stdout.splitlines())
            if (second["supervisor"] == first["supervisor"] or recovered_unit.get("MainPID") != str(second["supervisor"])
                    or recovered_unit.get("ActiveState") != "active" or recovered_unit.get("Result") != "success"
                    or recovered_unit.get("SubState") != "running"):
                raise RuntimeError("manager-timeout recovery did not establish a fresh installed generation")
            print("LINUX_RECEIVER_NOTIFICATION_RECOVERY_OBSERVED=" + json.dumps(
                {"previous": first, "recovered": second, "unit": recovered_unit}, sort_keys=True), flush=True)
            keyed("Receiver-fixture-notification-2026!", "notification-failure-recovery", second, probe_spec["sha256"])
            stale_refused("Receiver-fixture-first-2026!", "notification-failure-recovery", second, probe_spec["sha256"])
        else:
            for uid in (4001, 4002):
                change(uid, f"Receiver-refused-{uid}-2026!", False)
                if credential() != before or child_record() != first:
                    raise RuntimeError("unauthorized caller changed credential or service generation")
                print(f"LINUX_RECEIVER_CASE=principal-denied uid={uid} durable=unchanged", flush=True)
            for endpoint in ("_service", "_service_password"):
                peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    peer.settimeout(5)
                    peer.connect(f"/run/RustDesk-service/ipc{endpoint}")
                    try:
                        data = peer.recv(1)
                    except ConnectionResetError:
                        data = b""
                    if data:
                        raise RuntimeError("arbitrary-image peer received a service response")
                finally:
                    peer.close()
                if credential() != before or child_record() != first:
                    raise RuntimeError("arbitrary-image peer affected service state")
                print(f"LINUX_RECEIVER_CASE=wrong-image endpoint={endpoint} prebody=refused", flush=True)
            change(0, "Receiver-fixture-second-2026!", True)
            after = credential()
            if after == before or child_record() != first:
                raise RuntimeError("second root credential change did not converge")
            print("LINUX_RECEIVER_CASE=root-reapplied durable=changed convergence=Applied", flush=True)
            keyed("Receiver-fixture-second-2026!", "root-reapplied", first, probe_spec["sha256"])
            stale_refused("Receiver-fixture-first-2026!", "root-reapplied", first, probe_spec["sha256"])
            keyed("Receiver-fixture-second-2026!", "root-reapplied-after-refusal", first, probe_spec["sha256"])
            run(["/usr/bin/systemctl", "restart", "rustdesk.service"], timeout=40)
            second = ready(first)
            if second["supervisor"] == first["supervisor"]:
                raise RuntimeError("service restart retained the old supervisor")
            if credential() != after:
                raise RuntimeError("restart changed durable root credential")
            print(f"LINUX_RECEIVER_CASE=restart observed={json.dumps(second, sort_keys=True)} durable=unchanged", flush=True)
            keyed("Receiver-fixture-second-2026!", "restart", second, probe_spec["sha256"])
            stale_refused("Receiver-fixture-first-2026!", "restart", second, probe_spec["sha256"])
            keyed("Receiver-fixture-second-2026!", "restart-after-refusal", second, probe_spec["sha256"])
            credential_race("Receiver-fixture-second-2026!", None, "control", second, probe_spec["sha256"])
            credential_race("Receiver-fixture-second-2026!", "Receiver-fixture-third-2026!",
                            "before-keys", second, probe_spec["sha256"])
            keyed("Receiver-fixture-third-2026!", "race-before-keys-recovery", second, probe_spec["sha256"])
            credential_race("Receiver-fixture-third-2026!", "Receiver-fixture-fourth-2026!",
                            "before-login", second, probe_spec["sha256"])
            keyed("Receiver-fixture-fourth-2026!", "race-before-login-recovery", second, probe_spec["sha256"])
            admin_change("Receiver-abandoned-admin-2026!", second, "requester-exit")
            keyed("Receiver-fixture-fourth-2026!", "requester-exit-recovery", second, probe_spec["sha256"])
            admin_change("Receiver-revoked-admin-2026!", second, "session-close",
                         {"process": actor, "session": session, "uid": 4001, "type": "x11"})
            actor.stdin.write(b"quit\n")
            actor.stdin.flush()
            if actor.wait(timeout=10) != 0:
                raise RuntimeError("closed PAM/desktop actor failed to retire")
            actor.stdin.close()
            actor.stdout.close()
            deadline = time.monotonic() + 5
            while session in pam.sessions() or Path("/tmp/.X11-unix/X77").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("closed session or desktop survived actor retirement")
                time.sleep(0.05)
            deadline = time.monotonic() + 10
            while True:
                try:
                    fields = Path(f"/proc/{second['pid']}/stat").read_bytes().rsplit(b") ", 1)[1].split()
                    retired = int(fields[19]) != second["start"]
                except (FileNotFoundError, ProcessLookupError):
                    retired = True
                if retired and not Path("/run/rustdesk/service-child.record").exists():
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("closed desktop retained its old service-child identity")
                time.sleep(0.05)
            run(["/usr/bin/systemctl", "stop", "user@4001.service", "user-runtime-dir@4001.service"])
            if Path("/run/user/4001").exists():
                raise RuntimeError("closed user's runtime survived fixture retirement")
            actor = subprocess.Popen(["/usr/bin/python3", "-B", "-I", "-S", str(Path(__file__)), "--pam-actor"],
                                     env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            opened = pam.reply(actor)
            session = opened["session"]
            pam.properties({"process": actor, "session": session, "uid": 4001, "type": "x11"}, "active")
            recovered = ready(second, child_replacement=True)
            if recovered["supervisor"] != second["supervisor"]:
                raise RuntimeError("session recovery replaced the stable supervisor")
            print("LINUX_RECEIVER_SESSION_RECOVERY_OBSERVED=" + json.dumps(
                {"previous": second, "recovered": recovered, "session": session}, sort_keys=True), flush=True)
            second = recovered
            keyed("Receiver-fixture-fourth-2026!", "session-close-recovery", second, probe_spec["sha256"])
            admin_change("Receiver-invalid-admin-2026!", second, "bad-password")
            keyed("Receiver-fixture-fourth-2026!", "admin-denied-recovery", second, probe_spec["sha256"])
            admin_change("Receiver-agent-lost-2026!", second, "agent-exit")
            keyed("Receiver-fixture-fourth-2026!", "agent-exit-recovery", second, probe_spec["sha256"])
            admin_change("Receiver-shutdown-admin-2026!", second, "supervisor-shutdown")
            run(["/usr/bin/systemctl", "start", "rustdesk.service"])
            second = ready(second)
            print("LINUX_RECEIVER_SHUTDOWN_RECOVERY_OBSERVED=" + json.dumps(second, sort_keys=True), flush=True)
            keyed("Receiver-fixture-fourth-2026!", "supervisor-shutdown-recovery", second, probe_spec["sha256"])
            admitted_password_shutdown("Receiver-fixture-shutdown-2026!", second)
            run(["/usr/bin/systemctl", "start", "rustdesk.service"])
            second = ready(second)
            print("LINUX_RECEIVER_ADMITTED_RECOVERY_OBSERVED=" + json.dumps(second, sort_keys=True), flush=True)
            keyed("Receiver-fixture-shutdown-2026!", "admitted-shutdown-recovery", second, probe_spec["sha256"])
            stale_refused("Receiver-fixture-fourth-2026!", "admitted-shutdown-recovery", second, probe_spec["sha256"])
            admitted_password_shutdown("Receiver-fixture-unit-stop-2026!", second, unit_stop=True)
            run(["/usr/bin/systemctl", "start", "rustdesk.service"])
            second = ready(second)
            print("LINUX_RECEIVER_UNIT_STOP_RECOVERY_OBSERVED=" + json.dumps(second, sort_keys=True), flush=True)
            keyed("Receiver-fixture-unit-stop-2026!", "unit-stop-recovery", second, probe_spec["sha256"])
            stale_refused("Receiver-fixture-shutdown-2026!", "unit-stop-recovery", second, probe_spec["sha256"])
        admin_change("Receiver-fixture-admin-2026!", second)
        keyed("Receiver-fixture-admin-2026!", "admin-applied", second, probe_spec["sha256"])
        before = credential()
        listener = direct_listener(second)
        change(4001, "Receiver-admin-not-cached-2026!", False)
        if credential() != before or direct_listener(second) != listener:
            raise RuntimeError("fresh unauthenticated request reused administrator authority")
        print("LINUX_RECEIVER_ADMIN_FRESH=pass uid=4001 authentication=required result=denied "
              "durable=unchanged listener=owned", flush=True)
        if file_workflow:
            file_cm = installed_file_transfer("Receiver-fixture-admin-2026!", second, probe_spec["sha256"])
    finally:
        try:
            if started:
                run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
                if Path("/sys/fs/cgroup/system.slice/rustdesk.service").exists():
                    raise RuntimeError("owned receiver cgroup remains after stop")
                if file_cm is not None:
                    fd, cm = file_cm
                    if not select.select([fd], [], [], 0)[0] or Path(f"/proc/{cm['pid']}").exists():
                        raise RuntimeError("installed file CM survived service stop or was not reaped")
                    print("LINUX_RECEIVER_FILE_CM_RETIRED=pass process=exited-reaped cgroup=absent", flush=True)
        finally:
            if file_cm is not None:
                os.close(file_cm[0])
            try:
                if actor is not None:
                    if actor.poll() is None:
                        actor.stdin.write(b"quit\n")
                        actor.stdin.flush()
                    if actor.wait(timeout=10) != 0:
                        raise RuntimeError("PAM/desktop actor cleanup failed")
                    actor.stdin.close()
                    actor.stdout.close()
            finally:
                for uid in users:
                    run(["/usr/bin/systemctl", "stop", f"user@{uid}.service", f"user-runtime-dir@{uid}.service"])
                    run(["/usr/sbin/userdel", f"rdreceiver{uid}"])
    if Path("/tmp/.X11-unix/X77").exists() or pam.sessions():
        raise RuntimeError("owned X11 or PAM session remains after cleanup")
    if committed_requester_exit:
        print(f"LINUX_SERVICE_COMMITTED_EXIT_NATIVE=pass cpace=4 stale_refusals=2 admitted_exits=1 "
              f"restarts=1 admin_grants=2 fresh_refusals=1 source={commit} binary_sha256={spec['sha256']} "
              f"probe_sha256={probe_spec['sha256']} fixture=installed-layout polkit=actual logind=actual "
              "child=supervised cleanup=joined", flush=True)
        return
    if authorization_timeout:
        print(f"LINUX_SERVICE_AUTHORIZATION_NATIVE=pass cases=4 cpace=4 timeouts=1 root_grants=2 "
              f"admin_grants=1 fresh_refusals=1 source={commit} binary_sha256={spec['sha256']} "
              f"probe_sha256={probe_spec['sha256']} fixture=installed-layout polkit=actual logind=actual "
              "child=supervised cleanup=joined", flush=True)
        return
    if network_drain:
        print(f"LINUX_SERVICE_NETWORK_NATIVE=pass cases=4 cpace=3 network_drains=1 "
              f"admin_grants=1 fresh_refusals=1 source={commit} binary_sha256={spec['sha256']} "
              f"probe_sha256={probe_spec['sha256']} fixture=installed-layout polkit=actual logind=actual "
              "child=supervised cleanup=joined", flush=True)
        return
    if convergence_failure:
        print(f"LINUX_SERVICE_CONVERGENCE_NATIVE=pass cases=4 cpace=3 stale_refusals=1 convergence_failures=1 "
              f"admin_grants=1 fresh_refusals=1 source={commit} binary_sha256={spec['sha256']} "
              f"probe_sha256={probe_spec['sha256']} fixture=installed-layout polkit=actual logind=actual "
              "child=supervised cleanup=joined", flush=True)
        return
    if notification_failure:
        print(f"LINUX_SERVICE_NOTIFICATION_NATIVE=pass cases=4 cpace=3 stale_refusals=1 notification_failures=1 "
              f"admin_grants=1 fresh_refusals=1 source={commit} binary_sha256={spec['sha256']} "
              f"probe_sha256={probe_spec['sha256']} fixture=installed-layout polkit=actual logind=actual "
              "child=supervised cleanup=joined", flush=True)
        return
    print(f"LINUX_SERVICE_RECEIVER_NATIVE=pass cases=17 cpace=15 file_peers=5 stale_refusals=4 races=2 proxy_control=1 admin_grants=1 admin_failures=1 fresh_refusals=1 requester_exits=1 agent_exits=1 supervisor_shutdowns=1 admitted_shutdowns=1 unit_stops=1 session_revocations=1 source={commit} binary_sha256={spec['sha256']} "
          f"probe_sha256={probe_spec['sha256']} "
          "fixture=installed-layout polkit=actual logind=actual child=supervised cleanup=joined", flush=True)


def actor(uid=4001, display=77, settings=False):
    guard()
    # pam_systemd creates the user's runtime directory during open_session. The desktop
    # command creates its authority file after that session is registered.
    command = ["/usr/bin/python3", "-B", "-I", "-S", str(Path(__file__)),
               "--settings-desktop" if settings else "--desktop" if uid == 4001 else "--handoff-desktop"]
    application = None
    if settings:
        application = ["/usr/bin/setpriv", "--reuid=4001", "--regid=4001", "--clear-groups",
                       "--inh-caps=-all", "--ambient-caps=-all", "/usr/bin/python3", "-B", "-I", "-S",
                       str(MEDIA / "repo/scripts/test-linux-installed-settings.py"), "--session-graphical"]
    pam_module().pam_actor(f"rdreceiver{uid}", "x11", WORK / "pam", display=f":{display}",
                          desktop_command=command, application_command=application)


def desktop(uid=4001, display=77, settings=False):
    guard()
    auth = Path(f"/run/user/{uid}/gdm/Xauthority")
    auth.parent.mkdir(mode=0o700)
    os.chown(auth.parent, uid, uid)
    def field(value):
        return struct.pack("!H", len(value)) + value
    auth.write_bytes(struct.pack("!H", 65535) + field(b"") + field(str(display).encode())
                     + field(b"MIT-MAGIC-COOKIE-1") + field(bytes.fromhex("112233445566778899aabbccddeeff00")))
    os.chown(auth, uid, uid)
    os.chmod(auth, 0o600)
    os.execve("/usr/bin/setpriv", ["/usr/bin/setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
              "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
              str(WORK / "Xvfb"), f":{display}", "-nolisten", "tcp", "-auth", str(auth),
              "-screen", "0", "1024x768x24" if settings else "640x480x24",
              "-xkbdir", str(WORK / "xkb"), "-fp", "built-ins"], ENV)


def polkit_agent(subject, notify):
    guard()
    if re.fullmatch(r"[1-9][0-9]*,[1-9][0-9]*", subject) is None or not notify.isdecimal():
        raise RuntimeError("closed authentication-agent arguments required")
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    # The ordinary agent uses the packaged setuid PAM helper inside this disposable VM.
    os.execve("/usr/bin/setpriv", ["/usr/bin/setpriv", "--reuid=4001", "--regid=4001", "--clear-groups",
              "--inh-caps=-all", "--ambient-caps=-all", "/usr/bin/pkttyagent",
              "--process", subject, "--notify-fd", notify], ENV)


if __name__ == "__main__":
    if sys.argv[1:] == ["--prepare-container"]:
        prepare_container()
    elif sys.argv[1:] == ["--prepare-openrc-container"]:
        prepare_container(openrc=True)
    elif len(sys.argv) == 4 and sys.argv[1] == "--install-polkit":
        guard()
        install_polkit(*sys.argv[2:])
    elif sys.argv[1:] == ["--pam-actor"]:
        actor()
    elif sys.argv[1:] == ["--settings-pam-actor"]:
        actor(settings=True)
    elif sys.argv[1:] == ["--settings-desktop"]:
        desktop(settings=True)
    elif sys.argv[1:] == ["--desktop"]:
        desktop()
    elif sys.argv[1:] == ["--handoff-actor"]:
        actor(4003, 78)
    elif sys.argv[1:] == ["--handoff-desktop"]:
        desktop(4003, 78)
    elif len(sys.argv) == 4 and sys.argv[1] == "--polkit-agent":
        polkit_agent(*sys.argv[2:])
    elif len(sys.argv) == 7 and sys.argv[-1] == "--convergence-failure":
        tests(sys.argv[1:6], convergence_failure=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--notification-failure":
        tests(sys.argv[1:6], notification_failure=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--network-drain":
        tests(sys.argv[1:6], network_drain=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--authorization-timeout":
        tests(sys.argv[1:6], authorization_timeout=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--committed-requester-exit":
        tests(sys.argv[1:6], committed_requester_exit=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--startup":
        tests(sys.argv[1:6], startup=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--incumbent":
        tests(sys.argv[1:6], incumbent=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--collisions":
        tests(sys.argv[1:6], collisions=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--exclusive":
        tests(sys.argv[1:6], exclusive=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--desktop-exclusive":
        tests(sys.argv[1:6], desktop_exclusive=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--crash":
        tests(sys.argv[1:6], crash=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--child-crash":
        tests(sys.argv[1:6], child_crash=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--parent-death":
        tests(sys.argv[1:6], parent_death=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--handoff":
        tests(sys.argv[1:6], handoff=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--openrc":
        tests(sys.argv[1:6], openrc=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--limiter":
        tests(sys.argv[1:6], limiter=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--stopped-child":
        tests(sys.argv[1:6], stopped_child=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--record-cleanup":
        tests(sys.argv[1:6], record_cleanup=True)
    elif len(sys.argv) == 7 and sys.argv[-1] == "--recovery-refusal":
        tests(sys.argv[1:6], recovery=True)
    elif len(sys.argv) == 6:
        tests(sys.argv[1:])
    else:
        raise SystemExit("closed native receiver arguments required")
