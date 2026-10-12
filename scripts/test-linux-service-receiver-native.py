#!/usr/bin/env python3
"""Installed-layout Linux receiver behavior in the owned zero-NIC systemd VM."""

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


def prepare_container():
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


def child_record():
    main = int(run(["/usr/bin/systemctl", "show", "rustdesk.service",
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
                           rb"uid=4001\ngeneration=([0-9a-f-]{36})\n"
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
    if status["PPid"].strip() != str(main) or status["Uid"].split() != ["4001"] * 4:
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


def ready(previous=None, child_replacement=False):
    deadline = time.monotonic() + 25
    last = ""
    while time.monotonic() < deadline:
        try:
            record = child_record()
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


def pending_admin_helper(client, start, record):
    expected = [b"/usr/bin/pkcheck", b"--action-id",
                b"com.carriez.RustDesk.set-unattended-password", b"--process",
                f"{client.pid},{start},4001".encode(), b"--allow-user-interaction", b""]
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
    if len(helpers) != 1:
        raise RuntimeError("pending administrator request has no unique service-owned pkcheck")
    proc, helper_start = helpers[0]
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
    if (status["Uid"].split() != ["0"] * 4
            or not (proc / "exe").samefile("/usr/bin/pkcheck")):
        raise RuntimeError("pending pkcheck has the wrong principal or image")
    return proc, helper_start


def observe_admin_requester_exit(client, agent, terminal, start, record, before, listener):
    proc, helper_start = pending_admin_helper(client, start, record)
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


def close_admin_requester_session(client, agent, start, record, actor):
    pam = pam_module()
    pam.properties(actor, "active")
    helper, helper_start = pending_admin_helper(client, start, record)
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


def admin_change(value, record, phase="apply", actor=None):
    if phase not in ("apply", "requester-exit", "session-close", "bad-password") or (phase == "session-close" and actor is None):
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
                    if phase == "requester-exit":
                        observe_admin_requester_exit(client, agent, terminal, start,
                                                    record, before, listener)
                        break
                    if phase == "session-close":
                        denial = close_admin_requester_session(client, agent, start, record, actor)
                    if phase == "bad-password":
                        helper, helper_start = pending_admin_helper(client, start, record)
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
        if phase != "requester-exit":
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
                    or "Changing service-owned unattended password was rejected by service" not in stderr):
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
    changed = credential() != before
    if phase == "session-close":
        if changed:
            raise RuntimeError("revoked administrator request changed the durable credential during cleanup")
        print("LINUX_RECEIVER_SESSION_REVOKED=pass uid=4001 session=closing requester=alive "
              "authentication=polkit-pam authorization=fresh-denied durable=unchanged "
              "supervisor=retained helper=reaped cleanup=agent-client-joined", flush=True)
        return
    retained = direct_listener(record) == listener
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


def direct_listener(record):
    if child_record() != record:
        raise RuntimeError("serving child changed before listener proof")
    proc = Path("/proc") / str(record["pid"])
    listeners = []
    for line in (proc / "net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            raise RuntimeError("kernel TCP socket row is incomplete")
        if fields[1].endswith(":527E") and fields[3] == "0A":
            if fields[1] != "00000000:527E" or fields[7] != "4001":
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
    if listeners[0] not in sockets or child_record() != record:
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


def tests(args):
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
    pam = pam_module()
    confdir = WORK / "pam"
    confdir.mkdir(mode=0o700)
    (confdir / "rustdesk-logind-fixture").write_text("session required pam_systemd.so\n")
    actor = None
    users = []
    started = False
    try:
        for uid in (4001, 4002, 4003):
            try:
                pwd.getpwuid(uid)
            except KeyError:
                groups = ["--groups", "sudo"] if uid == 4003 else []
                run(["/usr/sbin/useradd", "--uid", str(uid), "--user-group", "--create-home",
                     "--shell", "/usr/sbin/nologin", *groups, f"rdreceiver{uid}"])
                users.append(uid)
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
        for uid in (4001, 4002):
            change(uid, f"Receiver-refused-{uid}-2026!", False)
            if credential() != before or child_record() != first:
                raise RuntimeError("unauthorized caller changed credential or service generation")
            print(f"LINUX_RECEIVER_CASE=principal-denied uid={uid} durable=unchanged", flush=True)
        for endpoint in ("_service", "_service_password"):
            peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                peer.settimeout(5)
                peer.connect(f"/tmp/RustDesk-service/ipc{endpoint}")
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
        admin_change("Receiver-fixture-admin-2026!", second)
        keyed("Receiver-fixture-admin-2026!", "admin-applied", second, probe_spec["sha256"])
        before = credential()
        listener = direct_listener(second)
        change(4001, "Receiver-admin-not-cached-2026!", False)
        if credential() != before or direct_listener(second) != listener:
            raise RuntimeError("fresh unauthenticated request reused administrator authority")
        print("LINUX_RECEIVER_ADMIN_FRESH=pass uid=4001 authentication=required result=denied "
              "durable=unchanged listener=owned", flush=True)
    finally:
        try:
            if started:
                run(["/usr/bin/systemctl", "stop", "rustdesk.service"], timeout=40)
                if Path("/sys/fs/cgroup/system.slice/rustdesk.service").exists():
                    raise RuntimeError("owned receiver cgroup remains after stop")
        finally:
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
    print(f"LINUX_SERVICE_RECEIVER_NATIVE=pass cases=13 cpace=11 stale_refusals=2 races=2 proxy_control=1 admin_grants=1 admin_failures=1 fresh_refusals=1 requester_exits=1 session_revocations=1 source={commit} binary_sha256={spec['sha256']} "
          f"probe_sha256={probe_spec['sha256']} "
          "fixture=installed-layout polkit=actual logind=actual child=supervised cleanup=joined", flush=True)


def actor():
    guard()
    # pam_systemd creates /run/user/4001 during open_session. The desktop
    # command creates its authority file after that session is registered.
    command = ["/usr/bin/python3", "-B", "-I", "-S", str(Path(__file__)), "--desktop"]
    pam_module().pam_actor("rdreceiver4001", "x11", WORK / "pam", display=":77", desktop_command=command)


def desktop():
    guard()
    auth = Path("/run/user/4001/gdm/Xauthority")
    auth.parent.mkdir(mode=0o700)
    os.chown(auth.parent, 4001, 4001)
    def field(value):
        return struct.pack("!H", len(value)) + value
    auth.write_bytes(struct.pack("!H", 65535) + field(b"") + field(b"77")
                     + field(b"MIT-MAGIC-COOKIE-1") + field(bytes.fromhex("112233445566778899aabbccddeeff00")))
    os.chown(auth, 4001, 4001)
    os.chmod(auth, 0o600)
    os.execve("/usr/bin/setpriv", ["/usr/bin/setpriv", "--reuid=4001", "--regid=4001", "--clear-groups",
              "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
              str(WORK / "Xvfb"), ":77", "-nolisten", "tcp", "-auth", str(auth),
              "-screen", "0", "640x480x24", "-xkbdir", str(WORK / "xkb"), "-fp", "built-ins"], ENV)


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
    elif len(sys.argv) == 4 and sys.argv[1] == "--install-polkit":
        guard()
        install_polkit(*sys.argv[2:])
    elif sys.argv[1:] == ["--pam-actor"]:
        actor()
    elif sys.argv[1:] == ["--desktop"]:
        desktop()
    elif len(sys.argv) == 4 and sys.argv[1] == "--polkit-agent":
        polkit_agent(*sys.argv[2:])
    elif len(sys.argv) == 6:
        tests(sys.argv[1:])
    else:
        raise SystemExit("closed native receiver arguments required")
