#!/usr/bin/env python3
"""Installed-layout Linux receiver behavior in the owned zero-NIC systemd VM."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid


MEDIA = Path("/mnt/rustdesk-verifier-inputs")
WORK = Path("/var/tmp/rustdesk-linux-service-receiver")
PRIMARY = Path("/usr/share/rustdesk/rustdesk")
CHILD = PRIMARY.with_name("rustdesk-service-child")
PROBE = WORK / "probe_client"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


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


def ready(previous=None):
    deadline = time.monotonic() + 25
    last = ""
    while time.monotonic() < deadline:
        try:
            record = child_record()
            if previous is None or (record["supervisor"] != previous["supervisor"]
                                    and record["generation"] != previous["generation"]):
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


def tests(args):
    guard()
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
        for uid in (4001, 4002):
            try:
                pwd.getpwuid(uid)
            except KeyError:
                run(["/usr/sbin/useradd", "--uid", str(uid), "--user-group", "--create-home",
                     "--shell", "/usr/sbin/nologin", f"rdreceiver{uid}"])
                users.append(uid)
            else:
                raise RuntimeError("receiver fixture UID already exists")
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
        if credential() != after:
            raise RuntimeError("restart changed durable root credential")
        print(f"LINUX_RECEIVER_CASE=restart observed={json.dumps(second, sort_keys=True)} durable=unchanged", flush=True)
        keyed("Receiver-fixture-second-2026!", "restart", second, probe_spec["sha256"])
        stale_refused("Receiver-fixture-first-2026!", "restart", second, probe_spec["sha256"])
        keyed("Receiver-fixture-second-2026!", "restart-after-refusal", second, probe_spec["sha256"])
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
    print(f"LINUX_SERVICE_RECEIVER_NATIVE=pass cases=8 cpace=5 stale_refusals=2 source={commit} binary_sha256={spec['sha256']} "
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
    elif len(sys.argv) == 6:
        tests(sys.argv[1:])
    else:
        raise SystemExit("closed native receiver arguments required")
