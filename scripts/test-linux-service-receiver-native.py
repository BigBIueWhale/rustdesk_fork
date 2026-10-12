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
    print("LINUX_RECEIVER_PREPARE=pass xdo=checked-in xkb=pinned-image", flush=True)


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
    result = run(argv, input=value + "\n", timeout=20, allowed=(0, 1))
    if admitted != (result.returncode == 0 and result.stdout.strip() == "Done!"):
        raise RuntimeError(f"password result differs for UID {uid}: exit {result.returncode}")
    if not admitted and result.returncode != 1:
        raise RuntimeError("denied password operation did not report failure")


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
                          "--property=User,Type,State,Display,Seat", "--", session]).stdout
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
        run(["/usr/bin/systemctl", "restart", "rustdesk.service"], timeout=40)
        second = ready(first)
        if credential() != after:
            raise RuntimeError("restart changed durable root credential")
        print(f"LINUX_RECEIVER_CASE=restart observed={json.dumps(second, sort_keys=True)} durable=unchanged", flush=True)
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
    print(f"LINUX_SERVICE_RECEIVER_NATIVE=pass cases=8 source={commit} binary_sha256={spec['sha256']} "
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
