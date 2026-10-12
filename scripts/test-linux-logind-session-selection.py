#!/usr/bin/env python3
"""Real pam_systemd fixture; run only by the isolated verifier VM supervisor."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import subprocess
import sys
import time


ROOT = Path("/var/tmp/rustdesk-verifier-authority")
TEST = "platform::linux::tests::r_s11at_loginctl_native_session_selection"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def run(command, timeout=10):
    result = subprocess.run(command, env=ENV, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}: {result.stdout[-4096:]} {result.stderr[-4096:]}")
    if len(result.stdout) > 1048576:
        raise RuntimeError("fixture command output exceeded its bound")
    return result.stdout


def guard():
    authority = Path("/run/rustdesk-verifier-vm").stat()
    if (os.geteuid() != 0 or authority.st_uid != 0
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or sorted(p.name for p in Path("/sys/class/net").iterdir()) != ["lo"]
            or Path(__file__).resolve().parent.parent != ROOT / "focused-rust-test-source"):
        raise RuntimeError("this fixture requires the owned zero-NIC systemd verifier VM")


def pam_actor(username, session_type, confdir, display=None, desktop_command=None):
    # Linux-PAM 1.5.2 pam_appl.h/_pam_types.h; one PAM session per retained process.
    # systemd v252 pam_systemd.c intentionally retains the FIFO until process exit.
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
    callback = callback_type(lambda _count, _messages, _response, _data: 19)

    class Conversation(ctypes.Structure):
        _fields_ = [("conv", callback_type), ("appdata_ptr", ctypes.c_void_p)]

    pam = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libpam.so.0")
    handle = ctypes.c_void_p()
    conversation = Conversation(callback, None)
    pam.pam_start_confdir.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                     ctypes.POINTER(Conversation), ctypes.c_char_p,
                                     ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_putenv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    pam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    pam.pam_getenv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    pam.pam_getenv.restype = ctypes.c_char_p
    for name in ("pam_open_session", "pam_close_session", "pam_end"):
        getattr(pam, name).argtypes = [ctypes.c_void_p, ctypes.c_int]

    def check(status):
        if status != 0:
            raise RuntimeError(f"PAM session operation failed: {status}")

    check(pam.pam_start_confdir(b"rustdesk-logind-fixture", username.encode(),
                              ctypes.byref(conversation), os.fsencode(confdir),
                              ctypes.byref(handle)))
    opened = closed = False
    desktop = None
    try:
        check(pam.pam_putenv(handle, f"XDG_SESSION_TYPE={session_type}".encode()))
        check(pam.pam_putenv(handle, b"XDG_SESSION_CLASS=user"))
        if display is not None:
            # Linux-PAM 1.5.2 defines PAM_XDISPLAY=11; pam_systemd v252
            # reads this item when registering the session's Display property.
            check(pam.pam_set_item(handle, 11, ctypes.c_char_p(display.encode())))
        check(pam.pam_open_session(handle, 0))
        opened = True
        session = pam.pam_getenv(handle, b"XDG_SESSION_ID")
        if not session or not re.fullmatch(rb"[a-zA-Z0-9]+", session):
            raise RuntimeError("pam_systemd did not create a native session")
        session = session.decode("ascii")
        response = {"session": session, "phase": "opened"}
        if desktop_command is not None:
            desktop = subprocess.Popen(desktop_command, env=ENV, stdin=subprocess.DEVNULL,
                                       stdout=sys.stderr, stderr=sys.stderr)
            response["desktop_pid"] = desktop.pid
        print(json.dumps(response), flush=True)
        for line in sys.stdin:
            if line == "close\n" and not closed:
                check(pam.pam_close_session(handle, 0))
                closed = True
                print(json.dumps({"session": session, "phase": "closed"}), flush=True)
            elif line == "quit\n":
                break
            else:
                raise RuntimeError("unexpected PAM actor command")
        else:
            raise RuntimeError("PAM actor lost its owning controller")
    finally:
        try:
            if desktop is not None:
                if desktop.poll() is None:
                    desktop.terminate()
                try:
                    status = desktop.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    desktop.kill()
                    desktop.wait()
                    raise RuntimeError("PAM-owned desktop required forced termination")
                if status not in (0, -15):
                    raise RuntimeError(f"PAM-owned desktop exited {status}")
        finally:
            try:
                if opened and not closed:
                    check(pam.pam_close_session(handle, 0))
            finally:
                check(pam.pam_end(handle, 0))


def reply(process):
    data = bytearray()
    deadline = time.monotonic() + 8
    while len(data) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
            raise RuntimeError("PAM actor readiness timed out")
        value = os.read(process.stdout.fileno(), 1)
        if not value:
            raise RuntimeError("PAM actor exited before its reply")
        data.extend(value)
        if value == b"\n":
            return json.loads(data)
    raise RuntimeError("PAM actor reply exceeded its bound")


def sessions():
    output = run(["/usr/bin/loginctl", "list-sessions", "--no-legend", "--no-pager"])
    return {line.split()[0] for line in output.splitlines() if line.strip()}


def properties(actor, state):
    deadline = time.monotonic() + 3
    while True:
        command = ["/usr/bin/loginctl", "show-session", actor["session"], "--no-pager"]
        for key in ("User", "Type", "State", "Seat", "Class", "Leader"):
            command.extend(["--property", key])
        values = dict(line.split("=", 1) for line in run(command).splitlines())
        expected = {"User": str(actor["uid"]), "Type": actor["type"], "State": state,
                    "Seat": "", "Class": "user", "Leader": str(actor["process"].pid)}
        if values == expected:
            return values
        if time.monotonic() >= deadline:
            raise RuntimeError(f"native session properties differ: {values}, expected {expected}")
        time.sleep(0.02)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def native_tests(args):
    artifact = Path(args.artifact)
    if (artifact.parent != ROOT / "focused-rust-test-target/debug/deps"
            or not re.fullmatch(r"hbb_common-[0-9a-f]{16}", artifact.name)
            or artifact.is_symlink() or artifact.stat().st_uid != 1000
            or artifact.stat().st_nlink != 1 or digest(artifact) != args.sha256
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image)):
        raise RuntimeError("source-bound native artifact identity differs")
    print(f"LINUX_LOGINCTL_ARTIFACT=observed sha256={args.sha256} executable={artifact}", flush=True)
    docker = ["/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
              args.docker_client, "--host", "unix://" + args.docker_socket]
    # Use the guest's actual loginctl and its distro libraries, never a command shim.
    # The pinned Debian verifier supplies the Rust binary's other dependencies.
    commands = {Path("/usr/bin/loginctl")}
    for line in run(["/usr/bin/ldd", "/usr/bin/loginctl"]).splitlines():
        if "not found" in line:
            raise RuntimeError("guest loginctl dependency is unavailable")
        match = re.search(r"(?:=>\s+|^\s*)(/\S+)\s+\(", line)
        if match:
            commands.add(Path(match[1]).resolve())
    mounts = [(str(artifact), "/native-test"),
              ("/run/dbus/system_bus_socket", "/run/dbus/system_bus_socket"),
              ("/run/systemd/system", "/run/systemd/system")]
    for path in sorted(commands):
        current = path
        while current != current.parent:
            metadata = current.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise RuntimeError("guest loginctl dependency is not protected")
            current = current.parent
        if not stat.S_ISREG(path.stat().st_mode):
            raise RuntimeError("guest loginctl dependency is not a regular file")
        mounts.append((str(path), str(path)))
    confdir = ROOT / "logind-native-pam"
    confdir.mkdir(mode=0o700)
    (confdir / "rustdesk-logind-fixture").write_text(
        "session required /usr/lib/x86_64-linux-gnu/security/pam_systemd.so\n")
    actors = []
    users = []

    def start(uid, session_type):
        username = f"rdlogind{uid}"
        process = subprocess.Popen(
            ["/usr/bin/python3", "-I", "-S", str(Path(__file__).resolve()),
             "--pam-actor", username, session_type, str(confdir)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
        actor = {"process": process, "uid": uid, "type": session_type}
        actors.append(actor)
        result = reply(process)
        if result.get("phase") != "opened":
            raise RuntimeError("native PAM session was not opened")
        actor["session"] = result["session"]
        properties(actor, "active")
        return actor

    def close(actor):
        actor["process"].stdin.write(b"close\n")
        actor["process"].stdin.flush()
        if reply(actor["process"]) != {"session": actor["session"], "phase": "closed"}:
            raise RuntimeError("PAM session did not acknowledge close")
        properties(actor, "closing")

    def case(name, expected, states):
        if sessions() != {actor["session"] for actor, _state in states}:
            raise RuntimeError("native fixture has missing or foreign sessions")
        observed = [properties(actor, state) for actor, state in states]
        if digest(artifact) != args.sha256:
            raise RuntimeError("native test artifact changed before execution")
        command = docker + ["create", "--pull=never", "--network=none", "--read-only",
                            "--user=1000:1000", "--cap-drop=ALL",
                            "--security-opt=no-new-privileges", "--security-opt=apparmor=docker-default",
                            "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=2",
                            "--ulimit=core=0:0", "--env=RUSTDESK_NATIVE_LOGINCTL_EXPECTED_UID=" + expected,
                            "--tmpfs=/tmp:rw,nosuid,nodev,size=16m,mode=700,uid=1000,gid=1000"]
        for source, destination in mounts:
            command.extend(["--mount", f"type=bind,source={source},target={destination},readonly,bind-recursive=disabled"])
        command.extend([args.image, "/native-test", TEST, "--exact", "--ignored",
                        "--test-threads=1", "--color", "never"])
        container = run(command).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise RuntimeError("owned native container ID is invalid")
        try:
            inspection = json.loads(run(docker + ["inspect", container]))[0]
            config = inspection["HostConfig"]
            if (inspection["Image"] != args.image or inspection["Config"]["User"] != "1000:1000"
                    or config["NetworkMode"] != "none" or not config["ReadonlyRootfs"]
                    or config["Privileged"] or config["PidMode"] or config["Devices"]
                    or config["PortBindings"] or config["CapDrop"] != ["ALL"]
                    or config["SecurityOpt"] != ["no-new-privileges", "apparmor=docker-default"]
                    or config["IpcMode"] != "private" or config["CgroupnsMode"] != "private"):
                raise RuntimeError("native container isolation differs")
            if sorted((item["Source"], item["Destination"], item["RW"]) for item in inspection["Mounts"]
                      if item["Type"] == "bind") != sorted(
                    (source, destination, False) for source, destination in mounts):
                raise RuntimeError("native container mounts differ")
            if any(item["Type"] != "bind" and (item["Type"] != "tmpfs" or item["Destination"] != "/tmp")
                   for item in inspection["Mounts"]):
                raise RuntimeError("native container has an unexpected mount")
            output = run(docker + ["start", "--attach", container], timeout=8)
            if (f"test {TEST} ... ok\n" not in output
                    or len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.M)) != 1
                    or run(docker + ["inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", container]).strip() != "exited:0"
                    or digest(artifact) != args.sha256):
                raise RuntimeError(f"native UID selection failed: {output[-4096:]}")
            print(f"LINUX_LOGINCTL_CASE=pass name={name} expected_uid={expected or 'none'} sessions={json.dumps(observed, sort_keys=True)}", flush=True)
        finally:
            run(docker + ["rm", "--force", container])

    def retire_actors():
        errors = []
        for actor in reversed(actors):
            process = actor["process"]
            try:
                if process.poll() is None:
                    process.stdin.write(b"quit\n")
                    process.stdin.flush()
                _output, stderr = process.communicate(timeout=5)
                if process.returncode != 0:
                    raise RuntimeError(f"PAM actor failed: {stderr[-4096:]!r}")
            except Exception as error:
                errors.append(str(error))
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        actors.clear()
        if errors:
            raise RuntimeError("; ".join(errors))
        deadline = time.monotonic() + 5
        while sessions():
            if time.monotonic() >= deadline:
                raise RuntimeError("native logind session cleanup did not finish")
            time.sleep(0.02)

    try:
        if sessions():
            raise RuntimeError("native logind fixture requires an empty initial session set")
        print(f"LINUX_LOGINCTL_FIXTURE=observed systemd={run(['/usr/bin/loginctl', '--version']).splitlines()[0]!r} pam={run(['/usr/bin/dpkg-query', '-W', '-f=${Version}', 'libpam0g'])!r} loginctl_sha256={digest(Path('/usr/bin/loginctl'))}", flush=True)
        for uid in (4001, 4002):
            try:
                pwd.getpwuid(uid)
            except KeyError:
                run(["/usr/sbin/useradd", "--uid", str(uid), "--no-create-home", "--shell",
                     "/usr/sbin/nologin", f"rdlogind{uid}"])
                users.append(uid)
            else:
                raise RuntimeError("fixture UID already exists")
        case("empty", "", [])
        unspecified = start(4001, "unspecified")
        case("unspecified-refused", "", [(unspecified, "active")])
        tty = start(4002, "tty")
        background = [(unspecified, "active"), (tty, "active")]
        case("seatless-tty-refused", "", background)
        first = start(4001, "x11")
        case("active-x11", "4001", background + [(first, "active")])
        close(first)
        second = start(4002, "x11")
        case("fresh-x11-switch", "4002", background + [(first, "closing"), (second, "active")])
        close(second)
        case("closing-x11-refused", "", background + [(first, "closing"), (second, "closing")])
        retire_actors()
        case("all-removed", "", [])
    finally:
        try:
            retire_actors()
        finally:
            for uid in users:
                run(["/usr/bin/systemctl", "stop", f"user@{uid}.service", f"user-runtime-dir@{uid}.service"])
                run(["/usr/sbin/userdel", f"rdlogind{uid}"])
            (confdir / "rustdesk-logind-fixture").unlink()
            confdir.rmdir()
    print(f"LINUX_LOGINCTL_NATIVE=pass cases=7 artifact_sha256={args.sha256} fixture=systemd-pam scope=logind-session-selection installed=unexecuted uid=1000 caps=none nnp=on cleanup=joined")


def main():
    guard()
    if len(sys.argv) == 5 and sys.argv[1] == "--pam-actor":
        pam_actor(*sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("docker-client", "docker-socket", "image", "artifact", "sha256"):
        parser.add_argument("--" + name, required=True)
    native_tests(parser.parse_args())


if __name__ == "__main__":
    main()
