#!/usr/bin/env python3
"""Exercise production passwd lookup in fresh, confined verifier-VM processes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


ROOT = Path("/var/tmp/rustdesk-verifier-authority")
TEST = "config::tests::linux_service_owned_config_root_native_passwd"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
CASES = (("root", 0), ("user-service", 1000), ("user-owned", 1000),
         ("missing-account", 1001), ("missing-home", 1000), ("relative-home", 1000))


def run(command, timeout=10):
    result = subprocess.run(command, env=ENV, capture_output=True, text=True, timeout=timeout)
    if result.returncode or len(result.stdout) + len(result.stderr) > 1048576:
        raise RuntimeError(f"fixture command failed ({result.returncode}): "
                           f"{result.stdout[-4096:]} {result.stderr[-4096:]}")
    return result.stdout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(directory):
    result = {}
    for path in [directory, *sorted(directory.rglob("*"))]:
        metadata = path.lstat()
        if (metadata.st_uid != 0 or metadata.st_mode & 0o022 or path.is_symlink()
                or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode))):
            raise RuntimeError("passwd fixture authority differs")
        result[str(path.relative_to(directory))] = (
            metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
            metadata.st_mode, metadata.st_nlink, digest(path) if path.is_file() else None)
    return result


def main(args):
    if (os.geteuid() != 0 or Path("/run/rustdesk-verifier-vm").stat().st_uid != 0
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or sorted(p.name for p in Path("/sys/class/net").iterdir()) != ["lo"]
            or Path(__file__).resolve().parent.parent != ROOT / "focused-rust-test-source"):
        raise RuntimeError("this fixture requires the owned zero-NIC verifier VM")
    artifact = Path(args.artifact)
    metadata = artifact.lstat()
    if (artifact.parent != ROOT / "focused-rust-test-target/debug/deps"
            or not re.fullmatch(r"hbb_common-[0-9a-f]{16}", artifact.name)
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 1000
            or metadata.st_nlink != 1 or digest(artifact) != args.sha256
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image)):
        raise RuntimeError("source-bound native artifact identity differs")
    docker = ["/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
              args.docker_client, "--host", "unix://" + args.docker_socket]
    fixture = ROOT / "service-config-root-native"
    fixture.mkdir(mode=0o755)
    fixture.chmod(0o755)
    directories = [fixture / name for name in ("root-home", "user-home", "relative-home")]
    for directory in directories:
        directory.mkdir(mode=0o555)
        directory.chmod(0o555)
    files = [fixture / "nsswitch.conf"]
    files[0].write_text("passwd: files\ngroup: files\nshadow: files\n")
    files[0].chmod(0o444)
    for name, _uid in CASES:
        home = {"missing-home": "/fixture/absent", "relative-home": "relative-home"}.get(
            name, "/fixture/user-home")
        passwd = fixture / (name + ".passwd")
        passwd.write_text("root:x:0:0::/fixture/root-home:/bin/false\n"
                          f"fixture-user:x:1000:1000::{home}:/bin/false\n")
        passwd.chmod(0o444)
        files.append(passwd)
    before = snapshot(fixture)
    for name, uid in CASES:
        mounts = [(str(artifact), "/native-test"), (str(fixture), "/fixture"),
                  (str(fixture / (name + ".passwd")), "/etc/passwd"),
                  (str(fixture / "nsswitch.conf"), "/etc/nsswitch.conf")]
        command = docker + ["create", "--pull=never", "--network=none", "--read-only",
                            f"--user={uid}:{uid}", "--cap-drop=ALL",
                            "--security-opt=no-new-privileges", "--security-opt=apparmor=docker-default",
                            "--pids-limit=64", "--memory=256m", "--memory-swap=256m", "--cpus=2",
                            "--ulimit=core=0:0", "--workdir=/fixture",
                            "--env=HOME=/ambient-home", "--env=XDG_CONFIG_HOME=/ambient-xdg",
                            "--env=RUSTDESK_NATIVE_SERVICE_CONFIG_CASE=" + name,
                            f"--tmpfs=/tmp:rw,nosuid,nodev,size=16m,mode=700,uid={uid},gid={uid}"]
        for source, destination in mounts:
            command.extend(["--mount", f"type=bind,source={source},target={destination},readonly,bind-recursive=disabled"])
        command.extend([args.image, "/native-test", TEST, "--exact", "--ignored", "--nocapture",
                        "--test-threads=1", "--color", "never"])
        if digest(artifact) != args.sha256 or snapshot(fixture) != before:
            raise RuntimeError("native inputs changed before execution")
        container = run(command).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise RuntimeError("owned native container ID is invalid")
        try:
            inspection = json.loads(run(docker + ["inspect", container]))[0]
            config = inspection["HostConfig"]
            if (inspection["Image"] != args.image or inspection["Config"]["User"] != f"{uid}:{uid}"
                    or config["NetworkMode"] != "none" or not config["ReadonlyRootfs"]
                    or config["Privileged"] or config["PidMode"] or config["Devices"]
                    or config["PortBindings"] or config["CapDrop"] != ["ALL"] or config["CapAdd"]
                    or config["GroupAdd"] or config["UsernsMode"]
                    or config["SecurityOpt"] != ["no-new-privileges", "apparmor=docker-default"]
                    or config["IpcMode"] != "private" or config["CgroupnsMode"] != "private"
                    or config["Memory"] != 268435456 or config["MemorySwap"] != 268435456
                    or config["PidsLimit"] != 64):
                raise RuntimeError("native container isolation differs")
            if sorted((item["Source"], item["Destination"], item["RW"]) for item in inspection["Mounts"]
                      if item["Type"] == "bind") != sorted(
                    (source, destination, False) for source, destination in mounts):
                raise RuntimeError("native container mounts differ")
            if any(item["Type"] != "bind" and (item["Type"] != "tmpfs" or item["Destination"] != "/tmp")
                   for item in inspection["Mounts"]):
                raise RuntimeError("native container has an unexpected mount")
            output = run(docker + ["start", "--attach", container], timeout=8)
            receipt = f"LINUX_SERVICE_CONFIG_CASE=pass name={name} uid={uid}"
            if (output.count(receipt + "\n") != 1
                    or len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.M)) != 1
                    or run(docker + ["inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", container]).strip() != "exited:0"
                    or digest(artifact) != args.sha256 or snapshot(fixture) != before):
                raise RuntimeError(f"native configuration-root case failed: {output[-4096:]}")
            print(output, end="", flush=True)
        finally:
            if run(docker + ["rm", "--force", container]).strip() != container:
                raise RuntimeError("native container removal differs")
            if run(docker + ["ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + container]).strip():
                raise RuntimeError("native container survived removal")
    if digest(artifact) != args.sha256 or snapshot(fixture) != before:
        raise RuntimeError("native inputs changed after execution")
    for path in files:
        path.unlink()
    for path in directories:
        path.rmdir()
    fixture.rmdir()
    print(f"LINUX_SERVICE_CONFIG_NATIVE=pass cases={len(CASES)} artifact_sha256={args.sha256} "
          "scope=configuration-root installed=unexecuted caps=none nnp=on cleanup=joined", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("artifact", "sha256", "image", "docker-client", "docker-socket"):
        parser.add_argument("--" + argument, required=True)
    main(parser.parse_args())
