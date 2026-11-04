"""Read-only storage observation inside the disposable AOSP emulator."""
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET


adb, serial, pid, baseline, phase = sys.argv[1:]
if serial != "emulator-5554" or not re.fullmatch(r"[1-9][0-9]*", pid):
    raise ValueError("unexpected emulator/process")
if phase not in ("before", "relaunched", "after"):
    raise ValueError("unexpected observation phase")


def shell(*args):
    result = subprocess.run([adb, "-s", serial, "shell", "-T", shlex.join(args)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 4096:
        raise RuntimeError("bounded emulator storage observation failed")
    return result.stdout


package = "com.carriez.flutter_hbb"
principal = shell("cmd", "package", "list", "packages", "-U", "--user", "0", package).decode().strip()
match = re.fullmatch(r"package:" + re.escape(package) + r" uid:(\d+)", principal)
if not match or not 10000 <= int(match[1]) < 20000:
    raise ValueError("unexpected installed application UID")
uid = int(match[1])
status = shell("cat", f"/proc/{pid}/status").decode()
uids = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", status, re.M)
if not uids or list(map(int, uids.groups())) != [uid] * 4:
    raise ValueError("application process is not its ordinary package principal")
if shell("cat", f"/proc/{pid}/cmdline").rstrip(b"\0") != package.encode():
    raise ValueError("application process identity differs")
root = f"/data/user/0/{package}"
paths = {
    "envelope": root + "/shared_prefs/rustdesk_mobile_at_rest_storage.xml",
    "credential": root + "/app_flutter/RustDesk.toml",
}
records = {}
for name, path in paths.items():
    metadata = shell("stat", "-c", "%u:%g:%a:%h:%s:%i:%f", path).decode().strip()
    owner, group, mode, links, size, inode, kind = metadata.split(":")
    private_modes = (0o600, 0o660) if name == "envelope" else (0o600,)
    if (int(owner) != uid or int(group) != uid or int(mode, 8) not in private_modes
            or int(links) != 1 or not 0 < int(size) <= 65536
            or int(kind, 16) & 0o170000 != 0o100000):
        raise ValueError(f"private {name} file metadata differs")
    raw = shell("cat", path)
    if len(raw) != int(size) or shell("stat", "-c", "%u:%g:%a:%h:%s:%i:%f", path).decode().strip() != metadata:
        raise ValueError(f"{name} changed during observation")
    if name == "envelope":
        document = ET.fromstring(raw)
        values = {node.attrib.get("name"): node.text for node in document}
        if (document.tag != "map" or len(document) != 2
                or set(values) != {"storage_key_ciphertext_v1", "storage_key_iv_v1"}
                or len(base64.b64decode(values["storage_key_ciphertext_v1"], validate=True)) != 48
                or len(base64.b64decode(values["storage_key_iv_v1"], validate=True)) != 12):
            raise ValueError("unexpected Android key envelope")
    else:
        config = tomllib.loads(raw.decode())
        for field, prefix, length in (("password", "01", 87), ("password_prs", "00", 85)):
            credential = config[field]
            if not isinstance(credential, str) or not credential.startswith(prefix):
                raise ValueError("credential is not wrapped storage")
            wrapped = base64.b64decode(credential[2:], validate=True)
            if len(wrapped) != length or wrapped[0] != 1 or b"Runtime1x" in raw:
                raise ValueError("credential storage is not the current encrypted format")
    records[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                     "uid": uid, "mode": mode, "inode": inode}
state = {"uid": uid, "files": records}
if phase == "before":
    with Path(baseline).open("x") as output:
        json.dump(state, output, sort_keys=True)
elif json.loads(Path(baseline).read_text()) != state:
    raise ValueError("persisted key envelope or credential changed across process restart")
print("ANDROID_STORAGE_SNAPSHOT=" + json.dumps({"phase": phase, "pid": int(pid), **state}, sort_keys=True))
