#!/usr/bin/env python3
"""Native Android 14 LocalTransport test, inside the owned offline emulator only."""
import argparse
import hashlib
import io
import pathlib
import re
import shlex
import subprocess
import tarfile


APP = "com.carriez.flutter_hbb"
CONTROL = "org.rustdesk.backupcontrol"
TRANSPORT = "com.android.localtransport/.LocalTransport"
DOMAINS = ("r", "f", "db", "sp", "ef", "d_r", "d_f", "d_db", "d_sp")


def payload(domain):
    return f'<map><string name="probe">rustdesk-backup-{domain}</string></map>\n'.encode()


def fixture(package, domain):
    storage = "user_de" if domain.startswith("d_") else "user"
    root = f"/data/{storage}/0/{package}"
    subdir = {"r": "", "f": "/files", "db": "/databases", "sp": "/shared_prefs"}
    directory = (f"/sdcard/Android/data/{package}/files" if domain == "ef"
                 else root + subdir[domain.removeprefix("d_")])
    return directory + f"/rd_backup_{domain}.xml"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--control-apk", required=True, type=pathlib.Path)
    parser.add_argument("--apk-sha256", required=True)
    args = parser.parse_args()
    if args.serial != "emulator-5554" or not re.fullmatch(r"[0-9a-f]{64}", args.apk_sha256):
        raise ValueError("unexpected emulator/artifact identity")

    def adb(*command, data=None, timeout=30):
        result = subprocess.run([args.adb, "-s", args.serial, *command], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"adb {command}: {result.stderr.decode(errors='replace')[:4096]}")
        return result.stdout

    def shell(*command, data=None, timeout=30):
        return adb("exec-out", shlex.join(command), data=data, timeout=timeout)

    def text(*command, timeout=30):
        return shell(*command, timeout=timeout).decode().replace("\r", "").strip()

    def package_uid(package):
        state = text("dumpsys", "package", package)
        ids = re.findall(r"^\s*userId=(\d+)\s*$", state, re.MULTILINE)
        if len(ids) != 1 or not 10000 <= int(ids[0]) < 20000:
            raise RuntimeError(f"package UID differs: {package}")
        return ids[0]

    def verify_data(package, uid, present):
        for domain in DOMAINS:
            path = fixture(package, domain)
            if present:
                if shell("su", uid, "cat", path) != payload(domain):
                    raise RuntimeError(f"fixture unreadable or changed: {package}/{domain}")
            elif text("su", uid, "sh", "-c", f"test ! -e {shlex.quote(path)}; echo $?") != "0":
                raise RuntimeError(f"fixture still present: {package}/{domain}")

    def archive(package):
        path = f"/data/user/0/com.android.localtransport/files/1/_full/{package}"
        size = int(text("stat", "-c", "%s", path))
        if not 0 < size <= 1048576:
            raise RuntimeError("transport archive exceeds the fixture bound")
        raw = shell("cat", path)
        if len(raw) != size:
            raise RuntimeError("transport archive size changed")
        files = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
            for entry in stream:
                if (len(files) >= 256 or entry.name in files or entry.size > 65536
                        or not (entry.isfile() or entry.isdir())):
                    raise RuntimeError(f"unexpected transport entry: {entry.name}")
                files[entry.name] = stream.extractfile(entry).read() if entry.isfile() else None
        print(f"ANDROID_BACKUP_ARCHIVE package={package} bytes={size} sha256={hashlib.sha256(raw).hexdigest()} members={','.join(sorted(files))}", flush=True)
        return files

    if text("getprop", "ro.build.version.sdk") != "34" or text("getenforce") != "Enforcing":
        raise RuntimeError("unexpected Android platform authority")
    adb("root")
    adb("wait-for-device")
    if text("id", "-u") != "0":
        raise RuntimeError("the disposable AOSP emulator lacks its root test interface")
    installed = False
    try:
        if text("pm", "list", "packages", CONTROL):
            raise RuntimeError("positive-control package already exists")
        install = adb("install", "--no-streaming", str(args.control_apk)).decode()
        if install.replace("\r", "").splitlines().count("Success") != 1:
            raise RuntimeError("positive-control installation failed")
        installed = True
        started = text("am", "start", "-W", "-n", CONTROL + "/.AndroidBackupControl", timeout=60)
        if "Status: ok" not in started:
            raise RuntimeError("positive-control Activity did not start")
        control_uid, app_uid = package_uid(CONTROL), package_uid(APP)
        for uid in (control_uid, app_uid):
            if text("su", uid, "id", "-u") != uid:
                raise RuntimeError("fixture reader did not enter the application UID")
        verify_data(CONTROL, control_uid, True)
        verify_data(APP, app_uid, False)
        for domain in DOMAINS:
            path = fixture(APP, domain)
            parent = str(pathlib.PurePosixPath(path).parent)
            command = f"umask 077; mkdir -p {shlex.quote(parent)} && cat > {shlex.quote(path)}"
            shell("su", app_uid, "sh", "-c", command, data=payload(domain))
        # Reapply Android's own labels after test-UID fixture creation. SELinux stays enforcing.
        shell("restorecon", "-R", f"/data/user/0/{APP}", f"/data/user_de/0/{APP}")
        verify_data(APP, app_uid, True)
        print("ANDROID_BACKUP_FIXTURES=pass packages=2 domains=9 readable=application-uid", flush=True)
        text("bmgr", "enable", "true")
        text("settings", "put", "secure", "backup_local_transport_parameters",
             "is_device_transfer=true,is_encrypted=true")
        selected = text("bmgr", "transport", TRANSPORT)
        if "Selected transport" not in selected:
            raise RuntimeError("local backup transport selection failed")
        text("bmgr", "init", TRANSPORT, timeout=90)
        for package in (CONTROL, APP):
            result = text("bmgr", "backupnow", "--non-incremental", package, timeout=180)
            print(f"ANDROID_BACKUP_RESULT package={package} output={result!r}", flush=True)
            if f"Package {package} with result: Success" not in result:
                raise RuntimeError("D2D backup did not execute successfully")
            files = archive(package)
            if package == CONTROL:
                for domain in DOMAINS:
                    name = f"apps/{package}/{domain}/rd_backup_{domain}.xml"
                    if files.get(name) != payload(domain):
                        raise RuntimeError(f"positive control did not transfer {domain}")
            elif (f"apps/{APP}/_manifest" not in files or set(files)
                  - {f"apps/{APP}/_manifest", f"apps/{APP}/_meta", "apps", f"apps/{APP}"}):
                raise RuntimeError("excluded application data reached the transfer archive")
        for package, uid in ((CONTROL, control_uid), (APP, app_uid)):
            shell("su", uid, "rm", *[fixture(package, domain) for domain in DOMAINS])
            verify_data(package, uid, False)
            restored = text("bmgr", "restore", "1", package, timeout=180)
            print(f"ANDROID_BACKUP_RESTORE package={package} output={restored!r}", flush=True)
            if "restoreFinished: 0" not in restored:
                raise RuntimeError("local D2D restore did not finish successfully")
            verify_data(package, uid, package == CONTROL)
        text("settings", "put", "secure", "backup_local_transport_parameters", "is_device_transfer=false,is_encrypted=true")
        text("bmgr", "init", TRANSPORT, timeout=90)
        cloud_path = f"/data/user/0/com.android.localtransport/files/1/_full/{APP}"
        if text("sh", "-c", f"test ! -e {cloud_path}; echo $?") != "0":
            raise RuntimeError("old transfer archive survived transport initialization")
        cloud = text("bmgr", "backupnow", "--non-incremental", APP, timeout=180)
        print(f"ANDROID_BACKUP_CLOUD output={cloud!r}", flush=True)
        if f"Package {APP} with result: Backup is not allowed" not in cloud:
            raise RuntimeError("cloud backup did not refuse the application")
        if text("sh", "-c", f"test ! -e {cloud_path}; echo $?") != "0":
            raise RuntimeError("refused cloud backup created an application archive")
        text("bmgr", "enable", "false")
        if text("getenforce") != "Enforcing":
            raise RuntimeError("SELinux enforcement changed")
    finally:
        if installed and adb("uninstall", CONTROL).decode().strip() != "Success":
            raise RuntimeError("positive-control package did not retire")
        adb("unroot")
        adb("wait-for-device")
        if text("id", "-u") != "2000":
            raise RuntimeError("disposable Android shell did not drop root")
    print(f"ANDROID_BACKUP_NATIVE=pass domains=9 control=transferred-restored app=excluded-restored-empty cloud=refused selinux=Enforcing apk_sha256={args.apk_sha256} cleanup=fixtures-removed", flush=True)


if __name__ == "__main__":
    main()
