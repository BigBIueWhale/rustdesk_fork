#!/usr/bin/env python3
"""Acquire source-pinned bootstrap tools, then probe the sealed client offline."""

import argparse
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import resource
import ssl
import stat
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request


LIMIT = 64 * 1024 * 1024
DEPOT_URL = "https://chromium.googlesource.com/chromium/tools/depot_tools.git"
CLIENT_ENDPOINT = "https://chrome-infra-packages.appspot.com/client"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_file(path, size, digest):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid() and before.st_gid == os.getgid()
                and stat.S_IMODE(before.st_mode) == 0o400
                and 0 < size <= LIMIT and before.st_size == size,
                "bootstrap input authority differs")
        data = source.read(size + 1)
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) for key in fields),
                "bootstrap input identity changed")
    require(len(data) == size and hashlib.sha256(data).hexdigest() == digest,
            "bootstrap input bytes differ")
    return data


def discovery(args):
    record = json.loads(read_file("/discovery.json", args.discovery_size,
                                  args.discovery_sha256))
    require(record["format"] == "rustdesk-flutter-linux-engine-bootstrap-discovery-v1"
            and record["framework_revision"] == args.framework_revision
            and record["depot_tools_revision"] == args.depot_revision
            and record["cipd_linux_amd64_sha256"] == args.cipd_sha256
            and record["cipd_version"]["text"] == args.cipd_version + "\n"
            and record["complete_engine_closure"] is False
            and record["downloaded_code_executed"] is False,
            "source-bound discovery selections differ")
    for name in ("deps", "cipd_version", "cipd_publisher_digests", "standard_gclient"):
        body = record[name]["text"].encode("utf-8")
        require(len(body) == record[name]["bytes"]
                and hashlib.sha256(body).hexdigest() == record[name]["sha256"],
                "captured publisher metadata differs")
    require(re.findall(r"^linux-amd64\s+sha256\s+([0-9a-f]{64})$",
                       record["cipd_publisher_digests"]["text"], re.MULTILINE)
            == [args.cipd_sha256], "publisher client digest differs")
    return record


def output_file(root, name):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=root)
    return os.fdopen(fd, "wb")


def seal(output):
    output.flush()
    size = os.fstat(output.fileno()).st_size
    require(0 < size <= LIMIT, "bootstrap output exceeds bound")
    os.fchmod(output.fileno(), 0o400)
    os.fsync(output.fileno())
    return size


def git(work, *arguments, stdout=subprocess.PIPE):
    env = {"PATH": "/usr/bin:/bin", "HOME": work, "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ALLOW_PROTOCOL": "https"}
    command = ["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "-c", "credential.helper=",
               "-c", "http.followRedirects=false", "-c", "http.sslVerify=true",
               "-c", "fetch.fsckObjects=true", "-c", "transfer.fsckObjects=true",
               "-c", "core.autocrlf=false", *arguments]
    completed = subprocess.run(command, cwd=work, env=env, stdout=stdout,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    require(completed.returncode == 0,
            "pinned depot Git operation failed: "
            + completed.stderr[:4096].decode("utf-8", errors="replace"))
    require(len(completed.stderr) <= 65536, "Git diagnostics exceed bound")
    if stdout == subprocess.PIPE:
        require(len(completed.stdout) <= 65536, "Git result exceeds bound")
        return completed.stdout


class ClientRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, args):
        super().__init__()
        self.args = args
        self.count = 0

    def redirect_request(self, request, fp, code, msg, headers, new_url):
        target = urllib.parse.urlsplit(new_url)
        require(self.count == 0 and code == 302
                and request.full_url.startswith(CLIENT_ENDPOINT + "?")
                and headers.get("X-CIPD-Instance") == self.args.cipd_instance
                and target.scheme == "https" and target.netloc == "storage.googleapis.com"
                and target.path == "/chrome-infra-packages/store/SHA256/" + self.args.cipd_sha256
                and not target.fragment, "CIPD client redirect authority differs")
        self.count += 1
        return super().redirect_request(request, fp, code, msg, headers, new_url)


def acquire(args, record, root):
    require(not os.listdir(root), "bootstrap output is occupied")
    print("ENGINE_BOOTSTRAP_STAGE=fetch-exact-depot-commit", flush=True)
    # Fetch objects only: no checkout, hooks, gclient, vpython or downloaded code.
    with tempfile.TemporaryDirectory(prefix="depot-", dir="/tmp") as work:
        git(work, "init", "--bare", "--template=", work)
        git(work, "fetch", "--depth=1", "--no-tags", DEPOT_URL, args.depot_revision)
        require(git(work, "rev-parse", "FETCH_HEAD^{commit}").decode().strip()
                == args.depot_revision, "depot commit differs")
        require(git(work, "rev-parse", args.depot_revision + "^{tree}").decode().strip()
                == args.depot_tree, "depot source tree differs")
        git(work, "fsck", "--strict", "--no-reflogs")
        for path, role in (("cipd_client_version", "cipd_version"),
                           ("cipd_client_version.digests", "cipd_publisher_digests")):
            require(git(work, "show", args.depot_revision + ":" + path)
                    == record[role]["text"].encode(), "depot publisher metadata differs")
        with output_file(root, "depot-tools.tar") as output:
            git(work, "archive", "--format=tar", "--prefix=depot_tools/",
                args.depot_revision, stdout=output)
            archive_size = seal(output)
    archive_path = "/output/depot-tools.tar"
    with open(archive_path, "rb") as source:
        archive_sha256 = hashlib.file_digest(source, "sha256").hexdigest()
    names = set()
    with tarfile.open(archive_path, "r|") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(len(names) < 16384 and member.name not in names
                    and not path.is_absolute() and ".." not in path.parts
                    and path.parts and path.parts[0] == "depot_tools"
                    and (member.isfile() or member.isdir() or member.issym())
                    and 0 <= member.size <= LIMIT, "depot archive inventory differs")
            names.add(member.name)
    require("depot_tools/gclient.py" in names and "depot_tools/cipd" in names,
            "depot bootstrap source is incomplete")
    print("ENGINE_BOOTSTRAP_STAGE=fetch-publisher-digest-client", flush=True)
    redirect = ClientRedirect(args)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), redirect,
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    url = CLIENT_ENDPOINT + "?" + urllib.parse.urlencode(
        {"platform": "linux-amd64", "version": args.cipd_version})
    client_hash = hashlib.sha256()
    client_size = 0
    with opener.open(url, timeout=30) as response, output_file(root, "cipd-client") as output:
        require(response.status == 200 and redirect.count == 1, "CIPD response differs")
        while True:
            block = response.read(1048576)
            if not block:
                break
            client_size += len(block)
            require(client_size <= LIMIT, "CIPD client exceeds bound")
            client_hash.update(block)
            output.write(block)
        require(client_hash.hexdigest() == args.cipd_sha256, "CIPD publisher digest mismatch")
        require(seal(output) == client_size, "CIPD output size differs")
    manifest = {"format": "rustdesk-flutter-engine-bootstrap-tools-v1",
                "source_commit": args.source_commit,
                "framework_revision": args.framework_revision,
                "discovery_sha256": args.discovery_sha256,
                "depot_revision": args.depot_revision, "depot_tree": args.depot_tree,
                "depot_archive_sha256": archive_sha256, "depot_archive_size": archive_size,
                "cipd_version": args.cipd_version, "cipd_instance": args.cipd_instance,
                "cipd_sha256": args.cipd_sha256, "cipd_size": client_size,
                "complete_engine_closure": False, "acquisition_executed_downloaded_code": False}
    with output_file(root, "manifest.json") as output:
        output.write((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
        seal(output)
    os.fsync(root)
    print("ENGINE_BOOTSTRAP_TOOLS=pass depot=" + args.depot_revision
          + " cipd_sha256=" + args.cipd_sha256
          + " downloaded_code_executed=no complete_engine_closure=no", flush=True)


def probe(args, root):
    require(sorted(os.listdir(root)) == ["cipd-client", "depot-tools.tar", "manifest.json"],
            "sealed bootstrap inventory differs")
    require(0 < args.tools_manifest_size <= 16384, "bootstrap manifest exceeds bound")
    payload = read_file("/output/manifest.json", args.tools_manifest_size,
                        args.tools_manifest_sha256)
    manifest = json.loads(payload)
    require(manifest["format"] == "rustdesk-flutter-engine-bootstrap-tools-v1"
            and manifest["source_commit"] == args.tools_source_commit
            and manifest["framework_revision"] == args.framework_revision
            and manifest["discovery_sha256"] == args.discovery_sha256
            and manifest["depot_revision"] == args.depot_revision
            and manifest["depot_tree"] == args.depot_tree
            and manifest["cipd_version"] == args.cipd_version
            and manifest["cipd_instance"] == args.cipd_instance
            and manifest["cipd_sha256"] == args.cipd_sha256
            and manifest["complete_engine_closure"] is False,
            "bootstrap execution selections differ")
    read_file("/output/depot-tools.tar", manifest["depot_archive_size"],
              manifest["depot_archive_sha256"])
    client = read_file("/output/cipd-client", manifest["cipd_size"], args.cipd_sha256)
    require(client[:6] == b"\x7fELF\x02\x01" and client[18:20] == b"\x3e\x00",
            "CIPD client is not Linux x86_64 ELF")
    fd = os.open("/build/cipd", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
    with os.fdopen(fd, "wb") as output:
        output.write(client)
        output.flush()
        os.fsync(output.fileno())
    env = {"PATH": "/usr/bin:/bin", "HOME": "/build", "LC_ALL": "C"}
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    with open("/build/stdout", "xb") as stdout, open("/build/stderr", "xb") as stderr:
        completed = subprocess.run(["/build/cipd", "version"], cwd="/build", env=env,
                                   stdout=stdout, stderr=stderr, timeout=15, check=False)
    with open("/build/stdout", "rb") as source:
        result = source.read(4097)
    with open("/build/stderr", "rb") as source:
        errors = source.read(4097)
    require(completed.returncode == 0 and 0 < len(result) <= 4096 and not errors,
            "offline pinned CIPD version probe failed")
    # Artifact/platform authority is the independently pinned publisher digest
    # and ELF header, not incidental wording in a version command's output.
    print("ENGINE_BOOTSTRAP_CIPD_OFFLINE=pass network=none uid=" + str(os.getuid())
          + " sha256=" + args.cipd_sha256 + " version="
          + json.dumps(result.decode("utf-8")) + " complete_engine_closure=no", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-commit", "framework-revision", "discovery-sha256", "depot-revision",
                 "depot-tree", "cipd-version", "cipd-instance", "cipd-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--discovery-size", type=int, required=True)
    parser.add_argument("--phase", choices=("acquire", "probe"), required=True)
    parser.add_argument("--tools-source-commit")
    parser.add_argument("--tools-manifest-sha256")
    parser.add_argument("--tools-manifest-size", type=int)
    args = parser.parse_args()
    require(os.getuid() != 0 and os.getgid() != 0, "root bootstrap execution refused")
    for value in (args.source_commit, args.framework_revision, args.depot_revision, args.depot_tree):
        require(re.fullmatch("[0-9a-f]{40}", value), "malformed source pin")
    for value in (args.discovery_sha256, args.cipd_sha256):
        require(re.fullmatch("[0-9a-f]{64}", value), "malformed content pin")
    require(re.fullmatch("git_revision:[0-9a-f]{40}", args.cipd_version)
            and re.fullmatch("[A-Za-z0-9_-]{43}C", args.cipd_instance), "malformed CIPD pin")
    if args.phase == "probe":
        require(args.tools_source_commit is not None and args.tools_manifest_sha256 is not None
                and args.tools_manifest_size is not None
                and re.fullmatch("[0-9a-f]{40}", args.tools_source_commit)
                and re.fullmatch("[0-9a-f]{64}", args.tools_manifest_sha256),
                "independent bootstrap artifact pins are required")
    else:
        require(args.tools_source_commit is None and args.tools_manifest_sha256 is None
                and args.tools_manifest_size is None, "artifact pins are probe-only")
    # Bound generated archives/pack files and probe output at the filesystem sink.
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))
    record = discovery(args)
    root = os.open("/output", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(root)
        require(metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid()
                and stat.S_IMODE(metadata.st_mode) == 0o700, "bootstrap output authority differs")
        if args.phase == "acquire":
            acquire(args, record, root)
        else:
            probe(args, root)
    finally:
        os.close(root)


if __name__ == "__main__":
    main()
