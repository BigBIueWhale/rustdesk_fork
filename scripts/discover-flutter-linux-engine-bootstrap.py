#!/usr/bin/env python3
"""Authenticate engine bootstrap metadata; never execute or promote fetched code."""

import argparse
import base64
import hashlib
import json
import os
import re
import ssl
import stat
import tarfile
import urllib.request


DEPS_SHA256 = "495c99dafa4dab8e538c10679ef56242defa6d7f7c81aca5849057a582be12d5"
DEPOT_REVISION = "580b4ff3f5cd0dcaa2eacda28cefe0f45320e8f7"
CIPD_VERSION = "git_revision:200dbdf0e967e81388359d3f85f095d39b35db67"
CIPD_SHA256 = "341314febc2b0e447914a20a3b845eb5052957451b30ed27b6221e8ddf9e0ed0"
METADATA_LIMIT = 131072
OUTPUT_LIMIT = 262144


def require(condition, message):
    if not condition:
        raise ValueError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):
        raise ValueError("bootstrap metadata redirect refused")


def fetch(url, encoded=False):
    print("ENGINE_BOOTSTRAP_STAGE=metadata url=" + url, flush=True)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(url, timeout=30) as response:
        require(response.status == 200 and response.url == url,
                "metadata response identity differs")
        data = response.read(METADATA_LIMIT + 1)
        require(len(data) <= METADATA_LIMIT, "metadata exceeds bound")
    if encoded:
        data = base64.b64decode(data, validate=True)
    return {"url": url, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "text": data.decode("utf-8", errors="strict")}


def read_sdk(expected_size, expected_sha256):
    print("ENGINE_BOOTSTRAP_STAGE=authenticate-sdk", flush=True)
    fd = os.open("/sdk.tar.xz", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.getuid() and before.st_gid == os.getgid()
                and stat.S_IMODE(before.st_mode) == 0o400
                and before.st_size == expected_size, "SDK metadata differs")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = source.read(1048576)
            if not block:
                break
            total += len(block)
            require(total <= expected_size, "SDK exceeds size pin")
            digest.update(block)
        require(total == expected_size and digest.hexdigest() == expected_sha256,
                "SDK bytes differ from publisher-backed pin")
        source.seek(0)
        deps = None
        with tarfile.open(fileobj=source, mode="r|xz") as archive:
            for count, member in enumerate(archive):
                require(count < 524288, "SDK inventory exceeds bound")
                if member.name != "flutter/DEPS":
                    continue
                require(member.isfile() and 0 < member.size <= METADATA_LIMIT,
                        "SDK DEPS is not bounded regular data")
                with archive.extractfile(member) as content:
                    deps = content.read(METADATA_LIMIT + 1)
                require(len(deps) == member.size, "SDK DEPS length differs")
                break
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, field) == getattr(after, field) for field in fields),
                "SDK identity or metadata changed")
    require(deps is not None and hashlib.sha256(deps).hexdigest() == DEPS_SHA256,
            "SDK root DEPS differs")
    return deps.decode("utf-8", errors="strict")


def publish(record):
    payload = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8")
    require(len(payload) <= OUTPUT_LIMIT, "discovery record exceeds bound")
    root = os.open("/output", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(root)
        require(metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid()
                and stat.S_IMODE(metadata.st_mode) == 0o700,
                "discovery output authority differs")
        require(not os.listdir(root), "discovery output is occupied")
        fd = os.open("discovery.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600, dir_fd=root)
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fsync(output.fileno())
        os.fsync(root)
    finally:
        os.close(root)
    print("ENGINE_BOOTSTRAP_DISCOVERY=pass complete_engine_closure=no "
          "downloaded_code_executed=no bytes={} sha256={}".format(
              len(payload), hashlib.sha256(payload).hexdigest()), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--framework-revision", required=True)
    parser.add_argument("--sdk-sha256", required=True)
    parser.add_argument("--sdk-size", required=True, type=int)
    args = parser.parse_args()
    require(os.getuid() != 0 and os.getgid() != 0, "root discovery refused")
    require(re.fullmatch("[0-9a-f]{64}", DEPS_SHA256)
            and re.fullmatch("[0-9a-f]{64}", CIPD_SHA256)
            and re.fullmatch("[0-9a-f]{40}", DEPOT_REVISION),
            "malformed bootstrap metadata constant")
    for revision in (args.source_commit, args.framework_revision):
        require(re.fullmatch("[0-9a-f]{40}", revision), "malformed revision")
    require(re.fullmatch("[0-9a-f]{64}", args.sdk_sha256) and args.sdk_size > 0,
            "malformed SDK pin")
    deps = read_sdk(args.sdk_size, args.sdk_sha256)
    upstream = fetch("https://raw.githubusercontent.com/flutter/flutter/"
                     + args.framework_revision + "/DEPS")
    require(upstream["text"] == deps and upstream["sha256"] == DEPS_SHA256,
            "upstream and publisher-backed SDK dependency graphs differ")
    depot_entry = (r"'engine/src/flutter/third_party/depot_tools':\s*"
                   r"Var\('chromium_git'\)\s*\+\s*'/chromium/tools/depot_tools\.git'"
                   r"\s*\+\s*'@'\s*\+\s*'([0-9a-f]{40})'")
    require(re.findall(depot_entry, deps)
            == [DEPOT_REVISION], "root graph depot-tools revision differs")
    depot_url = ("https://chromium.googlesource.com/chromium/tools/depot_tools/+/"
                 + DEPOT_REVISION + "/")
    version = fetch(depot_url + "cipd_client_version?format=TEXT", encoded=True)
    digests = fetch(depot_url + "cipd_client_version.digests?format=TEXT", encoded=True)
    require(version["text"].strip() == CIPD_VERSION, "CIPD version differs")
    require(re.findall(r"^linux-amd64\s+sha256\s+([0-9a-f]{64})$",
                       digests["text"], flags=re.MULTILINE) == [CIPD_SHA256],
            "publisher Linux CIPD client digest differs")
    standard = fetch("https://raw.githubusercontent.com/flutter/flutter/"
                     + args.framework_revision + "/engine/scripts/standard.gclient")
    publish({"format": "rustdesk-flutter-linux-engine-bootstrap-discovery-v1",
             "source_commit": args.source_commit,
             "framework_revision": args.framework_revision,
             "sdk_sha256": args.sdk_sha256, "sdk_size": args.sdk_size,
             "deps": upstream, "depot_tools_revision": DEPOT_REVISION,
             "cipd_version": version, "cipd_publisher_digests": digests,
             "cipd_linux_amd64_sha256": CIPD_SHA256,
             "standard_gclient": standard, "complete_engine_closure": False,
             "downloaded_code_executed": False})


if __name__ == "__main__":
    main()
