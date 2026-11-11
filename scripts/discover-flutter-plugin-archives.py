#!/usr/bin/env python3
"""Authenticate the fourteen changed Pub inputs without publishing or executing them.

Versions and observed hashes come from the retained 2aa4157d migration lock
(SHA-256 e03728db829b4d7e0fd100f3b3e9846caad0a2dcbeecba7ad142bb19c2972279).
Each must match publisher metadata and bytes independently served by CFUG.
"""

import argparse
import concurrent.futures
import copy
import gzip
import hashlib
import io
import json
import os
import re
import ssl
import tarfile
import urllib.parse
import urllib.request


PACKAGES = (
    ("file_selector", "1.1.0", "bd15e43e9268db636b53eeaca9f56324d1622af30e5c34d6e267649758c84d9a"),
    ("file_selector_android", "0.5.2+11", "d670cd0ce77a2e785b18d8b4d0a8d6a222d6a813ec9b7ddf2790a1b4fb6fa92c"),
    ("file_selector_ios", "0.5.3+7", "5b42ec0ef7626124b4624ea244341e9df780406793c204e89fa68a2e71af115c"),
    ("file_selector_linux", "0.9.4+1", "da76400e7872ce7637ffdce12749ec24169c25f6195c28372208e65a24bcd2ab"),
    ("file_selector_macos", "0.9.5+2", "d785431f1910aac8a50e5c492cae912320158030a88703c67b9ef7f1f96fd7ba"),
    ("file_selector_platform_interface", "2.7.0", "35e0bd61ebcdb91a3505813b055b09b79dfdc7d0aee9c09a7ba59ae4bb13dc85"),
    ("file_selector_web", "0.9.5", "73181fbc5257776d8ecaa6a94ab3c8e920ad143b9132a6d984a9271dfc6928d3"),
    ("file_selector_windows", "0.9.3+6", "fbefc5fb92c6d3cbe8d284a2cd971b593bb07d2cd6da8557b81a862250b4acec"),
    ("sqflite_android", "2.4.6", "e75917dbfe721e6938fc4ff18d3e61549f17cf88a4eba189e2b270290d0c9be3"),
    ("sqflite_darwin", "2.4.6", "6ef57df819b502e306d0b58ba6cb614952d294b825c003feba3c47764c20a825"),
    ("sqflite_platform_interface", "2.4.4", "7bfeb7f9e09761147e8e3a4ff3f1d8979fe46a736f03f3805f572599ade69308"),
    ("sqflite", "2.4.6", "ed2ff27268e051bde8f0848d6ab86e0f6c01566484d3d358a46ff5e842b36216"),
    ("sqflite_common", "2.5.17", "35a65713b6695fbc5f3596921c8af1dfe767942c96b6c5c80a739b16a10d47eb"),
    ("synchronized", "3.6.1+1", "a77637ebe1460f3b48cac89a790d2eb634f0a8593cab0d3f340c6db174ba9b94"),
)
ORIGINS = ("https://pub.dev", "https://pub.flutter-io.cn")
METADATA_LIMIT = 256 * 1024
ARCHIVE_LIMIT = 16 * 1024 * 1024
EXPANDED_LIMIT = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate metadata key")
        result[key] = value
    return result


def metadata(data, origin, name, version, sha256):
    require(0 < len(data) <= METADATA_LIMIT, "metadata size differs")
    value = json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, "nonfinite JSON"))
    require(isinstance(value, dict), "metadata is not an object")
    require(value.get("version") == version, "metadata version differs")
    require(value.get("retracted", False) is False, "package is retracted")
    require(value.get("archive_sha256") == sha256, "publisher archive hash differs")
    pubspec = value.get("pubspec")
    require(isinstance(pubspec, dict) and pubspec.get("name") == name
            and pubspec.get("version") == version, "package identity differs")
    url = value.get("archive_url")
    require(isinstance(url, str) and urllib.parse.unquote(url)
            == f"{origin}/api/archives/{name}-{version}.tar.gz", "archive URL differs")
    return value


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(opener, url, limit):
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.pub.v2+json", "Accept-Encoding": "identity",
        "User-Agent": "rustdesk-fork-plugin-provenance/1",
    })
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, "response URL/status differs")
        require(response.headers.get("Content-Encoding") in (None, "", "identity"),
                "response is transformed")
        length = response.headers.get("Content-Length")
        if length is not None:
            require(re.fullmatch(r"[1-9][0-9]{0,8}", length) is not None
                    and int(length) <= limit, "declared response size differs")
        data = response.read(limit + 1)
        require(0 < len(data) <= limit, "response exceeds its bound")
        require(length is None or len(data) == int(length), "response is incomplete")
    return data


def inspect_archive(data, sha256):
    require(digest(data) == sha256, "archive bytes differ from publisher/lock")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(EXPANDED_LIMIT + 1)
        require(len(expanded) <= EXPANDED_LIMIT, "expanded archive exceeds its bound")
    files = {}
    names = set()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for entry in archive:
            require(len(names) < 10000, "archive entry bound exceeded")
            name = entry.name
            require(name and name not in names and not name.startswith("/")
                    and all(part not in ("", ".", "..") for part in name.split("/"))
                    and "\\" not in name, "archive path is ambiguous")
            require(entry.isfile() or entry.isdir(), "archive contains a link or special entry")
            names.add(name)
            if name in ("pubspec.yaml", "android/build.gradle", "android/build.gradle.kts"):
                require(entry.isfile() and 0 < entry.size <= 64 * 1024,
                        "package manifest/build metadata exceeds its bound")
                with archive.extractfile(entry) as source:
                    files[name] = source.read().decode("utf-8")
    require("pubspec.yaml" in files, "archive lacks package manifest")
    return {"entries": len(names), "expanded_bytes": len(expanded), "files": files}


def discover(package):
    name, version, sha256 = package
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context), NoRedirects())
    sources = []
    archive_size = None
    structure = None
    pubspec = None
    for origin in ORIGINS:
        url = f"{origin}/api/packages/{name}/versions/{urllib.parse.quote(version, safe='')}"
        raw = fetch(opener, url, METADATA_LIMIT)
        value = metadata(raw, origin, name, version, sha256)
        data = fetch(opener, value["archive_url"], ARCHIVE_LIMIT)
        require(digest(data) == sha256, f"{name}: archive hash disagrees at {origin}")
        if archive_size is None:
            archive_size = len(data)
            structure = inspect_archive(data, sha256)
            pubspec = value["pubspec"]
        require(len(data) == archive_size and value["pubspec"] == pubspec,
                f"{name}: publisher/mirror content differs")
        sources.append({"metadata_url": url, "metadata_sha256": digest(raw),
                        "metadata": value, "archive_url": value["archive_url"],
                        "archive_size": len(data), "archive_sha256": digest(data)})
    result = {"name": name, "version": version, "sha256": sha256,
              "size": archive_size, "sources": sources, "archive": structure}
    return result


def self_test():
    name, version, sha256 = PACKAGES[0]
    good = {"version": version, "archive_sha256": sha256,
            "archive_url": f"{ORIGINS[0]}/api/archives/{name}-{version}.tar.gz",
            "pubspec": {"name": name, "version": version}}
    metadata(json.dumps(good).encode(), ORIGINS[0], name, version, sha256)
    cases = []
    for key, value in (("version", "0.0.0"), ("retracted", True),
                       ("archive_sha256", "0" * 64), ("pubspec", {}),
                       ("archive_url", "https://example.invalid/archive.tar.gz")):
        bad = copy.deepcopy(good)
        bad[key] = value
        cases.append(json.dumps(bad).encode())
    cases.append(b'{"version":"1","version":"2"}')
    for case in cases:
        try:
            metadata(case, ORIGINS[0], name, version, sha256)
        except ValueError:
            continue
        raise ValueError("invalid package metadata accepted")
    try:
        inspect_archive(b"changed publisher bytes", sha256)
    except ValueError:
        pass
    else:
        raise ValueError("changed archive accepted")
    print(f"FLUTTER_PLUGIN_ARCHIVE_CONTROLS=pass metadata_refused={len(cases)} changed_archive_refused=1")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    require(os.geteuid() != 0 and os.getegid() != 0, "discovery refuses root")
    if args.self_test:
        self_test()
        return
    count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for result in pool.map(discover, PACKAGES):
            print("FLUTTER_PLUGIN_ARCHIVE=" + json.dumps(
                result, sort_keys=True, separators=(",", ":")), flush=True)
            count += 1
    print("FLUTTER_PLUGIN_ARCHIVES=pass packages=" + str(count)
          + " cache_published=false code_executed=false", flush=True)


if __name__ == "__main__":
    main()
