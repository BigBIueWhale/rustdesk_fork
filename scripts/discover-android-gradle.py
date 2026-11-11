#!/usr/bin/env python3
"""Read exact candidate Gradle asset metadata; never download or execute code."""

import argparse
import copy
import hashlib
import json
import os
import re
import ssl
import urllib.request


METADATA_LIMIT = 256 * 1024
ARCHIVE_LIMIT = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate metadata key")
        result[key] = value
    return result


def asset_identity(data, version, digest):
    require(0 < len(data) <= METADATA_LIMIT, "metadata size differs")
    release = json.loads(data, object_pairs_hook=unique_object,
                         parse_constant=lambda value: require(False, "nonfinite JSON"))
    require(isinstance(release, dict), "release is not an object")
    require(release.get("tag_name") == "v" + version, "release tag differs")
    require(release.get("draft") is False and release.get("prerelease") is False,
            "release is not published stable metadata")
    assets = release.get("assets")
    require(isinstance(assets, list) and 0 < len(assets) <= 32,
            "release asset inventory differs")
    require(all(isinstance(asset, dict) for asset in assets), "asset is not an object")
    name = f"gradle-{version}-bin.zip"
    matches = [asset for asset in assets if asset.get("name") == name]
    require(len(matches) == 1, "exact binary distribution is absent or duplicated")
    asset = matches[0]
    url = f"https://github.com/gradle/gradle-distributions/releases/download/v{version}/{name}"
    require(asset.get("browser_download_url") == url, "asset URL differs")
    require(asset.get("state") == "uploaded", "asset is not fully uploaded")
    require(asset.get("digest") == "sha256:" + digest, "asset digest differs from reviewed pin")
    size = asset.get("size")
    require(type(size) is int and 0 < size <= ARCHIVE_LIMIT, "asset size is not bounded integer")
    identity = asset.get("id")
    require(type(identity) is int and identity > 0, "asset identity differs")
    return {"name": name, "url": url, "size": size, "sha256": digest,
            "asset_id": identity, "state": "uploaded"}


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def discover(version, digest):
    url = f"https://api.github.com/repos/gradle/gradle-distributions/releases/tags/v{version}"
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context), NoRedirects())
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "rustdesk-fork-android-gradle-discovery/1",
    })
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, "metadata response differs")
        require(response.headers.get("Content-Encoding") in (None, "", "identity"),
                "metadata response is transformed")
        length = response.headers.get("Content-Length")
        if length is not None:
            require(re.fullmatch(r"[1-9][0-9]{0,8}", length) is not None
                    and int(length) <= METADATA_LIMIT, "metadata declared size differs")
        data = response.read(METADATA_LIMIT + 1)
        require(length is None or len(data) == int(length), "metadata response is incomplete")
    asset = asset_identity(data, version, digest)
    print("ANDROID_GRADLE_DISCOVERY=" + json.dumps({
        "version": version, "asset": asset, "metadata_url": url,
        "metadata_bytes": len(data), "metadata_sha256": hashlib.sha256(data).hexdigest(),
        "publisher_checksum_url": "https://gradle.org/release-checksums/",
        "archive_downloaded": False, "inputs_published": False,
    }, sort_keys=True, separators=(",", ":")))


def self_test(version, digest):
    asset = {"name": f"gradle-{version}-bin.zip", "state": "uploaded", "size": 1024,
             "id": 1, "digest": "sha256:" + digest,
             "browser_download_url": f"https://github.com/gradle/gradle-distributions/releases/download/v{version}/gradle-{version}-bin.zip"}
    release = {"tag_name": "v" + version, "draft": False, "prerelease": False, "assets": [asset]}
    require(asset_identity(json.dumps(release).encode(), version, digest)["size"] == 1024,
            "positive metadata control failed")
    rejected = []
    for key, value in (("tag_name", "v0.0.0"), ("draft", True), ("prerelease", True),
                       ("assets", []), ("assets", [asset, asset])):
        candidate = copy.deepcopy(release)
        candidate[key] = value
        rejected.append(json.dumps(candidate).encode())
    for key, value in (("size", True), ("size", ARCHIVE_LIMIT + 1), ("digest", "sha256:" + "0" * 64),
                       ("state", "new"), ("browser_download_url", "https://example.invalid/input")):
        candidate = copy.deepcopy(release)
        candidate["assets"][0][key] = value
        rejected.append(json.dumps(candidate).encode())
    rejected.append(b'{"tag_name":"v0","tag_name":"v1"}')
    for data in rejected:
        try:
            asset_identity(data, version, digest)
        except ValueError:
            continue
        raise ValueError("malformed metadata control was accepted")
    print(f"ANDROID_GRADLE_DISCOVERY_CONTROLS=pass accepted=1 refused={len(rejected)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    require(os.geteuid() != 0 and os.getegid() != 0, "discovery refuses root")
    require(re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", args.version) is not None,
            "candidate version is not exact stable version")
    require(re.fullmatch(r"[0-9a-f]{64}", args.sha256) is not None, "candidate SHA-256 differs")
    if args.self_test:
        self_test(args.version, args.sha256)
    else:
        discover(args.version, args.sha256)


if __name__ == "__main__":
    main()
