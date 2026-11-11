#!/usr/bin/env python3
"""Cross-check the candidate Build Tools pin before its first archive acquisition."""

import argparse
import copy
import hashlib
import json
import os
import re
import ssl
import urllib.request
from xml.etree import ElementTree


PUBLISHER = "https://dl.google.com/android/repository/repository2-3.xml"
INDEPENDENT = "https://raw.githubusercontent.com/f-droid/android-sdk-transparency-log/master/checksums.json"
ARCHIVE = "https://dl.google.com/android/repository/build-tools_r35_linux.zip"
LIMIT = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate checksum key")
        result[key] = value
    return result


def verify(publisher, independent, size, sha1, sha256):
    require(0 < len(publisher) <= LIMIT and 0 < len(independent) <= LIMIT,
            "metadata size differs")
    require(b"<!DOCTYPE" not in publisher and b"<!ENTITY" not in publisher,
            "repository metadata contains a document declaration")
    root = ElementTree.fromstring(publisher)
    for element in root.iter():
        element.tag = element.tag.rsplit("}", 1)[-1]
    packages = root.findall("./remotePackage[@path='build-tools;35.0.0']")
    require(len(packages) == 1, "exact Build Tools package is absent or duplicated")
    package = packages[0]
    require(package.get("obsolete") is None, "Build Tools package is obsolete")
    revisions = package.findall("./revision")
    require(len(revisions) == 1 and [(e.tag, e.text) for e in revisions[0]] ==
            [("major", "35"), ("minor", "0"), ("micro", "0")], "package revision differs")
    channels = package.findall("./channelRef")
    require(len(channels) == 1 and channels[0].get("ref") == "channel-0",
            "package is not stable")
    archives = [a for a in package.findall("./archives/archive")
                if [e.text for e in a.findall("./host-os")] == ["linux"]]
    require(len(archives) == 1, "Linux archive is absent or duplicated")
    complete = archives[0].findall("./complete")
    require(len(complete) == 1, "complete archive record differs")
    expected = {"size": str(size), "url": "build-tools_r35_linux.zip", "checksum": sha1}
    require(len(complete[0]) == len(expected), "archive record inventory differs")
    for key, value in expected.items():
        values = complete[0].findall("./" + key)
        require(len(values) == 1 and values[0].text == value, "archive " + key + " differs")
    require(complete[0].find("./checksum").get("type") == "sha1", "checksum type differs")
    checksums = json.loads(independent, object_pairs_hook=unique_object,
                           parse_constant=lambda value: require(False, "nonfinite checksum JSON"))
    require(isinstance(checksums, dict), "independent checksums are not an object")
    records = checksums.get(ARCHIVE)
    require(isinstance(records, list) and len(records) == 1 and isinstance(records[0], dict),
            "independent archive record is absent or ambiguous")
    require(records[0].get("sha256") == sha256 and records[0].get("sha1") == sha1,
            "independent checksums differ from reviewed pins")
    return {"package": "build-tools;35.0.0", "url": ARCHIVE, "size": size,
            "publisher_sha1": sha1, "independent_sha256": sha256}


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=context), NoRedirects())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity",
                                                  "User-Agent": "rustdesk-build-tools-provenance/1"})
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, "metadata response differs")
        require(response.headers.get("Content-Encoding") in (None, "", "identity"),
                "metadata encoding differs")
        length = response.headers.get("Content-Length")
        require(length is None or (re.fullmatch(r"[1-9][0-9]{0,8}", length) is not None
                                   and int(length) <= LIMIT), "declared metadata size differs")
        data = response.read(LIMIT + 1)
        require(0 < len(data) <= LIMIT and (length is None or len(data) == int(length)),
                "received metadata size differs")
        return data


def self_test(size, sha1, sha256):
    package = ("<remotePackage path='build-tools;35.0.0'><revision><major>35</major>"
               "<minor>0</minor><micro>0</micro></revision><channelRef ref='channel-0'/>"
               "<archives><archive><host-os>linux</host-os><complete>"
               f"<size>{size}</size><checksum type='sha1'>{sha1}</checksum>"
               "<url>build-tools_r35_linux.zip</url></complete></archive></archives></remotePackage>")
    publisher = ("<repository>" + package + "</repository>").encode()
    independent = json.dumps({ARCHIVE: [{"sha1": sha1, "sha256": sha256}]}).encode()
    verify(publisher, independent, size, sha1, sha256)
    rejected = [(publisher.replace(old, new), independent) for old, new in (
        (b"<major>35</major>", b"<major>36</major>"),
        (b"channel-0", b"channel-1"),
        (str(size).encode(), b"1"),
        (sha1.encode(), b"0" * 40),
        (b"build-tools_r35_linux.zip", b"../other.zip"),
        (b"</repository>", package.encode() + b"</repository>"),
    )]
    duplicate_archive = ElementTree.fromstring(publisher)
    archives = duplicate_archive.find("./remotePackage/archives")
    archives.append(copy.deepcopy(archives[0]))
    rejected.append((ElementTree.tostring(duplicate_archive), independent))
    rejected.extend((publisher, data) for data in (
        b"{}", independent.replace(sha256.encode(), b"0" * 64),
        independent.replace(sha1.encode(), b"0" * 40), b'{"x":1,"x":2}',
    ))
    for first, second in rejected:
        try:
            verify(first, second, size, sha1, sha256)
        except ValueError:
            continue
        raise ValueError("malformed Build Tools metadata was accepted")
    print(f"ANDROID_BUILD_TOOLS_METADATA_CONTROLS=pass accepted=1 refused={len(rejected)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", required=True, type=int)
    parser.add_argument("--sha1", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    require(os.geteuid() != 0 and os.getegid() != 0, "metadata verification refuses root")
    require(0 < args.size <= 128 * 1024 * 1024, "archive size is out of bounds")
    require(re.fullmatch(r"[0-9a-f]{40}", args.sha1) is not None, "SHA-1 pin differs")
    require(re.fullmatch(r"[0-9a-f]{64}", args.sha256) is not None, "SHA-256 pin differs")
    if args.self_test:
        self_test(args.size, args.sha1, args.sha256)
        return
    publisher, independent = fetch(PUBLISHER), fetch(INDEPENDENT)
    result = verify(publisher, independent, args.size, args.sha1, args.sha256)
    result["metadata"] = [{"url": url, "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()}
                          for url, data in ((PUBLISHER, publisher), (INDEPENDENT, independent))]
    result["archive_downloaded"] = False
    print("ANDROID_BUILD_TOOLS_METADATA=" + json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
