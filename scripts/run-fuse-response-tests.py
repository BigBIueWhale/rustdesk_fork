#!/usr/bin/env python3
"""Execute the root clipboard dispatcher with the real clipboard library on Linux."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

PACKAGE = "rustdesk-fuse-response"
BASELINE = "scripts/fixtures/clipboard-file-before-response-bootstrap.rs"
BASELINE_SHA = "9f009cf5a6658afa538ff7ce2e5ac8f6350f87d690e7dfd0af90867dfd6cd53c"
INPUTS = ("Cargo.lock", "src/clipboard_file.rs", "src/clipboard.rs", BASELINE,
          "libs/clipboard/Cargo.toml", "libs/clipboard/src/lib.rs",
          "libs/clipboard/src/platform/unix/fuse/mod.rs",
          "libs/clipboard/src/platform/unix/fuse/cs.rs",
          "scripts/test-fuse-response-dispatch.rs", "scripts/run-fuse-response-tests.py")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if len(sys.argv) != 3 or os.geteuid() != 1000 or os.getegid() != 1000:
        raise ValueError("FUSE dispatch tests require the isolated compiler principal")
    repo = Path(sys.argv[1]).resolve(strict=True)
    config = ["--config", str(Path(sys.argv[2]).resolve(strict=True))]
    inputs = {name: (repo / name).read_bytes() for name in INPUTS}
    baseline = inputs[BASELINE].split(b"\n", 2)[2]
    if digest(baseline) != BASELINE_SHA:
        raise ValueError("prior production FUSE dispatcher differs")
    side_source = inputs["src/clipboard.rs"].decode()
    begin = "#[derive(PartialEq, Eq, Clone, Copy)]\npub enum ClipboardSide {"
    end = "\nimpl ClipboardSide {"
    if side_source.count(begin) != 1 or side_source.count(end) != 1:
        raise ValueError("production clipboard side declaration differs")
    side = side_source[side_source.index(begin):side_source.index(end)]
    root_lock = {(p["name"], p["version"]): p
                 for p in tomllib.loads(inputs["Cargo.lock"].decode())["package"] if "source" in p}
    environment = {k: v for k, v in os.environ.items() if not k.startswith("RD_FUSE_DISPATCH_")}
    environment.update(CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_BUILD_JOBS="1")

    with tempfile.TemporaryDirectory(prefix="fuse-response-", dir="/tmp") as temporary:
        root = Path(temporary)
        observations = root / "observations"
        observations.touch(mode=0o600, exist_ok=False)
        environment["RD_FUSE_DISPATCH_OBSERVATIONS"] = str(observations)
        (root / "Cargo.toml").write_text(
            f'[package]\nname="{PACKAGE}"\nversion="0.0.0"\nedition="2021"\n'
            '[features]\ndefault=["unix-file-copy-paste"]\nunix-file-copy-paste=[]\n'
            '[dependencies]\nlazy_static="=1.5.0"\n'
            f'clipboard={{path="{repo / "libs/clipboard"}",features=["unix-file-copy-paste"]}}\n'
            f'hbb_common={{path="{repo / "libs/hbb_common"}"}}\n'
            '[lib]\nname="rustdesk_fuse_response"\npath="lib.rs"\n')
        (root / "lib.rs").write_text(
            'mod clipboard { pub use ::clipboard::*;\n' + side + '\n'
            'pub struct ClipboardContext;\n'
            'pub fn update_clipboard_files(_: Vec<String>, _: ClipboardSide) { panic!("unexpected native clipboard publication"); }\n'
            'pub fn try_empty_clipboard_files(_: ClipboardSide, _: i32) { panic!("unexpected clipboard empty"); }\n}\n'
            f'#[path="{repo / "src/clipboard_file.rs"}"] mod clipboard_file;\n'
            'mod before { use ::clipboard::ClipboardFile; use hbb_common::message_proto::*; '
            'use crate::clipboard_file::clip_2_msg;\n'
            f'include!("{repo / BASELINE}"); }}\n'
            f'#[path="{repo / "scripts/test-fuse-response-dispatch.rs"}"] mod dispatch_tests;\n')

        def run(command, timeout):
            result = subprocess.run(command, cwd=root, env=environment, timeout=timeout,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if len(result.stdout) > 2 * 1024 * 1024:
                raise ValueError("FUSE dispatch output exceeds its bound")
            print(result.stdout.decode(errors="replace"), end="", flush=True)
            if result.returncode:
                raise ValueError(f"FUSE dispatch command failed: {result.returncode}")
            return result.stdout

        run(["cargo", "generate-lockfile", "--offline", *config], 30)
        lock = (root / "Cargo.lock").read_bytes()
        for p in tomllib.loads(lock.decode())["package"]:
            if "source" not in p:
                if p["name"] not in (PACKAGE, "clipboard", "hbb_common", "pake"):
                    raise ValueError("unrecognized FUSE dispatch path dependency")
                continue
            expected = root_lock.get((p["name"], p["version"]))
            if expected is None or any(p.get(k) != expected.get(k) for k in ("source", "checksum")):
                raise ValueError("FUSE dispatch dependency differs from the root lock")

        artifacts = []
        for package, manifest, name, expected_tests, filters in (
            (PACKAGE, root / "Cargo.toml", "rustdesk_fuse_response", 7, []),
            ("clipboard", repo / "libs/clipboard/Cargo.toml", "clipboard", 18,
             ["platform::unix::fuse::cs::fuse_test::"]),
        ):
            output = run(["cargo", "test", "--offline", "--locked", "-p", package,
                          "--features", "unix-file-copy-paste", "--lib", "--no-run",
                          "--message-format=json", *config], 180)
            messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
            candidates = [Path(m["executable"]) for m in messages
                          if m.get("reason") == "compiler-artifact" and m.get("executable")
                          and m.get("manifest_path") == str(manifest)
                          and m.get("target", {}).get("name") == name
                          and m.get("target", {}).get("kind") == ["lib"]
                          and m.get("profile", {}).get("test") is True]
            if len(candidates) != 1 or candidates[0].is_symlink() or not candidates[0].is_file():
                raise ValueError("FUSE dispatch artifact is absent or ambiguous")
            artifact = candidates[0]
            before = digest(artifact.read_bytes())
            output = run([str(artifact), *filters, "--test-threads=1", "--color", "never"], 30)
            summaries = re.findall(rb"^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+s$", output, re.M)
            if len(summaries) != 1 or int(summaries[0]) != expected_tests:
                raise ValueError("FUSE dispatch test count differs")
            if digest(artifact.read_bytes()) != before:
                raise ValueError("FUSE dispatch artifact changed")
            artifacts.append({"package": package, "sha256": before, "tests": expected_tests})

        lines = observations.read_text().splitlines()
        expected = set()
        for case in ("reply-client", "reply-host", "format-client", "format-host",
                     "failed-format-client", "failed-format-host"):
            for implementation in ("before", "current"):
                client = implementation == "before" or case == "format-client"
                host = implementation == "current" and case == "format-host"
                expected.add(f"FUSE_DISPATCH_OBSERVATION=case={case} implementation={implementation} client_dir={str(client).lower()} host_dir={str(host).lower()} context=absent cleanup=removed")
        if len(lines) != 12 or set(lines) != expected:
            raise ValueError("native FUSE dispatch observations differ")
        for line in sorted(lines):
            print(line)
        if (root / "Cargo.lock").read_bytes() != lock:
            raise ValueError("FUSE dispatch lock changed")
        for name, data in inputs.items():
            if (repo / name).read_bytes() != data:
                raise ValueError(f"FUSE dispatch source changed: {name}")
            print(f"FUSE_DISPATCH_INPUT=pass path={name} bytes={len(data)} sha256={digest(data)}")
        print("FUSE_DISPATCH_ARTIFACT=pass " + json.dumps({
            "tests": 25, "groups": 2, "comparisons": 6, "observations": 12,
            "baseline_module_sha256": BASELINE_SHA, "side_sha256": digest(side.encode()),
            "lock_sha256": digest(lock), "artifacts": artifacts,
            "scope": "production-root-dispatch-and-native-fuse-routing",
            "clipboard_publication": "unexercised-panicking-facade", "mounted_fuse": False,
        }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"FUSE dispatch native test failed: {error}") from error
