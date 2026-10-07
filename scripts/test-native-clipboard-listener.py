#!/usr/bin/env python3
"""Run the exact desktop listener and pinned clipboard-master against private Xvfb.

Only the error callback is historical in the controlled A/B. This is a Linux
component lifecycle test, not whole-app, Windows/macOS, or display-delay evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time
import tomllib


ROOT = Path("/work")
BUILD = Path("/build/clipboard")
PACKAGE = "rustdesk-clipboard-listener-native"


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(arguments, environment, timeout=90):
    result = subprocess.run(arguments, cwd=BUILD, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(len(result.stdout) + len(result.stderr) <= 2 * 1024 * 1024,
            "compiler output exceeded its bound")
    if result.returncode != 0:
        print(result.stdout[:32768].decode("utf-8", errors="replace"), flush=True)
        print(result.stderr[:32768].decode("utf-8", errors="replace"), flush=True)
    require(result.returncode == 0, f"compiler command failed: {arguments[:2]}")
    return result.stdout


def inputs():
    records = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    locked = {(item["name"], item["version"]): item for item in records if "source" in item}
    manifest = ROOT / "scripts/clipboard-listener-inputs.txt"
    entries = [line.split() for line in manifest.read_text().splitlines() if not line.startswith("#")]
    require(len(entries) == 86 and len({entry[0] for entry in entries}) == 86,
            "clipboard dependency inventory differs")
    for package, expected in entries:
        directory = ROOT / "clipboard-vendor" / package
        checksum = directory / ".cargo-checksum.json"
        require(digest(checksum.read_bytes()) == expected, f"dependency manifest differs: {package}")
        checked = json.loads(checksum.read_bytes())
        metadata = tomllib.loads((directory / "Cargo.toml").read_text())["package"]
        key = (metadata["name"], metadata["version"])
        require(key in locked and checked["package"] == locked[key].get("checksum"),
                f"dependency root-lock identity differs: {package}")
        actual = {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()}
        require(actual == set(checked["files"]) | {".cargo-checksum.json"},
                f"dependency file closure differs: {package}")
        for relative, expected_file in checked["files"].items():
            path = directory / relative
            require(not path.is_symlink() and digest(path.read_bytes()) == expected_file,
                    f"dependency bytes differ: {package}/{relative}")
    print(f"CLIPBOARD_NATIVE_INPUTS=pass packages={len(entries)} manifest_sha256={digest(manifest.read_bytes())}", flush=True)
    return locked


def build(environment, locked):
    BUILD.mkdir(mode=0o700)
    (BUILD / "src").mkdir(mode=0o700)
    (BUILD / "Cargo.toml").write_text(f'''[package]
name = "{PACKAGE}"
version = "0.0.0"
edition = "2021"
[lib]
name = "rustdesk_clipboard_listener_native"
[dependencies]
anyhow = "=1.0.103"
log = {{ version = "=0.4.22", features = ["std"] }}
lazy_static = "=1.5.0"
clipboard-master = {{ git = "https://github.com/rustdesk-org/clipboard-master" }}
x11rb = {{ version = "=0.13.1", features = ["xfixes"] }}
[profile.dev]
debug = 0
incremental = false
''')
    config = BUILD / "config.toml"
    config.write_text('''[source.crates-io]
replace-with = "vendored-sources"
[source."git+https://github.com/rustdesk-org/clipboard-master"]
git = "https://github.com/rustdesk-org/clipboard-master"
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "/work/clipboard-vendor"
''')
    source = (ROOT / "src/clipboard.rs").read_bytes()
    start = b'#[cfg(not(target_os = "android"))]\npub mod clipboard_listener {'
    require(source.count(start) == 1 and source.rstrip().endswith(b"}"), "listener extraction differs")
    module = source[source.index(start):].rstrip()[:-1]
    method_start = b"        fn on_clipboard_error(&mut self, error: io::Error) -> CallbackResult {"
    method_end = b"    }\n\n    #[derive(Default)]\n    pub struct ClipboardListener"
    require(module.count(method_start) == 1 and module.count(method_end) == 1,
            "error callback extraction differs")
    begin = module.index(method_start)
    finish = module.index(method_end, begin)
    historical = (ROOT / "scripts/fixtures/clipboard-error-before-stop.rs").read_bytes()
    require(digest(historical) == "3abd72ef62ed4da2c0a545748fba1feed86b1e013222c152637f1c502ab9f6d6",
            "exact 1fb8e076 error callback differs")
    binaries = {}
    for variant in ("historical", "current"):
        selected = module if variant == "current" else module[:begin] + historical + module[finish:]
        scaffold = b"extern crate self as hbb_common;\npub use anyhow::{bail, Result as ResultType};\npub use log;\n" + selected
        scaffold += (f'\n#[cfg(test)] mod native_tests {{\nconst HISTORICAL_CLIPBOARD_ERROR: bool = {str(variant == "historical").lower()};\n'
                     'include!("/work/scripts/test-native-clipboard-listener.rs");\n}\n}\n').encode()
        (BUILD / "src/lib.rs").write_bytes(scaffold)
        if variant == "historical":
            (BUILD / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
            command(["cargo", "metadata", "--offline", "--format-version=1", "--config", str(config)], environment, 30)
        lock_bytes = (BUILD / "Cargo.lock").read_bytes()
        selected_records = tomllib.loads(lock_bytes.decode())["package"]
        dependencies = []
        for item in selected_records:
            if item["name"] == PACKAGE and "source" not in item:
                continue
            expected = locked.get((item["name"], item["version"]))
            require(expected is not None and all(item.get(field) == expected.get(field)
                    for field in ("source", "checksum")), "fixture escaped the root dependency lock")
            dependencies.append({field: item.get(field) for field in ("name", "version", "source", "checksum")})
        output = command(["cargo", "test", "--no-run", "--lib", "--locked", "--offline", "--jobs", "2",
                          "--message-format=json", "--config", str(config)], environment)
        print(f"CLIPBOARD_NATIVE_COMPILER variant={variant} bytes={len(output)} "
              f"sha256={digest(output)} dependencies={len(dependencies)}", flush=True)
        messages = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
        for item in messages:
            if item.get("reason") == "compiler-artifact" and item.get("manifest_path") == str(BUILD / "Cargo.toml"):
                print("CLIPBOARD_NATIVE_ARTIFACT " + json.dumps(item, sort_keys=True), flush=True)
        artifacts = [Path(item["executable"]) for item in messages if item.get("reason") == "compiler-artifact"
                     and item.get("target", {}).get("name") == PACKAGE.replace("-", "_")
                     and item.get("manifest_path") == str(BUILD / "Cargo.toml")
                     and item.get("target", {}).get("src_path") == str(BUILD / "src/lib.rs")
                     and item.get("target", {}).get("kind") == ["lib"]
                     and item.get("profile", {}).get("test") is True and item.get("executable")]
        require(len(artifacts) == 1 and any(item.get("reason") == "build-finished" and item.get("success") is True
                for item in messages), "exact native fixture executable is missing")
        binary = BUILD / f"{variant}.test"
        shutil.copyfile(artifacts[0], binary)
        binary.chmod(0o700)
        binaries[variant] = binary
        require((BUILD / "Cargo.lock").read_bytes() == lock_bytes, "locked compiler changed dependencies")
        print(f"CLIPBOARD_NATIVE_BUILD variant={variant} source_sha256={digest(source)} "
              f"component_sha256={digest(module)} fixture_sha256={digest(scaffold)} binary_sha256={digest(binary.read_bytes())} "
              f"lock_sha256={digest(lock_bytes)} dependencies_sha256={digest(json.dumps(dependencies, sort_keys=True).encode())}", flush=True)
    return binaries


def scenario(binary, variant, environment):
    require(variant in ("historical", "current", "startup", "warm-restart"), "unknown native scenario")
    log_path = BUILD / f"{variant}.xvfb.log"
    output = bytearray()
    with log_path.open("xb") as log:
        server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":94", "-screen", "0", "640x480x24",
                                   "-nolisten", "tcp", "-ac", "-noreset"], env=environment,
                                  stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        child = None
        try:
            deadline = time.monotonic() + 5
            while not Path("/tmp/.X11-unix/X94").is_socket():
                require(server.poll() is None and time.monotonic() < deadline, "private Xvfb not ready")
                time.sleep(0.02)
            arguments = [str(binary), "--test-threads=1", "--nocapture", "--color", "never"]
            if variant in ("historical", "current"):
                arguments.append("native_tests::z_native_x11_peer_retirement")
            elif variant == "startup":
                arguments.append("native_tests::a_retired_startup_observer")
            else:
                arguments.append("native_tests::y_native_x11_warm_restart")
            child = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            retired = False
            deadline = time.monotonic() + 20
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    require(time.monotonic() < deadline, "native clipboard scenario exceeded 20 seconds")
                    if not selector.select(0.1):
                        continue
                    data = os.read(child.stdout.fileno(), 4096)
                    if not data:
                        break
                    output.extend(data)
                    require(len(output) <= 65536, "native clipboard output exceeded 64 KiB")
                    if not retired and b"CLIPBOARD_NATIVE_READY callbacks=2 subscribers=2\n" in output:
                        server.terminate()
                        require(server.wait(timeout=3) == 0, "private Xvfb did not retire cleanly")
                        retired = True
            status = child.wait(timeout=2)
            print(output.decode("utf-8"), end="", flush=True)
            single_pass = status == 0 and re.search(
                rb"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;", output)
            if variant in ("historical", "current"):
                require(retired, "fixture did not reach real clipboard callbacks before server retirement")
            if variant == "historical":
                require(status == 86 and output.count(b"CLIPBOARD_NATIVE_OLD=retained terminal=delivered worker=live process_reset=required\n") == 1,
                        "historical callback did not demonstrate a retained live worker")
            elif variant == "current":
                require(single_pass and output.count(
                    b"CLIPBOARD_NATIVE_CURRENT=pass callbacks=2 subscribers=2 late_refusals=64 workers=joined\n") == 1,
                    "current listener did not pass native terminal retirement")
            elif variant == "startup":
                require(single_pass and not retired and output.count(
                    b"CLIPBOARD_NATIVE_STARTUP=pass observer=retired worker=joined\n") == 1,
                    "retired startup observer did not join its worker")
            else:
                require(single_pass and not retired and output.count(
                    b"CLIPBOARD_NATIVE_WARM=pass callbacks=4 normal_cycles=4 workers=joined\n") == 1,
                    "native warm-restart regression remains open")
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=3)
                child.stdout.close()
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=3)
    require(not Path("/tmp/.X11-unix/X94").exists(), "private Xvfb socket survived owner retirement")


def main():
    require((os.getuid(), os.getgid()) == (4000, 4000), "native fixture principal differs")
    environment = {"PATH": "/usr/local/cargo/bin:/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp",
                   "DISPLAY": "unix/:94.0", "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "RUSTUP_HOME": "/usr/local/rustup", "CARGO_HOME": "/tmp/clipboard-cargo",
                   "CARGO_TARGET_DIR": "/build/clipboard-target", "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    version = subprocess.run(["rustc", "--version"], env=environment, check=True,
                             capture_output=True, text=True, timeout=5)
    require(version.stdout.strip() == "rustc 1.75.0 (82e1608df 2023-12-21)", "Rust version differs")
    locked = inputs()
    binaries = build(environment, locked)
    state_output = command([str(binaries["current"]), "--test-threads=1", "--nocapture", "--color", "never",
                            "clipboard_listener::tests::"], environment, 5)
    print(state_output.decode("utf-8"), end="", flush=True)
    require(re.search(rb"test result: ok\. 6 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;", state_output),
            "production clipboard state tests did not all execute")
    print("CLIPBOARD_NATIVE_STATE=pass tests=6", flush=True)
    scenario(binaries["current"], "startup", environment)
    scenario(binaries["historical"], "historical", environment)
    scenario(binaries["current"], "current", environment)
    # Keep the original four restart cycles and three-second callback bound.
    # Failure here must still fail the aggregate, independently of terminal results.
    scenario(binaries["current"], "warm-restart", environment)
    inputs()
    print("CLIPBOARD_LISTENER_NATIVE=pass scope=linux-component source=production master=pinned callbacks=actual "
          "old=retained current=joined late_admission=refused startup_observer=retired tests=9 network=none cleanup=joined", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"native clipboard listener: FAIL: {error}") from error
