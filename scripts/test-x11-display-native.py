#!/usr/bin/env python3
"""Run production TFC input and capture checks against isolated Xvfb."""
import hashlib
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time
import tomllib


def require(value, message):
    if not value:
        raise RuntimeError(message)


def build_input_abi(root, environment):
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    tfc = [package for package in packages if package["name"] == "tfc"]
    require(len(tfc) == 1 and tfc[0]["version"] == "0.7.0" and "source" not in tfc[0]
            and tfc[0]["dependencies"] == ["core-graphics 0.23.2", "unicode-segmentation", "winapi 0.3.9"],
            "repository-owned TFC lockfile selection differs")
    dependency = tomllib.loads((root / "libs/enigo/Cargo.toml").read_text())["dependencies"]["tfc"]
    require(dependency == {"path": "../tfc"}, "Enigo TFC selection differs")
    x11 = [package for package in packages if package["name"] == "x11"]
    require(len(x11) == 1 and x11[0]["version"] == "2.21.0"
            and x11[0]["source"] == "registry+https://github.com/rust-lang/crates.io-index",
            "retired Git X11 package remains selected")
    manifest = tomllib.loads((root / "libs/tfc/Cargo.toml").read_text())
    require(manifest["package"]["name"] == "tfc" and manifest["package"]["version"] == "0.7.0"
            and manifest["package"]["edition"] == "2021" and "dependencies" not in manifest
            and set(manifest["target"]) == {'cfg(target_os = "macos")', 'cfg(target_os = "windows")'}
            and "libs/tfc" in tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["members"],
            "owned TFC manifest/workspace differs")
    work = Path("/build/input-abi")
    (work / "ffi").mkdir(mode=0o700, parents=True)
    for name, digest in (("xkb", "128afcecd57843f7855289ecaf445a2ce8383383b143656a67c2d4acd3c4cffc"),
                         ("xlib", "74eb55c515efddf93c404e9ddb4f96cb1bc6977e68b8c3fbae96e5c60e4202f2")):
        source = root / f"vendor/tfc/ffi/{name}.rs"
        require(hashlib.sha256(source.read_bytes()).hexdigest() == digest, "pinned TFC FFI bytes differ")
        shutil.copyfile(source, work / f"ffi/{name}.rs")
    shutil.copyfile(root / "scripts/test-x11-input-abi.rs", work / "test.rs")
    oracle = root / "scripts/test-x11-input-abi.c"
    subprocess.run(["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-c", str(oracle), "-o", str(work / "oracle.o")],
                   env=environment, check=True, timeout=15)
    binary = work / "native"
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2021", str(work / "test.rs"),
                    "-C", f"link-arg={work / 'oracle.o'}", "-o", str(binary)],
                   env=environment, check=True, timeout=30)
    header = Path("/usr/include/X11/extensions/XKBstr.h")
    library = Path("/usr/lib/x86_64-linux-gnu/libX11.so.6").resolve(strict=True)
    print("X11_INPUT_ABI_BUILD "
          f"rust_sha256={hashlib.sha256((work / 'test.rs').read_bytes()).hexdigest()} "
          f"oracle_sha256={hashlib.sha256(oracle.read_bytes()).hexdigest()} "
          f"header_sha256={hashlib.sha256(header.read_bytes()).hexdigest()} "
          f"xkb_protocol_sha256={hashlib.sha256(Path('/usr/include/X11/extensions/XKB.h').read_bytes()).hexdigest()} "
          f"xi_header_sha256={hashlib.sha256(Path('/usr/include/X11/extensions/XI.h').read_bytes()).hexdigest()} "
          f"library_sha256={hashlib.sha256(library.read_bytes()).hexdigest()} "
          f"binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()}", flush=True)
    return binary, library


def build_input_native(root, environment):
    work = Path("/build/input-native")
    work.mkdir(mode=0o700)
    source_digest = hashlib.sha256()
    records = (root / "libs/tfc/UPSTREAM_BLOBS.tsv").read_text().splitlines()[1:]
    require(len(records) == 67, "TFC retained source inventory differs")
    paths = []
    for record in records:
        name, original_blob = record.split("\t")
        require(re.fullmatch(r"(?:src/[a-z_0-9/]+\.rs|LICENSE-(?:MIT|APACHE))", name)
                and re.fullmatch(r"[0-9a-f]{40}", original_blob) and name not in paths,
                "TFC source record differs")
        paths.append(name)
        source_digest.update(name.encode() + b"\0" + (root / "libs/tfc" / name).read_bytes() + b"\0")
    require(set(paths) == {str(p.relative_to(root / "libs/tfc"))
                           for p in (root / "libs/tfc/src").rglob("*.rs")} | {"LICENSE-MIT", "LICENSE-APACHE"},
            "TFC source closure differs")
    library = work / "libtfc.rlib"
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2021", "--crate-name", "tfc",
                    "--crate-type", "rlib", str(root / "libs/tfc/src/lib.rs"), "-o", str(library)],
                   env=environment, check=True, timeout=30)
    objects = []
    for name in ("test-x11-input-abi", "test-x11-input-native"):
        obj = work / f"{name}.o"
        subprocess.run(["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                        "-c", str(root / f"scripts/{name}.c"), "-o", str(obj)],
                       env=environment, check=True, timeout=15)
        objects.append(obj)
    binary = work / "native"
    command = ["/usr/local/cargo/bin/rustc", "--edition=2021",
               str(root / "scripts/test-x11-input-native.rs"), "--extern", f"tfc={library}", "-o", str(binary)]
    for obj in objects:
        command += ["-C", f"link-arg={obj}"]
    for symbol in ("XOpenDisplay", "XCloseDisplay", "XkbGetMap", "XkbFreeKeyboard",
                   "XGetKeyboardMapping", "XFree", "XGetModifierMapping", "XFreeModifiermap",
                   "XkbGetState", "XTestFakeKeyEvent"):
        command += ["-C", f"link-arg=-Wl,--wrap={symbol}"]
    subprocess.run(command, env=environment, check=True, timeout=30)
    print("X11_INPUT_BUILD "
          f"source_set_sha256={source_digest.hexdigest()} "
          f"manifest_sha256={hashlib.sha256((root / 'libs/tfc/Cargo.toml').read_bytes()).hexdigest()} "
          f"fixture_rust_sha256={hashlib.sha256((root / 'scripts/test-x11-input-native.rs').read_bytes()).hexdigest()} "
          f"fixture_c_sha256={hashlib.sha256((root / 'scripts/test-x11-input-native.c').read_bytes()).hexdigest()} "
          f"rlib_sha256={hashlib.sha256(library.read_bytes()).hexdigest()} "
          f"binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()} scope=whole-linux-tfc cargo_graph=unvalidated", flush=True)
    return binary, library


def capture_connection_loss(binary, environment, xserver):
    ready = b"X11_CAPTURE_CONNECTION_READY callers=direct,public segments=2 pixels=red\n"
    output, errors = bytearray(), bytearray()
    native = subprocess.Popen([str(binary), "capture-connection-loss"], env=environment,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, bufsize=0)
    deadline = time.monotonic() + 15
    retired = False
    try:
        with selectors.DefaultSelector() as streams:
            streams.register(native.stdout, selectors.EVENT_READ, output)
            streams.register(native.stderr, selectors.EVENT_READ, errors)
            while streams.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "capture connection-loss handshake timed out")
                for key, _ in streams.select(remaining):
                    chunk = os.read(key.fd, 4097 - len(output) - len(errors))
                    if not chunk:
                        streams.unregister(key.fileobj)
                        continue
                    key.data.extend(chunk)
                    require(len(output) + len(errors) <= 4096, "connection-loss output exceeded its limit")
                    if not retired and b"\n" in output:
                        require(output == ready and not errors and native.poll() is None
                                and xserver.poll() is None, "live-capture readiness differs")
                        xserver.terminate()
                        xserver.wait(timeout=5)
                        require(xserver.returncode == 0, "owned Xvfb did not retire cleanly")
                        require(native.stdin.write(b"X") == 1, "server retirement token was not delivered")
                        native.stdin.close()
                        retired = True
            native.wait(timeout=max(0, deadline - time.monotonic()))
        lines = output.decode("utf-8").splitlines()
        require(retired and native.returncode == 0 and len(lines) == 6
                and lines[0] == ready.decode("ascii").strip()
                and lines[5] == "X11_DISPLAY_COMPONENT=pass scenario=capture-connection-loss replies=exact errors=explicit cleanup=joined",
                "connection-loss capture completion differs")
        receipt = re.fullmatch(
            r"X11_CAPTURE_CONNECTION_NATIVE=pass callers=direct,public repeats=3 connection_error=([1-9][0-9]*) "
            r"requests=8 replies=2 errors=0 comparisons=2 segments=retired", lines[1])
        require(receipt is not None, "exact connection-loss result absent")
        probe_receipt = (f"X11_SHM_STATUS_CONNECTION_NATIVE=pass connection_error={receipt.group(1)} "
                         "queries=1 replies=0 protocol_errors=0 allocations=retired")
        require(lines[2] == probe_receipt, "exact dead-connection probe result absent")
        construction = re.fullmatch(
            r"X11_CONSTRUCTOR_CONNECTION_NATIVE=pass callers=direct,public repeats=3 cases=6 "
            r"connection_errors=([1-9][0-9]*(?:,[1-9][0-9]*){5}) attach_requests=8 attach_checks=8 "
            r"connection_failures=6 rejected_segments=retired survivor_retirement=independent comparison_on_error=none",
            lines[3])
        require(construction is not None, "exact dead-connection constructor result absent")
        require(construction.group(1).split(",")[::2] == [receipt.group(1)] * 3,
                "retained direct connection's constructor status differs")
        lifetime = ("X11_SHM_LIFETIME_NATIVE=pass callers=direct,public segments=2 checks=17 "
                    "owner=4000:4000 creator=exact-child mode=0600 deletion_pending=true size=exact-buffer "
                    "attachment_transition=2-to-1 retirement=independent")
        require(lines[4] == lifetime, "exact kernel capture-lifetime observation absent")
        diagnostic = ("failed to detach X11 capture shared memory from XCB: "
                      "X connection failed during MIT-SHM drop detach: " + receipt.group(1))
        require(errors.decode("utf-8").splitlines() == [diagnostic, diagnostic],
                "dead-server cleanup diagnostics differ")
        print(lines[1], flush=True)
        print(probe_receipt, flush=True)
        print(lines[3], flush=True)
        print(lifetime, flush=True)
        print("X11_CAPTURE_CONNECTION_FINALITY=pass server=terminated-and-joined "
              "detach_errors=2 segment_retirement=independent output=bounded child=joined", flush=True)
    except BaseException:
        print(f"X11_CAPTURE_CONNECTION_FAILURE stdout={bytes(output)!r} stderr={bytes(errors)!r}", flush=True)
        raise
    finally:
        if native.poll() is None:
            native.kill()
        native.wait(timeout=5)
        for stream in (native.stdin, native.stdout, native.stderr):
            stream.close()


def main():
    require(os.getuid() == 4000 and os.getgid() == 4000, "nonroot fixture principal differs")
    root = Path("/work")
    baseline = root / "scripts/fixtures/x11-display-iter-before.rs"
    require(hashlib.sha256(baseline.read_bytes()).hexdigest() ==
            "1a38147b260c75c2171e3949f9dbb9341ca9986579b6af1fd84ad7848d34e6af",
            "historical e8898566 iterator with constructor-only test adaptation differs")
    environment = {"PATH": "/usr/local/cargo/bin:/usr/bin:/bin", "LC_ALL": "C",
                   "HOME": "/tmp", "DISPLAY": ":98", "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "RUSTUP_HOME": "/usr/local/rustup", "CARGO_HOME": "/usr/local/cargo",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    version = subprocess.run(["/usr/local/cargo/bin/rustc", "--version"], env=environment,
                             check=True, capture_output=True, text=True, timeout=5)
    require(version.stdout.strip() == "rustc 1.75.0 (82e1608df 2023-12-21)", "Rust version differs")
    input_abi, input_library = build_input_abi(root, environment)
    comparator = root / "libs/scrap/src/common/frame_compare.rs"
    comparator_test = Path("/build/frame-compare-tests")
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2018", "--test",
                    str(comparator), "-o", str(comparator_test)],
                   env=environment, check=True, timeout=30)
    comparison = subprocess.run([str(comparator_test), "--test-threads=1"],
                                env=environment, capture_output=True, text=True, timeout=5)
    require(comparison.returncode == 0 and not comparison.stderr
            and len(comparison.stdout) <= 4096
            and re.search(r"^test result: ok\. 3 passed; 0 failed; 0 ignored; 0 measured; "
                          r"0 filtered out; finished in [0-9.]+s$", comparison.stdout, re.M),
            f"production frame-comparison tests differ: {comparison}")
    print(comparison.stdout.strip(), flush=True)
    print("FRAME_COMPARISON_UNIT=pass source=production tests=3 scope=byte-cache "
          f"source_sha256={hashlib.sha256(comparator.read_bytes()).hexdigest()} "
          f"binary_sha256={hashlib.sha256(comparator_test.read_bytes()).hexdigest()}", flush=True)
    comparator_test.unlink()
    with open("/tmp/x11-display-xvfb.log", "xb") as log:
        child = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                                  "-screen", "1", "800x600x24", "-nolisten", "tcp", "-ac", "-noreset"],
                                 env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not Path("/tmp/.X11-unix/X98").is_socket():
                require(child.poll() is None and time.monotonic() < deadline, "Xvfb not ready")
                time.sleep(0.05)
            abi = subprocess.run([str(input_abi)], env=environment, capture_output=True,
                                 text=True, timeout=10)
            abi_lines = abi.stdout.splitlines()
            require(abi.returncode == 0 and not abi.stderr and len(abi.stdout) <= 4096
                    and abi_lines == [
                        "X11_INPUT_ABI_OFFSETS rust=[16, 2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14] "
                        "native=[18, 2, 0, 2, 4, 1, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16]",
                        "X11_INPUT_ABI_FINDING=confirmed supplier=historical-tfc rust_size=16 native_size=18 align=2 "
                        "fields=14 offset_mismatches=13 oracle=client-header product_acceptance=false",
                        f"X11_INPUT_ABI_LOADED library={input_library}",
                        "X11_INPUT_ABI_NATIVE=confirmed supplier=historical-tfc queries=32 controls=33 rejected=16 "
                        "rejection=XI-BadDevice:XKB-BadDevice recovery=same-connection write_beyond_rust_type=2 allocation_overrun=false "
                        "guards=intact descriptors=retired product_acceptance=false"],
                    f"native TFC ABI diagnostic differs: {abi}")
            print(abi.stdout.strip(), flush=True)
            input_abi.unlink()
            native_input, input_rlib = build_input_native(root, environment)
            native = subprocess.run([str(native_input)], env=environment, capture_output=True,
                                    text=True, timeout=15)
            require(native.returncode == 0 and not native.stderr and len(native.stdout) <= 4096
                    and native.stdout.splitlines() == [
                        "X11_INPUT_LAYOUT=pass source=production fields=14 size=18 align=2 oracle=client-header",
                        f"X11_INPUT_LOADED library={input_library}",
                        "X11_INPUT_EVENTS=pass source=whole-production-tfc repeats=16 characters=a,b,c events=96 observer=real-window query_rejections=16 rejected_emissions=0 recovery=same-context",
                        "X11_INPUT_LIFETIME=pass source=whole-production-tfc successful_contexts=16 connection=one failures=64 cause=injected-null,invalid-count symbols=paired keyboard=full-free modifiers=paired descriptors=retired scope=direct-owned-calls"],
                    f"production TFC native input differs: {native}")
            print(native.stdout.strip(), flush=True)
            native_input.unlink()
            input_rlib.unlink()
            binaries = {}
            for variant in ("historical", "corrected"):
                work = Path("/build") / variant
                (work / "x11").mkdir(mode=0o700, parents=True)
                (work / "common").mkdir(mode=0o700)
                shutil.copyfile(root / "scripts/test-x11-display.rs", work / "test.rs")
                for name in ("display", "ffi", "iter", "server", "capturer"):
                    if name == "capturer" and variant == "historical":
                        continue
                    source = baseline if name == "iter" and variant == "historical" else root / f"libs/scrap/src/x11/{name}.rs"
                    shutil.copyfile(source, work / f"x11/{name}.rs")
                shutil.copyfile(root / "libs/scrap/src/common/x11.rs", work / "common/x11.rs")
                shutil.copyfile(comparator, work / "common/frame_compare.rs")
                binary = work / "native"
                command = ["/usr/local/cargo/bin/rustc", "--edition=2018", "-C", "debuginfo=1",
                           "-o", str(binary), str(work / "test.rs")]
                if variant == "corrected":
                    command += ["--cfg", "corrected"]
                for symbol in ("get_monitors", "get_monitors_unchecked", "get_monitors_reply",
                               "get_monitors_monitors_iterator", "monitor_info_next"):
                    command += ["-C", f"link-arg=-Wl,--wrap=xcb_randr_{symbol}"]
                for symbol in ("xcb_get_setup", "xcb_get_atom_name", "xcb_get_atom_name_reply", "xcb_get_atom_name_name", "xcb_get_geometry_reply",
                               "xcb_shm_get_image", "xcb_shm_get_image_reply", "xcb_shm_attach_checked",
                               "xcb_shm_detach_checked", "xcb_request_check",
                               "xcb_shm_query_version", "xcb_shm_query_version_reply"):
                    command += ["-C", f"link-arg=-Wl,--wrap={symbol}"]
                subprocess.run(command, env=environment, check=True, timeout=30)
                binaries[variant] = binary
                print(f"X11_DISPLAY_NATIVE_BUILD variant={variant} sha256="
                      f"{hashlib.sha256(binary.read_bytes()).hexdigest()}", flush=True)
            probe = subprocess.run([str(binaries["corrected"]), "shm-status"], env=environment,
                                   capture_output=True, text=True, timeout=15)
            probe_receipt = ("X11_SHM_STATUS_NATIVE=pass request_fault=oversized-query-version "
                             "server_error=BadLength callers=direct,public repeats=16 cases=32 "
                             "queries=3 replies=2 protocol_errors=1 recovery=same-connection "
                             "capture=fresh allocations=retired segments=retired")
            require(probe.returncode == 0 and not probe.stderr and len(probe.stdout) <= 4096
                    and probe.stdout.splitlines() == [probe_receipt,
                        "X11_DISPLAY_COMPONENT=pass scenario=shm-status replies=exact errors=explicit cleanup=joined"],
                    f"native MIT-SHM availability probe finality differs: {probe}")
            print(probe_receipt, flush=True)
            for scenario, status, marker in (
                    ("enumerate", 42, "monitor-used-after-reply-retirement"),
                    ("reject", 43, "null-reply-passed-to-iterator")):
                old = subprocess.run([str(binaries["historical"]), scenario], env=environment,
                                     capture_output=True, text=True, timeout=10)
                require(old.returncode == status and f"X11_DISPLAY_OLD_FAILURE={marker}" in old.stderr,
                        f"historical {scenario} did not fail at its actual ownership defect: {old}")
                print(old.stderr.strip(), flush=True)
                subprocess.run([str(binaries["corrected"]), scenario], env=environment,
                               check=True, timeout=15)
            subprocess.run([str(binaries["corrected"]), "atom-reject"], env=environment,
                           check=True, timeout=15)
            subprocess.run([str(binaries["corrected"]), "atom-name"], env=environment,
                           check=True, timeout=15)
            for scenario in ("setup-short", "setup-vendor", "setup-formats", "setup-roots",
                             "setup-depths", "setup-visuals", "setup-trailing"):
                result = subprocess.run([str(binaries["corrected"]), scenario], env=environment,
                                        capture_output=True, text=True, timeout=15)
                old_cursor = " old_cursor=admitted" if scenario == "setup-short" else ""
                expected = (f"X11_SETUP_NATIVE=pass scenario={scenario} repeats=16 "
                            f"monitor_queries=0 enumeration=fused{old_cursor}")
                require(result.returncode == 0 and result.stdout.splitlines() == [expected]
                        and not result.stderr and len(result.stdout) <= 4096,
                        f"malformed setup case differs: {scenario}: {result}")
                print(expected, flush=True)
            failures = 0
            for scenario in ("bounds-atom-length", "bounds-atom-padding", "bounds-mon-count",
                             "bounds-mon-length", "bounds-mon-total", "bounds-mon-span", "bounds-mon-sum"):
                result = subprocess.run([str(binaries["corrected"]), scenario], env=environment,
                                        capture_output=True, text=True, timeout=15)
                require(len(result.stdout) + len(result.stderr) <= 4096, "bounds output exceeded its limit")
                print(result.stdout.strip(), flush=True)
                if result.returncode != 0:
                    status = 44 if scenario.startswith("bounds-atom") else 45
                    marker = "unchecked-atom-span" if status == 44 else "unchecked-monitor-span"
                    require(result.returncode == status and result.stderr.strip() == f"X11_BOUNDS_OLD_FAILURE={marker}",
                            f"unexpected native bounds failure in {scenario}: {result}")
                    print(f"X11_BOUNDS_BEFORE scenario={scenario} status={status} {result.stderr.strip()}", flush=True)
                    failures += 1
                else:
                    require(f"X11_BOUNDS_CASE=pass scenario={scenario} repeats=32 replies=exact enumeration=fused public_callers=explicit"
                            in result.stdout.splitlines(), "exact bounds result absent")
            require(failures == 0, f"{failures} unchecked received-header shapes remain")
            subprocess.run([str(binaries["corrected"]), "bounds-valid"], env=environment,
                           check=True, timeout=15)
            subprocess.run([str(binaries["corrected"]), "capture-24"], env=environment,
                           check=True, timeout=15)
            rejection = subprocess.run([str(binaries["corrected"]), "capture-reject"], env=environment,
                                       capture_output=True, text=True, timeout=15)
            rejection_receipt = ("X11_CAPTURE_REJECTION_NATIVE=pass server_error=BadDrawable repeats=16 "
                                 "callers=direct,public requests=4 replies=3 errors=1 comparison_on_error=none "
                                 "same_capture=recovered pixels=red,blue segment=retired")
            require(rejection.returncode == 0 and not rejection.stderr
                    and len(rejection.stdout) <= 4096
                    and rejection.stdout.splitlines() == [rejection_receipt,
                        "X11_DISPLAY_COMPONENT=pass scenario=capture-reject replies=exact errors=explicit cleanup=joined"],
                    f"native capture rejection/recovery differs: {rejection}")
            print(rejection_receipt, flush=True)
            attach = subprocess.run([str(binaries["corrected"]), "capture-attach-reject"], env=environment,
                                    capture_output=True, text=True, timeout=15)
            attach_lines = attach.stdout.splitlines()
            require(attach.returncode == 0 and not attach.stderr and len(attach.stdout) <= 4096
                    and len(attach_lines) == 2
                    and attach_lines[1] == "X11_DISPLAY_COMPONENT=pass scenario=capture-attach-reject replies=exact errors=explicit cleanup=joined",
                    f"native attach rejection/retry differs: {attach}")
            require(re.fullmatch(
                r"X11_CAPTURE_ATTACH_NATIVE=pass callers=direct,public repeats=16 server_error=([1-9][0-9]*) "
                r"attach_requests=3 capture_requests=3 capture_replies=3 attach_errors=1 survivor=fresh retry=valid segments=retired",
                attach_lines[0]) is not None, "exact attach rejection/retry result absent")
            print(attach_lines[0], flush=True)
            construction = subprocess.run([str(binaries["corrected"]), "capture-construction-failure"],
                                          env=environment, capture_output=True, text=True, timeout=15)
            construction_receipt = ("X11_CAPTURE_CONSTRUCTION_NATIVE=pass faults=local-attach,removal-pending "
                                    "cause=kernel-invalid-argument callers=direct,public repeats=16 cases=64 "
                                    "rejected_segments=retired xcb_detach=checked survivor=fresh retry=valid "
                                    "pixels=red,blue allocations=retired")
            require(construction.returncode == 0 and not construction.stderr
                    and len(construction.stdout) <= 4096
                    and construction.stdout.splitlines() == [construction_receipt,
                        "X11_DISPLAY_COMPONENT=pass scenario=capture-construction-failure replies=exact errors=explicit cleanup=joined"],
                    f"native local-construction failure cleanup/retry differs: {construction}")
            print(construction_receipt, flush=True)
            layout = subprocess.run([str(binaries["corrected"]), "capture-reply-layout"], env=environment,
                                    capture_output=True, text=True, timeout=15)
            layout_receipt = ("X11_CAPTURE_REPLY_NATIVE=pass received_header=injected fields=size,depth,visual "
                              "callers=direct,public repeats=16 cases=96 requests=4 replies=4 protocol_errors=0 "
                              "comparison_on_rejection=none same_capture=recovered pixels=red,blue "
                              "allocations=retired segments=retired")
            require(layout.returncode == 0 and not layout.stderr and len(layout.stdout) <= 4096
                    and layout.stdout.splitlines() == [layout_receipt,
                        "X11_DISPLAY_COMPONENT=pass scenario=capture-reply-layout replies=exact errors=explicit cleanup=joined"],
                    f"native received-reply rejection/recovery differs: {layout}")
            print(layout_receipt, flush=True)
            missing = subprocess.run([str(binaries["corrected"]), "capture-missing-reply"], env=environment,
                                     capture_output=True, text=True, timeout=15)
            missing_receipt = ("X11_CAPTURE_MISSING_NATIVE=pass cause=xcb-discard connection=healthy "
                               "callers=direct,public repeats=16 cases=32 requests=4 replies=3 missing=1 "
                               "completion=get-input-focus protocol_errors=0 comparison_on_rejection=none same_capture=recovered "
                               "pixels=red,blue allocations=retired segments=retired")
            require(missing.returncode == 0 and not missing.stderr and len(missing.stdout) <= 4096
                    and missing.stdout.splitlines() == [missing_receipt,
                        "X11_DISPLAY_COMPONENT=pass scenario=capture-missing-reply replies=exact errors=explicit cleanup=joined"],
                    f"native missing-reply rejection/recovery differs: {missing}")
            print(missing_receipt, flush=True)
            print("X11_BOUNDS_NATIVE=pass received_header=injected rejected_shapes=7 repeats=32 "
                  "enumeration=fused public_callers=explicit valid_outputless=injected screens=server-real replies=exact", flush=True)
            print("X11_SETUP_NATIVE=pass received_header=injected rejected_shapes=7 repeats=16 "
                  "old_cursor=admitted monitor_queries=0 screens=server-real network=none", flush=True)
            require(child.poll() is None, "Xvfb exited during native cases")
            capture_connection_loss(binaries["corrected"], environment, child)
        except BaseException:
            log.flush()
            print(f"X11_DISPLAY_XVFB_FAILURE_STATUS={child.poll()}", flush=True)
            print("X11_DISPLAY_XVFB_FAILURE_LOG_BEGIN", flush=True)
            print(Path(log.name).read_text()[:16384], flush=True)
            print("X11_DISPLAY_XVFB_FAILURE_LOG_END", flush=True)
            raise
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        require(child.returncode == 0, "Xvfb retirement failed")
    with open("/tmp/x11-display-xvfb-16.log", "xb") as log:
        child = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "641x479x16",
                                  "-nolisten", "tcp", "-ac", "-noreset"],
                                 env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not Path("/tmp/.X11-unix/X98").is_socket():
                require(child.poll() is None and time.monotonic() < deadline, "16-bit Xvfb not ready")
                time.sleep(0.05)
            subprocess.run([str(binaries["corrected"]), "capture-16"], env=environment,
                           check=True, timeout=15)
            require(child.poll() is None, "16-bit Xvfb exited during capture")
        except BaseException:
            log.flush()
            print(f"X11_DISPLAY_XVFB16_FAILURE_STATUS={child.poll()}", flush=True)
            print(Path(log.name).read_text()[:16384], flush=True)
            raise
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        require(child.returncode == 0, "16-bit Xvfb retirement failed")
    for name in ("tcp", "tcp6"):
        require(not any(row.split()[3] == "0A" for row in Path("/proc/net", name).read_text().splitlines()[1:]),
                "native test opened a TCP listener")
    for name in ("udp", "udp6"):
        require(len(Path("/proc/net", name).read_text().splitlines()) == 1, "native test opened UDP")
    print("X11_DISPLAY_NATIVE=pass source=production-component xcb=real old=refused "
          "screens=2 repeat=32 drop=exact query_error=explicit public_callers=executed "
          "allocator_reuse=unclaimed network=none uid=4000 cleanup=joined", flush=True)
    print("X11_LAYOUT_NATIVE=pass xvfb_depths=24,16 stride_16_odd=1284 "
          "pixels=actual capture=production-shm public=production-buffer network=none uid=4000 cleanup=joined", flush=True)


if __name__ == "__main__":
    main()
