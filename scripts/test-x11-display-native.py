#!/usr/bin/env python3
"""Run production X11 enumeration and capture against real isolated Xvfb."""
import hashlib
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


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
        require(retired and native.returncode == 0 and len(lines) == 3
                and lines[0] == ready.decode("ascii").strip()
                and lines[2] == "X11_DISPLAY_COMPONENT=pass scenario=capture-connection-loss replies=exact errors=explicit cleanup=joined",
                "connection-loss capture completion differs")
        receipt = re.fullmatch(
            r"X11_CAPTURE_CONNECTION_NATIVE=pass callers=direct,public repeats=3 connection_error=([1-9][0-9]*) "
            r"requests=8 replies=2 errors=0 comparisons=2 segments=retired", lines[1])
        require(receipt is not None, "exact connection-loss result absent")
        diagnostic = ("failed to detach X11 capture shared memory from XCB: "
                      "X connection failed during MIT-SHM drop detach: " + receipt.group(1))
        require(errors.decode("utf-8").splitlines() == [diagnostic, diagnostic],
                "dead-server cleanup diagnostics differ")
        print(lines[1], flush=True)
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
    guard_command = ["/usr/bin/python3", "-B", "-I", "-S",
                     str(root / "scripts/verify-x11-capture-shm.py"), "--repo"]
    guard = subprocess.run(guard_command + [str(root)], env=environment,
                           capture_output=True, text=True, timeout=5)
    require(guard.returncode == 0 and guard.stdout == "verify-x11-capture-shm: ok\n"
            and not guard.stderr, f"current X11 source contract differs: {guard}")
    negative = Path("/build/x11-source-negative")
    (negative / "libs/scrap/src/x11").mkdir(mode=0o700, parents=True)
    for name in ("capturer", "ffi"):
        source = (root / f"libs/scrap/src/x11/{name}.rs").read_text()
        if name == "capturer":
            needle = "const SHM_OWNER_READ_WRITE: libc::c_int = 0o600;"
            require(source.count(needle) == 1, "exact source-mode fixture anchor differs")
            source = source.replace(needle, "const SHM_OWNER_READ_WRITE: libc::c_int = 0o666;", 1)
        (negative / f"libs/scrap/src/x11/{name}.rs").write_text(source)
    refusal = subprocess.run(guard_command + [str(negative)], env=environment,
                             capture_output=True, text=True, timeout=5)
    expected = ("verify-x11-capture-shm: FAIL: missing exact owner-only shared-memory mode: "
                "'const SHM_OWNER_READ_WRITE: libc::c_int = 0o600;'\n")
    require(refusal.returncode == 1 and refusal.stdout == expected and not refusal.stderr,
            f"permissive source fixture was not refused exactly: {refusal}")
    print("X11_SOURCE_CONTRACT=pass current=accepted permissive_source=refused "
          "cases=2 scope=source-only kernel_permission_denial=unclaimed", flush=True)
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
                       "xcb_shm_get_image", "xcb_shm_get_image_reply", "xcb_shm_attach_checked", "xcb_request_check"):
            command += ["-C", f"link-arg=-Wl,--wrap={symbol}"]
        subprocess.run(command, env=environment, check=True, timeout=30)
        binaries[variant] = binary
        print(f"X11_DISPLAY_NATIVE_BUILD variant={variant} sha256="
              f"{hashlib.sha256(binary.read_bytes()).hexdigest()}", flush=True)
    with open("/tmp/x11-display-xvfb.log", "xb") as log:
        child = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                                  "-screen", "1", "800x600x24", "-nolisten", "tcp", "-ac", "-noreset"],
                                 env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not Path("/tmp/.X11-unix/X98").is_socket():
                require(child.poll() is None and time.monotonic() < deadline, "Xvfb not ready")
                time.sleep(0.05)
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
