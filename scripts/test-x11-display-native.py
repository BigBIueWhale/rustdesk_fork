#!/usr/bin/env python3
"""Run production X11 owner and capture checks against isolated Xvfb."""
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import socket
import subprocess
import threading
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def thread_contexts(root, environment):
    owner = root / "src/platform/linux/native_context.rs"
    fixture = root / "scripts/test-x11-thread-context.rs"
    binary = Path("/build/thread-contexts")
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2021", str(fixture),
                    "-o", str(binary)], env=environment, check=True, timeout=30)
    print("X11_THREAD_CONTEXT_BUILD "
          f"owner_sha256={hashlib.sha256(owner.read_bytes()).hexdigest()} "
          f"fixture_sha256={hashlib.sha256(fixture.read_bytes()).hexdigest()} "
          f"consumer_sha256={hashlib.sha256((root / 'src/platform/linux.rs').read_bytes()).hexdigest()} "
          f"binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()} "
          "scope=production-owner whole_app=unexecuted loader=direct-native-test", flush=True)
    result = subprocess.run([str(binary)], env=environment, capture_output=True,
                            text=True, timeout=15)
    receipt = ("X11_THREAD_CONTEXT_NATIVE=pass source=production-owner old=retained-after-thread-exit "
               "old_threads=8 corrected_threads=32 unwind_threads=16 contexts=64 "
               "constructor_refusals=32 callbacks=paired descriptors=retired scope=native-owner")
    lines = result.stdout.splitlines()
    # The pinned libxdo reports each deliberate failed constructor on stderr.
    refusals = "Error: Can't open display: :97\n" * 16
    require(result.returncode == 0 and result.stderr == refusals
            and len(result.stdout) + len(result.stderr) <= 4096
            and len(lines) == 3 and lines[-1] == receipt,
            f"native thread-context result differs: {result}")
    for line, name in zip(lines[:2], ("libX11", "libxdo")):
        library = line.removeprefix("X11_THREAD_CONTEXT_LOADED library=")
        require(re.fullmatch(rf"/usr/lib/x86_64-linux-gnu/{name}\.so\.[0-9.]+", library),
                "native context library identity differs")
        print(f"{line} sha256={hashlib.sha256(Path(library).read_bytes()).hexdigest()}", flush=True)
    print(receipt, flush=True)
    binary.unlink()


def build_focus(root, environment, binary, fixture, historical=False):
    helper = binary.with_suffix(".o")
    compiler = ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c"]
    if historical:
        compiler += ["-DHISTORICAL"]
    subprocess.run(compiler + [
                    str(root / "scripts/test-x11-window-focus.c"), "-o", str(helper)],
                   env=environment, check=True, timeout=15)
    command = ["/usr/local/cargo/bin/rustc", "--edition=2021",
               str(fixture), "-o", str(binary),
               "-C", f"link-arg={helper}", "-C", "link-arg=-lX11"]
    if historical:
        command += ["--cfg", "historical"]
    symbols = ("intern_atom", "get_geometry", "poll_for_reply" if historical else "wait_for_reply")
    for name in symbols + ("get_setup",):
        command += ["-C", f"link-arg=-Wl,--wrap=xcb_{name}"]
    command += ["-C", "link-arg=-Wl,--wrap=free"]
    subprocess.run(command, env=environment, check=True, timeout=30)
    helper.unlink()


def window_focus(root, environment):
    binary = Path("/build/window-focus")
    build_focus(root, environment, binary, root / "scripts/test-x11-window-focus.rs")
    print("X11_FOCUS_BUILD " + " ".join(
        f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}" for name, path in (
            ("source", root / "src/platform/linux/window_focus.rs"),
            ("deadline", root / "src/platform/linux/window_focus_deadline.rs"),
            ("rust_fixture", root / "scripts/test-x11-window-focus.rs"),
            ("c_fixture", root / "scripts/test-x11-window-focus.c"),
            ("binary", binary))) + " whole_app=unexecuted", flush=True)
    result = subprocess.run([str(binary)], env=environment, capture_output=True,
                            text=True, timeout=15)
    receipt = ("X11_FOCUS_NATIVE=pass source=production-module old=unrelated-error-swallowed "
               "cases=12 repeats=16 geometry=server-real destroy_after_geometry=16 unrelated_errors=16 "
               "setup_faults=7 constructors_refused=16 thread_exits=16 allocations=paired "
               "descriptors=retired deadline_workers=constant-and-joined handler=unchanged scope=focus-component")
    lines = result.stdout.splitlines()
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 4096
            and len(lines) == 2 and lines[-1] == receipt, f"native focus result differs: {result}")
    library = lines[0].removeprefix("X11_FOCUS_LOADED library=")
    require(re.fullmatch(r"/usr/lib/x86_64-linux-gnu/libxcb\.so\.[0-9.]+", library),
            "native focus library identity differs")
    print(f"{lines[0]} sha256={hashlib.sha256(Path(library).read_bytes()).hexdigest()}", flush=True)
    print(receipt, flush=True)
    binary.unlink()


class FragmentedReply:
    """Private Unix relay: hold the last four bytes of a real property reply."""

    def __init__(self):
        self.path = Path("/tmp/.X11-unix/X99")
        require(not self.path.exists(), "private focus relay socket already exists")
        self.ready = threading.Event()
        self.arm = threading.Event()
        self.fragment = threading.Event()
        self.release = threading.Event()
        self.stop = threading.Event()
        self.failure = None
        self.identity = None
        self.worker = threading.Thread(target=self.run, name="focus-reply-relay")
        self.worker.start()
        try:
            require(self.ready.wait(5) and self.failure is None, "private focus relay did not start")
        except BaseException:
            self.close()
            raise

    def run(self):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(self.path))
                status = self.path.stat()
                self.identity = status.st_dev, status.st_ino
                listener.listen(1)
                listener.settimeout(0.05)
                self.ready.set()
                while not self.stop.is_set():
                    try:
                        client, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                else:
                    return
                with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                    server.settimeout(1)
                    server.connect("/tmp/.X11-unix/X98")
                    client.setblocking(False)
                    server.setblocking(False)
                    to_server, to_client, packets = bytearray(), bytearray(), bytearray()
                    setup = True
                    held = None
                    header_pending = False
                    with selectors.DefaultSelector() as streams:
                        streams.register(client, selectors.EVENT_READ)
                        streams.register(server, selectors.EVENT_READ)
                        while not self.stop.is_set():
                            if held is not None and self.release.is_set():
                                to_client.extend(held)
                                held = None
                            streams.modify(client, selectors.EVENT_READ | (selectors.EVENT_WRITE if to_client else 0))
                            streams.modify(server, selectors.EVENT_READ | (selectors.EVENT_WRITE if to_server else 0))
                            for key, events in streams.select(0.05):
                                peer = key.fileobj
                                if events & selectors.EVENT_READ:
                                    try:
                                        data = peer.recv(32769)
                                    except BlockingIOError:
                                        data = None
                                    if data == b"":
                                        return
                                    if data:
                                        if peer is client:
                                            to_server.extend(data)
                                        else:
                                            packets.extend(data)
                                            while len(packets) >= (8 if setup else 32):
                                                if setup:
                                                    require(packets[0] == 1, "real X server refused relay setup")
                                                    length = 8 + int.from_bytes(packets[6:8], "little") * 4
                                                else:
                                                    length = 32 + (int.from_bytes(packets[4:8], "little") * 4
                                                                   if packets[0] in (1, 35) else 0)
                                                require(length <= 32768, "focus relay packet exceeds budget")
                                                if len(packets) < length:
                                                    break
                                                packet = bytes(packets[:length])
                                                del packets[:length]
                                                if not setup and self.arm.is_set() and not self.fragment.is_set() and length > 32:
                                                    require(held is None and length == 36 and packet[0:2] == b"\x01\x20"
                                                            and int.from_bytes(packet[8:12], "little") == 4
                                                            and int.from_bytes(packet[16:20], "little") == 1,
                                                            "fragment target is not the real one-ATOM property reply")
                                                    to_client.extend(packet[:32])
                                                    held = packet[32:]
                                                    header_pending = True
                                                else:
                                                    to_client.extend(packet)
                                                setup = False
                                if events & selectors.EVENT_WRITE:
                                    pending = to_client if peer is client else to_server
                                    try:
                                        count = peer.send(pending)
                                    except BlockingIOError:
                                        count = 0
                                    del pending[:count]
                                    if peer is client and header_pending and not pending:
                                        header_pending = False
                                        self.fragment.set()
                            require(len(to_server) + len(to_client) + len(packets) <= 32768,
                                    "focus relay buffered-byte budget exceeded")
        except BaseException as error:
            self.failure = error
        finally:
            self.ready.set()

    def close(self):
        self.stop.set()
        self.worker.join(timeout=2)
        require(not self.worker.is_alive(), "owned focus relay did not join")
        if self.identity is not None:
            status = self.path.stat()
            require((status.st_dev, status.st_ino) == self.identity, "owned relay socket identity changed")
            self.path.unlink()
            self.identity = None
        require(self.failure is None, f"focus relay failed: {self.failure}")


def focus_lifecycle(root, environment):
    baseline = root / "scripts/fixtures/x11-window-focus-before-deadline.rs"
    require(hashlib.sha256(baseline.read_bytes()).hexdigest() ==
            "11e9b4b577e28216f14eabd7eca3a210d00b987768d157e36c50ad852433ad2d",
            "exact historical 1f4a01b3 focus module differs")
    fixture = root / "scripts/test-x11-focus-lifecycle.rs"
    with open("/tmp/x11-focus-lifecycle-xvfb.log", "xb") as log:
        def start_server():
            require(not Path("/tmp/.X11-unix/X98").exists(), "previous private X socket remains")
            server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                                       "-nolisten", "tcp", "-ac", "-noreset"],
                                      env=environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                until = time.monotonic() + 5
                while not Path("/tmp/.X11-unix/X98").is_socket():
                    require(server.poll() is None and time.monotonic() < until, "focus Xvfb not ready")
                    time.sleep(0.01)
                return server
            except BaseException:
                if server.poll() is None:
                    server.kill()
                server.wait(timeout=5)
                raise

        def case(binary, variant, scenario):
            server = start_server()
            native = None
            relay = None
            output, errors = bytearray(), bytearray()
            stopped = False
            try:
                if scenario == "fragmented":
                    relay = FragmentedReply()
                native = subprocess.Popen([str(binary), scenario], env=environment,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, bufsize=0)
                deadline = time.monotonic() + 15
                offset = 0
                with selectors.DefaultSelector() as streams:
                    streams.register(native.stdout, selectors.EVENT_READ, output)
                    streams.register(native.stderr, selectors.EVENT_READ, errors)

                    def read_output(timeout):
                        for key, _ in streams.select(timeout):
                            chunk = os.read(key.fd, 4097 - len(output) - len(errors))
                            if not chunk:
                                streams.unregister(key.fileobj)
                            else:
                                key.data.extend(chunk)
                                require(len(output) + len(errors) <= 4096, "focus lifecycle output exceeded limit")

                    def line():
                        nonlocal offset
                        while True:
                            end = output.find(b"\n", offset)
                            if end >= 0:
                                value = output[offset:end].decode("ascii")
                                offset = end + 1
                                require(not errors, "focus lifecycle child reported an error")
                                return value
                            remaining = deadline - time.monotonic()
                            require(remaining > 0 and streams.get_map(), "focus lifecycle handshake incomplete")
                            read_output(remaining)

                    def token(value):
                        require(native.stdin.write(value) == 1, "focus lifecycle token not delivered")

                    require(line() == "X11_FOCUS_LIFECYCLE_READY established=true fixture=closed"
                            and native.poll() is None and server.poll() is None, "focus established readiness differs")
                    if scenario in ("stalled", "backpressure"):
                        server.send_signal(signal.SIGSTOP)
                        stopped = True
                        until = time.monotonic() + 2
                        while True:
                            require(server.poll() is None, "owned Xvfb exited before pause observation")
                            state = Path(f"/proc/{server.pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
                            if state == "T":
                                break
                            require(time.monotonic() < until, "owned Xvfb pause unobserved")
                            time.sleep(0.005)
                        token(b"B" if scenario == "backpressure" else b"T")
                    elif scenario == "dead":
                        server.terminate()
                        server.wait(timeout=5)
                        require(server.returncode == 0, "owned Xvfb retirement differs")
                        token(b"D")
                    else:
                        relay.arm.set()
                        token(b"F")
                    require(line() == "X11_FOCUS_LIFECYCLE_ENTERING source=complete-module", "focus wait entry differs")
                    if scenario == "backpressure":
                        pressure = line()
                        receipt = re.fullmatch(r"X11_FOCUS_BACKPRESSURE_READY bytes=([0-9]+) "
                                               r"writable=false sigpipe=default", pressure)
                        require(receipt is not None and 0 < int(receipt.group(1)) < 16384,
                                "actual bounded socket backpressure was not observed")
                        print(pressure, flush=True)
                    if relay is not None:
                        require(relay.fragment.wait(2) and relay.failure is None,
                                "real property reply header was not forwarded with tail held")
                    if variant == "historical":
                        until = time.monotonic() + 0.3
                        while time.monotonic() < until:
                            read_output(max(0, until - time.monotonic()))
                            require(len(output) == offset and not errors and native.poll() is None,
                                    "historical native wait completed before its controlled release")
                        if scenario == "backpressure":
                            server.send_signal(signal.SIGCONT)
                            stopped = False
                        else:
                            relay.release.set()
                    waited = line()
                    require(re.fullmatch(rf"X11_FOCUS_WAIT_NATIVE variant={variant} scenario={scenario} "
                                         r"elapsed_ms=[0-9]+ result=retired descriptors=retired", waited),
                            "focus wait outcome differs")
                    print(waited, flush=True)
                    if variant == "corrected":
                        if stopped:
                            server.send_signal(signal.SIGCONT)
                            stopped = False
                        elif scenario == "dead":
                            server = start_server()
                        else:
                            relay.close()
                            relay = FragmentedReply()
                        token(b"R")
                        recovered = line()
                        require(recovered == f"X11_FOCUS_RECOVERY_NATIVE scenario={scenario} owner=same connection=fresh "
                                "geometry=server-real center=164,92 allocations=paired descriptors=retired",
                                "same-owner focus recovery differs")
                        print(recovered, flush=True)
                    native.stdin.close()
                    while streams.get_map():
                        remaining = deadline - time.monotonic()
                        require(remaining > 0, "focus lifecycle terminal output deadline")
                        read_output(remaining)
                    native.wait(timeout=max(0, deadline - time.monotonic()))
                    require(native.returncode == 0 and not errors and len(output) == offset,
                            "focus lifecycle finality differs")
                require(server.poll() is None, "focus Xvfb exited unexpectedly")
            except BaseException:
                print(f"X11_FOCUS_LIFECYCLE_FAILURE stdout={bytes(output)!r} stderr={bytes(errors)!r}", flush=True)
                raise
            finally:
                try:
                    if native is not None:
                        if native.poll() is None:
                            native.kill()
                        native.wait(timeout=5)
                        for stream in (native.stdin, native.stdout, native.stderr):
                            stream.close()
                finally:
                    try:
                        if relay is not None:
                            relay.close()
                    finally:
                        if server.poll() is None:
                            if stopped:
                                server.send_signal(signal.SIGCONT)
                            server.terminate()
                        server.wait(timeout=5)
            require(server.returncode == 0, "focus Xvfb terminal status differs")

        for variant in ("historical", "corrected"):
            binary = Path("/build/focus-lifecycle")
            build_focus(root, environment, binary, fixture, historical=variant == "historical")
            source = baseline if variant == "historical" else root / "src/platform/linux/window_focus.rs"
            print(f"X11_FOCUS_LIFECYCLE_BUILD variant={variant} " + " ".join(
                f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}" for name, path in (
                    ("source", source), ("fixture", fixture), ("c_fixture", root / "scripts/test-x11-window-focus.c"),
                    ("deadline", root / "src/platform/linux/window_focus_deadline.rs"),
                    ("binary", binary))) + " scope=complete-focus-module whole_app=unexecuted", flush=True)
            if variant == "historical":
                case(binary, variant, "fragmented")
                case(binary, variant, "backpressure")
            else:
                for _ in range(4):
                    for scenario in ("stalled", "dead", "fragmented", "backpressure"):
                        case(binary, variant, scenario)
            binary.unlink()
    print("X11_FOCUS_LIFECYCLE_NATIVE=pass old=fragmented-and-send-wait source=complete-module "
          "deadline_ms=100 stalled=4 dead=4 fragmented=4 backpressure=4 recovery=same-owner-fresh-connection "
          "allocations=paired descriptors=retired deadline_workers=joined relay=owned-and-joined "
          "server=owned-and-joined network=none scope=focus-component", flush=True)


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
            thread_contexts(root, environment)
            window_focus(root, environment)
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
    for binary in binaries.values():
        binary.unlink()
    focus_lifecycle(root, environment)
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
