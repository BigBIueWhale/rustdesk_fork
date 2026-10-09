#!/usr/bin/env python3
"""Run production X11 owner and capture checks against isolated Xvfb."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def macos_cursor_snapshot_state(root, environment):
    source = root / "src/platform/macos/cursor_snapshot.rs"
    binary = Path("/build/macos-cursor-snapshot-state")
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2021", "--test", str(source),
                    "-o", str(binary)], env=environment, check=True, timeout=30)
    print("MACOS_CURSOR_SNAPSHOT_BUILD "
          f"source_sha256={hashlib.sha256(source.read_bytes()).hexdigest()} "
          f"macos_parent_sha256={hashlib.sha256((root / 'src/platform/macos.rs').read_bytes()).hexdigest()} "
          f"service_parent_sha256={hashlib.sha256((root / 'src/server/input_service.rs').read_bytes()).hexdigest()} "
          f"binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()} "
          "macos_parent=uncompiled whole_service=unexecuted", flush=True)
    result = subprocess.run([str(binary), "--test-threads=1"], env=environment,
                            capture_output=True, text=True, timeout=5)
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 4096
            and re.search(r"^test result: ok\. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
                          result.stdout, re.MULTILINE),
            f"production macOS snapshot cache state tests differ: {result}")
    print(result.stdout, end="", flush=True)
    binary.unlink()
    print("MACOS_CURSOR_SNAPSHOT_STATE=pass source=complete-module tests=5 "
          "zero_seed=accepted failed_capture=not-memoized stale_image=absent "
          "same_seed=reused publication_retry=captured-image unwind=empty "
          "reset=idempotent worker=joined scope=portable-cache-state macOS_native=false", flush=True)


def logging_library(root, environment):
    logging = root / "test-inputs/log-0.4.22"
    checksum = logging / ".cargo-checksum.json"
    require(hashlib.sha256(checksum.read_bytes()).hexdigest() ==
            "eface4bae11ea2b6ba81ed2b07f0705d076456e4a61e2ca7409bb5649ce0c894",
            "native backend logging input manifest differs")
    manifest = json.loads(checksum.read_text())
    require(manifest["package"] == "a7a70ba024b9dc04c27ea2f0c0548feb474ec5c54bba33a7f72f873a39d07b24",
            "logging crate package identity differs")
    for name in ("lib.rs", "macros.rs", "__private_api.rs", "serde.rs"):
        path = logging / "src" / name
        require(hashlib.sha256(path.read_bytes()).hexdigest() == manifest["files"][f"src/{name}"],
                "native logging source differs")
    library = Path("/build/liblog.rlib")
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2021", "--crate-name", "log",
                    "--crate-type=rlib", "--cfg", 'feature="std"', str(logging / "src/lib.rs"),
                    "-o", str(library)], env=environment, check=True, timeout=30)
    return checksum, library


def input_exports(root):
    data = (root / "scripts/fixtures/xdo-input-exports.txt").read_bytes()
    require(len(data) <= 1024, "private input export inventory exceeded bound")
    names = data.decode("ascii").splitlines()
    require(len(names) == len(set(names)) == 11
            and all(re.fullmatch(r"xdo_[a-z_]+", name) for name in names),
            "private input export inventory differs")
    return set(names)


def native_xdo(root, environment, historical_destructor=True):
    source = root / "libs/libxdo-sys-stub/native"
    required_exports = input_exports(root)
    checker_source = root / "scripts/verify-debian-package-authority.py"
    spec = importlib.util.spec_from_file_location("package_authority", checker_source)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    names = ("build.py", "xdo.c", "xdo.h",
             "xdo_version.h", "COPYRIGHT", "SOURCE.txt")
    before_source = None
    variants = [("corrected", source)]
    if historical_destructor:
        before_source = Path("/build/native-xdo-before-source")
        before_source.mkdir(mode=0o700)
        for name in names:
            shutil.copyfile(source / name, before_source / name)
        text = (before_source / "xdo.c").read_text()
        destructor = "XkbFreeKeyboard(desc, 0, True);"
        require(text.count(destructor) == 1, "native XDO descriptor destructor differs")
        (before_source / "xdo.c").write_text(text.replace(destructor, "XkbFreeClientMap(desc, 0, 1);"))
        variants.insert(0, ("before", before_source))
    directories = {}
    for variant, inputs in variants:
        directory = Path("/build") / f"native-xdo-{variant}"
        directory.mkdir(mode=0o700)
        output = directory / "libxdo.so.3"
        subprocess.run(["/usr/bin/python3", "-I", "-S", str(inputs / "build.py"),
                        "--output", str(output)], env=environment, check=True, timeout=35)
        member = "./usr/lib/rustdesk-fork/libxdo.so.3"
        require(member in checker.DATA_REQUIRED_FILES and member in checker.MANDATORY_ELVES,
                "private XDO object is absent from the closed package inventory")
        actual, present = checker.validate_elf_identity(output.read_bytes(), member, str(output))
        checker.validate_runpath_policy(actual, present, member, str(output))
        require(not actual and not present, "private XDO object has an unexpected runtime search path")
        print(f"X11_XDO_PACKAGE_ELF variant={variant} result=pass required=true runpath=absent "
              f"checker_sha256={hashlib.sha256(checker_source.read_bytes()).hexdigest()} "
              "full_package=unexecuted", flush=True)
        (directory / "libxdo.so").symlink_to(output.name)
        print("X11_XDO_PRODUCT_BUILD " + " ".join(
            f"{name.replace('.', '_')}_sha256={hashlib.sha256((inputs / name).read_bytes()).hexdigest()}"
            for name in names) +
            f" binary_sha256={hashlib.sha256(output.read_bytes()).hexdigest()} variant={variant} "
            f"compiler=product-helper source_delta={'one-call' if variant == 'before' else 'none'} "
            "loader=direct-native-test installed=false", flush=True)
        result = subprocess.run(["/usr/bin/nm", "-D", "--defined-only", str(output)],
                                env=environment, capture_output=True, text=True, timeout=5)
        require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 65536,
                "native XDO export inventory failed")
        exports = {line.split()[-1] for line in result.stdout.splitlines() if line.split()}
        require({name for name in exports if name.startswith("xdo_")} == required_exports,
                "private XDO input export closure differs")
        directories[variant] = directory
    print(f"X11_XDO_PACKAGE_ELF=pass variants={len(variants)} required=true runpath=absent full_package=unexecuted", flush=True)
    print(f"XDO_INPUT_API_NATIVE=pass providers={len(variants)} exports=11 scope=closed-private-abi", flush=True)
    return directories, before_source


def constructor_contexts(root, environment):
    fixture = root / "scripts/test-xdo-constructor.c"
    native_source = root / "libs/libxdo-sys-stub/native"
    binary = Path("/build/xdo-constructor")
    command = ["/usr/bin/cc", "-std=c99", "-O1", "-g", "-fsanitize=address",
               "-fno-omit-frame-pointer", str(fixture), str(native_source / "xdo.c"),
               "-lX11", "-lXtst", "-lX11-xcb", "-lxcb", "-o", str(binary)]
    for symbol in ("calloc", "free", "XOpenDisplay", "XCloseDisplay", "XTestQueryExtension", "XkbGetMap",
                   "XkbFreeKeyboard", "XGetKeyboardMapping", "XkbKeycodeToKeysym", "XGetModifierMapping"):
        command += [f"-Wl,--wrap={symbol}"]
    subprocess.run(command, env=environment, check=True, timeout=30)
    print("XDO_CONSTRUCTOR_BUILD " + " ".join(
        f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}" for name, path in (
            ("fixture", fixture), ("native_c", native_source / "xdo.c"), ("binary", binary))) +
        " native_source=complete sanitizer=address whole_app=false", flush=True)
    native_environment = dict(environment, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:disable_coredump=1")
    result = subprocess.run([str(binary)], env=native_environment, capture_output=True,
                            text=True, timeout=10)
    receipt = ("XDO_CONSTRUCTOR_NATIVE=pass cases=276 faults=22 paths=3 repeats=4 accepted=12 refused=264 "
               "events=24 xtest_refusal=pre-allocation snapshot=single allocations=paired maps=paired display_transfer=success-only "
               "caller_display=usable descriptors=retired tasks=retired sanitizer=address "
               "heap_scope=owned-allocations whole_app=false")
    expected = [f"XDO_CONSTRUCTOR_ROUND=pass round={round} cases=69" for round in range(4)] + [receipt]
    errors = ("xdo_new: XTEST extension unavailable on 'unix/:98.0'\n" * 3
              + "xdo_new: context allocation failed\n" * 3
              + "xdo_new: keyboard map unavailable or invalid\n" * 60) * 4
    require(result.returncode == 0 and result.stdout.splitlines() == expected and result.stderr == errors,
            f"native constructor result differs: {result}")
    print(result.stdout, end="", flush=True)
    binary.unlink()


def input_state_queries(root, environment):
    fixture = root / "scripts/test-xdo-input-state.c"
    native = root / "libs/libxdo-sys-stub/native/xdo.c"
    binary = Path("/build/xdo-input-state")
    command = ["/usr/bin/cc", "-std=c99", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
               "-fsanitize=address", "-fno-omit-frame-pointer", str(fixture), str(native),
               "-lX11", "-lXtst", "-lX11-xcb", "-lxcb", "-o", str(binary)]
    for symbol in ("free", "XGetXCBConnection", "xcb_connection_has_error",
                   "xcb_query_pointer_reply", "xcb_query_keymap_reply", "XInternAtom",
                   "XkbGetNamedIndicator", "XTestFakeKeyEvent", "XTestFakeButtonEvent",
                   "XChangeKeyboardMapping", "XkbLockGroup"):
        command.append(f"-Wl,--wrap={symbol}")
    subprocess.run(command, env=environment, check=True, timeout=30)
    print("XDO_INPUT_STATE_BUILD " + " ".join(
        f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}"
        for name, path in (("fixture", fixture), ("native_c", native), ("binary", binary))) +
        " native_source=complete sanitizer=address whole_app=false", flush=True)
    receipt = ("XDO_INPUT_STATE_NATIVE=pass faults=23 repeats=4 refused=92 recovery=92 "
               "output=unpublished-on-error effects=none replies=retired pointer_screens=2 "
               "button_mask=preserved mapping=unchanged descriptors=retired tasks=retired "
               "sanitizer=address whole_app=false")
    result = subprocess.run([str(binary)], env=dict(environment, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:disable_coredump=1"),
                            capture_output=True, text=True, timeout=10)
    require(result.returncode == 0 and not result.stderr and result.stdout.splitlines() == [receipt],
            f"native input-state query result differs: {result}")
    print(receipt, flush=True)
    binary.unlink()


def scratch_keys(root, environment):
    scratch_source = root / "scripts/test-xdo-scratch-key.c"
    scratch_binary = Path("/build/xdo-scratch-key")
    native_source = root / "libs/libxdo-sys-stub/native"
    subprocess.run(["/usr/bin/cc", "-std=c99", "-O1", "-g", "-fsanitize=address",
                    "-fno-omit-frame-pointer", "-Wl,--wrap=XkbGetMap", "-Wl,--wrap=XkbFreeKeyboard",
                    "-Wl,--wrap=XkbChangeMap",
                    "-Wl,--wrap=XkbGetState", "-Wl,--wrap=XkbLockGroup",
                    "-Wl,--wrap=XTestFakeKeyEvent", "-Wl,--wrap=XChangeKeyboardMapping",
                    "-Wl,--wrap=XGetModifierMapping", "-Wl,--wrap=XFreeModifiermap",
                    "-Wl,--wrap=XGetXCBConnection", "-Wl,--wrap=xcb_connection_has_error",
                    "-Wl,--wrap=xcb_query_keymap_reply", "-Wl,--wrap=free",
                    "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=realloc", "-Wl,--wrap=strdup",
                    str(scratch_source), str(native_source / "xdo.c"),
                    "-lX11", "-lXtst", "-lX11-xcb", "-lxcb", "-o", str(scratch_binary)],
                   env=environment, check=True, timeout=30)
    print("XDO_SCRATCH_BUILD " + " ".join(
        f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}" for name, path in (
            ("fixture", scratch_source), ("native_c", native_source / "xdo.c"),
            ("binary", scratch_binary))) + " native_source=complete sanitizer=address whole_app=false", flush=True)
    scratch_environment = dict(environment, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:disable_coredump=1")
    socket_path, lock_path = Path("/tmp/.X11-unix/X98"), Path("/tmp/.X98-lock")
    require(not socket_path.exists() and not lock_path.exists(), "scratch display already present")
    with open("/tmp/xdo-scratch-xvfb.log", "xb") as log:
        server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                                   "-nolisten", "tcp", "-ac", "-noreset"],
                                  env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while not socket_path.is_socket():
                require(server.poll() is None and time.monotonic() < deadline, "scratch Xvfb not ready")
                time.sleep(0.01)
            subprocess.run([str(scratch_binary)], env=scratch_environment, check=True, timeout=5)
            require(server.poll() is None, "scratch Xvfb exited during native cases")
        except BaseException:
            log.flush()
            print(Path(log.name).read_text()[:4096], flush=True)
            raise
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
    require(server.returncode == 0 and not socket_path.exists() and not lock_path.exists(),
            "scratch Xvfb/socket/lock retirement differs")
    scratch_binary.unlink()
    print("XDO_SCRATCH_DISPLAY=retired owner=dedicated-xvfb server=joined socket=absent lock=absent "
          "later_tests=fresh-display", flush=True)


def rdev_keyboard_mapping(root, environment, build):
    # Compile the complete pinned mapping and enum bodies, without rdev's listener,
    # simulator or optional serialization/EnumIter derives. This is a partial crate.
    directory = root / "xdo-vendor/rdev-0.5.0-2"
    checksum = directory / ".cargo-checksum.json"
    require(hashlib.sha256(checksum.read_bytes()).hexdigest() ==
            "20fd1e4760d42f53240bb8da143336977afc390fd83188abac8316b43a0141ef",
            "rdev mapping manifest differs")
    manifest = json.loads(checksum.read_bytes())
    for name, expected in manifest["files"].items():
        path = directory / name
        require(not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                f"rdev mapping input differs: {name}")
    source = (directory / "src/rdev.rs").read_text()
    enums = []
    for name in ("Key", "RawKey"):
        start = f"pub enum {name} {{"
        require(source.count(start) == 1, "rdev enum extraction differs")
        begin = source.index(start)
        end = source.index("\n}", begin) + 2
        enums.append("#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]\n" + source[begin:end])
    facade = build / "rdev-mapping.rs"
    facade.write_text("pub mod rdev { pub type KeyCode = u32;\n" + "\n".join(enums) +
                      "\n}\npub use rdev::Key;\n" +
                      f'#[path="{directory}/src/keycodes/linux.rs"] mod linux;\n' +
                      "pub use linux::code_from_key as linux_keycode_from_key;\n")
    library = build / "librdev.rlib"
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2021", "--crate-type=rlib",
                    "--crate-name=rdev", str(facade), "-o", str(library)],
                   env=environment, check=True, timeout=30)
    print(f"XDO_RDEV_MAPPING_BUILD=pass source=pinned-complete-mapping enum_bodies=exact "
          f"derives=primitive-only simulator=unexecuted facade_sha256={hashlib.sha256(facade.read_bytes()).hexdigest()} "
          f"binary_sha256={hashlib.sha256(library.read_bytes()).hexdigest()}", flush=True)
    return library


def enigo_route(root, environment, checksum, library, providers, before_source):
    mouse_source = root / "scripts/test-xdo-mouse-modifiers.c"
    mouse_binary = Path("/build/xdo-mouse-modifiers")
    subprocess.run(["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(mouse_source),
                    "-L", str(providers["corrected"]), f"-Wl,-rpath,{providers['corrected']}",
                    "-lxdo", "-lX11", "-lXtst", "-o", str(mouse_binary)],
                   env=environment, check=True, timeout=15)
    print("XDO_MOUSE_MODIFIERS_BUILD " + " ".join(
        f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}" for name, path in (
            ("fixture", mouse_source), ("binary", mouse_binary),
            ("provider", providers["corrected"] / "libxdo.so.3"))) +
        " loader=direct-native-test whole_app=unexecuted", flush=True)
    subprocess.run([str(mouse_binary)], env=environment, check=True, timeout=5)
    mouse_binary.unlink()
    # Extract the real public types, scroll check and traits; never substitute a test API.
    source = (root / "libs/enigo/src/lib.rs").read_text()
    start = "///\npub type ResultType ="
    end = '#[cfg(any(target_os = "android", target_os = "ios"))]\nstruct Enigo;'
    require(source.count(start) == 1 and source.count(end) == 1,
            "production Enigo API extraction boundary differs")
    declarations = source[source.index(start):source.index(end)]
    require(declarations.count("mod keyboard_state;") == 1, "keyboard state module boundary differs")
    declarations = declarations.replace("mod keyboard_state;",
        '#[path="/work/libs/enigo/src/keyboard_state.rs"] mod keyboard_state;')
    api = Path("/build/enigo-api.rs")
    with api.open("x") as output:
        output.write(declarations)
    loader = (root / "libs/libxdo-sys-stub/src/lib.rs").read_text()
    state = "#[repr(C)]\n#[derive(Default)]\npub struct XdoInputState {"
    require(loader.count(state) == 1, "native state declaration boundary differs")
    start = loader.index(state)
    Path("/build/xdo-input-state.rs").write_text(loader[start:loader.index("\n}", start)+2])
    binary = Path("/build/enigo-corrected")
    mapping = rdev_keyboard_mapping(root, environment, Path("/build"))
    cleanup_source = root / "scripts/test-x11-enigo-cleanup.c"
    cleanup_helper = Path("/build/enigo-cleanup.o")
    subprocess.run(["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-c",
                    str(cleanup_source), "-o", str(cleanup_helper)],
                   env=environment, check=True, timeout=15)
    command = ["/usr/local/cargo/bin/rustc", "--edition=2021",
               str(root / "scripts/test-x11-enigo-route.rs"), "-o", str(binary),
               "--extern", f"log={library}", "--extern", f"rdev={mapping}",
               "-L", f"native={providers['corrected']}",
               "-C", f"link-arg=-Wl,-rpath,{providers['corrected']}",
               "-C", f"link-arg={cleanup_helper}", "-C", "link-arg=-ldl",
               "-C", "link-arg=-Wl,--export-dynamic-symbol=XkbChangeMap"]
    for symbol in ("xdo_new_with_opened_display", "xdo_free", "XOpenDisplay", "XCloseDisplay"):
        command += ["-C", f"link-arg=-Wl,--wrap={symbol}"]
    subprocess.run(command, env=environment, check=True, timeout=30)
    print("X11_ENIGO_BUILD " + " ".join(
        f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}" for name, path in (
            ("backend", root / "libs/enigo/src/linux/xdo.rs"),
            ("api_source", root / "libs/enigo/src/lib.rs"), ("api_declarations", api),
            ("selector", root / "libs/hbb_common/src/platform/x11_display.rs"),
            ("fixture", root / "scripts/test-x11-enigo-route.rs"),
            ("cleanup_fixture", cleanup_source), ("cleanup_helper", cleanup_helper),
            ("provider", providers["corrected"] / "libxdo.so.3"),
            ("log_manifest", checksum), ("log_library", library), ("binary", binary)))
          + " variant=corrected parent_enigo=unexecuted loader=direct-native-test whole_app=unexecuted", flush=True)
    cleanup_helper.unlink()
    result = subprocess.run([str(binary)], env=environment, capture_output=True,
                            text=True, timeout=15)
    receipt = ("X11_ENIGO_NATIVE=pass source=complete-backend api=production-declarations "
               "selectors_refused=18 canonical_screens=3 contexts=24 context_refusals=32 "
               "constructor_unwinds=16 display_connections=one pointer=selected-root "
               "callbacks=paired descriptors=retired threads=retired scope=xdo-backend")
    require(result.returncode == 0 and not result.stderr and result.stdout.splitlines() == [receipt],
            f"native Enigo backend result differs: {result}")
    print(receipt, flush=True)
    cleanup = subprocess.run([str(binary), "cleanup-refusal"], env=environment,
                             capture_output=True, text=True, timeout=5)
    cleanup_receipt = ("X11_ENIGO_CLEANUP_REFUSAL=pass source=complete-backend-and-provider "
                       "fault=restore-submission repeats=4 cases=8 unwind=4 later_requests=64 "
                       "native_calls=8 contexts=16 events=16 pending=retained teardown=text-before-display "
                       "mapping=restored keys=clear descriptors=retired tasks=retired whole_app=false")
    require(cleanup.returncode == 0 and not cleanup.stderr and cleanup.stdout.splitlines() == [cleanup_receipt],
            f"Enigo cleanup refusal differs: {cleanup}")
    print(cleanup_receipt, flush=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 6095))
        listener.listen(1)
        for scenario in ("route", "diagnostic"):
            native = subprocess.Popen([str(binary), scenario], env=environment,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                output, errors = native.communicate(timeout=5)
                receipt = (f"X11_ENIGO_{scenario.upper()}_CHILD variant=corrected "
                           f"result={'refused' if scenario == 'route' else 'selected-once'} "
                           "descriptors=retired threads=retired")
                require(native.returncode == 0 and not errors
                        and output.decode("ascii").splitlines() == [receipt],
                        f"native Enigo route differs: stdout={output!r} stderr={errors!r}")
                listener.settimeout(0.1)
                try:
                    peer, _ = listener.accept()
                except socket.timeout:
                    pass
                else:
                    peer.close()
                    raise RuntimeError("corrected Enigo constructor attempted TCP")
                print(f"X11_ENIGO_ROUTE_OBSERVED variant=corrected scenario={scenario} "
                      "tcp_accepts=0 native=complete-backend", flush=True)
            finally:
                if native.poll() is None:
                    native.kill()
                native.wait(timeout=5)
                for stream in (native.stdout, native.stderr):
                    stream.close()
    print("X11_ENIGO_ROUTE_NATIVE=pass source=production-backend current_accepts=0 "
          "scenarios=constructor,diagnostic-display-change listener=container-loopback-only "
          "peer=closed children=joined scope=xdo-backend", flush=True)
    enigo_text(root, environment, binary, providers.get("before"))
    for path in (binary, api):
        path.unlink()
    for directory in providers.values():
        (directory / "libxdo.so").unlink()
        (directory / "libxdo.so.3").unlink()
        directory.rmdir()
    if before_source is not None:
        shutil.rmtree(before_source)


def enigo_text(root, environment, binary, before_provider):
    source = root / "scripts/test-x11-text-observer.c"
    observer = Path("/build/text-observer")
    subprocess.run(["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source),
                    "-lX11", "-o", str(observer)], env=environment, check=True, timeout=30)
    print("X11_ENIGO_TEXT_BUILD "
          f"observer_source_sha256={hashlib.sha256(source.read_bytes()).hexdigest()} "
          f"observer_binary_sha256={hashlib.sha256(observer.read_bytes()).hexdigest()} "
          f"injector_binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()}", flush=True)
    for scenario, locale in (("cleared", None), ("C", "C"), ("invalid", "rd-test-unavailable")):
        native_env = {key: value for key, value in environment.items()
                      if key != "LANG" and not key.startswith("LC_")}
        if locale is not None:
            native_env["LC_ALL"] = locale
        native = subprocess.Popen([str(observer)], env=native_env,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as streams:
                streams.register(native.stdout, selectors.EVENT_READ)
                require(streams.select(2), "native text observer did not become ready")
                require(os.read(native.stdout.fileno(), 64) == b"X11_TEXT_OBSERVER=ready\n",
                        "native text observer readiness differs")
            result = subprocess.run([str(binary), "text"], env=native_env, capture_output=True,
                                    text=True, timeout=5)
            output, errors = native.communicate(timeout=5)
            print(output.decode("ascii"), end="", flush=True)
            require(result.returncode == 0 and not result.stderr and result.stdout.splitlines() ==
                    ["X11_ENIGO_TEXT_CHILD=pass scalar_pairs=7 controls=preadmission-refused descriptors=retired threads=retired"]
                    and native.returncode == 0 and not errors
                    and output.splitlines()[-1:] == [b"X11_TEXT_OBSERVER=retired events=14 keys_clear=1"],
                    f"native text differs in {scenario}: injector={result} observer={output!r} errors={errors!r}")
            print(f"X11_ENIGO_TEXT_OBSERVED scenario={scenario} scalar_pairs=7 events=14 keys_clear=1", flush=True)
        finally:
            if native.poll() is None:
                native.kill()
            native.wait(timeout=5)
            for stream in (native.stdout, native.stderr):
                stream.close()
    print("X11_ENIGO_TEXT_NATIVE=pass source=complete-backend locale_scenarios=3 scalar_pairs=21 "
          "events=42 controls=preadmission-refused keys=clear observers=joined descriptors=retired "
          "scope=native-key-events whole_app=false", flush=True)
    probe_source = root / "scripts/test-xdo-keymap-lifetime.c"
    probe = Path("/build/xdo-keymap-lifetime.so")
    subprocess.run(["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
                    str(probe_source), "-ldl", "-o", str(probe)], env=environment, check=True, timeout=30)
    print("X11_XDO_KEYMAP_PROBE_BUILD "
          f"source_sha256={hashlib.sha256(probe_source.read_bytes()).hexdigest()} "
          f"binary_sha256={hashlib.sha256(probe.read_bytes()).hexdigest()}", flush=True)
    enigo_layout(environment, binary, observer, probe, before_provider)
    probe.unlink()
    observer.unlink()


def enigo_layout(environment, binary, observer, probe, before_provider):
    def phase(child, expected):
        with selectors.DefaultSelector() as streams:
            streams.register(child.stdout, selectors.EVENT_READ)
            require(streams.select(2), "native layout phase did not become ready")
            require(os.read(child.stdout.fileno(), 64) == expected, "native layout phase differs")

    cases = [("corrected", "layout", 1), ("corrected", "layout-repeat", 32)]
    if before_provider is not None:
        cases.insert(0, ("before", "layout", 1))
    for variant, scenario, pairs in cases:
        native = subprocess.Popen([str(observer), scenario], env=environment,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        injector = None
        try:
            phase(native, b"X11_TEXT_OBSERVER=ready\n")
            injector_env = {**environment, "LD_PRELOAD": str(probe)}
            if variant == "before":
                injector_env["LD_LIBRARY_PATH"] = str(before_provider) + ":" + environment["LD_LIBRARY_PATH"]
            injector = subprocess.Popen([str(binary), scenario], env=injector_env,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            phase(injector, b"X11_ENIGO_LAYOUT_CHILD=ready\n")
            native.stdin.write(b"M")
            native.stdin.flush()
            phase(native, b"X11_TEXT_LAYOUT=changed-after-construction\n")
            start = time.monotonic()
            output, errors = injector.communicate(input=b"D", timeout=5)
            observed, native_errors = native.communicate(timeout=5)
            elapsed_ms = (time.monotonic() - start) * 1000
            print(observed.decode("ascii"), end="", flush=True)
            print(errors.decode("ascii"), end="", flush=True)
            receipt = (f"X11_ENIGO_LAYOUT_CHILD=pass pairs={pairs} mapping_refusal=explicit "
                       "descriptors=retired threads=retired").encode("ascii")
            heap = ("X11_XDO_KEYMAP_HEAP allocations=2 retirements=0 live=2\n" if variant == "before" else
                    f"X11_XDO_KEYMAP_HEAP allocations={pairs + 1} retirements={pairs + 1} live=0\n")
            require(injector.returncode == 0 and errors.decode("ascii") == heap
                    and output.splitlines() == [receipt]
                    and native.returncode == 0 and not native_errors
                    and observed.splitlines()[-1:] ==
                    [f"X11_TEXT_OBSERVER=retired events={pairs * 2} keys_clear=1".encode("ascii")],
                    f"native layout differs: injector={injector.returncode}/{output!r}/{errors!r} "
                    f"observer={native.returncode}/{observed!r}/{native_errors!r}")
            if variant == "before":
                print("X11_XDO_DESTRUCTOR_BEFORE=observed source_delta=one-call allocations=2 "
                      "retirements=0 live=2 keys=correct children=joined scope=xdo-descriptor-class", flush=True)
            print(f"X11_ENIGO_LAYOUT_OBSERVED variant={variant} scenario={scenario} pairs={pairs} "
                  f"submission_and_retirement_ms={elapsed_ms:.3f}", flush=True)
        finally:
            for child in (injector, native):
                if child is None:
                    continue
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout, child.stderr):
                    stream.close()
    print("X11_ENIGO_LAYOUT_NATIVE=pass source=complete-backend map=changed-after-construction "
          "cases=2 scalar_pairs=33 events=66 mapping_refusals=2 keys=clear children=joined "
          "descriptors=retired keymap_descriptors=freed scope=native-key-events whole_app=false",
          flush=True)


def thread_contexts(root, environment, checksum, library, provider, position_only=False):
    owner = root / "src/platform/linux/native_context.rs"
    fixture = root / "scripts/test-x11-thread-context.rs"
    binary = Path("/build/thread-contexts")
    provider_library = (provider / "libxdo.so.3").resolve(strict=True)
    provider_digest = hashlib.sha256(provider_library.read_bytes()).hexdigest()
    source = (root / "src/platform/linux.rs").read_text()
    start, end = "pub fn get_cursor_pos()", "/// Clip cursor - Linux implementation is a no-op."
    require(source.count(start) == 1 and source.count(end) == 1,
            "production cursor-position extraction boundaries differ")
    cursor = Path("/build/x11-cursor-position.rs")
    with cursor.open("x") as output:
        output.write(source[source.index(start):source.index(end)])
    start, end = "pub fn reset_input_cache()", "pub fn get_focused_display("
    require(source.count(start) == 1 and source.count(end) == 1,
            "production cursor reset extraction boundaries differ")
    reset = Path("/build/x11-cursor-reset.rs")
    with reset.open("x") as output:
        output.write(source[source.index(start):source.index(end)])
    bounds_source = root / "src/platform/mod.rs"
    bounds_text = bounds_source.read_text()
    start, end = "pub(crate) const MAX_CURSOR_RGBA_BYTES:", "#[cfg(all(test, not(any(target_os"
    require(bounds_text.count(start) == 1 and bounds_text.count(end) == 1,
            "production cursor bound extraction boundaries differ")
    bounds = Path("/build/x11-cursor-bounds.rs")
    with bounds.open("x") as output:
        output.write(bounds_text[bounds_text.index(start):bounds_text.index(end)])
    subprocess.run(["/usr/local/cargo/bin/rustc", "--edition=2021", str(fixture),
                    "-o", str(binary), "--extern", f"log={library}",
                    "-L", f"native={provider}", "-C", f"link-arg=-Wl,-rpath,{provider}",
                    "-C", "link-arg=-Wl,--wrap=XCloseDisplay", "-C", "link-arg=-Wl,--wrap=XOpenDisplay",
                    "-C", "link-arg=-Wl,--wrap=xdo_free", "-C", "link-arg=-Wl,--wrap=xdo_new",
                    "-C", "link-arg=-Wl,--wrap=XFixesGetCursorImage", "-C", "link-arg=-Wl,--wrap=XFree"],
                   env={**environment, "X11_CONTEXT_TEST_XDO": str(provider_library)},
                   check=True, timeout=30)
    print("X11_THREAD_CONTEXT_BUILD "
          f"owner_sha256={hashlib.sha256(owner.read_bytes()).hexdigest()} "
          f"fixture_sha256={hashlib.sha256(fixture.read_bytes()).hexdigest()} "
          f"constructors_sha256={hashlib.sha256((root / 'src/platform/linux/x11_context.rs').read_bytes()).hexdigest()} "
          f"selector_sha256={hashlib.sha256((root / 'libs/hbb_common/src/platform/x11_display.rs').read_bytes()).hexdigest()} "
          f"consumer_sha256={hashlib.sha256((root / 'src/platform/linux.rs').read_bytes()).hexdigest()} "
          f"cursor_declarations_sha256={hashlib.sha256(cursor.read_bytes()).hexdigest()} "
          f"cursor_reset_declarations_sha256={hashlib.sha256(reset.read_bytes()).hexdigest()} "
          f"cursor_snapshot_sha256={hashlib.sha256((root / 'src/platform/linux/x11_cursor.rs').read_bytes()).hexdigest()} "
          f"cursor_bounds_source_sha256={hashlib.sha256(bounds_source.read_bytes()).hexdigest()} "
          f"cursor_bounds_declarations_sha256={hashlib.sha256(bounds.read_bytes()).hexdigest()} "
          f"log_manifest_sha256={hashlib.sha256(checksum.read_bytes()).hexdigest()} "
          f"log_library_sha256={hashlib.sha256(library.read_bytes()).hexdigest()} "
          f"provider_sha256={provider_digest} "
          f"binary_sha256={hashlib.sha256(binary.read_bytes()).hexdigest()} "
          "scope=production-owner whole_app=unexecuted loader=direct-native-test", flush=True)
    result = subprocess.run([str(binary), "cursor-position"], env=environment,
                            capture_output=True, text=True, timeout=15)
    receipt = ("XDO_CURSOR_POSITION_NATIVE=pass selectors=3 contexts=12 moves=96 roots=0,1 "
               "starting_root=opposite selected_root=observed retained_display=unchanged "
               "callbacks=paired descriptors=retired tasks=retired "
               "scope=production-platform-component whole_app=false")
    require(result.returncode == 0 and not result.stderr and result.stdout.splitlines() == [receipt],
            f"native platform cursor destination result differs: {result}")
    print(receipt, flush=True)
    if position_only:
        return
    result = subprocess.run([str(binary)], env=environment, capture_output=True,
                            text=True, timeout=15)
    receipt = ("X11_THREAD_CONTEXT_NATIVE=pass source=production-owner-and-constructors old=retained-after-thread-exit "
               "old_threads=8 corrected_threads=32 unwind_threads=16 contexts=70 "
               "constructor_refusals=32 selectors_refused=18 canonical_screens=3 "
               "callbacks=paired descriptors=retired scope=native-owner")
    lines = result.stdout.splitlines()
    # The private product provider reports each deliberate failed constructor on stderr.
    refusals = "Error: Can't open display: unix/:97.0\n" * 16
    require(result.returncode == 0 and result.stderr == refusals
            and len(result.stdout) + len(result.stderr) <= 4096
            and len(lines) == 3 and lines[-1] == receipt,
            f"native thread-context result differs: {result}")
    loaded = [line.removeprefix("X11_THREAD_CONTEXT_LOADED library=") for line in lines[:2]]
    require(len(set(loaded)) == 2 and str(provider_library) in loaded
            and sum(bool(re.fullmatch(r"/usr/lib/x86_64-linux-gnu/libX11\.so\.[0-9.]+", path))
                    for path in loaded) == 1, "native context library identity differs")
    for line, path in zip(lines[:2], loaded):
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        require(path != str(provider_library) or digest == provider_digest,
                "loaded private XDO provider changed after compilation")
        print(f"{line} sha256={digest}", flush=True)
    print(receipt, flush=True)
    require(not Path("/tmp/.X11-unix/X95").exists(), "platform route's Unix display is present")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as route_listener:
        route_listener.bind(("127.0.0.1", 6095))
        route_listener.listen(1)
        for component in ("xlib", "xdo"):
            for variant in ("historical", "corrected"):
                local_route(binary, variant, environment, route_listener, component)
    print("X11_PLATFORM_ROUTE_NATIVE=pass source=production-constructors old=null-call-shape "
          "callers=xlib,xdo old_accepts=2 current_accepts=0 listener=container-loopback-only "
          "peer=closed children=joined scope=platform-constructors", flush=True)
    startup_retry(root, binary, environment)
    authenticated_contexts(binary, environment)
    result = subprocess.run([str(binary), "concurrent-contexts"], env=environment,
                            capture_output=True, text=True, timeout=5)
    receipt = ("X11_CONCURRENT_CONTEXTS_NATIVE=pass source=complete-context-module "
               "native_init=ready-at-main fixture_init=none workers=8 simultaneous_contexts=16 "
               "unique_owners=16 reuses_per_owner=64 queries=1024 server=real callbacks=paired "
               "live_resources=observed descriptors=retired threads=joined scope=private-product-provider")
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 4096
            and result.stdout.splitlines() == [receipt],
            f"native concurrent thread-context result differs: {result}")
    print(receipt, flush=True)
    result = subprocess.run([str(binary), "cursor-snapshots"], env=environment,
                            capture_output=True, text=True, timeout=5)
    receipt = ("X11_CURSOR_SNAPSHOT_NATIVE=pass source=complete-module old=two-query-call-shape "
               "serial_mismatches=32 current_snapshots=64 changes_between_phases=32 pixels=server-real "
               "second_query=absent query_calls=170 images=170 frees=170 live_image_peak=1 "
               "replacements=16 wrong_serial=refused repeated_consume=refused reset=discarded-and-idempotent retained_thread_exits=8 "
               "display_owners=9 descriptors=retired threads=joined scope=native-cursor-snapshot")
    lines = result.stdout.splitlines()
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 4096
            and len(lines) == 2 and lines[1] == receipt,
            f"native cursor snapshot result differs: {result}")
    path = lines[0].removeprefix("X11_CURSOR_LOADED library=")
    require(re.fullmatch(r"/usr/lib/x86_64-linux-gnu/libXfixes\.so\.[0-9.]+", path),
            "native cursor library identity differs")
    print(f"{lines[0]} sha256={hashlib.sha256(Path(path).read_bytes()).hexdigest()}", flush=True)
    print(receipt, flush=True)
    binary.unlink()
    cursor.unlink()
    reset.unlink()
    bounds.unlink()


def startup_retry(root, binary, environment):
    snapshot = root / "scripts/fixtures/x11-thread-context-before-retry.rs"
    require(hashlib.sha256(snapshot.read_bytes()).hexdigest() ==
            "3b58902c6ee90116375b77b461b642937e1f7a78dbf7ee6778fb64d4b771749c",
            "exact historical 7519afaf platform X11/XDO initializers differ")
    print(f"X11_STARTUP_BASELINE source=7519afaf initializers_sha256="
          f"{hashlib.sha256(snapshot.read_bytes()).hexdigest()} scope=exact-tls-declarations", flush=True)
    with open("/tmp/x11-startup-retry-xvfb.log", "xb") as log:
        for component in ("xlib", "xdo"):
            for variant in ("historical", "corrected"):
                require(not Path("/tmp/.X11-unix/X97").exists(), "startup display is not initially absent")
                native = subprocess.Popen([str(binary), f"retry-{component}-{variant}"], env=environment,
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                server = None
                try:
                    # Read one bounded readiness line without leaving an unbounded pipe wait.
                    ready = bytearray()
                    deadline = time.monotonic() + 5
                    with selectors.DefaultSelector() as streams:
                        streams.register(native.stdout, selectors.EVENT_READ)
                        while b"\n" not in ready:
                            remaining = deadline - time.monotonic()
                            require(remaining > 0 and streams.select(remaining), "startup refusal readiness timed out")
                            data = os.read(native.stdout.fileno(), 257 - len(ready))
                            require(data and len(ready) + len(data) <= 256, "startup readiness missing or oversized")
                            ready.extend(data)
                    require(ready.decode("ascii") == f"X11_STARTUP_READY variant={variant} component={component} "
                            "failed=1 cooldown_calls=32 native_opens=1\n" and native.poll() is None,
                            "startup cached-failure/cooldown observation differs")
                    server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":97", "-screen", "0", "640x480x24",
                                               "-nolisten", "tcp", "-ac", "-noreset"],
                                              env=environment, stdout=log, stderr=subprocess.STDOUT)
                    deadline = time.monotonic() + 5
                    while not Path("/tmp/.X11-unix/X97").is_socket():
                        require(server.poll() is None and time.monotonic() < deadline, "startup Xvfb not ready")
                        time.sleep(0.01)
                    output, errors = native.communicate(input=b"S", timeout=5)
                    expected_errors = b"Error: Can't open display: unix/:97.0\n" if component == "xdo" else b""
                    receipt = (f"X11_STARTUP_CHILD variant={variant} component={component} "
                               f"result={'cached-failure' if variant == 'historical' else 'recovered'} "
                               f"native_opens={1 if variant == 'historical' else 2} worker=same callbacks=paired "
                               "descriptors=retired threads=retired")
                    require(native.returncode == 0 and errors == expected_errors
                            and output.decode("ascii").splitlines() == [receipt]
                            and server.poll() is None, f"native same-worker startup result differs: {output!r} {errors!r}")
                    print(receipt, flush=True)
                finally:
                    try:
                        if native.poll() is None:
                            native.kill()
                        native.wait(timeout=5)
                        for stream in (native.stdin, native.stdout, native.stderr):
                            stream.close()
                    finally:
                        if server is not None:
                            if server.poll() is None:
                                server.terminate()
                            server.wait(timeout=5)
                require(server.returncode == 0 and not Path("/tmp/.X11-unix/X97").exists(),
                        "startup Xvfb/socket retirement differs")
    print("X11_STARTUP_RETRY_NATIVE=pass source=complete-context-module old=exact-tls-initializers "
          "components=xlib,xdo cases=4 old=cached-failure current=same-worker-recovery "
          "cooldown_ms=1000 cooldown_calls=32 healthy_reuses=32 reentrant=refused "
          "queries=server-real callbacks=paired descriptors=retired threads=retired "
          "server=owned-and-joined scope=thread-context-startup", flush=True)


def authenticated_contexts(binary, environment):
    directory = Path("/tmp/x11-native-auth")
    directory.mkdir(mode=0o700)
    server = None
    try:
        # XauReadAuth's big-endian family and four counted fields. These known
        # fixture cookies belong only to this disposable, networkless display.
        # FamilyLocal/hostname/display matching is left to the native library.
        fields = (socket.gethostname().encode("ascii"), b"93", b"MIT-MAGIC-COOKIE-1")
        prefix = struct.pack(">H", 256) + b"".join(struct.pack(">H", len(field)) + field for field in fields)
        for credential, cookie in (("valid", bytes(range(16))), ("wrong", bytes(reversed(range(16))))):
            path = directory / credential
            with path.open("xb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(prefix + struct.pack(">H", len(cookie)) + cookie)
        require(not (directory / "missing").exists(), "missing Xauthority fixture unexpectedly exists")
        require(not Path("/tmp/.X11-unix/X93").exists(), "authenticated display is already present")
        with (directory / "server.log").open("xb") as log:
            server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":93", "-screen", "0", "640x480x24",
                                       "-nolisten", "tcp", "-auth", str(directory / "valid"), "-noreset"],
                                      env=environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 5
                while not Path("/tmp/.X11-unix/X93").is_socket():
                    require(server.poll() is None and time.monotonic() < deadline, "authenticated Xvfb not ready")
                    time.sleep(0.01)
                # A second valid connection after both negatives distinguishes
                # credential refusal from a dead server or broken constructor.
                for credential in ("valid", "wrong", "missing", "valid"):
                    env = dict(environment, DISPLAY=":93", XAUTHORITY=str(directory / credential))
                    result = subprocess.run([str(binary), f"auth-{credential}"], env=env,
                                            capture_output=True, text=True, timeout=5)
                    admitted = credential == "valid"
                    reason = ("Invalid MIT-MAGIC-COOKIE-1 key" if credential == "wrong" else
                              "Authorization required, but no authorization protocol specified")
                    expected_errors = [] if admitted else [reason, reason, "Error: Can't open display: unix/:93.0"]
                    receipt = (f"X11_AUTH_CHILD credential={credential} result={'admitted' if admitted else 'refused'} "
                               f"components=xlib,xdo native_opens=2 contexts={2 if admitted else 0} "
                               f"queries={'server-real' if admitted else 'unavailable'} callbacks=paired "
                               "descriptors=retired threads=retired")
                    require(result.returncode == 0 and [line for line in result.stderr.splitlines() if line] == expected_errors
                            and len(result.stdout) + len(result.stderr) <= 4096
                            and result.stdout.splitlines() == [receipt] and server.poll() is None,
                            f"native authenticated-context result differs: {result}")
                    print(receipt, flush=True)
            except BaseException:
                log.flush()
                print((directory / "server.log").read_text()[:4096], flush=True)
                raise
            finally:
                if server.poll() is None:
                    server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
        require(server.returncode == 0 and not Path("/tmp/.X11-unix/X93").exists(),
                "authenticated Xvfb/socket retirement differs")
    finally:
        for name in ("valid", "wrong", "server.log"):
            path = directory / name
            if path.exists():
                path.unlink()
        directory.rmdir()
    print("X11_AUTH_NATIVE=pass source=complete-context-module components=xlib,xdo cases=4 "
          "valid=2 wrong=1 missing=1 contexts=4 refusals=4 queries=server-real "
          "callbacks=paired descriptors=retired threads=retired server=owned-and-joined "
          "credentials=private-fixture network=none scope=native-cookie-authentication", flush=True)


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
               "--extern", "libc=/focus-input/liblibc.rlib",
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
               "setup_faults=7 selectors_refused=18 canonical=normalized screen=selected constructors_refused=16 thread_exits=16 allocations=paired "
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


def local_route(binary, variant, environment, listener, component):
    # This listener exists only on the network-none container's private loopback.
    # Acceptance observes the actual native connector's route, not a mock login.
    require(component in ("focus", "capture", "xlib", "xdo"), "unknown route-fixture component")
    prefix = f"X11_{component.upper()}_ROUTE"
    scenario = ("route" if component == "focus" else "server-route" if component == "capture"
                else f"route-{component}-{variant}")
    native = subprocess.Popen([str(binary), scenario], env=environment,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if variant == "historical":
            listener.settimeout(2)
            peer, address = listener.accept()
            with peer:
                require(address[0] == "127.0.0.1", "unexpected route-fixture peer")
            # Closing the exact accepted peer releases native setup without
            # sending an X11 reply or accepting application/session authority.
        output, errors = native.communicate(timeout=5)
        expected_errors = b""
        if component == "xdo":
            name = "(default)" if variant == "historical" else "unix/:95.0"
            expected_errors = f"Error: Can't open display: {name}\n".encode("ascii")
        require(native.returncode == 0 and errors == expected_errors and len(output) <= 4096
                and output.decode("ascii").splitlines() == [
                    f"{prefix}_CHILD variant={variant} result=refused descriptors=retired threads=retired"],
                f"native route completion differs: stdout={output!r} stderr={errors!r}")
        if variant == "corrected":
            listener.settimeout(0.1)
            try:
                peer, _ = listener.accept()
            except socket.timeout:
                pass
            else:
                peer.close()
                raise RuntimeError("corrected local display attempted a TCP fallback")
        print(f"{prefix}_OBSERVED variant={variant} tcp_accepts={int(variant == 'historical')} "
              "native=complete-module connection=retired", flush=True)
    finally:
        if native.poll() is None:
            native.kill()
        native.wait(timeout=5)
        for stream in (native.stdout, native.stderr):
            stream.close()


def authenticated_focus(binary, environment):
    directory = Path("/tmp/x11-focus-auth")
    directory.mkdir(mode=0o700)
    try:
        for protocol in ("MIT-MAGIC-COOKIE-1", "XDM-AUTHORIZATION-1"):
            fields = (socket.gethostname().encode("ascii"), b"92", protocol.encode("ascii"))
            prefix = struct.pack(">H", 256) + b"".join(struct.pack(">H", len(field)) + field for field in fields)
            valid = bytearray(range(16))
            if protocol == "XDM-AUTHORIZATION-1":
                valid[8] = 0  # Xserver requires the first XDM key octet to be zero.
            for credential, cookie in (("valid", bytes(valid)), ("wrong", bytes(reversed(valid)))):
                with (directory / credential).open("xb") as output:
                    os.fchmod(output.fileno(), 0o600)
                    output.write(prefix + struct.pack(">H", len(cookie)) + cookie)
            require(not (directory / "missing").exists() and not Path("/tmp/.X11-unix/X92").exists(),
                    "focus authentication fixture already exists")
            with (directory / "server.log").open("xb") as log:
                server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":92", "-screen", "0", "640x480x24",
                                           "-nolisten", "tcp", "-auth", str(directory / "valid"), "-noreset"],
                                          env=environment, stdout=log, stderr=subprocess.STDOUT)
                try:
                    until = time.monotonic() + 5
                    while not Path("/tmp/.X11-unix/X92").is_socket():
                        require(server.poll() is None and time.monotonic() < until, "authenticated focus Xvfb not ready")
                        time.sleep(0.01)
                    for credential in ("valid", "wrong", "missing", "valid"):
                        env = dict(environment, DISPLAY=":92", XAUTHORITY=str(directory / credential))
                        result = subprocess.run([str(binary), f"auth-{credential}"], env=env,
                                                capture_output=True, text=True, timeout=5)
                        admitted = credential == "valid"
                        receipt = (f"X11_FOCUS_AUTH_NATIVE credential={credential} "
                                   f"result={'admitted' if admitted else 'refused'} "
                                   f"geometry={'server-real' if admitted else 'unavailable'} "
                                   "descriptors=retired workers=joined")
                        require(result.returncode == 0 and result.stdout.splitlines() == [receipt]
                                and bool(result.stderr) == (not admitted)
                                and len(result.stdout) + len(result.stderr) <= 4096 and server.poll() is None,
                                f"native focus authentication differs: {protocol} {result}")
                        print(receipt + f" protocol={protocol}", flush=True)
                except BaseException:
                    log.flush()
                    print((directory / "server.log").read_text()[:4096], flush=True)
                    raise
                finally:
                    if server.poll() is None:
                        server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)
                require(server.returncode == 0 and not Path("/tmp/.X11-unix/X92").exists(),
                        "authenticated focus server/socket retirement differs")
            for name in ("valid", "wrong", "server.log"):
                (directory / name).unlink()
    finally:
        for name in ("valid", "wrong", "server.log"):
            path = directory / name
            if path.exists():
                path.unlink()
        directory.rmdir()
    print("X11_FOCUS_AUTH_NATIVE=pass protocols=MIT-MAGIC-COOKIE-1,XDM-AUTHORIZATION-1 cases=8 "
          "valid=4 wrong=2 missing=2 geometry=server-real descriptors=retired workers=joined "
          "server=owned-and-joined scope=focus-component", flush=True)


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

                    ready = ("X11_FOCUS_LIFECYCLE_READY established=false fixture=open" if scenario == "constructor" else
                             "X11_FOCUS_LIFECYCLE_READY established=true fixture=closed")
                    require(line() == ready
                            and native.poll() is None and server.poll() is None, "focus established readiness differs")
                    if scenario in ("stalled", "backpressure", "constructor"):
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
                        token(b"B" if scenario == "backpressure" else b"C" if scenario == "constructor" else b"T")
                    elif scenario == "dead":
                        server.terminate()
                        server.wait(timeout=5)
                        require(server.returncode == 0, "owned Xvfb retirement differs")
                        token(b"D")
                    else:
                        relay.arm.set()
                        token(b"F")
                    require(line() == "X11_FOCUS_LIFECYCLE_ENTERING source=complete-module", "focus wait entry differs")
                    if scenario == "constructor":
                        # The exact production constructor must return before
                        # this independently owned setup-stall observation ends.
                        deadline = time.monotonic() + 2
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

        route_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            route_listener.bind(("127.0.0.1", 6097))
            route_listener.listen(1)
            for variant in ("historical", "corrected"):
                binary = Path("/build/focus-lifecycle")
                build_focus(root, environment, binary, fixture, historical=variant == "historical")
                source = baseline if variant == "historical" else root / "src/platform/linux/window_focus.rs"
                print(f"X11_FOCUS_LIFECYCLE_BUILD variant={variant} " + " ".join(
                    f"{name}_sha256={hashlib.sha256(path.read_bytes()).hexdigest()}" for name, path in (
                        ("source", source), ("fixture", fixture), ("c_fixture", root / "scripts/test-x11-window-focus.c"),
                        ("deadline", root / "src/platform/linux/window_focus_deadline.rs"),
                        ("auth", root / "src/platform/linux/window_focus_auth.rs"),
                        ("display", root / "libs/hbb_common/src/platform/x11_display.rs"),
                        ("libc", Path("/focus-input/liblibc.rlib")),
                        ("binary", binary))) + " scope=complete-focus-module whole_app=unexecuted", flush=True)
                local_route(binary, variant, environment, route_listener, "focus")
                if variant == "historical":
                    case(binary, variant, "fragmented")
                    case(binary, variant, "backpressure")
                else:
                    for _ in range(4):
                        for scenario in ("stalled", "dead", "fragmented", "backpressure"):
                            case(binary, variant, scenario)
                    for _ in range(4):
                        case(binary, variant, "constructor")
                    authenticated_focus(binary, environment)
                binary.unlink()
        finally:
            route_listener.close()
    print("X11_FOCUS_ROUTE_NATIVE=pass old=tcp-fallback current=unix-only old_accepts=1 current_accepts=0 "
          "listener=container-loopback-only peer=closed children=joined scope=focus-component", flush=True)
    print("X11_FOCUS_LIFECYCLE_NATIVE=pass old=fragmented-and-send-wait source=complete-module "
          "deadline_ms=100 stalled=4 dead=4 fragmented=4 backpressure=4 constructor=4 recovery=same-owner-fresh-connection "
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


def key_input_main():
    require(os.getuid() == 4000 and os.getgid() == 4000 and Path("/.dockerenv").is_file(),
            "key-input shard requires the isolated nonroot container")
    root = Path("/work")
    environment = {"PATH": "/usr/local/cargo/bin:/usr/bin:/bin", "LC_ALL": "C",
                   "HOME": "/tmp", "DISPLAY": ":98", "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "RUSTUP_HOME": "/usr/local/rustup", "CARGO_HOME": "/usr/local/cargo",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    version = subprocess.run(["/usr/local/cargo/bin/rustc", "--version"], env=environment,
                             check=True, capture_output=True, text=True, timeout=5)
    require(version.stdout.strip() == "rustc 1.75.0 (82e1608df 2023-12-21)", "Rust version differs")
    scratch_keys(root, environment)
    checksum, logging = logging_library(root, environment)
    with open("/tmp/xdo-key-xvfb.log", "xb") as log:
        server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                                   "-screen", "1", "800x600x24", "-nolisten", "tcp", "-ac", "-noreset"],
                                  env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while not Path("/tmp/.X11-unix/X98").is_socket():
                require(server.poll() is None and time.monotonic() < deadline, "key-input Xvfb not ready")
                time.sleep(0.01)
            constructor_contexts(root, environment)
            input_state_queries(root, environment)
            providers, before_source = native_xdo(root, environment, historical_destructor=False)
            thread_contexts(root, environment, checksum, logging, providers["corrected"], position_only=True)
            enigo_route(root, environment, checksum, logging, providers, before_source)
            require(server.poll() is None, "key-input Xvfb exited during native cases")
        finally:
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=5)
        require(server.returncode == 0 and not Path("/tmp/.X11-unix/X98").exists()
                and not Path("/tmp/.X98-lock").exists(), "key-input Xvfb/socket/lock retirement differs")
    logging.unlink()
    for name in ("tcp", "tcp6"):
        require(not any(row.split()[3] == "0A" for row in Path("/proc/net", name).read_text().splitlines()[1:]),
                "key-input shard retained TCP")
    for name in ("udp", "udp6"):
        require(len(Path("/proc/net", name).read_text().splitlines()) == 1, "key-input shard retained UDP")
    print("XDO_KEY_INPUT_SHARD=pass source=production-components provider=current-only "
          "parser=absent real_events=observed maps=restored network=none uid=4000 cleanup=joined "
          "whole_app=false", flush=True)


def main():
    require(os.getuid() == 4000 and os.getgid() == 4000, "nonroot fixture principal differs")
    root = Path("/work")
    baseline = root / "scripts/fixtures/x11-display-iter-before.rs"
    require(hashlib.sha256(baseline.read_bytes()).hexdigest() ==
            "1a38147b260c75c2171e3949f9dbb9341ca9986579b6af1fd84ad7848d34e6af",
            "historical e8898566 iterator with constructor-only test adaptation differs")
    old_server = root / "scripts/fixtures/x11-server-before-local-route.rs"
    require(hashlib.sha256(old_server.read_bytes()).hexdigest() ==
            "eddbaf3bec50bf8f37488bb8c080ab9a5e7fa45ba7737a588649fa1216595583",
            "exact historical 0ecef962 capture constructor differs")
    environment = {"PATH": "/usr/local/cargo/bin:/usr/bin:/bin", "LC_ALL": "C",
                   "HOME": "/tmp", "DISPLAY": ":98", "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "RUSTUP_HOME": "/usr/local/rustup", "CARGO_HOME": "/usr/local/cargo",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    version = subprocess.run(["/usr/local/cargo/bin/rustc", "--version"], env=environment,
                             check=True, capture_output=True, text=True, timeout=5)
    require(version.stdout.strip() == "rustc 1.75.0 (82e1608df 2023-12-21)", "Rust version differs")
    macos_cursor_snapshot_state(root, environment)
    checksum, logging = logging_library(root, environment)
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
    scratch_keys(root, environment)
    with open("/tmp/x11-display-xvfb.log", "xb") as log:
        child = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                                  "-screen", "1", "800x600x24", "-nolisten", "tcp", "-ac", "-noreset"],
                                 env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not Path("/tmp/.X11-unix/X98").is_socket():
                require(child.poll() is None and time.monotonic() < deadline, "Xvfb not ready")
                time.sleep(0.05)
            constructor_contexts(root, environment)
            input_state_queries(root, environment)
            providers, before_source = native_xdo(root, environment)
            thread_contexts(root, environment, checksum, logging, providers["corrected"])
            enigo_route(root, environment, checksum, logging, providers, before_source)
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
                    if name == "iter" and variant == "historical":
                        source = baseline
                    elif name == "server" and variant == "historical":
                        source = old_server
                    else:
                        source = root / f"libs/scrap/src/x11/{name}.rs"
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
                      f"{hashlib.sha256(binary.read_bytes()).hexdigest()} "
                      f"server_sha256={hashlib.sha256((work / 'x11/server.rs').read_bytes()).hexdigest()}", flush=True)
            require(not Path("/tmp/.X11-unix/X96").exists(), "capture route's Unix display is present")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as route_listener:
                route_listener.bind(("127.0.0.1", 6096))
                route_listener.listen(1)
                for variant in ("historical", "corrected"):
                    local_route(binaries[variant], variant, environment, route_listener, "capture")
            print("X11_CAPTURE_ROUTE_NATIVE=pass old=tcp-fallback current=unix-only old_accepts=1 current_accepts=0 "
                  "listener=container-loopback-only peer=closed children=joined scope=capture-constructor", flush=True)
            selectors_result = subprocess.run([str(binaries["corrected"]), "server-selectors"], env=environment,
                                              capture_output=True, text=True, timeout=15)
            selectors_receipt = ("X11_CAPTURE_SELECTORS_NATIVE=pass selectors_refused=18 callers=direct,primary,all "
                                 "canonical=normalized screens=server-real descriptors=retired threads=retired "
                                 "scope=capture-constructor")
            require(selectors_result.returncode == 0 and not selectors_result.stderr
                    and len(selectors_result.stdout) <= 4096
                    and selectors_result.stdout.splitlines() == [selectors_receipt],
                    f"native capture selectors differ: {selectors_result}")
            print(selectors_receipt, flush=True)
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
    logging.unlink()
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
    require(sys.argv in ([sys.argv[0]], [sys.argv[0], "--key-input"]), "unknown native shard")
    if len(sys.argv) == 2:
        key_input_main()
    else:
        main()
