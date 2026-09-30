#!/usr/bin/env python3
"""Exercise the real X11 source and Android pixel decoder in an isolated container."""

import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    require(os.getuid() == 4000 and os.getgid() == 4000, "numeric nonroot principal differs")
    module_path = Path("/work/scripts/android-emulator-frame.py")
    spec = importlib.util.spec_from_file_location("frame_decoder", module_path)
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    decoder.self_test()
    fixture = Path("/build/fixture")
    fixture.mkdir(mode=0o700)
    source_sha = hashlib.sha256(Path("/work/scripts/flutter-peer-source-x11.c").read_bytes()).hexdigest()
    build_command = ["/usr/bin/python3", "-B", "-I", "-S",
                     "/work/scripts/build-x11-frame-source.py",
                     "/work/scripts/flutter-peer-source-x11.c", str(fixture), source_sha]
    subprocess.run(build_command, check=True, timeout=45)
    fixture_bytes = (fixture / "frame-source").read_bytes()
    refusal = subprocess.run(build_command, capture_output=True, text=True, timeout=5)
    require(refusal.returncode != 0 and "empty private directory" in refusal.stderr
            and (fixture / "frame-source").read_bytes() == fixture_bytes,
            "fixture builder replaced retained output")
    wrong_output = Path("/build/wrong-digest")
    wrong_output.mkdir(mode=0o700)
    refusal = subprocess.run(build_command[:-2] + [str(wrong_output), "0" * 64],
                             capture_output=True, text=True, timeout=5)
    require(refusal.returncode != 0 and "source digest differs" in refusal.stderr
            and not list(wrong_output.iterdir()), "fixture builder admitted wrong source")
    alias = Path("/build/output-alias")
    alias.symlink_to(wrong_output, target_is_directory=True)
    refusal = subprocess.run(build_command[:-2] + [str(alias), source_sha],
                             capture_output=True, text=True, timeout=5)
    require(refusal.returncode != 0 and "paths are not canonical" in refusal.stderr
            and not list(wrong_output.iterdir()), "fixture builder admitted an output alias")
    fifo = Path("/build/source-fifo")
    os.mkfifo(fifo, mode=0o600)
    refusal = subprocess.run(build_command[:-3] + [str(fifo), str(wrong_output), source_sha],
                             capture_output=True, text=True, timeout=5)
    require(refusal.returncode != 0 and "file authority differs" in refusal.stderr
            and not list(wrong_output.iterdir()), "fixture builder blocked or admitted a FIFO")
    alias.unlink()
    fifo.unlink()
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "DISPLAY": ":98",
                   "LC_ALL": "C", "RUSTDESK_PRESENTATION_TRACE": "1",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    children = []
    display = None
    lib = ctypes.CDLL("libX11.so.6")
    lib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    lib.XOpenDisplay.restype = ctypes.c_void_p
    lib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    lib.XDefaultRootWindow.restype = ctypes.c_ulong
    lib.XGetImage.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                             ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong, ctypes.c_int]
    lib.XGetImage.restype = ctypes.c_void_p
    lib.XGetPixel.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    lib.XGetPixel.restype = ctypes.c_ulong
    lib.XDestroyImage.argtypes = [ctypes.c_void_p]
    lib.XCloseDisplay.argtypes = [ctypes.c_void_p]
    source_path = Path("/tmp/frame-source.log")
    started = time.monotonic()
    try:
        with open("/tmp/frame-xvfb.log", "wb") as xvfb_log:
            children.append(subprocess.Popen([
                "/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                "-nolisten", "tcp", "-ac", "-noreset",
            ], env=environment, stdout=xvfb_log, stderr=subprocess.STDOUT))
        while time.monotonic() - started < 10:
            require(children[0].poll() is None, "Xvfb exited during startup")
            if Path("/tmp/.X11-unix/X98").is_socket():
                display = lib.XOpenDisplay(b":98")
                if display:
                    break
            time.sleep(0.05)
        require(display, "X11 Unix display is unavailable")
        with source_path.open("wb") as source_log:
            children.append(subprocess.Popen([str(fixture / "frame-source")], env=environment,
                                             stdout=source_log, stderr=subprocess.STDOUT))
        source_path.chmod(0o600)
        root = lib.XDefaultRootWindow(display)

        def capture():
            image = lib.XGetImage(display, root, 0, 0, 640, 480, ctypes.c_ulong(-1).value, 2)
            require(image, "actual X11 framebuffer capture failed")
            pixels = bytearray(bytes((197, 190, 184)) * (120 * 200))
            try:
                for y in range(90):
                    for x in range(120):
                        pixel = lib.XGetPixel(image, x * 640 // 120, y * 480 // 90)
                        offset = ((200 - 1 - (55 + y)) * 120 + x) * 3
                        pixels[offset:offset + 3] = bytes(((pixel >> 16) & 255,
                                                        (pixel >> 8) & 255, pixel & 255))
            finally:
                lib.XDestroyImage(image)
            return bytes(pixels)

        def record(pixels, sequence):
            epoch_us = time.time_ns() // 1000
            monotonic_ns = time.monotonic_ns()
            header = (f"seq={sequence} timestamp_us={epoch_us} observed_epoch_us={epoch_us} "
                      f"observed_monotonic_ns={monotonic_ns} width=120 height=200 "
                      f"format=rgb888 orientation=bottom-up bytes={len(pixels)}\n").encode()
            return decoder.parse_record(decoder.MAGIC + header + pixels)

        initial = None
        while time.monotonic() - started < 15:
            require(all(child.poll() is None for child in children), "native child exited")
            try:
                history = decoder.source_history(source_path)
            except decoder.InvalidFrame:
                time.sleep(0.05)
                continue
            old_pixels = capture()
            old_record = record(old_pixels, 1)
            initial = decoder.classify(old_record, history)
            if initial is not None:
                break
        require(initial is not None, "fresh native source pixels were not decoded")
        identity = initial["state"]
        print(f"ANDROID_FRAME_NATIVE_PROGRESS stage=initial identity={identity}", flush=True)
        reported = 0
        history = {}
        while time.monotonic() - started < 100:
            require(all(child.poll() is None for child in children), "native child exited")
            history = decoder.source_history(source_path)
            current = max(history)
            if current - identity >= 256:
                break
            if current // 64 > reported:
                reported = current // 64
                print(f"ANDROID_FRAME_NATIVE_PROGRESS stage=whole-cycle identity={current}", flush=True)
            time.sleep(0.05)
        require(256 <= max(history) - identity <= 264, "actual whole-cycle publication deadline differs")
        fresh_record = record(capture(), 2)
        history = decoder.source_history(source_path)
        fresh = decoder.classify(fresh_record, history)
        require(fresh is not None and 256 <= fresh["state"] - identity <= 264,
                "fresh native full identity was not observed after a whole cycle")
        cli_frame = Path("/tmp/frame-record")
        # The CLI reads the identical real pixel record and exact live publication file.
        epoch_us = time.time_ns() // 1000
        cli_frame.write_bytes(decoder.MAGIC + (
            f"seq=4 timestamp_us={epoch_us} observed_epoch_us={epoch_us} "
            f"observed_monotonic_ns={time.monotonic_ns()} width=120 height=200 "
            f"format=rgb888 orientation=bottom-up bytes={len(fresh_record['pixels'])}\n"
        ).encode() + fresh_record["pixels"])
        cli = subprocess.run(["/usr/bin/python3", "-B", "-I", "-S", str(module_path),
                              "decode", str(cli_frame), str(source_path)], check=True,
                             capture_output=True, text=True, timeout=5)
        require(cli.stdout.split()[0] == str(fresh["state"]), "actual decoder CLI lost full identity")
        # Give old pixels a brand-new capture envelope: observation freshness cannot rescue content.
        stale_record = record(old_pixels, 3)
        analysis = decoder.analyze(stale_record, history)
        require(analysis["chosen"] is None, "whole-cycle stale native pixels passed freshness")
        stale = next((entry for entry in analysis["candidates"] if entry["state"] == identity), None)
        require(stale is not None and stale["age"] >= 64000, "stale native identity or real age was lost")
        require((fresh["state"] - identity) % 256 <= 8, "old modulo predicate would not alias")
        print(f"ANDROID_FRAME_NATIVE_AB=pass old_predicate=accept new=refuse stale_age_ms={stale['age']} "
              f"old_identity={identity} fresh_identity={fresh['state']} fresh_age_ms={fresh['age']}", flush=True)
    finally:
        if display:
            lib.XCloseDisplay(display)
        for child in reversed(children):
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    require(all(child.returncode == 0 for child in children), "native child did not retire cleanly")
    require((fixture / "frame-source").read_bytes() == fixture_bytes,
            "independent fixture changed during native execution")
    history = decoder.source_history(source_path)
    require(source_path.read_bytes().endswith(
        f"FLUTTER_PEER_SOURCE_COMPLETE frames={len(history)}\n".encode()), "source finality is absent")
    for name in ("tcp", "tcp6"):
        require(not any(row.split()[3] == "0A" for row in Path("/proc/net", name).read_text().splitlines()[1:]),
                "native test opened a TCP listener")
    for name in ("udp", "udp6"):
        require(len(Path("/proc/net", name).read_text().splitlines()) == 1, "native test opened UDP")
    print("ANDROID_FRAME_NATIVE=pass source=x11 pixels=actual counter=uint32 age=monotonic "
          "whole_cycle=refused network=none uid=4000 cleanup=joined", flush=True)


if __name__ == "__main__":
    main()
