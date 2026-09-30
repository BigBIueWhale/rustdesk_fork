#!/usr/bin/env python3
"""Exercise the real X11 source and Android pixel decoder in an isolated container."""

import base64
import ctypes
import gzip
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



def inspect_retained_android_frame(decoder):
    # Exact failed Android decoder input from b126297e, not its later ADB PNG.
    # Freeze only the historical envelope clock; no publication history grants freshness.
    data = gzip.decompress(base64.b64decode(
        """H4sIAAAAAAAAA+2d22/b5h2GKcnumuR/KDxgbR2L1MFpanuAsRRIBwxF18F2Gh1ICUnq1b6w5drq
hiU3a4ANSLGbAd12scPFejNgh7sBmxdZoijHbVFg6y6KtiiwFe2wHoat6IZhWy1xv4+kZIqSKMoW
SYl5H7wgePgO5MPPH0UWQZcuLa9cfHT5sfwjX7649MSXLua/uPTI44/mn0ye3ll9ZjF5fn5hqri+
sbpTvLKxlX92ZzE5t5CYOzd/LvnwXPLcwkJyqnB1Z3X7a6tP5Ve3CtfWrEXOJxKJoyIbhc1CsbC5
fi2/ubN4fiG58PBDC7PzD83OTX19/ani2mJyNjG1trr+9FpxcZbqfbWwvXGluLj99NX5+fmpwvb6
6mbxSnG9sLl4tVAsFjaEZ7emrn6juLqzOEfFE6c/CwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAO5i4vH49PS032cRZK5fvy5JEsdx6XTa73MJMpFIhCRvbW1xGo1G
QzUR0uCaNJroR7l26vW6ubrlaOBbtmAprHPjxg0nLXc2ZTkryzmbqwe+ZXvP6+vrc3Nz4XD4woUL
g97BznM217XcysC3bO95oJY7mxrWOQeg5c6O4Bmex7flzo7gGZ7Ht+XOjuB5vDzbX8Jo2giS565d
jIiNAHhuFYPnzsLDbblXs6NjIwCebSSPjo0AeMZ4tikMz8NqubMjeIZnt22MjudeH1RbJ9mr+pja
6KVi9D3rjYyX565a4Bmeh2ID8wY8e+PZpjo82xS2b7nrWQXJs43krmfl0h3sWjdInu1tdBaG5+PZ
sFHR9ax88WyZzMPhsLlx/VBraTnJrnJa2Isd6JztCw/q2eaofeEheu46CPt6dvJj297GSTwPOm/Y
HIXnY7fsl2e9zHA9n9yGZ57tj1oYtfF8chvBmTcaxkIvMwqeQ1rszvm4LduYtD9q7znMhc1R65rQ
huG25Zm26qwjoxhdJS0bdZViajlCBULtTekF6OLoqF5AL9PWUUPV97faNzerXWDYFNPaOHmeNEf9
VFUPm6lbE+HuoTK0DHETtNI4VFkaRkIh2j+pFWhvqq7W6SirdQ/HTepljnrRCoSM/RN6qFm12ax2
FyZNYUOZLoLdbG2l3mgYo6LRZZDYe3Zn3mBjKBRu/tUZf3unzakfqvoobWhyWOpMpi4kpJXRlqf0
woeHRhmyGuHOtDWlN1I3CoS5M5PcmXD70VY4o+VTYe5UiLu3oTdLJ6PdLI671xTmdoLjPsNxES3q
YcMYCZYRogkPtV/ukMez9bbW2Umz8/7PBBeJcOFWlPxZPdXctKeRzlalGS18j0RN66ykIs3sizMH
mUQ6tpuJ7Ym8TMnGSizCXlqoZPlalpdpJR3buxwvXUreXkmWV5J7y4nySqK8nJCXkpTqSkJhSZb0
oyuJveUkO0rLldnfsT20kqg+GZcvx8v65iVtMxUvi0I5y1cpYrTGOhKqaf7O5QR1tLsSe2Ulriwl
KFW2TFa17owoOUFP7+t1KdRjjEVMaIkZm2xPXNvTXBrOWSq5mUouLvK3RbpSXhGjima7qq3QHlni
y/qeDF+je5EWXkrFaqmYkhKUVGxfSy0Vr6TipXSslIrT7aikYnIqVm0uFdpzOVFi+4V9bU+FbhkJ
p02yyjrlW0vqqEJJx/fS8d2UcId11DWC4p9nPTEHEcyey7m4xJckXa8lQolFW2ejTpBZ2CDXoxh7
rKlkaZSyFaqlZAQlrSXDUs20rVSbkhVzv9lWWFPd47dnhzdCn2FoMJ+Vc4LIlzJCN89dzFdsC9Ta
Y0hjVmOVruneRSu9+xp5z7pqY72Si8oSzRvl3p5l8Wio07WzGbX35SvtMXsuayG3shZjs8fdlJuq
e979cfNMU/CsGJWbf8Ini6CFby5bnkmvUNOiNGNs9vYs249nvx0OFs1zsp9nue1v2cEftXkSoLm0
16ThdLKC5xN6ZvOGs3aC4bltEvbWs8N2xtxzlZ6Duaj+q/XYl2wf4znYI3fDvEEPoTvi2Vruc+LM
nZRQsx3S8HxSz/v5+7NRejVT4NmlaO8SMzUxSS9u9JrukmeX4ru9wTxL00ru/nTsICvUpOM++uHZ
wXhmj8Icv5cVZHh2zzNNypU8L0XLPV/NRjW+2xt0PGue6T2l5ru6YHumeTmtfe30XV1QPRvJwbMX
keHZk9D8nOUxP7ueUj6qPQfxe8MDz1V4djtKTqD5eTj/PQWeu0X7XRdVpCS9dIsxRfJbXZA9Sw/W
cg+khZez/AE8uzme2e9neu/Oavt8txdUz6bvG/hd5+54xvcNbzzj+4ZHwXu3J8H3DW+C7xvepGQ8
B/He7bZnfN/wIvi+4XbwfcM7z9KDCr5veDGe2e/nHL5vuOwZ3zc8G8/4vuGN55rE3lPwPuh6csyz
GCXf/tsLsGeZfeeHZ9dTzvMi+0fcbN7I6P/Uehziu7fBx3O0NT/Ds3upSO2ex+QF3HdvgyXHy3ny
XNH1Yjy7FzZvCGUxJkt+qwu2Z5o3xOhLIn+Qi/pvL8Ce9ecgvYLDs9ue08Ke5Le3u8NzdbwG83h6
5sfRs8v/u3sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQcKaAJ3DPqAiCIAiCnCRfeEF9
4sfW0E73evzrJ+rv31P/8Be24rDK2s/Vm7tHoU1/pd13Uw1vG+uhbfW+5/pXeesj9Ss/sYZ22tfK
vqi+/I41mRcddPehSuieiTc/7F/l1p7ayTd/49TJex+r7348ZM/kliDV+kpou3+VV9/tvjNkW6ve
UH/xmnrnT2xMvv+JevBntnlY79+dTssz0bfKr/7Iil37mfrr1488//I1p06E51X+1mAaIzvWlV6q
HUq28Wxfizy//Tdm+F//ZaEV2nTi+bEfWuPQ86d19fPfPfJMOx1K+/6++r3aYJ6JiR11smg3DLzz
/NFxPHfi0DPxv0O2+fd/Dzaef7CvvjCg59Z52ksOeTJvEN+6bWzqU6hLnqO3utSKOp4K2Lzx/MCe
7UPPwZD5OXizf5XdN9VX3mEPCx1aoc3dN/rUokceFbMk89P+3b3xQZuu1993dF3P/dbRTewa9hz8
x5A9HzsPfFt9/EcstOJ2Xx/805BMKw6rJL/jvyIEQRAEuTvzf4V2zEsMGgEA"""
    ))
    require(len(data) == 72204 and hashlib.sha256(data).hexdigest()
            == "45a449f9a67d9221a824cfec0466a6f4760035a163a2baf6881c9778901a21f2",
            "retained Android input bytes differ")
    metadata = decoder.METADATA.fullmatch(data.split(b"\n", 2)[1] + b"\n")
    require(metadata is not None, "retained Android metadata differs")
    observed = int(metadata.group(4))
    record = decoder.parse_record(data, observed)
    require((record["width"], record["height"]) == (120, 200),
            "retained Android dimensions differ")
    pixels = memoryview(record["pixels"])
    runs = []
    for y in range(200):
        row = decoder.decode_state_code_row(pixels, 120, 200, y, 0, 120)
        state = None if row is None else row[0]
        if runs and runs[-1][0] == state:
            runs[-1][1] += 1
        else:
            runs.append([state, 1, y])
    analysis = decoder.analyze(record, {}, observed)
    require(analysis["chosen"] is None, "historical pixels acquired freshness without history")
    summary = ",".join(f"{state}:{count}@{top}" for state, count, top in runs)
    print("ANDROID_FRAME_RETAINED_GEOMETRY source=actual-android-decoder-input "
          f"bytes={len(data)} seq={record['sequence']} "
          f"candidates={len(analysis['candidates'])} full_span_runs={summary}", flush=True)

def main():
    require(os.getuid() == 4000 and os.getgid() == 4000, "numeric nonroot principal differs")
    module_path = Path("/work/scripts/android-emulator-frame.py")
    spec = importlib.util.spec_from_file_location("frame_decoder", module_path)
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    decoder.self_test()
    inspect_retained_android_frame(decoder)
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
    oracle_binaries = [Path(f"/build/x11-frame-oracle-{index}") for index in range(2)]
    for binary in oracle_binaries:
        subprocess.run(["/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "/work/scripts/test-x11-frame-oracle.c", "-lX11", "-o", str(binary)],
                       env=environment, check=True, timeout=30)
        binary.chmod(0o500)
    oracle_bytes = oracle_binaries[0].read_bytes()
    require(oracle_bytes == oracle_binaries[1].read_bytes(), "C frame oracle builds differ")
    controller_flags = subprocess.run([
        "/usr/bin/pkg-config", "--cflags", "--libs", "x11", "xtst", "atspi-2", "gobject-2.0",
    ], env=environment, check=True, capture_output=True, text=True, timeout=5).stdout.split()
    subprocess.run(["/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    "/work/scripts/flutter-peer-presentation-x11.c", *controller_flags,
                    "-o", "/build/x11-controller"], env=environment, check=True, timeout=30)
    print("ANDROID_FRAME_NATIVE_X11_BUILD copies=2 equal=true controller=compiled "
          f"sha256={hashlib.sha256(oracle_bytes).hexdigest()} bytes={len(oracle_bytes)}", flush=True)
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
    source_directory = Path("/tmp/frame-source")
    source_directory.mkdir(mode=0o700)
    source_path = source_directory / "frame-source.log"
    started = time.monotonic()
    try:
        with open("/tmp/frame-xvfb.log", "wb") as xvfb_log:
            children.append(subprocess.Popen([
                "/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "1920x1080x24",
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
        refusal = subprocess.run([str(fixture / "frame-source")], env=environment,
                                 capture_output=True, text=True, timeout=5)
        require(refusal.returncode != 0 and "screen dimensions differ" in refusal.stderr
                and "FLUTTER_PEER_SOURCE_READY" not in refusal.stdout,
                "fixture admitted a mismatched screen")
        refusal = subprocess.run([str(fixture / "frame-source"), "--unknown"], env=environment,
                                 capture_output=True, text=True, timeout=5)
        require(refusal.returncode != 0 and "usage:" in refusal.stderr
                and "FLUTTER_PEER_SOURCE_READY" not in refusal.stdout,
                "fixture admitted an unknown workload")
        with source_path.open("wb") as source_log:
            children.append(subprocess.Popen([str(fixture / "frame-source"), "--full-hd"], env=environment,
                                             stdout=source_log, stderr=subprocess.STDOUT))
        source_path.chmod(0o600)
        root = lib.XDefaultRootWindow(display)

        def capture():
            image = lib.XGetImage(display, root, 0, 0, 1920, 1080, ctypes.c_ulong(-1).value, 2)
            require(image, "actual X11 framebuffer capture failed")
            pixels = bytearray(bytes((197, 190, 184)) * (120 * 200))
            try:
                for y in range(68):
                    for x in range(120):
                        pixel = lib.XGetPixel(image, x * 1920 // 120, y * 1080 // 68)
                        offset = ((200 - 1 - (66 + y)) * 120 + x) * 3
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
        subprocess.run([str(oracle_binaries[0]), str(source_directory)],
                       env=environment, check=True, timeout=30)
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
        diagnostic = subprocess.run([
            "/usr/bin/python3", "-B", "-I", "-S", str(module_path), "decode",
            str(cli_frame), str(source_path), "diagnose",
        ], check=True, capture_output=True, text=True, timeout=5)
        lines = diagnostic.stdout.splitlines()
        retained = cli_frame.read_bytes()
        require(lines[1] == "ANDROID_PEER_FRAMEBUFFER_RECORD_BEGIN "
                f"bytes={len(retained)} sha256={hashlib.sha256(retained).hexdigest()} "
                "encoding=base64 source=decoder-input"
                and lines[-1] == "ANDROID_PEER_FRAMEBUFFER_RECORD_END"
                and base64.b64decode("".join(lines[2:-1]), validate=True) == retained,
                "failure diagnostic did not retain the exact real decoder input")
        # Give old pixels a brand-new capture envelope: observation freshness cannot rescue content.
        stale_record = record(old_pixels, 3)
        analysis = decoder.analyze(stale_record, history)
        require(analysis["chosen"] is None, "whole-cycle stale native pixels passed freshness")
        stale = next((entry for entry in analysis["candidates"] if entry["state"] == identity), None)
        require(stale is not None and stale["age"] >= 256 * 33,
                "stale native identity or whole-cycle real age was lost")
        require((fresh["state"] - identity) % 256 <= 8, "old modulo predicate would not alias")
        intervals = max(history) - identity
        interval_us = (history[max(history)] - history[identity] + intervals - 1) // intervals
        require(33000 <= interval_us <= 50000, "full-HD source did not sustain the required publication load")
        print("ANDROID_FRAME_NATIVE_WORKLOAD dimensions=1920x1080 nominal_interval_ms=33 "
              f"mean_interval_us={interval_us} bands=scaled-40-percent", flush=True)
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
    require(all(binary.read_bytes() == oracle_bytes for binary in oracle_binaries),
            "C frame oracle changed during native execution")
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
