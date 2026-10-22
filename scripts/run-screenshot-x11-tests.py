#!/usr/bin/env python3
"""Drive real confined X11 capture and independently inspect its screenshot PNG."""
import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time
import zlib


WIDTH, HEIGHT = 129, 33
WORK = Path('/tmp/video-vpx')
PALETTE = [(255, 0, 0), (0, 255, 0), (0, 0, 255), (255, 255, 255)]


def expected_rgb(x):
    for index, color in enumerate(PALETTE):
        if x < (index + 1) * WIDTH // 4:
            return color
    raise AssertionError('pixel outside palette')


def inspect_png(data):
    assert 0 < len(data) <= 65536 and data[:8] == b'\x89PNG\r\n\x1a\n'
    offset = 8
    header = None
    compressed = bytearray()
    ended = False
    while offset < len(data):
        assert offset + 12 <= len(data)
        length = struct.unpack_from('>I', data, offset)[0]
        assert length <= 65536 and offset + length + 12 <= len(data)
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        crc = struct.unpack_from('>I', data, offset + 8 + length)[0]
        assert zlib.crc32(kind + body) & 0xffffffff == crc
        offset += length + 12
        if header is None:
            assert kind == b'IHDR' and length == 13
            header = struct.unpack('>IIBBBBB', body)
            assert header == (WIDTH, HEIGHT, 8, 6, 0, 0, 0)
        elif kind == b'IDAT':
            compressed.extend(body)
        elif kind == b'IEND':
            assert not body and offset == len(data)
            ended = True
            break
        else:
            assert kind[0] & 32, 'unexpected critical PNG chunk'
    assert ended and compressed
    row_bytes = WIDTH * 4
    decoded_bytes = (row_bytes + 1) * HEIGHT
    inflater = zlib.decompressobj()
    filtered = inflater.decompress(compressed, decoded_bytes + 1)
    assert len(filtered) == decoded_bytes and inflater.eof
    assert not inflater.unused_data and not inflater.unconsumed_tail
    pixels = bytearray()
    previous = bytearray(row_bytes)
    for y in range(HEIGHT):
        start = y * (row_bytes + 1)
        method = filtered[start]
        assert method <= 4
        row = bytearray(filtered[start + 1:start + 1 + row_bytes])
        for index in range(row_bytes):
            left = row[index - 4] if index >= 4 else 0
            up = previous[index]
            diagonal = previous[index - 4] if index >= 4 else 0
            if method == 0:
                prediction = 0
            elif method == 1:
                prediction = left
            elif method == 2:
                prediction = up
            elif method == 3:
                prediction = (left + up) // 2
            else:
                estimate = left + up - diagonal
                distances = [abs(estimate - value) for value in (left, up, diagonal)]
                prediction = (left, up, diagonal)[distances.index(min(distances))]
            row[index] = (row[index] + prediction) & 255
        pixels.extend(row)
        previous = row
    colors = all(tuple(pixels[(y * WIDTH + x) * 4:(y * WIDTH + x) * 4 + 3]) == expected_rgb(x)
                 for y in range(HEIGHT) for x in range(WIDTH))
    opaque = all(alpha == 255 for alpha in pixels[3::4])
    return colors, opaque, hashlib.sha256(pixels).hexdigest()


def oracle_controls():
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)

    def encode(pixels):
        raw = b''.join(b'\0' + pixels[y * WIDTH * 4:(y + 1) * WIDTH * 4] for y in range(HEIGHT))
        return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', WIDTH, HEIGHT, 8, 6, 0, 0, 0))
                + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))

    good = bytearray(value for _ in range(HEIGHT) for x in range(WIDTH) for value in (*expected_rgb(x), 255))
    assert inspect_png(encode(good))[:2] == (True, True)
    transparent = bytearray(good)
    transparent[3::4] = bytes(WIDTH * HEIGHT)
    assert inspect_png(encode(transparent))[:2] == (True, False)
    for position in (0, len(good) - 4):
        wrong = bytearray(good)
        wrong[position:position + 3] = b'\x17\x29\x31'
        assert inspect_png(encode(wrong))[:2] == (False, True)
    for broken in (encode(good)[:-1], encode(good) + b'x', encode(good)[:32] + b'x' + encode(good)[33:]):
        try:
            inspect_png(broken)
        except (AssertionError, zlib.error):
            pass
        else:
            raise AssertionError('PNG oracle accepted malformed data')
    print('SCREENSHOT_X11_ORACLE=pass controls=7 pixels=all alpha=checked crc=checked stream=bounded', flush=True)


def paint(display_name, depth):
    x11 = ctypes.CDLL('libX11.so.6')
    signatures = {
        'XOpenDisplay': ([ctypes.c_char_p], ctypes.c_void_p),
        'XDefaultRootWindow': ([ctypes.c_void_p], ctypes.c_ulong),
        'XCreateGC': ([ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p], ctypes.c_void_p),
        'XSetForeground': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong], ctypes.c_int),
        'XFillRectangle': ([ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint], ctypes.c_int),
        'XSync': ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        'XFreeGC': ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        'XCloseDisplay': ([ctypes.c_void_p], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(x11, name)
        function.argtypes, function.restype = arguments, result
    display = x11.XOpenDisplay(('unix/' + display_name).encode('ascii'))
    assert display
    gc = None
    try:
        root = x11.XDefaultRootWindow(display)
        gc = x11.XCreateGC(display, root, 0, None)
        assert root and gc
        values = [0xf800, 0x07e0, 0x001f, 0xffff] if depth == 16 else [0xff0000, 0x00ff00, 0x0000ff, 0xffffff]
        for index, value in enumerate(values):
            left = index * WIDTH // 4
            right = (index + 1) * WIDTH // 4
            x11.XSetForeground(display, gc, value)
            x11.XFillRectangle(display, root, gc, left, 0, right - left, HEIGHT)
        x11.XSync(display, 0)
    finally:
        if gc:
            x11.XFreeGC(display, gc)
        x11.XCloseDisplay(display)


def main():
    assert len(sys.argv) == 2 and os.getuid() == os.getgid() == 1000
    assert Path.cwd() == Path('/source') and WORK.is_dir() and not WORK.is_symlink()
    executable = Path(sys.argv[1])
    assert re.fullmatch(r'/cargo-target/debug/deps/scrap-[0-9a-f]{16}', str(executable))
    metadata = executable.lstat()
    assert stat.S_ISREG(metadata.st_mode) and (metadata.st_uid, metadata.st_gid, metadata.st_nlink) == (1000, 1000, 1)
    artifact_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    oracle_controls()
    outcomes = []
    for depth, number in ((24, 91), (16, 92)):
        socket_path = Path(f'/tmp/.X11-unix/X{number}')
        lock_path = Path(f'/tmp/.X{number}-lock')
        png_path = WORK / f'screenshot-{depth}.png'
        assert not any(path.exists() for path in (socket_path, lock_path, png_path))
        environment = dict(os.environ, DISPLAY=f':{number}', XAUTHORITY='/nonexistent',
                           LD_LIBRARY_PATH='/xvfb-root/usr/lib/x86_64-linux-gnu', SCREENSHOT_X11_PNG_PATH=str(png_path))
        with (WORK / f'xvfb-{depth}.log').open('xb') as log:
            server = subprocess.Popen(['/xvfb-root/usr/bin/Xvfb', f':{number}', '-screen', '0',
                                       f'{WIDTH}x{HEIGHT}x{depth}', '-nolisten', 'tcp', '-noreset', '-ac'],
                                      env=environment, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while not socket_path.exists():
                    assert server.poll() is None and time.monotonic() < deadline, 'owned Xvfb not ready'
                    time.sleep(0.01)
                assert stat.S_ISSOCK(socket_path.lstat().st_mode) and socket_path.lstat().st_uid == 1000
                paint(f':{number}', depth)
                case = f'common::convert::tests::native_x11_capture_{depth}_png'
                result = subprocess.run([str(executable), '--exact', case, '--color', 'never', '--test-threads=1', '--show-output'],
                                        env=environment, capture_output=True, text=True, timeout=15)
                assert len(result.stdout) + len(result.stderr) <= 16384
                print(result.stdout, end='', flush=True)
                if result.stderr:
                    print(result.stderr, file=sys.stderr, end='', flush=True)
                assert result.returncode == 0 and f'test {case} ... ok\n' in result.stdout
                assert 'test result: ok. 1 passed; 0 failed;' in result.stdout
                png_metadata = png_path.lstat()
                assert stat.S_ISREG(png_metadata.st_mode) and png_metadata.st_nlink == 1
                assert (png_metadata.st_uid, png_metadata.st_gid) == (1000, 1000) and 0 < png_metadata.st_size <= 65536
                png = png_path.read_bytes()
                colors, opaque, rgba_sha = inspect_png(png)
                print(f'SCREENSHOT_X11_CASE=observed depth={depth} pixels={WIDTH * HEIGHT} colors_exact={str(colors).lower()} '
                      f'opaque={str(opaque).lower()} png_bytes={len(png)} png_sha256={hashlib.sha256(png).hexdigest()} rgba_sha256={rgba_sha}', flush=True)
                outcomes.append(colors and opaque)
                current = png_path.lstat()
                assert (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) == \
                       (png_metadata.st_dev, png_metadata.st_ino, png_metadata.st_size, png_metadata.st_mtime_ns)
                png_path.unlink()
            finally:
                if server.poll() is None:
                    server.terminate()
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
                    raise
                assert server.returncode == 0 and not socket_path.exists() and not lock_path.exists()
                assert log.tell() <= 16384
                print(f'SCREENSHOT_X11_CLEANUP=pass depth={depth} server=joined socket=retired lock=retired', flush=True)
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == artifact_sha
    assert len(outcomes) == 2
    print(f'SCREENSHOT_X11_NATIVE=complete cases=2 passed={sum(outcomes)} artifact_sha256={artifact_sha} children=joined', flush=True)
    return 0 if all(outcomes) else 1


if __name__ == '__main__':
    sys.exit(main())
