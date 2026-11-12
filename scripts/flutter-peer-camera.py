#!/usr/bin/env python3
"""Control the guest's vivid camera; observe the real server's retained handles."""
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import Path
import stat
import struct
import sys
import time


COORD = Path('/coord')
NODE = Path('/dev/video2')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def marker(name, publish=False):
    path = COORD / name
    if publish:
        temporary = COORD / (name + '.tmp')
        with temporary.open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(b'ready\n')
        require(not path.exists() and not path.is_symlink(), 'camera marker already exists')
        os.rename(temporary, path)
        return True
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_gid == os.getgid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 6
                and source.read(7) == b'ready\n', 'camera coordination record differs')
    return True


def alive(pid, start):
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(') ', 1)[1].split()
    require(fields[19] == start and fields[0] not in ('Z', 'X'),
            'camera server generation retired')


def wait_for(pid, start, predicate, label, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        alive(pid, start)
        require(not (COORD / 'stop').exists(), 'viewer stopped before camera observations')
        if predicate():
            return
        time.sleep(0.05)
    raise ValueError('camera deadline: ' + label)


def control(fd, offset, name, value, menu=None, kind=2):
    # Linux v6.1 videodev2.h, x86_64: QUERYCTRL=68, QUERYMENU=44, CTRL=8.
    ident = 0x00f0f000 + offset
    query = bytearray(68)
    struct.pack_into('<I', query, 0, ident)
    fcntl.ioctl(fd, 0xc0445624, query, True)
    require(query[8:40].split(b'\0')[0].decode() == name,
            'vivid control name differs')
    actual_kind = struct.unpack_from('<I', query, 4)[0]
    minimum, maximum = struct.unpack_from('<ii', query, 40)
    require(actual_kind == (3 if menu else kind) and minimum <= value <= maximum,
            'vivid control type or bounds differ')
    if menu:
        query = bytearray(44)
        struct.pack_into('<II', query, 0, ident, value)
        fcntl.ioctl(fd, 0xc02c5625, query, True)
        require(query[8:40].split(b'\0')[0].decode() == menu, 'vivid menu differs')
    data = bytearray(struct.pack('<Ii', ident, value))
    fcntl.ioctl(fd, 0xc008561c, data, True)
    if kind == 4:
        return  # Button controls have no persistent value to read back.
    fcntl.ioctl(fd, 0xc008561b, data, True)
    require(struct.unpack('<Ii', data) == (ident, value), 'vivid control readback differs')


@contextmanager
def native_device():
    fd = os.open(NODE, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 81
                and info.st_uid == os.getuid() and info.st_gid == os.getgid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'guest camera authority differs')
        capability = bytearray(104)
        fcntl.ioctl(fd, 0x80685600, capability, True)
        require(capability[:16].split(b'\0')[0] == b'vivid', 'guest camera driver differs')
        yield fd
    finally:
        os.close(fd)


def color(index):
    with native_device() as fd:
        control(fd, 1, 'OSD Text Mode', 2, 'None')
        control(fd, 4, 'Show Border', 0)
        control(fd, 5, 'Show Square', 0)
        control(fd, 0, 'Test Pattern', 7 + index, ('100% Red', '100% Green', '100% Blue')[index])


def drop_frames(percentage):
    with native_device() as fd:
        control(fd, 64, 'Percentage of Dropped Buffers', percentage, kind=1)


def disconnect():
    with native_device() as fd:
        control(fd, 65, 'Disconnect', 0, kind=4)
        try:
            fcntl.ioctl(fd, 0x80685600, bytearray(104), True)
        except OSError as error:
            require(error.errno == errno.ENODEV, 'camera disconnect errno differs')
        else:
            raise ValueError('camera disconnect did not reach the kernel')
    print('FLUTTER_PEER_CAMERA_DISCONNECTED querycap=ENODEV control_handle=closed', flush=True)


def descriptors(pid):
    expected = NODE.stat()
    matches = []
    for path in Path('/proc', str(pid), 'fd').iterdir():
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISCHR(info.st_mode) and info.st_rdev == expected.st_rdev:
            require((info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino),
                    'server camera node identity differs')
            matches.append(int(path.name))
    return sorted(matches)


def retained(pid, start, expected, phase):
    samples = 0
    def stable():
        nonlocal samples
        matches = descriptors(pid)
        samples = samples + 1 if len(matches) == expected else 0
        return samples == 10
    wait_for(pid, start, stable, phase, 10)
    print('FLUTTER_PEER_CAMERA_OWNER phase=' + phase + ' descriptors=' + str(expected)
          + ' samples=10 server_generation=unchanged', flush=True)


def main():
    os.umask(0o077)
    require(len(sys.argv) == 4 and sys.argv[1] in ('prepare', 'observe')
            and os.getuid() == 1000 and os.getgid() == 1000
            and os.uname().release == '6.1.0-50-amd64'
            and sorted(p.name for p in Path('/sys/class/net').iterdir()) == ['lo'],
            'guest camera fixture request or topology differs')
    pid, start = int(sys.argv[2]), sys.argv[3]
    alive(pid, start)
    if sys.argv[1] == 'prepare':
        retained(pid, start, 0, 'before-login')
        color(0)
        return
    wait_for(pid, start, lambda: marker('slow.ready') and marker('camera.main.ready'),
             'two authenticated red viewers')
    retained(pid, start, 1, 'two-viewers')
    color(1)
    marker('camera.green', True)
    wait_for(pid, start, lambda: marker('camera.slow.green') and marker('camera.main.green'),
             'two green viewers')
    marker('camera.close-slow', True)
    wait_for(pid, start, lambda: marker('camera.slow.closed'), 'first viewer joined')
    retained(pid, start, 1, 'one-viewer')
    color(2)
    marker('camera.blue', True)
    wait_for(pid, start, lambda: marker('camera.main.blue'), 'surviving blue viewer')
    drop_frames(100)
    # Let any buffer completed before the control drain before changing color.
    time.sleep(0.5)
    color(0)
    marker('camera.stalled', True)
    wait_for(pid, start, lambda: marker('camera.stall.observed'), 'withheld camera frames')
    retained(pid, start, 1, 'stalled-viewer')
    restored = time.monotonic_ns() // 1_000_000
    drop_frames(0)
    with (COORD / 'camera.restore-time').open('xb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write((str(restored) + '\n').encode())
    marker('camera.restored', True)
    wait_for(pid, start, lambda: marker('camera.recovered'), 'same-connection camera recovery')
    retained(pid, start, 1, 'recovered-viewer')
    disconnect()
    marker('camera.disconnected', True)
    wait_for(pid, start, lambda: marker('camera.loss.observed'), 'visible device loss and session retirement')
    wait_for(pid, start, lambda: marker('camera.main.closed'), 'last viewer joined')
    retained(pid, start, 0, 'no-viewers')
    color(1)
    marker('camera.reacquire.ready', True)
    wait_for(pid, start, lambda: marker('camera.reacquire.green'), 'fresh authenticated green viewer')
    retained(pid, start, 1, 'fresh-viewer')
    color(2)
    marker('camera.reacquire.blue', True)
    wait_for(pid, start, lambda: marker('camera.reacquire.closed'), 'fresh viewer joined')
    retained(pid, start, 0, 'fresh-viewer-closed')
    marker('camera.complete', True)
    print('FLUTTER_PEER_CAMERA_SHARED_OK viewers=2 generations=3 colors=3 first_close=survived '
          'timeout=recovered loss=visible reacquisition=presented '
          'last_close=devices-retired server=preserved', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, IndexError, struct.error) as error:
        print('FLUTTER_PEER_CAMERA_FAIL=' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
