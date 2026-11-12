#!/usr/bin/env python3
"""Guest-only pause of the retained peer while the viewer tests recording close."""
import contextlib
import ctypes
import os
import pathlib
import select
import signal
import stat
import sys
import time


def main():
    assert len(sys.argv) == 3 and os.getuid() != 0 and os.getgid() != 0
    pid, start = int(sys.argv[1]), sys.argv[2]
    coord = pathlib.Path('/coord')

    def marker(name):
        try:
            fd = os.open(coord / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return False
        with os.fdopen(fd, 'rb') as stream:
            s = os.fstat(stream.fileno())
            assert stat.S_ISREG(s.st_mode)
            assert (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink, s.st_size) == (
                os.getuid(), os.getgid(), 0o600, 1, 6)
            assert stream.read(7) == b'ready\n'
        return True

    def publish(name):
        temporary = coord / (name + '.tmp')
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              os.O_NOFOLLOW, 0o600), 'wb') as stream:
            stream.write(b'ready\n')
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        if rename(-100, os.fsencode(temporary), -100, os.fsencode(coord / name), 1) != 0:
            raise OSError(ctypes.get_errno(), 'publish recording peer state')

    def interrupted(number, _frame):
        raise SystemExit(128 + number)

    for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(number, interrupted)
    with contextlib.ExitStack() as cleanup:
        proc = os.open(f'/proc/{pid}', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        cleanup.callback(os.close, proc)
        owner = os.pidfd_open(pid)
        cleanup.callback(os.close, owner)

        def fields(name):
            with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=proc), 'rb') as f:
                data = f.read(4097)
            assert len(data) <= 4096
            return data.rsplit(b')', 1)[1].split()

        def live():
            assert not select.select([owner], [], [], 0)[0], 'recording peer exited'
            values = fields('stat')
            assert values[19].decode() == start and values[0] not in (b'Z', b'X')
            return values

        assert marker('recording.freeze') and not marker('recording.resume')
        assert live()[0] not in (b'T', b't')
        began = time.monotonic()
        try:
            signal.pidfd_send_signal(owner, signal.SIGSTOP)
            deadline = began + 3
            while True:
                live()
                tasks = os.open('task', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=proc)
                try:
                    names = os.listdir(tasks)
                finally:
                    os.close(tasks)
                assert 1 <= len(names) <= 256
                if all(fields('task/' + name + '/stat')[0] == b'T' for name in names):
                    break
                assert time.monotonic() < deadline, 'recording peer did not stop'
                time.sleep(0.02)
            publish('recording.frozen')
            while not marker('recording.resume'):
                assert live()[0] == b'T'
                assert time.monotonic() - began < 20, 'recording close deadline exceeded'
                time.sleep(0.02)
        finally:
            signal.pidfd_send_signal(owner, signal.SIGCONT)
        deadline = time.monotonic() + 3
        while live()[0] in (b'T', b't'):
            assert time.monotonic() < deadline, 'recording peer did not resume'
            time.sleep(0.02)
        publish('recording.resumed')
        print('FLUTTER_PEER_RECORDING_PEER_RESUMED threads=' + str(len(names))
              + ' held_ms=' + str(round((time.monotonic() - began) * 1000))
              + ' generation=unchanged identity=pidfd', flush=True)


if __name__ == '__main__':
    main()
