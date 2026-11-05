#!/usr/bin/env python3
"""Guest-only resource observation for the four-hour Linux presentation/input controls."""
import contextlib
import ctypes
import json
import os
import pathlib
import select
import stat
import sys
import time


def main():
    assert len(sys.argv) == 6 and os.getuid() != 0 and os.getgid() != 0
    pid, start, source_pid, source_start, scenario = sys.argv[1:]
    assert scenario in ('viewer-soak', 'input-soak', 'congestion-soak')
    minimum_seconds = 14699 if scenario == 'congestion-soak' else 14639 if scenario == 'input-soak' else 14459
    minimum_windows = 244 if scenario == 'congestion-soak' else 243 if scenario == 'input-soak' else 240
    maximum_seconds = 15120 if scenario == 'congestion-soak' else 14700
    pid, source_pid = int(pid), int(source_pid)
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

    with contextlib.ExitStack() as cleanup:
        proc = os.open(f'/proc/{pid}', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        source = os.open(f'/proc/{source_pid}', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        cleanup.callback(os.close, proc)
        cleanup.callback(os.close, source)
        owners = [os.pidfd_open(pid), os.pidfd_open(source_pid)]
        for owner in owners:
            cleanup.callback(os.close, owner)

        def fields(root, expected_pid, expected_start):
            with os.fdopen(os.open('stat', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root), 'rb') as f:
                raw = f.read(4097)
            assert len(raw) <= 4096 and raw.startswith(f'{expected_pid} ('.encode())
            values = raw.rsplit(b')', 1)[1].split()
            assert values[19].decode() == expected_start and values[0] not in (b'T', b't', b'Z', b'X')
            return values

        def sample():
            assert not select.select(owners, [], [], 0)[0], 'soak process exited'
            values = fields(proc, pid, start)
            fields(source, source_pid, source_start)
            fd = os.open('fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=proc)
            try:
                descriptors = len(os.listdir(fd))
            finally:
                os.close(fd)
            return dict(cpu_ticks=int(values[11]) + int(values[12]), threads=int(values[17]),
                        rss_bytes=int(values[21]) * os.sysconf('SC_PAGESIZE'), fds=descriptors)

        assert marker('soak.begin')
        baseline = sample()
        peak = baseline.copy()
        began = window_start = time.monotonic()
        cpu_start = baseline['cpu_ticks']
        windows = samples = 0
        while True:
            current = sample()
            now = time.monotonic()
            samples += 1
            assert now - began <= maximum_seconds and not (coord / 'stop').exists()
            assert current['threads'] <= baseline['threads'] + 8
            assert current['fds'] <= baseline['fds'] + 16
            assert current['rss_bytes'] <= baseline['rss_bytes'] + 128 * 1024 * 1024
            for key in peak:
                peak[key] = max(peak[key], current[key])
            done = marker('soak.done')
            if now - window_start >= 60 or done:
                cpu_ms = (current['cpu_ticks'] - cpu_start) * 1000 / os.sysconf('SC_CLK_TCK')
                assert 0 <= cpu_ms <= 10000
                print('FLUTTER_PEER_SOAK_SERVER_WINDOW=' + json.dumps(dict(
                    index=windows, elapsed_ms=round((now - window_start) * 1000),
                    cpu_ms=cpu_ms, resources=current), sort_keys=True), flush=True)
                windows += 1
                cpu_start, window_start = current['cpu_ticks'], now
            if done:
                break
            time.sleep(1)
        assert now - began >= minimum_seconds and windows >= minimum_windows and samples >= 14000
        print('FLUTTER_PEER_SOAK_SERVER_OK=' + json.dumps(dict(
            duration_ms=round((now - began) * 1000), samples=samples,
            baseline=baseline, peak=peak, final=current), sort_keys=True), flush=True)
        temporary = coord / 'soak.observed.tmp'
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600), 'wb') as f:
            f.write(b'ready\n')
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        if rename(-100, os.fsencode(temporary), -100, os.fsencode(coord / 'soak.observed'), 1) != 0:
            raise OSError(ctypes.get_errno(), 'publish soak observation')


if __name__ == '__main__':
    main()
