#!/usr/bin/env python3
"""Observe Android pixels through impairment of its retained ADB-reversed peer flow."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import socket
import struct
import subprocess
import sys
import time


PROFILES = (('delay', 6), ('random3', 8), ('random8', 8),
            ('burst', 10), ('loss', 2), ('loss', 6))
RECOVERY_MS = 8000
DRIFT_MS = 250
PERIOD_NS = 250_000_000


def require(value, message):
    if not value:
        raise RuntimeError(message)


def request(profile):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5)
        channel.connect('/netem.sock')
        _, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require((uid, gid) == (0, 0), 'impairment owner is not guest root')
        channel.sendall(profile.encode('ascii'))
        response, _, flags, _ = channel.recvmsg(128)
        require(not flags and re.fullmatch(rb'OK [0-9]+ [0-9]+ [0-9]+ [0-9]+', response),
                'impairment acknowledgement differs')
        timestamp, drops, packets, queued = map(int, response.split()[1:])
        require(queued <= 64, 'impairment queue exceeded its bound')
        return dict(monotonic_us=timestamp, drops=drops, packets=packets, queued=queued)


def main():
    require(os.getuid() == os.getgid() == 1000 and len(sys.argv) == 15,
            'network observer arguments or principal differ')
    (decoder_path, frame, source, server_log, observer_failure, adb, serial,
     app_pid, task_id, server_pid, server_start, source_pid, source_start, file_limit) = sys.argv[1:]
    require(serial == 'emulator-5554' and all(re.fullmatch('[1-9][0-9]*', value) for value in
            (app_pid, task_id, server_pid, server_start, source_pid, source_start, file_limit)),
            'network observer identities differ')
    file_limit = int(file_limit)
    require(file_limit <= 128 * 1024 * 1024, 'peer log bound differs')
    decoder = runpy.run_path(decoder_path)
    common = runpy.run_path(str(Path(__file__).with_name('android-peer-soak.py')))
    read_file = common['read_file']
    process_start = common['process_start']
    keyed_count = common['server_keyed_session_count']

    def identity():
        for pid, start in ((server_pid, server_start), (source_pid, source_start)):
            with open(f'/proc/{pid}/stat') as stream:
                require(process_start(stream.read(4097), pid) == int(start),
                        'peer/source process changed')
        with open('/proc/net/tcp') as stream:
            raw = stream.read(65537)
        require(len(raw) <= 65536, 'peer socket inventory exceeds bound')
        rows = [line.split() for line in raw.splitlines()[1:]]
        peers = [(row[1], row[2], row[9]) for row in rows
                 if row[1] == '0100007F:527E' and row[3] == '01']
        require(len(peers) == 1, 'network observation requires one established peer')
        return peers[0]

    connection = identity()
    keyed = keyed_count(server_log, file_limit)
    require(keyed > 0, 'authenticated peer is absent')

    def resources():
        command = (f'cat /proc/{app_pid}/stat; cat /proc/{app_pid}/status; '
                   'dumpsys activity recents')
        result = subprocess.run([adb, '-s', serial, 'shell', command], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        require(not result.stderr and len(result.stdout) < 131072, 'Android control observation failed')
        output = result.stdout.decode().replace('\r', '')
        first, _, status = output.partition('\n')
        start = process_start(first, app_pid)
        rss = re.findall(r'^VmRSS:\s+([1-9][0-9]*) kB$', status, re.M)
        threads = re.findall(r'^Threads:\s+([1-9][0-9]*)$', status, re.M)
        require(len(rss) == len(threads) == 1, 'Android resource fields are unavailable')
        tasks = set()
        for line in status.splitlines():
            if line.lstrip().startswith('* Recent #') and 'com.carriez.flutter_hbb' in line:
                match = re.search(r'Task\{[^}]* #([1-9][0-9]*)\b', line)
                require(match is not None, 'Android task identity is malformed')
                tasks.add(match[1])
        require(tasks == {task_id}, 'Android task changed')
        return dict(start=start, rss_kib=int(rss[0]), threads=int(threads[0]))

    baseline_resources = resources()
    previous_sequence = previous_state = -1
    last_frame = None

    def sample(phase):
        nonlocal previous_sequence, previous_state, last_frame
        started = time.monotonic_ns()
        require(identity() == connection, 'peer TCP connection changed')
        require(not os.path.lexists(observer_failure), 'frame observer failed')
        last_frame = read_file(frame, decoder['MAX_RECORD_BYTES'], replaceable=True)
        record = decoder['parse_record'](last_frame)
        analysis = decoder['analyze'](record, decoder['source_history'](Path(source)))
        ended = time.monotonic_ns()
        require(ended - started < 500_000_000 and record['observation_ms'] <= 500,
                'independent pixel observer exceeded its latency bound')
        sequence = record['sequence']
        require(sequence >= previous_sequence, 'frame observer sequence regressed')
        candidate = analysis['chosen']
        if candidate is not None:
            require(candidate['state'] >= previous_state, 'displayed source state regressed')
            previous_state = candidate['state']
        row = dict(phase=phase, sequence=sequence, independent=sequence > previous_sequence,
                   monotonic_us=ended // 1000, observer_ms=record['observation_ms'],
                   state=None if candidate is None else candidate['state'],
                   age_ms=None if candidate is None else candidate['age'],
                   candidates=analysis['candidates'] if candidate is None else [])
        previous_sequence = sequence
        print('ANDROID_PEER_NETWORK_SAMPLE=' + json.dumps(row, sort_keys=True), flush=True)
        return row

    def window(phase, seconds, limit=None):
        started = time.monotonic_ns()
        deadline = started + seconds * 1_000_000_000
        rows = []
        while time.monotonic_ns() < deadline:
            before = time.monotonic_ns()
            row = sample(phase)
            if limit is not None:
                require(row['age_ms'] is not None and row['age_ms'] <= limit,
                        phase + ' exceeded its healthy displayed-age bound')
            if row['independent']:
                rows.append(row)
            time.sleep(max(0, (before + PERIOD_NS - time.monotonic_ns()) / 1e9))
        require(len(rows) >= seconds * 2, phase + ' lacks independent pixel coverage')
        return rows

    def summarize(rows):
        ages = sorted(row['age_ms'] for row in rows)
        require(len({row['state'] for row in rows}) >= 4, 'healthy display did not advance')
        return dict(samples=len(rows), age_max_ms=max(ages), age_p95_ms=ages[(len(ages) * 95 + 99) // 100 - 1])

    def wait_fresh(phase, limit, started):
        states = set()
        while time.monotonic_ns() - started <= RECOVERY_MS * 1_000_000:
            row = sample(phase)
            if row['independent'] and row['age_ms'] is not None and row['age_ms'] <= limit:
                states.add(row['state'])
            if len(states) >= 4:
                break
            time.sleep(0.1)
        elapsed_ms = (time.monotonic_ns() - started + 999999) // 1000000
        require(len(states) >= 4 and elapsed_ms <= RECOVERY_MS,
                phase + ' did not reach four fresh states before the deadline')
        return elapsed_ms

    print('ANDROID_PEER_NETWORK_PLAN=' + json.dumps(dict(
        profiles=PROFILES, baseline_seconds=10, recovered_seconds=10, healthy_age_limit_ms=2000,
        baseline_settle_limit_ms=RECOVERY_MS,
        drift_limit_ms=DRIFT_MS, recovery_limit_ms=RECOVERY_MS, recovered_distinct_states=4,
        observer_limit_ms=500, sample_period_ms=250, queue_limit_packets=64,
        transport='adb-reverse-linux-tcp-leg', input_to_visible='unobserved')), flush=True)
    completed = []
    try:
        # The preceding static-screen cases have only just resumed drawing.
        settled_ms = wait_fresh('warmup', 2000, time.monotonic_ns())
        print('ANDROID_PEER_NETWORK_WARMUP=' + json.dumps(dict(
            elapsed_ms=settled_ms, distinct_states=4, deadline_ms=RECOVERY_MS)), flush=True)
        baseline = summarize(window('baseline', 10, 2000))
        age_limit = min(2000, baseline['age_max_ms'] + DRIFT_MS)
        print('ANDROID_PEER_NETWORK_BASELINE=' + json.dumps(baseline, sort_keys=True), flush=True)
        for ordinal, (profile, seconds) in enumerate(PROFILES, 1):
            before = request(profile)
            impaired = window(f'{ordinal}-{profile}', seconds)
            after = request('snapshot')
            require(after['packets'] >= before['packets'] and after['drops'] >= before['drops'],
                    'kernel impairment counters regressed')
            if profile != 'delay':
                require(after['drops'] > before['drops'], 'selected loss profile caused no kernel drops')
            else:
                require(after['packets'] > before['packets'], 'selected delay carried no peer packets')
            restored = time.monotonic_ns()
            request('healthy')
            recovery_ms = wait_fresh(f'{ordinal}-recovery', age_limit, restored)
            recovered = summarize(window(f'{ordinal}-healthy', 10, age_limit))
            require(recovered['age_p95_ms'] <= baseline['age_p95_ms'] + DRIFT_MS,
                    'recovered p95 display age drifted beyond the original baseline')
            current = resources()
            require(current['start'] == baseline_resources['start']
                    and current['rss_kib'] <= baseline_resources['rss_kib'] + 131072
                    and current['threads'] <= baseline_resources['threads'] + 8,
                    'Android process identity or resource bounds differ')
            require(identity() == connection and keyed_count(server_log, file_limit) == keyed,
                    'peer reauthenticated or changed connection')
            case = dict(ordinal=ordinal, profile=profile, seconds=seconds,
                        impaired_samples=len(impaired), kernel_before=before, kernel_after=after,
                        recovery_ms=recovery_ms, recovered=recovered, resources=current)
            completed.append(case)
            print('ANDROID_PEER_NETWORK_CASE=' + json.dumps(case, sort_keys=True), flush=True)
        request('finish')
    except Exception:
        if last_frame is not None:
            print('ANDROID_PEER_FRAMEBUFFER_RECORD_BEGIN '
                  f'bytes={len(last_frame)} sha256={hashlib.sha256(last_frame).hexdigest()} '
                  'encoding=base64 source=network-last-observation', flush=True)
            sys.stdout.write(base64.encodebytes(last_frame).decode('ascii'))
            print('ANDROID_PEER_FRAMEBUFFER_RECORD_END', flush=True)
        try:
            request('healthy')
        except Exception as restore_error:
            print('ANDROID_PEER_NETWORK_RESTORE_FAILED=' + repr(restore_error), flush=True)
        raise
    require(len(completed) == len(PROFILES), 'network schedule incomplete')
    print('ANDROID_PEER_NETWORK=pass cycles=6 pixels=actual connection=retained '
          'recovery_limit_ms=8000 drift_limit_ms=250 observer_limit_ms=500 '
          'transport=adb-reverse-linux-tcp-leg impairment=retired', flush=True)


if __name__ == '__main__':
    main()
