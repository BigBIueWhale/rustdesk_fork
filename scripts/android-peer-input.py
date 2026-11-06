#!/usr/bin/env python3
"""Measure Android framework keyboard input through actual remote display pixels."""
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import signal
import subprocess
import sys
import time


TRIALS = 120
RESPONSE_MS = 2000
QUIET_NS = 200_000_000


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    require(os.getuid() == os.getgid() == 1000 and len(sys.argv) == 17,
            'input observer principal or arguments differ')
    (decoder_path, frame, source, server_log, observer_failure, adb, serial,
     app_pid, task_id, server_pid, server_start, source_pid, source_start, file_limit,
     pause_path, response_directory) = sys.argv[1:]
    require(serial == 'emulator-5554' and all(re.fullmatch('[1-9][0-9]*', value) for value in
            (app_pid, task_id, server_pid, server_start, source_pid, source_start, file_limit)),
            'input observer identities differ')
    file_limit = int(file_limit)
    require(file_limit <= 128 * 1024 * 1024, 'peer log bound differs')
    decoder = runpy.run_path(decoder_path)
    common = runpy.run_path(str(Path(__file__).with_name('android-peer-soak.py')))
    read_file, process_start = common['read_file'], common['process_start']
    keyed_count = common['server_keyed_session_count']

    def identity():
        for pid, start in ((server_pid, server_start), (source_pid, source_start)):
            with open(f'/proc/{pid}/stat') as stream:
                require(process_start(stream.read(4097), pid) == int(start), 'peer/source process changed')
        with open('/proc/net/tcp') as stream:
            raw = stream.read(65537)
        require(len(raw) <= 65536, 'peer socket inventory exceeds bound')
        rows = [line.split() for line in raw.splitlines()[1:]]
        peers = [(row[1], row[2], row[9]) for row in rows
                 if row[1] == '0100007F:527E' and row[3] == '01']
        require(len(peers) == 1, 'input observation requires one established peer')
        return peers[0]

    connection = identity()
    clock_namespace = os.readlink('/proc/self/ns/time')
    require(all(os.readlink(f'/proc/{pid}/ns/time') == clock_namespace
                for pid in (source_pid, server_pid)), 'source and measurement clocks differ')
    keyed = keyed_count(server_log, file_limit)
    require(keyed > 0, 'authenticated peer is absent')

    def resources():
        command = (f'head -c 4096 /proc/{app_pid}/stat; head -c 65536 /proc/{app_pid}/status; '
                   'dumpsys activity recents | head -c 65536')
        result = subprocess.run([adb, '-s', serial, 'shell', command], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        require(not result.stderr and len(result.stdout) < 131072, 'Android resource observation failed')
        first, _, status = result.stdout.decode().replace('\r', '').partition('\n')
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
        require(identity() == connection and keyed_count(server_log, file_limit) == keyed,
                'peer changed or reauthenticated')
        return dict(start=start, rss_kib=int(rss[0]), threads=int(threads[0]))

    baseline_resources = resources()
    previous_sequence = previous_state = -1
    last_frame = None

    def sample(phase):
        nonlocal previous_sequence, previous_state, last_frame
        began = time.monotonic_ns()
        require(identity() == connection, 'input peer connection changed')
        require(not os.path.lexists(observer_failure), 'frame observer failed')
        last_frame = read_file(frame, decoder['MAX_RECORD_BYTES'], replaceable=True)
        record = decoder['parse_record'](last_frame)
        history = decoder['source_history'](Path(source))
        analysis = decoder['analyze'](record, history)
        ended = time.monotonic_ns()
        require(ended - began < 500_000_000 and record['observation_ms'] <= 500,
                'independent observer exceeded its latency bound')
        sequence = record['sequence']
        require(sequence >= previous_sequence, 'observer sequence regressed')
        # Quiet input-driven screens legitimately age; retain all identity/geometry checks.
        candidates = [entry for entry in analysis['candidates']
                      if entry['age'] >= 0 and entry['score'] >= entry['minimum']]
        states = {entry['state'] for entry in candidates}
        require(len(states) <= 1, 'displayed identity is ambiguous')
        state = next(iter(states), None)
        if state is not None:
            require(state >= previous_state, 'displayed source state regressed')
            previous_state = state
        row = dict(phase=phase, sequence=sequence, independent=sequence > previous_sequence,
                   state=state, source_state=max(history),
                   publication_us=None if state is None else history[state],
                   observed_monotonic_ns=record['observed_monotonic_ns'],
                   monotonic_ns=ended, observer_ms=record['observation_ms'])
        previous_sequence = sequence
        print('ANDROID_PEER_INPUT_SAMPLE=' + json.dumps(row, sort_keys=True), flush=True)
        return row, history

    def wait_target(target, began, limit_ms, phase):
        deadline = began + limit_ms * 1_000_000
        while time.monotonic_ns() < deadline:
            row, history = sample(phase)
            require(row['source_state'] <= target, 'source advanced without the next input')
            if row['state'] == target and row['independent']:
                require(row['monotonic_ns'] <= deadline, 'matching observation exceeded its deadline')
                return row, history
            time.sleep(0.05)
        raise RuntimeError(phase + ' did not display the expected input response')

    def quiet(target):
        began = time.monotonic_ns()
        samples = 0
        while True:
            row, history = sample('quiet')
            require(row['state'] == row['source_state'] == target,
                    'quiet interval advanced or lost the displayed state')
            if row['independent']:
                samples += 1
            if time.monotonic_ns() - began >= QUIET_NS and samples >= 2:
                return dict(start_ns=began, end_ns=time.monotonic_ns(), samples=samples,
                            state=target, publication_us=history[target])
            require(time.monotonic_ns() - began <= 1_000_000_000,
                    'quiet interval lacks independent observations')
            time.sleep(0.05)

    def acknowledge(event, previous, owner):
        began = time.monotonic_ns()
        while time.monotonic_ns() - began < 2_000_000_000:
            require(not select.select([owner], [], [], 0)[0] and identity() == connection,
                    'source exited or peer identity changed')
            lines = read_file(pause_path, 8192).splitlines()
            if len(lines) == previous + 1:
                match = re.fullmatch(event.encode() + rb' state=([0-9]+) monotonic_us=([0-9]+)', lines[-1])
                require(match is not None, 'pause/resume acknowledgement differs')
                return tuple(map(int, match.groups()))
            require(len(lines) == previous, 'pause/resume log length differs')
            time.sleep(0.01)
        raise RuntimeError('source did not acknowledge ' + event)

    print('ANDROID_PEER_INPUT_PLAN=' + json.dumps(dict(
        trials=TRIALS, response_limit_ms=RESPONSE_MS, quiet_min_ms=200,
        observer_limit_ms=500, initial_settle_limit_ms=2500, resume_limit_ms=8000,
        measurement='pre-adb-command-to-observed-pixels', input='android-framework-keyboard',
        workload='1920x1080-texture-one-outstanding-request', baseline_resources=baseline_resources,
        connection=connection, time_namespace=clock_namespace)), flush=True)
    responses = []
    with contextlib.ExitStack() as cleanup:
        owner = os.pidfd_open(int(source_pid))
        cleanup.callback(os.close, owner)
        require(identity() == connection and not select.select([owner], [], [], 0)[0],
                'source generation differs before pause')
        before = len(read_file(pause_path, 8192).splitlines())
        require(before == 16, 'the eight preceding static cases are incomplete')
        signal.pidfd_send_signal(owner, signal.SIGRTMIN)
        try:
            target, paused_us = acknowledge('paused', before, owner)
            wait_target(target, paused_us * 1000, 2500, 'initial-settle')
            for request in range(TRIALS + 1):
                control = quiet(target)
                keys = ['KEYCODE_' + chr(ord('A') + ((request >> shift) & 15))
                        for shift in (12, 8, 4, 0)] + ['KEYCODE_ENTER']
                began = time.monotonic_ns()
                injection = subprocess.run([adb, '-s', serial, 'shell', 'input', 'keyboard', '-d', '0',
                                            'keyevent', *keys], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, check=True, timeout=RESPONSE_MS / 1000)
                injected = time.monotonic_ns()
                require(not injection.stdout and not injection.stderr, 'Android key injection reported output')
                target += 1
                row, history = wait_target(target, began, RESPONSE_MS, 'response')
                require(began <= history[target] * 1000 <= row['observed_monotonic_ns'] <= row['monotonic_ns'],
                        'source/observation did not follow input')
                if request == 0:
                    ready = read_file(Path(response_directory) / 'input-response.ready', 16)
                    require(ready == f'{target}\n'.encode(), 'source input readiness differs')
                case = dict(request=request, target=target, quiet=control, sent_ns=began,
                            injected_ns=injected, publication_us=history[target],
                            observation_ns=row['observed_monotonic_ns'], completed_ns=row['monotonic_ns'],
                            response_ms=(row['monotonic_ns'] - began + 999999) // 1000000,
                            observer_ms=row['observer_ms'])
                print('ANDROID_PEER_INPUT_CASE=' + json.dumps(case, sort_keys=True), flush=True)
                if request:
                    responses.append(case['response_ms'])
                if request % 20 == 0:
                    current = resources()
                    require(current['start'] == baseline_resources['start']
                            and current['rss_kib'] <= baseline_resources['rss_kib'] + 131072
                            and current['threads'] <= baseline_resources['threads'] + 8,
                            'Android process identity or resource bounds differ')
                    print('ANDROID_PEER_INPUT_RESOURCES=' + json.dumps(current, sort_keys=True), flush=True)
            quiet(target)
        except Exception:
            if last_frame is not None:
                print('ANDROID_PEER_FRAMEBUFFER_RECORD_BEGIN '
                      f'bytes={len(last_frame)} sha256={hashlib.sha256(last_frame).hexdigest()} '
                      'encoding=base64 source=input-last-observation', flush=True)
                sys.stdout.write(base64.encodebytes(last_frame).decode('ascii'))
                print('ANDROID_PEER_FRAMEBUFFER_RECORD_END', flush=True)
            raise
        finally:
            signal.pidfd_send_signal(owner, signal.SIGUSR2)
            resumed, _ = acknowledge('resumed', before + 1, owner)
        require(resumed == target, 'source resume counter differs')
        began = time.monotonic_ns()
        fresh = set()
        while time.monotonic_ns() - began < 8_000_000_000:
            row, history = sample('resumed')
            if (row['independent'] and row['state'] is not None and row['state'] > target
                    and row['monotonic_ns'] - history[row['state']] * 1000 <= 2_000_000_000):
                fresh.add(row['state'])
            if len(fresh) >= 4:
                break
            time.sleep(0.05)
        require(len(fresh) >= 4 and time.monotonic_ns() - began <= 8_000_000_000,
                'moving display did not resume before deadline')
    require(len(responses) == TRIALS, 'input schedule is incomplete')
    ordered = sorted(responses)
    print('ANDROID_PEER_INPUT_SUMMARY=' + json.dumps(dict(
        trials=TRIALS, response_max_ms=max(ordered), response_p95_ms=ordered[113],
        response_p99_ms=ordered[118], resumed_distinct_states=len(fresh)), sort_keys=True), flush=True)
    print('ANDROID_PEER_INPUT=pass trials=120 bootstrap=1 pixels=actual input=android-framework-keyboard '
          'response_limit_ms=2000 quiet_min_ms=200 observer_limit_ms=500 connection=retained source=resumed', flush=True)


if __name__ == '__main__':
    main()
