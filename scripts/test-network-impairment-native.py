#!/usr/bin/env python3
"""Exercise receiver-ingress netem inside one disposable verifier namespace."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*args):
    return subprocess.check_output(args, text=True, timeout=3)


def qdisc(*options):
    run('tc', 'qdisc', 'replace', 'dev', 'rd-netem', 'root', 'handle', '1:',
        'netem', 'limit', '64', *options)


def interfaces():
    return sorted(entry['ifname'] for entry in json.loads(run('ip', '-j', 'link', 'show')))


def counters():
    records = json.loads(run('tc', '-s', '-j', 'qdisc', 'show', 'dev', 'rd-netem'))
    records = [entry for entry in records if entry['kind'] == 'netem']
    require(len(records) == 1, 'one exact netem queue is required')
    return records[0]


def receive(sock, expected):
    data = b''
    while len(data) < len(expected):
        block = sock.recv(len(expected) - len(data))
        require(bool(block), 'TCP closed before complete payload')
        data += block
    require(data == expected, 'TCP payload differs')


def exchange(client, server, sequence):
    payload = ('request-%04d' % sequence).encode()
    start = time.monotonic_ns()
    client.sendall(payload)
    receive(server, payload)
    server.sendall(payload)
    receive(client, payload)
    return (time.monotonic_ns() - start) / 1_000_000


def connection_identity(client, server):
    return [(os.fstat(s.fileno()).st_ino, s.getsockname(), s.getpeername())
            for s in (client, server)]


def main():
    require(os.getuid() == 0 and os.getgid() == 0, 'requires disposable guest administrator')
    require('rustdesk.verifier_vm=1' in Path('/proc/cmdline').read_text().split(),
            'verifier VM boot marker absent')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'guest init differs')
    require(os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino,
            'refuses the initial guest network namespace')
    require(interfaces() == ['lo'], 'private topology differs')
    require(not json.loads(run('ip', '-j', 'route', 'show')), 'unexpected private routes')
    run('ip', 'link', 'set', 'lo', 'up')
    interface_created = ingress_created = False
    try:
        run('ip', 'link', 'add', 'rd-netem', 'type', 'ifb')
        interface_created = True
        run('ip', 'link', 'set', 'rd-netem', 'up')
        qdisc('delay', '0ms')
        run('tc', 'qdisc', 'add', 'dev', 'lo', 'handle', 'ffff:', 'ingress')
        ingress_created = True
        filter_args = ('dev', 'lo', 'parent', 'ffff:', 'protocol', 'ip', 'pref', '1')
        run('tc', 'filter', 'add', *filter_args, 'matchall', 'action', 'mirred',
            'egress', 'redirect', 'dev', 'rd-netem')
        with socket.socket() as listener, socket.socket() as client:
            listener.settimeout(3)
            client.settimeout(3)
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            client.connect(listener.getsockname())
            server, _ = listener.accept()
            with server:
                server.settimeout(3)
                for endpoint in (client, server):
                    endpoint.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                identity = connection_identity(client, server)
                baseline = [exchange(client, server, i) for i in range(5)]
                require(max(baseline) < 100, 'healthy TCP exceeds 100 ms envelope')
                baseline_queue = counters()
                require(baseline_queue['packets'] > 0, 'traffic bypassed ingress netem')

                qdisc('delay', '125ms')
                delayed = [exchange(client, server, i) for i in range(5, 8)]
                require(all(200 <= value <= 1000 for value in delayed),
                        'bidirectional 125 ms ingress delay was not observed')
                delayed_queue = counters()

                # A configured qdisc alone must not satisfy the delay observation.
                run('tc', 'filter', 'del', *filter_args)
                bypass = [exchange(client, server, i) for i in range(8, 11)]
                require(max(bypass) < 100, 'removed classifier still delays TCP')
                run('tc', 'filter', 'add', *filter_args, 'matchall', 'action', 'mirred',
                    'egress', 'redirect', 'dev', 'rd-netem')
                qdisc('loss', '100%')
                before_loss = counters()
                payload = b'pending-during-complete-outage'
                lost_at = time.monotonic_ns()
                client.sendall(payload)
                server.settimeout(2)
                try:
                    unexpected = server.recv(len(payload))
                except socket.timeout:
                    pass
                else:
                    raise RuntimeError('complete outage delivered data or EOF: ' + repr(unexpected))
                held_ms = (time.monotonic_ns() - lost_at) / 1_000_000
                loss_queue = counters()
                require(held_ms >= 1900 and loss_queue['drops'] > before_loss['drops'],
                        'outage duration or actual kernel packet drops missing')

                restored_at = time.monotonic_ns()
                qdisc('delay', '0ms')
                server.settimeout(3)
                receive(server, payload)
                recovery_ms = (time.monotonic_ns() - restored_at) / 1_000_000
                require(recovery_ms <= 3000, 'same TCP connection did not recover')
                recovered = [exchange(client, server, i) for i in range(11, 16)]
                require(max(recovered) < 100, 'healthy latency did not return')
                require(connection_identity(client, server) == identity,
                        'connection changed across impairment')
                result = dict(baseline_ms=baseline, delayed_ms=delayed, bypass_ms=bypass,
                              outage_ms=held_ms, recovery_ms=recovery_ms, recovered_ms=recovered,
                              queue_limit_packets=64, baseline_queue=baseline_queue,
                              delayed_queue=delayed_queue, loss_queue=loss_queue,
                              recovered_queue=counters(), same_connection=True,
                              placement='loopback-receiver-ingress-via-ifb', product='unexecuted')
    finally:
        if ingress_created:
            run('tc', 'qdisc', 'del', 'dev', 'lo', 'ingress')
        if interface_created:
            run('ip', 'link', 'del', 'rd-netem')
    require(interfaces() == ['lo'], 'fixture interface retained')
    require(all(entry['kind'] != 'ingress'
                for entry in json.loads(run('tc', '-j', 'qdisc', 'show', 'dev', 'lo'))),
            'fixture ingress retained')
    print('NETWORK_IMPAIRMENT_NATIVE=' + json.dumps(result, sort_keys=True), flush=True)
    print('NETWORK_IMPAIRMENT_NATIVE_OK delay=observed bypass=observed loss=observed '
          'recovery=same-tcp sockets=closed interface=removed queue=removed product=unexecuted', flush=True)


if __name__ == '__main__':
    main()
