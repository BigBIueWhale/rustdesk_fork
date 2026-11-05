#!/usr/bin/env python3
"""Guest-only owner of impairment for one retained RustDesk test namespace."""
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time

ENDPOINT = '/run/rustdesk-verifier-vm/netem.sock'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def alive(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    return not poll.poll(0)


class Impairment:
    def __init__(self, image, congestion=False):
        self.image = image
        self.congestion = congestion
        self.namespace = self.process = None
        self.interface = self.ingress = False
        self.current_profile = None
        self.transport_active = False
        self.transport_identity = None
        self.transport_next = 0
        self.transport_count = 0
        self.transport_profiles = {}
        self.packet_size_baseline = None
        self.congestion_start = None

    def run(self, *args):
        require(self.namespace is not None, 'namespace is not attached')
        return subprocess.check_output(
            ['nsenter', '--net=/proc/self/fd/' + str(self.namespace), '--', *args],
            pass_fds=(self.namespace,), env=ENV, text=True, timeout=3)

    def inspect(self, cid):
        result = subprocess.check_output(
            ['/usr/bin/docker', '--host', 'unix:///run/rustdesk-verifier-vm/docker.sock',
             '--config', '/run/rustdesk-verifier-vm/docker-config', 'inspect', cid],
            env=ENV, text=True, timeout=3)
        records = json.loads(result)
        require(len(records) == 1, 'ambiguous container')
        record = records[0]
        host = record['HostConfig']
        require(record['Id'] == cid and record['Image'] == self.image
                and record['Config']['User'] == '1000:1000' and record['State']['Running']
                and host['NetworkMode'] == 'none' and host['ReadonlyRootfs']
                and not host['Privileged'] and not host['PidMode'] and not host['Devices']
                and not host['PortBindings'] and host['CapDrop'] == ['ALL']
                and host['SecurityOpt'] in (['no-new-privileges'], ['no-new-privileges:true']),
                'server container contract differs')
        return record['State']['Pid']

    def attach(self, cid):
        require(self.namespace is None and re.fullmatch('[0-9a-f]{64}', cid),
                'invalid or duplicate attachment')
        pid = self.inspect(cid)
        self.process = os.pidfd_open(pid)
        self.namespace = os.open(f'/proc/{pid}/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        require(alive(self.process) and self.inspect(cid) == pid, 'server generation changed')
        require(os.stat(f'/proc/{pid}/ns/time').st_ino == os.stat('/proc/self/ns/time').st_ino,
                'server and transport observer clocks differ')
        require(os.fstat(self.namespace).st_ino != os.stat('/proc/self/ns/net').st_ino,
                'initial guest namespace is forbidden')
        require([item['ifname'] for item in json.loads(self.run('ip', '-j', 'link', 'show'))]
                == ['lo'], 'server namespace topology differs')
        self.run('ip', 'link', 'add', 'rd-netem', 'type', 'ifb')
        self.interface = True
        self.run('ip', 'link', 'set', 'rd-netem', 'up')
        self.profile('healthy')
        self.run('tc', 'qdisc', 'add', 'dev', 'lo', 'handle', 'ffff:', 'ingress')
        self.ingress = True
        for preference, comparison in ((1, 'gt'), (2, 'eq')):
            self.run('tc', 'filter', 'add', 'dev', 'lo', 'parent', 'ffff:',
                     'protocol', 'ip', 'pref', str(preference), 'basic', 'match',
                     f'cmp(u16 at 2 layer network {comparison} 1500)',
                     'action', 'gact', 'continue', 'index', str(preference))
        self.run('tc', 'filter', 'add', 'dev', 'lo', 'parent', 'ffff:', 'protocol', 'ip',
                 'pref', '3', 'matchall', 'action', 'mirred', 'egress', 'redirect',
                 'dev', 'rd-netem')
        require(self.packet_sizes() == {'oversized': 0, 'at_mtu': 0},
                'packet size counters are not initially empty')
        # Exercise both sides of the boundary before reducing this private loopback MTU.
        self.run('python3', '-I', '-S', '-c', '''
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \\
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    receiver.bind(('127.0.0.1', 0))
    receiver.settimeout(1)
    for size in (1471, 1472, 1473):
        payload = bytes(size)
        assert sender.sendto(payload, receiver.getsockname()) == size
        assert receiver.recv(2048) == payload
''')
        self.packet_size_baseline = self.packet_sizes()
        require(self.packet_size_baseline == {'oversized': 1, 'at_mtu': 1},
                '1499/1500/1501-byte ingress controls differ')
        self.run('ip', 'link', 'set', 'dev', 'lo', 'mtu', '1500',
                 'gso_max_size', '1500', 'gso_max_segs', '1')
        links = json.loads(self.run('ip', '-d', '-j', 'link', 'show', 'dev', 'lo'))
        require(len(links) == 1 and links[0]['mtu'] == 1500
                and links[0]['gso_max_size'] == 1500 and links[0]['gso_max_segs'] == 1,
                'private packet sizing readback differs')
        print('FLUTTER_PEER_PACKET_CALIBRATION=' + json.dumps(
            dict(controls_ipv4_bytes=[1499, 1500, 1501], counters=self.packet_size_baseline,
                 link=links[0], observation='ipv4-total-length-before-ingress-netem'),
            sort_keys=True), flush=True)
        if self.congestion:
            self.calibrate_congestion()

    def tbf_options(self, name):
        limited = name in ('bandwidth', 'bandwidth-jitter')
        return ['tbf', 'rate', '32kbit' if limited else '10mbit',
                'burst', '1600' if limited else '16000', 'limit', '97500']

    def congestion_profile(self, name):
        require(name in ('healthy', 'jitter', 'bandwidth', 'bandwidth-jitter'),
                'unknown congestion profile')
        operation = 'add' if self.current_profile is None else 'change'
        # Change the existing queues: restoration must not discard their backlog.
        self.run('tc', 'qdisc', operation, 'dev', 'rd-netem', 'root', 'handle', '2:',
                 *self.tbf_options(name))
        delay = ['delay', '80ms', '30ms'] if 'jitter' in name else ['delay', '0ms']
        self.run('tc', 'qdisc', operation, 'dev', 'rd-netem', 'parent', '2:1',
                 'handle', '1:', 'netem', 'limit', '64', *delay)

    def calibrate_congestion(self):
        # No application connection exists yet. These sockets carry only test datagrams.
        self.congestion_profile('bandwidth')
        restore = ['tc', 'qdisc', 'change', 'dev', 'rd-netem', 'root', 'handle', '2:',
                   *self.tbf_options('healthy')]
        raw = self.run('python3', '-I', '-S', '-c', '''
import json, socket, subprocess, sys, time
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \\
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    receiver.bind(('127.0.0.1', 0))
    receiver.settimeout(2)
    started = time.monotonic_ns()
    for sequence in range(8):
        assert sender.sendto(bytes([sequence]) * 1000, receiver.getsockname()) == 1000
    for sequence in range(4):
        assert receiver.recv(2048) == bytes([sequence]) * 1000
    limited_ns = time.monotonic_ns() - started
    assert 500_000_000 <= limited_ns <= 1_500_000_000, limited_ns
    queued = json.loads(subprocess.check_output(
        ['tc', '-s', '-j', 'qdisc', 'show', 'dev', 'rd-netem']))
    root = [q for q in queued if q['kind'] == 'tbf']
    assert len(root) == 1 and root[0]['qlen'] >= 3 and root[0]['overlimits'] > 0, queued
    restored = time.monotonic_ns()
    subprocess.run(json.loads(sys.argv[1]), check=True, timeout=1)
    for sequence in range(4, 8):
        assert receiver.recv(2048) == bytes([sequence]) * 1000
    recovery_ns = time.monotonic_ns() - restored
    assert recovery_ns < 500_000_000, recovery_ns
    print(json.dumps(dict(limited_ns=limited_ns, restored_ns=recovery_ns,
                         queued_before_restore=root[0], received=8)))
''', json.dumps(restore))
        bandwidth = json.loads(raw)
        self.congestion_profile('jitter')
        raw = self.run('python3', '-I', '-S', '-c', '''
import json, socket, time
samples = []
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \\
     socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    receiver.bind(('127.0.0.1', 0))
    receiver.settimeout(1)
    for sequence in range(16):
        started = time.monotonic_ns()
        assert sender.sendto(bytes([sequence]), receiver.getsockname()) == 1
        assert receiver.recv(16) == bytes([sequence])
        samples.append(time.monotonic_ns() - started)
assert min(samples) >= 45_000_000 and max(samples) <= 250_000_000, samples
assert max(samples) - min(samples) >= 10_000_000, samples
print(json.dumps(samples))
''')
        self.congestion_profile('healthy')
        print('FLUTTER_PEER_CONGESTION_CALIBRATION=' + json.dumps(
            dict(bandwidth=bandwidth, jitter_ns=json.loads(raw), sockets='joined',
                 restoration='queued-datagrams-preserved'), sort_keys=True), flush=True)

    def packet_sizes(self):
        counts = {}
        for index, name in ((1, 'oversized'), (2, 'at_mtu')):
            raw = self.run('tc', '-s', 'actions', 'get', 'action', 'gact', 'index', str(index))
            matches = re.findall(r'\bSent [0-9]+ bytes ([0-9]+) pkt\b', raw)
            require(len(raw) <= 4096 and len(matches) == 1 and 'gact action continue' in raw
                    and re.search(r'\bindex ' + str(index) + r'\b', raw),
                    'packet size observation differs: ' + raw[:4096])
            counts[name] = int(matches[0])
        return counts

    def profile(self, name):
        require(self.process is not None and alive(self.process), 'server is no longer live')
        options = {'healthy': ['delay', '0ms'], 'delay': ['delay', '125ms'],
                   'loss': ['loss', '100%'],
                   'random3': ['loss', 'random', '3%'],
                   'random8': ['loss', 'random', '8%'],
                   'burst': ['loss', 'gemodel', '2%', '25%', '90%', '0.1%']}
        if self.congestion:
            if self.congestion_start is not None:
                root = next(q for q in self.congestion_queues() if q['kind'] == 'tbf')
                started, before = self.congestion_start
                elapsed = (time.monotonic_ns() - started) / 1e9
                delivered = root['bytes'] - before['bytes']
                require(root['overlimits'] > before['overlimits']
                        and 0 < delivered <= 4000 * elapsed + 3200,
                        'real-peer bandwidth constraint did not act as specified')
                print('FLUTTER_PEER_BANDWIDTH_OBSERVED=' + json.dumps(
                    dict(profile=self.current_profile, seconds=elapsed, bytes=delivered,
                         before=before, after=root), sort_keys=True), flush=True)
                self.congestion_start = None
            self.congestion_profile(name)
        else:
            require(name in options, 'unknown impairment profile')
            self.run('tc', 'qdisc', 'replace', 'dev', 'rd-netem', 'root', 'handle', '1:',
                     'netem', 'limit', '64', *options[name])
        self.current_profile = name
        if self.congestion and name in ('bandwidth', 'bandwidth-jitter'):
            root = next(q for q in self.congestion_queues() if q['kind'] == 'tbf')
            self.congestion_start = (time.monotonic_ns(), root)
        if name != 'healthy':
            self.transport_active = True
            self.transport_profiles.setdefault(name, 0)

    def observe_transport(self):
        if not self.transport_active or time.monotonic_ns() < self.transport_next:
            return
        started = time.monotonic_ns()
        self.transport_next = started + 200_000_000
        require(self.transport_count < 1024, 'transport observation budget exceeded')
        raw = self.run('ss', '-H', '-O', '-n', '-t', '-i', '-e', '-o',
                       'state', 'established', '(', 'sport', '=', ':21118',
                       'or', 'dport', '=', ':21118', ')')
        completed = time.monotonic_ns()
        require(len(raw.encode()) <= 8192, 'transport snapshot exceeds bound')
        records = []
        for line in raw.splitlines():
            fields = line.split()
            if fields and fields[0] == 'ESTAB':
                fields = fields[1:]
            require(len(fields) >= 4 and all(value.isdecimal() for value in fields[:2]),
                    'transport queue columns differ')
            local, peer = fields[2:4]
            require(all(re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}', value)
                        for value in (local, peer)) and '127.0.0.1:21118' in (local, peer),
                    'transport endpoint differs')
            inode = re.findall(r'\bino:([1-9][0-9]*)\b', line)
            cookie = re.findall(r'\bsk:([0-9a-f]+)\b', line)
            require(len(inode) == len(cookie) == 1 and re.search(r'\buid:1000\b', line),
                    'transport socket identity differs')
            mss = re.findall(r'\bmss:([0-9]+)\b', line)
            require(re.search(r'\bpmtu:1500\b', line) and len(mss) == 1
                    and 0 < int(mss[0]) <= 1460, 'transport packet sizing differs')
            records.append(dict(local=local, peer=peer, inode=int(inode[0]),
                                cookie=cookie[0], recv_queue=int(fields[0]),
                                send_queue=int(fields[1]), raw=line))
        require(len(records) <= 2, 'transport has more than one connection')
        identity = {(r['local'], r['peer'], r['inode'], r['cookie']) for r in records}
        if self.transport_identity is None:
            require(len(identity) == 2 and records[0]['local'] == records[1]['peer']
                    and records[0]['peer'] == records[1]['local'],
                    'transport does not contain the established peer pair')
            self.transport_identity = identity
        require(identity <= self.transport_identity, 'transport connection changed')
        complete = len(identity) == 2
        require(complete or self.current_profile == 'healthy',
                'transport closed during impairment')
        if complete and self.current_profile in self.transport_profiles:
            self.transport_profiles[self.current_profile] += 1
        self.transport_count += 1
        print('FLUTTER_PEER_TCP_SNAPSHOT=' + json.dumps(
            dict(sequence=self.transport_count, profile=self.current_profile,
                 started_us=started // 1000, completed_us=completed // 1000,
                 complete=complete, sockets=records,
                 queues=self.congestion_queues() if self.congestion else None),
            sort_keys=True), flush=True)
        if not records:
            self.transport_active = False

    def congestion_queues(self):
        queues = json.loads(self.run('tc', '-s', '-j', 'qdisc', 'show', 'dev', 'rd-netem'))
        require(len(queues) == 2 and {q['kind'] for q in queues} == {'tbf', 'netem'},
                'congestion queue topology differs')
        root = next(q for q in queues if q['kind'] == 'tbf')
        child = next(q for q in queues if q['kind'] == 'netem')
        limited = self.current_profile in ('bandwidth', 'bandwidth-jitter')
        burst = 1600 if limited else 16000
        delay = child['options'].get('delay', {})
        jitter = 'jitter' in self.current_profile
        require(root['handle'] == '2:' and root.get('root') is True
                and root['options']['rate'] == (4000 if limited else 1250000)
                and burst - 1 <= root['options']['burst'] <= burst
                and root['qlen'] <= 65 and root['backlog'] <= 65 * 1514
                and child['handle'] == '1:' and child['parent'] == '2:1'
                and child['options']['limit'] == 64 and child['qlen'] <= 64
                and abs(delay.get('delay', 0) - (0.08 if jitter else 0)) < 1e-6
                and abs(delay.get('jitter', 0) - (0.03 if jitter else 0)) < 1e-6,
                'congestion parameter/bound readback differs: ' + json.dumps(queues))
        return queues

    def snapshot(self, request):
        sizes = self.packet_sizes()
        require(self.packet_size_baseline is not None
                and sizes['oversized'] == self.packet_size_baseline['oversized'],
                'oversized IPv4 packet reached the impairment filter')
        queues = json.loads(self.run('tc', '-s', '-j', 'qdisc', 'show', 'dev', 'rd-netem'))
        queues = [q for q in queues if q['kind'] == 'netem']
        require(len(queues) == 1 and queues[0]['options']['limit'] == 64,
                'netem queue differs')
        queue = queues[0]
        options = queue['options']
        congestion = self.congestion_queues() if self.congestion else None
        random_loss = {'random3': 0.03, 'random8': 0.08}
        if self.current_profile in random_loss:
            observed = options.get('loss-random', {})
            require(abs(observed.get('loss', -1) - random_loss[self.current_profile]) < 1e-6
                    and observed.get('correlation') == 0,
                    'random loss profile readback differs')
        elif self.current_profile == 'burst':
            observed = options.get('loss-gemodel', {})
            require(all(abs(observed.get(key, -1) - value) < 1e-6
                        for key, value in {'p': 0.02, 'r': 0.25, '1-h': 0.9,
                                           '1-k': 0.001}.items()),
                    'burst loss profile readback differs')
        now = time.monotonic_ns() // 1000
        print('FLUTTER_PEER_NETEM=' + json.dumps(
            dict(request=request, monotonic_us=now, namespace=os.fstat(self.namespace).st_ino,
                 queue=queue, packet_sizes=sizes, congestion=congestion), sort_keys=True), flush=True)
        return f'OK {now} {queue["drops"]} {queue["packets"]} {queue["qlen"]}'.encode()

    def close(self):
        try:
            if self.ingress:
                self.run('tc', 'qdisc', 'del', 'dev', 'lo', 'ingress')
            if self.interface:
                self.run('ip', 'link', 'del', 'rd-netem')
        finally:
            for fd in (self.namespace, self.process):
                if fd is not None:
                    os.close(fd)
            self.namespace = self.process = None


def attach_client(cid):
    require(os.getuid() == 1000 and re.fullmatch('[0-9a-f]{64}', cid), 'attach caller differs')
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5)
        channel.connect(ENDPOINT)
        _, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require((uid, gid) == (0, 0), 'supervisor is not guest root')
        channel.sendall(('attach ' + cid).encode())
        reply = channel.recv(128)
        require(re.fullmatch(rb'OK [0-9]+ [0-9]+ [0-9]+ [0-9]+', reply), 'attach refused')
        print('FLUTTER_PEER_NETEM_ATTACHED=' + reply.decode())


def supervise(image, argv):
    require(os.getuid() == 0 and os.getgid() == 0, 'requires disposable guest root')
    require('rustdesk.verifier_vm=1' in Path('/proc/cmdline').read_text().split()
            and Path('/proc/1/comm').read_text().strip() == 'systemd', 'verifier guest absent')
    require(os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino,
            'supervisor must own the initial guest namespace')
    initial_links = subprocess.check_output(['ip', '-j', 'link', 'show'], env=ENV, timeout=3)
    require([link['ifname'] for link in json.loads(initial_links)] == ['lo'], 'guest NIC present')
    require(not os.path.lexists(ENDPOINT), 'supervisor endpoint occupied')
    subprocess.run(['modprobe', 'ifb', 'numifbs=0'], env=ENV, check=True, timeout=3)
    owner = Impairment(image, '--network-congestion' in argv or '--input-congestion' in argv)
    child = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(ENDPOINT)
        identity = os.lstat(ENDPOINT)
        os.chown(ENDPOINT, 1000, 1000)
        os.chmod(ENDPOINT, 0o600)
        listener.listen(1)
        listener.settimeout(0.2)
        try:
            child = subprocess.Popen(argv)
            requests = 0
            while child.poll() is None:
                owner.observe_transport()
                try:
                    channel, _ = listener.accept()
                except socket.timeout:
                    continue
                with channel:
                    channel.settimeout(3)
                    pid, uid, gid = struct.unpack('3i', channel.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    require((uid, gid) == (1000, 1000), 'foreign impairment requester')
                    requester = os.pidfd_open(pid)
                    try:
                        peer_namespace = os.stat(f'/proc/{pid}/ns/net').st_ino
                        require(alive(requester), 'requester exited')
                        data, _, flags, _ = channel.recvmsg(128)
                        require(not flags and data and len(data) < 128, 'invalid request frame')
                        request = data.decode('ascii')
                        requests += 1
                        # One attachment, nine profile/restore pairs, one failure restore.
                        require(requests <= 20, 'request budget exceeded')
                        if request.startswith('attach '):
                            require(peer_namespace == os.stat('/proc/self/ns/net').st_ino,
                                    'attachment requires the guest orchestrator')
                            owner.attach(request[7:])
                        else:
                            require(owner.namespace is not None
                                    and peer_namespace == os.fstat(owner.namespace).st_ino,
                                    'requester does not belong to the retained peer namespace')
                            owner.profile(request)
                        require(alive(requester), 'requester exited before acknowledgement')
                        channel.sendall(owner.snapshot(request))
                    finally:
                        os.close(requester)
            status = child.wait()
            if status == 0:
                sizes = owner.packet_sizes()
                require(sizes['oversized'] == owner.packet_size_baseline['oversized']
                        and sizes['at_mtu'] > owner.packet_size_baseline['at_mtu'],
                        'real-peer packet size coverage is missing or oversized')
                require(owner.transport_profiles
                        and all(count >= 2 for count in owner.transport_profiles.values()),
                        'impairment transport observations are incomplete')
                print('FLUTTER_PEER_TCP_OBSERVED=' + json.dumps(
                    dict(samples=owner.transport_count, profiles=owner.transport_profiles,
                         interval_ms=200, clock='shared-monotonic', socket_pair='retained',
                         source='ss-inet-diag', product_socket_changes=False,
                         packet_sizes=sizes), sort_keys=True),
                      flush=True)
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            owner.close()
            current = os.lstat(ENDPOINT)
            require(stat.S_ISSOCK(current.st_mode)
                    and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
                    'supervisor endpoint changed')
            os.unlink(ENDPOINT)
    require(subprocess.check_output(['ip', '-j', 'link', 'show'], env=ENV, timeout=3)
            == initial_links, 'initial guest links changed')
    print(f'FLUTTER_PEER_NETEM_JOINED status={status} namespace=retired socket=removed', flush=True)
    return status


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--attach':
        attach_client(sys.argv[2])
    else:
        require(len(sys.argv) > 3 and sys.argv[2] == '--', 'invalid supervisor command')
        raise SystemExit(supervise(sys.argv[1], sys.argv[3:]))
