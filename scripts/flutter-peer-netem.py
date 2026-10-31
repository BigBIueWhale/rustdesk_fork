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
    def __init__(self, image):
        self.image = image
        self.namespace = self.process = None
        self.interface = self.ingress = False

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
        self.run('tc', 'filter', 'add', 'dev', 'lo', 'parent', 'ffff:', 'protocol', 'ip',
                 'pref', '1', 'matchall', 'action', 'mirred', 'egress', 'redirect',
                 'dev', 'rd-netem')

    def profile(self, name):
        require(self.process is not None and alive(self.process), 'server is no longer live')
        options = {'healthy': ['delay', '0ms'], 'delay': ['delay', '125ms'],
                   'loss': ['loss', '100%']}
        require(name in options, 'unknown impairment profile')
        self.run('tc', 'qdisc', 'replace', 'dev', 'rd-netem', 'root', 'handle', '1:',
                 'netem', 'limit', '64', *options[name])

    def snapshot(self, request):
        queues = json.loads(self.run('tc', '-s', '-j', 'qdisc', 'show', 'dev', 'rd-netem'))
        queues = [q for q in queues if q['kind'] == 'netem']
        require(len(queues) == 1 and queues[0]['options']['limit'] == 64,
                'netem queue differs')
        queue = queues[0]
        now = time.monotonic_ns() // 1000
        print('FLUTTER_PEER_NETEM=' + json.dumps(
            dict(request=request, monotonic_us=now, namespace=os.fstat(self.namespace).st_ino,
                 queue=queue), sort_keys=True), flush=True)
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
    owner = Impairment(image)
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
                        require(requests <= 16, 'request budget exceeded')
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
