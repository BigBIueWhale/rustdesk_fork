#!/usr/bin/env python3
"""Observe the real core CLI helper and its owned native X11 window in isolation."""
import ctypes as c
import errno
import hashlib
import os
from pathlib import Path
import re
import selectors
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

CASES = ("creator-thread", "shutdown", "bad-proof", "proof-timeout", "proof-close", "stream-close", "window-close")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class XError(c.Structure):
    _fields_ = [("type", c.c_int), ("display", c.c_void_p), ("resourceid", c.c_ulong),
                ("serial", c.c_ulong), ("error_code", c.c_ubyte),
                ("request_code", c.c_ubyte), ("minor_code", c.c_ubyte)]


class ClientData(c.Union):
    _fields_ = [("bytes", c.c_char * 20), ("shorts", c.c_short * 10), ("longs", c.c_long * 5)]


class ClientMessage(c.Structure):
    _fields_ = [("type", c.c_int), ("serial", c.c_ulong), ("send_event", c.c_int),
                ("display", c.c_void_p), ("window", c.c_ulong), ("message_type", c.c_ulong),
                ("format", c.c_int), ("data", ClientData)]


class Event(c.Union):
    _fields_ = [("client", ClientMessage), ("padding", c.c_long * 24)]


class Display:
    def __init__(self):
        self.x = c.CDLL("libX11.so.6")
        signatures = {
            "XOpenDisplay": ([c.c_char_p], c.c_void_p),
            "XDefaultRootWindow": ([c.c_void_p], c.c_ulong),
            "XQueryTree": ([c.c_void_p, c.c_ulong, c.POINTER(c.c_ulong),
                            c.POINTER(c.c_ulong), c.POINTER(c.POINTER(c.c_ulong)),
                            c.POINTER(c.c_uint)], c.c_int),
            "XFetchName": ([c.c_void_p, c.c_ulong, c.POINTER(c.c_void_p)], c.c_int),
            "XInternAtom": ([c.c_void_p, c.c_char_p, c.c_int], c.c_ulong),
            "XGetWindowProperty": ([c.c_void_p, c.c_ulong, c.c_ulong, c.c_long,
                                    c.c_long, c.c_int, c.c_ulong, c.POINTER(c.c_ulong),
                                    c.POINTER(c.c_int), c.POINTER(c.c_ulong),
                                    c.POINTER(c.c_ulong), c.POINTER(c.c_void_p)], c.c_int),
            "XGetWindowAttributes": ([c.c_void_p, c.c_ulong, c.c_void_p], c.c_int),
            "XGetImage": ([c.c_void_p, c.c_ulong, c.c_int, c.c_int, c.c_uint,
                           c.c_uint, c.c_ulong, c.c_int], c.c_void_p),
            "XGetPixel": ([c.c_void_p, c.c_int, c.c_int], c.c_ulong),
            "XDestroyImage": ([c.c_void_p], c.c_int),
            "XGetWMProtocols": ([c.c_void_p, c.c_ulong, c.POINTER(c.POINTER(c.c_ulong)),
                                 c.POINTER(c.c_int)], c.c_int),
            "XSendEvent": ([c.c_void_p, c.c_ulong, c.c_int, c.c_long, c.POINTER(Event)], c.c_int),
            "XSync": ([c.c_void_p, c.c_int], c.c_int),
            "XFree": ([c.c_void_p], c.c_int),
            "XCloseDisplay": ([c.c_void_p], c.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.x, name)
            function.argtypes, function.restype = args, result
        self.errors = []
        self.callback_type = c.CFUNCTYPE(c.c_int, c.c_void_p, c.POINTER(XError))
        self.callback = self.callback_type(self.on_error)
        self.x.XSetErrorHandler.argtypes = [self.callback_type]
        self.x.XSetErrorHandler.restype = c.c_void_p
        self.x.XSetErrorHandler(self.callback)
        self.display = self.x.XOpenDisplay(b":98")
        require(self.display, "native observer could not open the private X11 display")
        self.root = self.x.XDefaultRootWindow(self.display)
        self.pid_atom = self.x.XInternAtom(self.display, b"_NET_WM_PID", 0)

    def on_error(self, display, error):
        self.errors.append((error.contents.error_code, error.contents.resourceid))
        return 0

    def helper_window(self, pid):
        root, parent, count = c.c_ulong(), c.c_ulong(), c.c_uint()
        children = c.POINTER(c.c_ulong)()
        require(self.x.XQueryTree(self.display, self.root, c.byref(root), c.byref(parent),
                                 c.byref(children), c.byref(count)), "X11 tree query failed")
        found = []
        try:
            for index in range(count.value):
                window = children[index]
                name = c.c_void_p()
                self.x.XFetchName(self.display, window, c.byref(name))
                try:
                    if not name.value or c.string_at(name) != b"RustDesk whiteboard":
                        continue
                finally:
                    if name.value:
                        self.x.XFree(name)
                actual, items, remaining = c.c_ulong(), c.c_ulong(), c.c_ulong()
                format_bits, data = c.c_int(), c.c_void_p()
                status = self.x.XGetWindowProperty(self.display, window, self.pid_atom,
                    0, 1, 0, 6, c.byref(actual), c.byref(format_bits), c.byref(items),
                    c.byref(remaining), c.byref(data))  # XA_CARDINAL = 6
                try:
                    require(status == 0 and actual.value == 6 and format_bits.value == 32
                            and items.value == 1 and remaining.value == 0 and data.value,
                            "whiteboard window lacks a coherent native PID property")
                    if c.cast(data, c.POINTER(c.c_ulong))[0] == pid:
                        found.append(window)
                finally:
                    if data.value:
                        self.x.XFree(data)
        finally:
            if children:
                self.x.XFree(children)
        self.x.XSync(self.display, 0)
        require(not self.errors and len(found) <= 1, "native window observation was ambiguous")
        return found[0] if found else None

    def require_destroyed(self, window):
        attributes = c.create_string_buffer(1024)
        status = self.x.XGetWindowAttributes(self.display, window, attributes)
        self.x.XSync(self.display, 0)
        require(status == 0 and self.errors == [(3, window)],
                "helper window survived core CLI return or X11 evidence differed")
        self.errors.clear()

    def wait_destroyed(self, window, owner, server):
        deadline = time.monotonic() + 1
        while True:
            attributes = c.create_string_buffer(1024)
            status = self.x.XGetWindowAttributes(self.display, window, attributes)
            self.x.XSync(self.display, 0)
            if status == 0:
                require(self.errors == [(3, window)], "helper crash X11 evidence differs")
                self.errors.clear()
                return
            require(not self.errors and owner.poll() is None and server.poll() is None
                    and time.monotonic() < deadline, "crashed helper retained its native window")
            time.sleep(0.01)

    def wait_pixels(self, window, expected, owner, server):
        deadline = time.monotonic() + 3
        while True:
            require(time.monotonic() < deadline and owner.poll() is None and server.poll() is None,
                    "authenticated overlay pixels did not converge")
            image = self.x.XGetImage(self.display, window, 0, 0, 160, 128, c.c_ulong(-1).value, 2)
            require(image and not self.errors, "native overlay readback failed")
            try:
                pixels = (self.x.XGetPixel(image, 35, 42) & 0xffffff,
                          self.x.XGetPixel(image, 131, 106) & 0xffffff)
            finally:
                self.x.XDestroyImage(image)
            if pixels == expected:
                return
            time.sleep(0.01)

    def request_close(self, window):
        protocol = self.x.XInternAtom(self.display, b"WM_PROTOCOLS", 0)
        close = self.x.XInternAtom(self.display, b"WM_DELETE_WINDOW", 0)
        protocols, count = c.POINTER(c.c_ulong)(), c.c_int()
        require(self.x.XGetWMProtocols(self.display, window, c.byref(protocols), c.byref(count)),
                "actual helper did not publish native window protocols")
        try:
            require(close in [protocols[index] for index in range(count.value)],
                    "actual helper does not support a native window close request")
        finally:
            if protocols:
                self.x.XFree(protocols)
        event = Event()
        event.client.type = 33  # ClientMessage
        event.client.display = self.display
        event.client.window = window
        event.client.message_type = protocol
        event.client.format = 32
        event.client.data.longs[0] = close
        event.client.data.longs[1] = 0  # CurrentTime
        require(self.x.XSendEvent(self.display, window, 0, 0, c.byref(event)),
                "owned native window close request failed")
        self.x.XSync(self.display, 0)
        require(not self.errors, "owned window close produced X11 errors")

    def close(self):
        self.x.XCloseDisplay(self.display)


def artifact_digest(executable):
    digest = hashlib.sha256()
    with executable.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def observe_owner(executable, environment, display, server, parent_exit=False):
    cases = ("parent-exit",) if parent_exit else CASES
    environment = dict(environment)
    if parent_exit:
        environment["WHITEBOARD_PROBE_PARENT_EXIT"] = "1"
    log_path = Path("/tmp/whiteboard-parent-exit.log" if parent_exit else "/tmp/whiteboard-helper.log")
    with log_path.open("xb") as log:
        owner = subprocess.Popen([str(executable), "--server"], env=environment,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        selector = selectors.DefaultSelector()
        selector.register(owner.stdout, selectors.EVENT_READ)
        os.set_blocking(owner.stdout.fileno(), False)
        pending, active, completed, wrong_parent = b"", None, [], 0
        returned, phases, creator = False, {"creator-thread": [], "window-close": []}, 0
        helper_fd, helper_pid, helper_reaped = None, None, False

        def helper_alive():
            poller = select.poll()
            poller.register(helper_fd, select.POLLIN)
            return not poller.poll(0)

        def reap_helper():
            reap_deadline = time.monotonic() + 5
            while True:
                pid, status = os.waitpid(helper_pid, os.WNOHANG)
                if pid:
                    return status
                require(time.monotonic() < reap_deadline, "adopted helper did not exit")
                time.sleep(0.01)
        deadline = time.monotonic() + 25
        try:
            while True:
                require(time.monotonic() < deadline and server.poll() is None,
                        "native helper deadline or Xvfb lifetime failed")
                events = selector.select(0.1)
                if not events:
                    require(owner.poll() is None or (parent_exit and active is not None and helper_alive()),
                            "owner/helper exited without final output")
                    continue
                chunk = os.read(owner.stdout.fileno(), 4096)
                if not chunk:
                    break
                pending += chunk
                require(len(pending) <= 8192, "native control output exceeds its bound")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    text = line.decode("ascii")
                    print(text, flush=True)
                    ready = re.fullmatch(r"WHITEBOARD_HELPER_READY case=([a-z-]+) pid=([1-9][0-9]*) address_hex=([0-9a-f]+)", text)
                    done = re.fullmatch(r"WHITEBOARD_HELPER_DONE case=([a-z-]+) pid=([1-9][0-9]*) status=0", text)
                    cli_return = re.fullmatch(r"WHITEBOARD_HELPER_RETURNED case=([a-z-]+) pid=([1-9][0-9]*) alive=true worker=absent stream=retired", text)
                    overlay = re.fullmatch(r"WHITEBOARD_HELPER_OVERLAY phase=(draw|clear|cancel)", text)
                    if ready:
                        case, pid_text, address_hex = ready.groups()
                        require(active is None and len(completed) < len(cases)
                                and case == cases[len(completed)], "native cases differ")
                        pid, address = int(pid_text), bytes.fromhex(address_hex)
                        require(address.startswith(b"\0") and len(address) <= 108,
                                "native endpoint address differs")
                        window = None
                        window_deadline = time.monotonic() + 3
                        while window is None:
                            require(time.monotonic() < window_deadline and owner.poll() is None
                                    and server.poll() is None, "actual helper window never appeared")
                            window = display.helper_window(pid)
                            if window is None:
                                time.sleep(0.01)
                        active = (case, pid, address, window)
                        if parent_exit:
                            helper_pid = pid
                            helper_fd = os.pidfd_open(pid, 0)
                            require(helper_alive(), "helper exited before parent retirement")
                            listener_deadline = time.monotonic() + 1
                            while True:
                                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                                    probe.settimeout(1)
                                    try:
                                        probe.connect(address)
                                    except OSError as error:
                                        require(error.errno == errno.ECONNREFUSED and helper_alive()
                                                and owner.poll() is None and time.monotonic() < listener_deadline,
                                                "parent-exit helper listener never became ready")
                                    else:
                                        peer_pid, peer_uid, peer_gid = struct.unpack("3i", probe.getsockopt(
                                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                                        require((peer_pid, peer_uid, peer_gid) == (pid, 1000, 1000)
                                                and probe.recv(1) == b"",
                                                "observer was not refused by its exact helper before proof")
                                        break
                                time.sleep(0.01)
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as duplicate:
                                try:
                                    duplicate.bind(address)
                                except OSError as error:
                                    require(error.errno == errno.EADDRINUSE,
                                            "pre-proof helper listener ownership differs")
                                else:
                                    raise RuntimeError("helper listener retired before its parent")
                        owner.stdin.write(b"go\n")
                        owner.stdin.flush()
                        if parent_exit:
                            require(owner.wait(timeout=5) == 0 and helper_alive(),
                                    "parent did not exit normally while its helper remained observable")
                    elif cli_return:
                        require(active is not None and not returned
                                and cli_return.groups() == (active[0], str(active[1])),
                                "native CLI return differs from its owned live helper")
                        if parent_exit:
                            require(owner.poll() == 0 and helper_alive(),
                                    "parent death or live helper CLI return was not observed")
                        display.require_destroyed(active[3])
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                            peer.settimeout(1)
                            try:
                                peer.connect(active[2])
                            except OSError as error:
                                require(error.errno == errno.ECONNREFUSED, "endpoint refusal differs")
                            else:
                                raise RuntimeError("helper endpoint survived normal completion")
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                            listener.bind(active[2])
                        returned = True
                        owner.stdin.write(b"finish\n" if parent_exit else b"retired\n")
                        owner.stdin.flush()
                        if parent_exit:
                            status = reap_helper()
                            helper_reaped = True
                            require(os.waitstatus_to_exitcode(status) == 0 and not helper_alive(),
                                    "adopted helper did not retire normally")
                            print(f"WHITEBOARD_HELPER_DONE case=parent-exit pid={helper_pid} status=0", flush=True)
                            print("WHITEBOARD_HELPER_PARENT=pass owner=normal-exit helper=alive-at-cli-return worker=joined child=adopted-reaped", flush=True)
                            completed.append(active[0])
                            active, returned = None, False
                    elif done:
                        require(active is not None and returned
                                and done.groups() == (active[0], str(active[1])),
                                "native completion preceded resource retirement")
                        completed.append(active[0])
                        active, returned = None, False
                    elif overlay:
                        phase = overlay.group(1)
                        require(active is not None and active[0] in phases and not returned,
                                "authenticated overlay case differs")
                        observed_phases = phases[active[0]]
                        expected_phases = ("draw", "clear", "cancel") if active[0] == "window-close" else ("draw", "clear")
                        require(len(observed_phases) < len(expected_phases)
                                and phase == expected_phases[len(observed_phases)],
                                "authenticated overlay observation order differs")
                        if phase == "draw":
                            display.wait_pixels(active[3], (0x00ff00, 0x0000ff), owner, server)
                            acknowledgement = b"drawn\n"
                        elif phase == "clear":
                            display.wait_pixels(active[3], (0, 0x0000ff), owner, server)
                            acknowledgement = b"cleared\n"
                        else:
                            display.request_close(active[3])
                            acknowledgement = b"cancelled\n"
                        observed_phases.append(phase)
                        owner.stdin.write(acknowledgement)
                        owner.stdin.flush()
                    elif text == ("WHITEBOARD_HELPER_WRONG_PARENT=pass same_image=true role=server "
                                  "copied_token=true outcome=preproof-eof child=joined"):
                        require(active is not None and active[0] == "shutdown" and wrong_parent == 0,
                                "wrong-parent observation differs")
                        wrong_parent += 1
                    elif text == "WHITEBOARD_HELPER_CREATOR=pass thread=joined owner=alive helper=live proof=mutual pixels=two-owner-clear":
                        require(active is not None and active[0] == "creator-thread" and creator == 0
                                and phases["creator-thread"] == ["draw", "clear"] and owner.poll() is None,
                                "creator-thread retirement was not observed with live authenticated rendering")
                        creator += 1
                    else:
                        raise RuntimeError("unexpected native control output")
            require(not pending and active is None and tuple(completed) == cases
                    and (parent_exit or (wrong_parent == 1 and creator == 1
                         and phases == {"creator-thread": ["draw", "clear"], "window-close": ["draw", "clear", "cancel"]})),
                    "native cases did not complete")
            require(owner.wait(timeout=5) == 0, "native owner did not exit normally")
        finally:
            selector.close()
            owner.stdin.close()
            owner.stdout.close()
            if owner.poll() is None:
                owner.terminate()
                try:
                    owner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owner.kill()
                    owner.wait()
            if helper_fd is not None:
                try:
                    if not helper_reaped:
                        if helper_alive():
                            signal.pidfd_send_signal(helper_fd, signal.SIGKILL)
                        reap_helper()
                finally:
                    os.close(helper_fd)
            if owner.returncode != 0:
                sys.stderr.write(log_path.read_text())


def observe_client_generation(executable, environment, display, server, case):
    environment = dict(environment, WHITEBOARD_PROBE_CLIENT_GENERATION=case)
    log_path = Path(f"/tmp/whiteboard-client-{case}.log")
    generations = 1 if case in ("shutdown", "root-shutdown", "parent-loss") else 2
    needs_idle = case in ("withdrawal", "helper-close", "helper-crash", "root-shutdown")
    idle_connections = 2 if case in ("helper-close", "helper-crash") else 0
    with log_path.open("xb") as log:
        owner = subprocess.Popen([str(executable), "--server"], env=environment,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        owner_fd, selector = None, None
        pending, helpers, active = b"", [], None
        cleaned, idle_seen, root_joined, parent_killed = False, False, False, False

        def helper_alive(helper):
            poller = select.poll()
            poller.register(helper["fd"], select.POLLIN)
            return not poller.poll(0)

        deadline = time.monotonic() + 25
        try:
            owner_fd = os.pidfd_open(owner.pid, 0)
            selector = selectors.DefaultSelector()
            selector.register(owner.stdout, selectors.EVENT_READ)
            os.set_blocking(owner.stdout.fileno(), False)
            while True:
                require(time.monotonic() < deadline and server.poll() is None,
                        "global client scenario deadline or Xvfb lifetime failed")
                if not selector.select(0.1):
                    require(owner.poll() is None or (parent_killed and active is not None and helper_alive(active)),
                            "global client owner exited without final output")
                    continue
                chunk = os.read(owner.stdout.fileno(), 4096)
                if not chunk:
                    break
                pending += chunk
                require(len(pending) <= 8192, "global client output exceeds its bound")
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    text = line.decode("ascii")
                    print(text, flush=True)
                    ready = re.fullmatch(rf"WHITEBOARD_CLIENT_READY case={case} generation=([1-9][0-9]*) pid=([1-9][0-9]*) connections=2 task=retained", text)
                    overlay = re.fullmatch(r"WHITEBOARD_HELPER_OVERLAY phase=(draw|clear)", text)
                    snapshot = re.fullmatch(rf"WHITEBOARD_CLIENT_STATE case={case} generation=([0-9]+) phase=(Idle|Starting|Running|Stopping) task=(true|false) connections=([0-9]+) expected_generation=([1-9][0-9]*) pid=([1-9][0-9]*) task_joined=true helper_owned=true", text)
                    reaped = re.fullmatch(rf"WHITEBOARD_CLIENT_REAPED case={case} generation=([1-9][0-9]*) pid=([1-9][0-9]*) status=0 owner=production task=joined", text)
                    cleanup = re.fullmatch(rf"WHITEBOARD_CLIENT_CLEANUP case={case} generation=([1-9][0-9]*) pid=([1-9][0-9]*) status=0 owner=production child=normal-exit-reaped task=joined", text)
                    window_close = re.fullmatch(r"WHITEBOARD_CLIENT_WINDOW_CLOSE case=helper-close generation=1 pid=([1-9][0-9]*)", text)
                    root_stop = re.fullmatch(r"WHITEBOARD_CLIENT_ROOT_STOP case=root-shutdown generation=1 pid=([1-9][0-9]*)", text)
                    parent_loss = re.fullmatch(r"WHITEBOARD_CLIENT_PARENT_LOSS_READY generation=1 pid=([1-9][0-9]*) address_hex=([0-9a-f]+)", text)
                    helper_loss = re.fullmatch(r"WHITEBOARD_CLIENT_HELPER_LOSS_READY generation=1 pid=([1-9][0-9]*) address_hex=([0-9a-f]+)", text)
                    crash_reaped = re.fullmatch(r"WHITEBOARD_CLIENT_CRASH_REAPED generation=1 pid=([1-9][0-9]*) status=failed owner=production phase=Idle task=joined connections=2", text)
                    if ready:
                        generation, pid = map(int, ready.groups())
                        require(not cleaned and len(helpers) < generations
                                and generation == len(helpers) + 1
                                and all(helper["reaped"] and not helper_alive(helper) for helper in helpers)
                                and (not needs_idle or generation == 1 or idle_seen),
                                "successor preceded old helper reap or explicit later demand")
                        active = {"generation": generation, "pid": pid, "fd": os.pidfd_open(pid, 0),
                                  "window": None, "phases": [], "returned": False,
                                  "state": False, "reaped": False}
                        helpers.append(active)
                        window_deadline = time.monotonic() + 3
                        while active["window"] is None:
                            require(helper_alive(active) and owner.poll() is None and server.poll() is None
                                    and time.monotonic() < window_deadline,
                                    "global client's live native window never appeared")
                            active["window"] = display.helper_window(pid)
                            if active["window"] is None:
                                time.sleep(0.01)
                        owner.stdin.write(b"go\n")
                        owner.stdin.flush()
                    elif overlay:
                        phase = overlay.group(1)
                        require(active is not None and not active["returned"] and helper_alive(active)
                                and len(active["phases"]) < 2
                                and phase == ("draw", "clear")[len(active["phases"])],
                                "global client overlay order differs")
                        display.wait_pixels(active["window"], (0x00ff00, 0x0000ff) if phase == "draw"
                                            else (0, 0x0000ff), owner, server)
                        active["phases"].append(phase)
                        owner.stdin.write(b"drawn\n" if phase == "draw" else b"cleared\n")
                        owner.stdin.flush()
                    elif window_close:
                        require(case == "helper-close" and active is not None and active["generation"] == 1
                                and window_close.group(1) == str(active["pid"])
                                and active["phases"] == ["draw"] and not active["returned"]
                                and helper_alive(active) and owner.poll() is None,
                                "global helper close did not follow live two-owner presentation")
                        display.request_close(active["window"])
                        active["phases"].append("cancel")
                    elif root_stop:
                        require(case == "root-shutdown" and active is not None
                                and root_stop.group(1) == str(active["pid"])
                                and active["phases"] == ["draw"] and not active["returned"]
                                and helper_alive(active) and owner.poll() is None,
                                "root shutdown did not follow live two-owner presentation")
                        active["phases"].append("stop")
                    elif parent_loss:
                        require(case == "parent-loss" and not parent_killed and active is not None
                                and parent_loss.group(1) == str(active["pid"])
                                and active["phases"] == ["draw"] and not active["returned"]
                                and helper_alive(active) and owner.poll() is None,
                                "parent loss did not follow live two-owner presentation")
                        address = bytes.fromhex(parent_loss.group(2))
                        require(address.startswith(b"\0") and len(address) <= 108,
                                "global helper endpoint address differs")
                        active["address"] = address
                        signal.pidfd_send_signal(owner_fd, signal.SIGKILL)
                        require(owner.wait(timeout=5) == -signal.SIGKILL and helper_alive(active),
                                "exact parent was not killed with its helper still observable")
                        parent_killed = True
                        active["phases"].append("kill")
                    elif helper_loss:
                        require(case == "helper-crash" and len(helpers) == 1 and active is not None
                                and helper_loss.group(1) == str(active["pid"])
                                and active["phases"] == ["draw"] and not active["returned"]
                                and helper_alive(active) and owner.poll() is None,
                                "helper loss did not follow live two-owner presentation")
                        address = bytes.fromhex(helper_loss.group(2))
                        require(address.startswith(b"\0") and len(address) <= 108,
                                "crashed helper endpoint address differs")
                        active["address"] = address
                        signal.pidfd_send_signal(active["fd"], signal.SIGKILL)
                        death_deadline = time.monotonic() + 2
                        while helper_alive(active):
                            require(owner.poll() is None and server.poll() is None
                                    and time.monotonic() < death_deadline, "exact helper did not die")
                            time.sleep(0.01)
                        active["phases"].append("kill")
                        owner.stdin.write(b"killed\n")
                        owner.stdin.flush()
                    elif crash_reaped:
                        require(case == "helper-crash" and len(helpers) == 1 and active is not None
                                and crash_reaped.group(1) == str(active["pid"])
                                and active["phases"] == ["draw", "kill"] and not active["reaped"]
                                and not helper_alive(active) and not Path(f"/proc/{active['pid']}").exists()
                                and owner.poll() is None,
                                "production owner did not reap/join its crashed helper while alive")
                        display.wait_destroyed(active["window"], owner, server)
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                            peer.settimeout(1)
                            try:
                                peer.connect(active["address"])
                            except OSError as error:
                                require(error.errno == errno.ECONNREFUSED,
                                        "crashed helper endpoint refusal differs")
                            else:
                                raise RuntimeError("crashed helper retained its endpoint")
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                            listener.bind(active["address"])
                        active["reaped"] = True
                    elif text == "returned":
                        expected_phases = (["draw", "kill"] if case == "parent-loss" else
                                           ["draw", "stop"] if case == "root-shutdown" else
                                           ["draw", "cancel"] if case == "helper-close" and len(helpers) == 1
                                           else ["draw", "clear"])
                        require(active is not None and active["phases"] == expected_phases
                                and not active["returned"] and helper_alive(active)
                                and (owner.poll() == -signal.SIGKILL if case == "parent-loss" else owner.poll() is None),
                                "global client helper did not return while alive")
                        display.require_destroyed(active["window"])
                        active["returned"] = True
                        if case == "parent-loss":
                            require(parent_killed, "helper retirement preceded parent loss")
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                                peer.settimeout(1)
                                try:
                                    peer.connect(active["address"])
                                except OSError as error:
                                    require(error.errno == errno.ECONNREFUSED,
                                            "orphan helper endpoint refusal differs")
                                else:
                                    raise RuntimeError("orphan helper retained its endpoint")
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                                listener.bind(active["address"])
                            print(f"WHITEBOARD_CLIENT_PARENT_LOSS_OBSERVED generation=1 pid={active['pid']} parent=sigkill helper=alive worker=joined window=badwindow endpoint=refused-rebindable", flush=True)
                            owner.stdin.write(b"finish\n")
                            owner.stdin.flush()
                            reap_deadline = time.monotonic() + 5
                            while True:
                                pid, status = os.waitpid(active["pid"], os.WNOHANG)
                                if pid:
                                    active["reaped"] = True
                                    require(pid == active["pid"] and os.waitstatus_to_exitcode(status) == 0
                                            and not helper_alive(active) and not Path(f"/proc/{pid}").exists(),
                                            "adopted global helper did not exit normally and reap")
                                    break
                                require(time.monotonic() < reap_deadline, "adopted global helper did not exit")
                                time.sleep(0.01)
                            print(f"WHITEBOARD_CLIENT_PARENT_LOSS_REAPED generation=1 pid={pid} status=0 owner=subreaper", flush=True)
                            cleaned = True
                        else:
                            signal.pidfd_send_signal(owner_fd, signal.SIGUSR1)
                    elif snapshot:
                        require(active is not None and active["returned"] and not active["state"]
                                and helper_alive(active) and owner.poll() is None,
                                "client snapshot missed its live helper")
                        expected_connections = "2" if case in ("replacement", "helper-close") and active["generation"] == 1 else "0"
                        generation = str(active["generation"])
                        require(snapshot.groups() == (generation, "Stopping", "false", expected_connections,
                                                      generation, str(active["pid"])),
                                "committed stop lost its exact generation or demand before helper reap")
                        active["state"] = True
                        print(f"WHITEBOARD_CLIENT_OBSERVED case={case} generation={generation} phase=Stopping task=false connections={expected_connections} helper=alive window=badwindow owner=alive", flush=True)
                        owner.stdin.write(b"finish\n")
                        owner.stdin.flush()
                        signal.pidfd_send_signal(owner_fd, signal.SIGUSR1)
                    elif reaped:
                        require(active is not None and active["state"] and not active["reaped"]
                                and reaped.groups() == (str(active["generation"]), str(active["pid"]))
                                and not helper_alive(active) and not Path(f"/proc/{active['pid']}").exists(),
                                "production owner did not normally reap its exact old helper")
                        active["reaped"] = True
                    elif text == "WHITEBOARD_CLIENT_ROOT_JOIN case=root-shutdown generation=1 phase=Idle connections=0 task=joined helper=reaped":
                        require(case == "root-shutdown" and not root_joined and active is not None
                                and active["state"] and not helper_alive(active)
                                and not Path(f"/proc/{active['pid']}").exists() and owner.poll() is None,
                                "root drain returned before exact helper retirement")
                        root_joined = True
                    elif text == f"WHITEBOARD_CLIENT_IDLE case={case} retired_generation=1 observation_ms=500 connections={idle_connections}":
                        require(needs_idle and not idle_seen and len(helpers) == 1
                                and active["reaped"] and not helper_alive(active) and owner.poll() is None,
                                "retired demand did not leave the generation idle before explicit retry")
                        idle_seen = True
                        owner.stdin.write(b"idle\n")
                        owner.stdin.flush()
                    elif cleanup:
                        require(active is not None and not cleaned and len(helpers) == generations
                                and cleanup.groups() == (str(generations), str(active["pid"]))
                                and all(helper["reaped"] and not helper_alive(helper) for helper in helpers)
                                and (case != "root-shutdown" or root_joined),
                                "production owner did not reap its exact helper")
                        cleaned = True
                    else:
                        raise RuntimeError("unexpected global client control output")
            require(not pending and cleaned and (not needs_idle or idle_seen)
                    and owner.wait(timeout=5) == (-signal.SIGKILL if case == "parent-loss" else 0),
                    "global client fixture did not complete normal cleanup")
        finally:
            if selector is not None:
                selector.close()
            owner.stdin.close()
            owner.stdout.close()
            if owner.poll() is None:
                owner.terminate()
                try:
                    owner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owner.kill()
                    owner.wait()
            if owner_fd is not None:
                os.close(owner_fd)
            for helper in helpers:
                try:
                    if helper_alive(helper):
                        try:
                            signal.pidfd_send_signal(helper["fd"], signal.SIGKILL)
                        except ProcessLookupError:
                            pass  # The retained process exited between observation and signal.
                    # Normal cleanup was performed by the production generation owner;
                    # on fixture failure the subreaper owns any orphan instead.
                    if not helper["reaped"] and Path(f"/proc/{helper['pid']}").exists():
                        os.waitpid(helper["pid"], 0)
                finally:
                    os.close(helper["fd"])
            if owner.returncode != (-signal.SIGKILL if case == "parent-loss" else 0):
                sys.stderr.write(log_path.read_text())
    if case == "shutdown":
        print("WHITEBOARD_CLIENT_PHASE=pass generation=retained-before-helper-exit producer=global-registration pixels=two-owner-clear cleanup=production-reap task=joined", flush=True)
    elif case == "replacement":
        print("WHITEBOARD_CLIENT_REPLACEMENT=pass old=retained-through-demand successor=after-normal-reap generations=2 duplicate=shared pixels=both-generations cleanup=production-reap task=joined", flush=True)
    elif case == "withdrawal":
        print("WHITEBOARD_CLIENT_WITHDRAWAL=pass old=retained-through-withdrawal idle_observation_ms=500 successor=later-explicit-demand generations=2 pixels=both-generations cleanup=production-reap task=joined", flush=True)
    elif case == "helper-close":
        print("WHITEBOARD_CLIENT_HELPER_CLOSE=pass failure=native-window-close demand=retained old=joined-before-process-exit idle_observation_ms=500 retry=later-explicit-registration generations=2 pixels=both-generations cleanup=production-reap", flush=True)
    elif case == "root-shutdown":
        print("WHITEBOARD_CLIENT_ROOT_SHUTDOWN=pass admission=closed-during-and-after-drain old=retained-before-helper-exit root=joined-after-production-reap idle_observation_ms=500 generations=1 pixels=two-owner cleanup=production-reap", flush=True)
    elif case == "parent-loss":
        print("WHITEBOARD_CLIENT_PARENT_LOSS=pass parent=pidfd-sigkill precondition=running-two-owner-pixels helper=alive-at-cli-return worker=joined window=badwindow endpoint=refused-rebindable child=normal-exit-subreaper-reaped generations=1", flush=True)
    elif case == "helper-crash":
        print("WHITEBOARD_CLIENT_HELPER_LOSS=pass helper=pidfd-sigkill parent=alive old=production-reaped task=joined window=badwindow endpoint=refused-rebindable idle_observation_ms=500 demand=retained retry=later-explicit-same-id generations=2 pixels=both-generations", flush=True)
    else:
        raise RuntimeError("unknown global client scenario")


def observe_launch_owner_loss(executable, environment, display, server):
    environment = dict(environment, WHITEBOARD_PROBE_CLIENT_GENERATION="launch-owner-loss")
    log_path = Path("/tmp/whiteboard-client-launch-owner-loss.log")
    with log_path.open("xb") as log:
        owner = subprocess.Popen([str(executable), "--server"], env=environment,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        helper_fd, pid, window, address = None, None, None, None
        pending, stage = b"", 0

        def helper_alive():
            poller = select.poll()
            poller.register(helper_fd, select.POLLIN)
            return not poller.poll(0)

        try:
            with selectors.DefaultSelector() as selector:
                selector.register(owner.stdout, selectors.EVENT_READ)
                os.set_blocking(owner.stdout.fileno(), False)
                deadline = time.monotonic() + 20
                while True:
                    require(time.monotonic() < deadline and server.poll() is None,
                            "late launch owner-loss deadline or Xvfb lifetime failed")
                    if not selector.select(0.1):
                        require(owner.poll() is None, "late launch parent exited before observation")
                        continue
                    chunk = os.read(owner.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    pending += chunk
                    require(len(pending) <= 8192, "late launch control output exceeds its bound")
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        text = line.decode("ascii")
                        print(text, flush=True)
                        blocked = re.fullmatch(r"WHITEBOARD_CLIENT_LAUNCH_BLOCKED generation=1 pid=([1-9][0-9]*) address_hex=([0-9a-f]+)", text)
                        if blocked:
                            require(stage == 0 and owner.poll() is None, "late launch barrier repeated or parent exited")
                            pid = int(blocked.group(1))
                            address = bytes.fromhex(blocked.group(2))
                            require(address.startswith(b"\0") and len(address) <= 108, "late helper address differs")
                            helper_fd = os.pidfd_open(pid, 0)
                            window_deadline = time.monotonic() + 3
                            while window is None:
                                require(helper_alive() and owner.poll() is None and server.poll() is None
                                        and time.monotonic() < window_deadline, "created late helper has no live native window")
                                window = display.helper_window(pid)
                                if window is None:
                                    time.sleep(0.01)
                            owner.stdin.write(b"drop\n")
                            stage = 1
                        elif text == f"WHITEBOARD_CLIENT_LAUNCH_DROPPED generation=1 pid={pid} phase=Stopping launch=retained helper=unpublished replacement=refused":
                            require(stage == 1 and owner.poll() is None and helper_alive(),
                                    "owner drop did not leave the real creation operation retained")
                            owner.stdin.write(b"release\n")
                            stage = 2
                        elif text == f"WHITEBOARD_CLIENT_LAUNCH_FINISHED generation=1 pid={pid} phase=Stopping task=false helper=unpublished replacement=refused":
                            require(stage == 2 and owner.poll() is None and not helper_alive()
                                    and not Path(f"/proc/{pid}").exists(),
                                    "finished cancelled launch retained a live or unreaped helper while parent stayed alive")
                            display.require_destroyed(window)
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                                peer.settimeout(1)
                                try:
                                    peer.connect(address)
                                except OSError as error:
                                    require(error.errno == errno.ECONNREFUSED, "late helper endpoint refusal differs")
                                else:
                                    raise RuntimeError("late helper endpoint survived retirement")
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                                listener.bind(address)
                            owner.stdin.write(b"observed\n")
                            stage = 3
                        elif text == f"WHITEBOARD_CLIENT_LAUNCH_OWNER_LOSS_DONE generation=1 pid={pid} parent=alive launch=finished admission=refused":
                            require(stage == 3 and owner.poll() is None and not helper_alive(),
                                    "late launch final observation lost parent or child identity")
                            owner.stdin.write(b"done\n")
                            stage = 4
                        else:
                            raise RuntimeError("unexpected late launch control output")
                        owner.stdin.flush()
                require(not pending and stage == 4 and owner.wait(timeout=5) == 0,
                        "late launch fixture did not finish normally after independent retirement")
        finally:
            owner.stdin.close()
            owner.stdout.close()
            if owner.poll() is None:
                owner.terminate()
                try:
                    owner.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    owner.kill()
                    owner.wait()
            if helper_fd is not None:
                try:
                    if helper_alive():
                        try:
                            signal.pidfd_send_signal(helper_fd, signal.SIGKILL)
                        except ProcessLookupError:
                            pass  # The retained helper exited between observation and signal.
                    if Path(f"/proc/{pid}").exists():
                        os.waitpid(pid, 0)
                finally:
                    os.close(helper_fd)
            if owner.returncode != 0:
                sys.stderr.write(log_path.read_text())
    print("WHITEBOARD_CLIENT_LAUNCH_OWNER_LOSS=pass boundary=created-before-handoff root=dropped parent=alive launch=finished helper=exited-reaped window=badwindow endpoint=refused-rebindable replacement=refused", flush=True)


def main():
    require(os.getuid() == 1000 and os.getgid() == 1000, "native test principal differs")
    libc = c.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [c.c_int, c.c_ulong, c.c_ulong, c.c_ulong, c.c_ulong]
    libc.prctl.restype = c.c_int
    require(libc.prctl(36, 1, 0, 0, 0) == 0, "owned observer could not become a child subreaper")
    require(len(sys.argv) == 2 and sys.argv[1] == "/cargo-target/whiteboard-helper-probe",
            "compiled helper probe path differs")
    executable = Path(sys.argv[1])
    metadata = executable.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
            and metadata.st_gid == 1000 and metadata.st_nlink == 1
            and os.access(executable, os.X_OK), "compiled helper artifact authority differs")
    x_socket, lock = Path("/tmp/.X11-unix/X98"), Path("/tmp/.X98-lock")
    require(not os.path.lexists(x_socket) and not os.path.lexists(lock), "X11 endpoint already exists")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp/home",
                   "DISPLAY": ":98", "XDG_SESSION_TYPE": "x11",
                   "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    digest = artifact_digest(executable)
    with open("/tmp/whiteboard-xvfb.log", "xb") as log:
        server = subprocess.Popen(["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "320x240x24",
                                   "-nolisten", "tcp", "-ac", "-noreset"],
                                  env=environment, stdout=log, stderr=subprocess.STDOUT)
        display = None
        try:
            deadline = time.monotonic() + 10
            while not x_socket.is_socket():
                require(server.poll() is None and time.monotonic() < deadline, "owned Xvfb did not become ready")
                time.sleep(0.05)
            display = Display()
            observe_owner(executable, environment, display, server)
            observe_owner(executable, environment, display, server, parent_exit=True)
            for case in ("shutdown", "replacement", "withdrawal", "helper-close", "root-shutdown", "parent-loss", "helper-crash"):
                observe_client_generation(executable, environment, display, server, case)
            observe_launch_owner_loss(executable, environment, display, server)
            require(artifact_digest(executable) == digest and server.poll() is None,
                    "compiled helper artifact or Xvfb changed during execution")
        finally:
            if display is not None:
                display.close()
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                raise RuntimeError("owned Xvfb required forced retirement")
            if server.returncode != 0:
                sys.stderr.write(Path("/tmp/whiteboard-xvfb.log").read_text())
            require(server.returncode == 0 and not os.path.lexists(x_socket) and not os.path.lexists(lock),
                    "Xvfb did not retire normally with its endpoints")
    print("WHITEBOARD_HELPER_NATIVE=pass cases=8 cli=core-main parent=kernel-admitted "
          "wrong_parent=preproof-eof listener=retired-before-proof helper=normal-exit "
          "worker=absent-before-exit window=badwindow-before-exit reconnect=refused address=rebindable "
          "overlay=two-owner-clear window_close=authenticated-cancel creator_thread=joined-live parent_exit=preproof-retired client_phase=retained-before-exit xvfb=joined", flush=True)


if __name__ == "__main__":
    main()
