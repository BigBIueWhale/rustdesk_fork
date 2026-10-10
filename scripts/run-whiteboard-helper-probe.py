#!/usr/bin/env python3
"""Observe the real core CLI helper and its owned native X11 window in isolation."""
import ctypes as c
import errno
import hashlib
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import subprocess
import sys
import time

CASES = ("shutdown", "bad-proof", "proof-timeout", "proof-close", "stream-close", "window-close")


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


def observe_owner(executable, environment, display, server):
    with open("/tmp/whiteboard-helper.log", "xb") as log:
        owner = subprocess.Popen([str(executable), "--server"], env=environment,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        selector = selectors.DefaultSelector()
        selector.register(owner.stdout, selectors.EVENT_READ)
        os.set_blocking(owner.stdout.fileno(), False)
        pending, active, completed, wrong_parent = b"", None, [], 0
        returned, phases = False, []
        deadline = time.monotonic() + 25
        try:
            while True:
                require(time.monotonic() < deadline and server.poll() is None,
                        "native helper deadline or Xvfb lifetime failed")
                events = selector.select(0.1)
                if not events:
                    require(owner.poll() is None, "owner exited without final output")
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
                        require(active is None and len(completed) < len(CASES)
                                and case == CASES[len(completed)], "native cases differ")
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
                        owner.stdin.write(b"go\n")
                        owner.stdin.flush()
                    elif cli_return:
                        require(active is not None and not returned
                                and cli_return.groups() == (active[0], str(active[1])),
                                "native CLI return differs from its owned live helper")
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
                        owner.stdin.write(b"retired\n")
                        owner.stdin.flush()
                    elif done:
                        require(active is not None and returned
                                and done.groups() == (active[0], str(active[1])),
                                "native completion preceded resource retirement")
                        completed.append(active[0])
                        active, returned = None, False
                    elif overlay:
                        phase = overlay.group(1)
                        require(active is not None and active[0] == "window-close" and not returned
                                and len(phases) < 3 and phase == ("draw", "clear", "cancel")[len(phases)],
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
                        phases.append(phase)
                        owner.stdin.write(acknowledgement)
                        owner.stdin.flush()
                    elif text == ("WHITEBOARD_HELPER_WRONG_PARENT=pass same_image=true role=server "
                                  "copied_token=true outcome=preproof-eof child=joined"):
                        require(active is not None and active[0] == "shutdown" and wrong_parent == 0,
                                "wrong-parent observation differs")
                        wrong_parent += 1
                    else:
                        raise RuntimeError("unexpected native control output")
            require(not pending and active is None and tuple(completed) == CASES and wrong_parent == 1
                    and phases == ["draw", "clear", "cancel"],
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
            if owner.returncode != 0:
                sys.stderr.write(Path("/tmp/whiteboard-helper.log").read_text())


def main():
    require(os.getuid() == 1000 and os.getgid() == 1000, "native test principal differs")
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
    print("WHITEBOARD_HELPER_NATIVE=pass cases=6 cli=core-main parent=kernel-admitted "
          "wrong_parent=preproof-eof listener=retired-before-proof helper=normal-exit "
          "worker=absent-before-exit window=badwindow-before-exit reconnect=refused address=rebindable "
          "overlay=two-owner-clear window_close=authenticated-cancel xvfb=joined", flush=True)


if __name__ == "__main__":
    main()
