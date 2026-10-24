#!/usr/bin/env python3
"""Record a program's pty output keystroke by keystroke, for replay in the
predictive-echo e2e test (replay_steps.py plays it back on the server side).

Format: records of a tag byte, a u32 big-endian length and the bytes:
b'O' output the program wrote, b'K' a keystroke (sent before the 'O' that
follows it). The first record is the startup output.

Usage: record_steps.py OUT.steps -- vim -u NONE ...
"""
import os, pty, select, struct, sys, time, termios, fcntl

ESC = b"\x1b"
# vim insert mode, then ESC to normal mode (its ESC timeout is 1 s with
# -u NONE), a normal-mode command, and quit.
KEYS = [b"i"] + [bytes([c]) for c in b"hello world"] + [ESC, b"x", b":", b"q", b"!", b"\r"]
QUIET = {ESC: 1.6}

def drain(fd, quiet):
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], quiet)
        if not r:
            return out
        try:
            b = os.read(fd, 65536)
        except OSError:
            return out
        if not b:
            return out
        out += b

def main():
    dest, argv = sys.argv[1], sys.argv[sys.argv.index("--") + 1:]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execvp(argv[0], argv)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    recs = [(b"O", drain(fd, 1.0))]
    for k in KEYS:
        os.write(fd, k)
        recs.append((b"K", k))
        recs.append((b"O", drain(fd, QUIET.get(k, 0.4))))
    os.waitpid(pid, 0)
    with open(dest, "wb") as f:
        for tag, b in recs:
            f.write(tag + struct.pack(">I", len(b)) + b)

main()
