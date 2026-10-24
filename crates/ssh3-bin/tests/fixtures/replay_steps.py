#!/usr/bin/env python3
"""Server side of the predictive-echo e2e test: plays a record_steps.py
recording on its pty — the startup output, then for each recorded
keystroke, once it arrives, the output that followed it. Exits 3 on a
keystroke other than the recorded one."""
import os, struct, sys, termios, tty

def records(path):
    data = open(path, "rb").read()
    i = 0
    while i < len(data):
        tag, n = data[i:i + 1], struct.unpack(">I", data[i + 1:i + 5])[0]
        yield tag, data[i + 5:i + 5 + n]
        i += 5 + n

tty.setraw(0)
out = os.fdopen(1, "wb", buffering=0)
for tag, b in records(sys.argv[1]):
    if tag == b"O":
        out.write(b)
    else:
        got = b""
        while len(got) < len(b):
            got += os.read(0, len(b) - len(got))
        if got != b:
            sys.exit(3)
