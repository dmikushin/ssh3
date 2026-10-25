#!/usr/bin/env python3
"""Host-side bounded receipt validator. Never probes a network or writes PASS facts."""
import argparse
import json
import os
import stat
import time
from pathlib import Path


def validate(path, request, ports, now, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_mode & 0o222 or st.st_size > 16384:
            return False
        data = os.read(fd, 16385)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate receipt key')
                result[key] = value
            return result
        receipt = json.loads(data, object_pairs_hook=unique)
        for field in ('nonce', 'old_pid', 'old_start', 'binary_sha256', 'go_exit_ns'):
            if receipt.get(field) != request[field]:
                return False
        observed = receipt.get('observed_at_ns')
        if type(observed) is not int or not request['go_exit_ns'] <= observed <= now:
            return False
        return receipt.get('ports') == {port: 'free' for port in ports}
    finally:
        os.close(fd)


def wait_receipt(path, request, ports, timeout, owner=0):
    end = time.monotonic() + timeout
    while True:
        try:
            if validate(path, request, ports, time.time_ns(), owner):
                return True
        except (OSError, ValueError, TypeError, KeyError):
            pass
        remaining = end - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--request', required=True)
    p.add_argument('--receipt', required=True)
    p.add_argument('--ports', nargs='+', required=True)
    p.add_argument('--timeout', type=float, default=30)
    p.add_argument('--recheck', action='store_true')
    a = p.parse_args()
    request = json.loads(Path(a.request).read_text())
    return 0 if wait_receipt(a.receipt, request, a.ports, 0 if a.recheck else a.timeout) else 1

if __name__ == '__main__':
    raise SystemExit(main())
