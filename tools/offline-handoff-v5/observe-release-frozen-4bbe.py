#!/usr/bin/env python3
"""Mint a v4 receipt from a trusted, immutable management observation.

Offline preparation only. This program opens no network connections. A future
privileged management collector must supply a complete socket snapshot taken
AFTER the matching Go exit. Collection/admission is not implemented here.
"""
import argparse
import json
import os
import stat
import re
import time
from pathlib import Path


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out


def read_owned(path, owner):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != owner or s.st_mode & 0o222 or s.st_size > 16384:
            raise ValueError('observation input must be immutable owner-controlled regular file <=16KiB')
        return json.loads(os.read(fd, 16385), object_pairs_hook=unique)
    finally:
        os.close(fd)


def port_set(values):
    if type(values) is not list or len(values) > 128:
        raise ValueError('port inventory must be a bounded list')
    if any(type(p) is not str or not re.fullmatch(r'[tu][1-9][0-9]{0,4}', p, flags=re.ASCII) or int(p[1:]) > 65535 for p in values):
        raise ValueError('noncanonical or invalid port')
    if len(set(values)) != len(values):
        raise ValueError('duplicate port')
    return set(values)


def transaction(value):
    if type(value) is not dict:
        raise ValueError('transaction object required')
    if type(value.get('old_pid')) is not int or value['old_pid'] <= 1:
        raise ValueError('invalid process identity')
    if type(value.get('go_exit_ns')) is not int or value['go_exit_ns'] <= 0:
        raise ValueError('invalid exit timestamp')
    for key, pattern in [('nonce', r'[0-9a-f]{64}'), ('binary_sha256', r'[0-9a-f]{64}'), ('old_start', r'[1-9][0-9]*')]:
        if type(value.get(key)) is not str or not re.fullmatch(pattern, value[key], flags=re.ASCII):
            raise ValueError('invalid transaction field ' + key)


def receipt(request, observation, ports, now):
    transaction(request)
    transaction(observation)
    requested = port_set(ports)
    covered = port_set(observation.get('covered_ports'))
    listening = port_set(observation.get('listening_ports'))
    if not requested or not requested <= covered:
        raise ValueError('missing requested port coverage')
    required = ('nonce', 'old_pid', 'old_start', 'binary_sha256', 'go_exit_ns')
    if any(observation[k] != request[k] for k in required):
        raise ValueError('observation belongs to another transaction')
    if observation.get('oracle_host') != 'glazomer.io':
        raise ValueError('unexpected management host')
    observed = observation.get('observed_at_ns')
    exited = request['go_exit_ns']
    if type(observed) is not int or type(exited) is not int or not exited <= observed <= now or now - observed > 5_000_000_000:
        raise ValueError('observation is stale or predates exit')
    if observation.get('old_process_state') != 'exited_identity_verified':
        raise ValueError('old process exit identity not verified')
    if observation.get('snapshot_complete') is not True or type(observation.get('socket_command_rc')) is not int or observation['socket_command_rc'] != 0:
        raise ValueError('socket inventory incomplete or failed')
    if requested & listening:
        raise ValueError('required port remains bound')
    return {**{k: request[k] for k in required}, 'observed_at_ns': observed,
            'ports': {p: 'free' for p in ports}}


def write_atomic(path, value):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError('receipt already exists; refusing replacement')
    temporary = path.with_name(path.name + '.next')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f)
            f.flush()
            os.fchmod(f.fileno(), 0o400)
            os.fsync(f.fileno())
        # link is exclusive: unlike replace it cannot overwrite an existing receipt.
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--request', required=True)
    p.add_argument('--observation', required=True)
    p.add_argument('--ports', required=True, nargs='+')
    p.add_argument('--output', required=True)
    args = p.parse_args()
    if os.geteuid() != 0:
        raise ValueError('production receipt writer requires root')
    trusted = Path('/var/lib/ssh3-rs-release-observer-20261025')
    for directory in (Path('/'), Path('/var'), Path('/var/lib'), trusted):
        s = directory.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('observer parent must be a nonsymlink root-controlled directory')
    for value in (args.request, args.observation, args.output):
        path = Path(value)
        if not path.is_absolute() or path.parent != trusted or path.name in ('', '.', '..'):
            raise ValueError('observer files must be direct children of the fixed trusted directory')
    write_atomic(args.output, receipt(read_owned(args.request, 0),
                                     read_owned(args.observation, 0), args.ports, time.time_ns()))


if __name__ == '__main__':
    main()
