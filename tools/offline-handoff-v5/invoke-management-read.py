#!/usr/bin/env python3
"""Root-only management collection invocation. No credentials or PASS defaults."""
import argparse,importlib.util,json,os,stat,time
from pathlib import Path
# Inline into each privileged wrapper; no local module is imported first.
import stat

def load_verified_adapter(root, owner=0, test_anchor=None):
    root=Path(root)
    directories=[*reversed(root.parents),root,root/'source']
    if test_anchor is not None:
        anchor=Path(test_anchor)
        if owner==0 or not root.is_relative_to(anchor):raise ValueError('invalid test anchor')
        directories=[anchor]+[anchor.joinpath(*root.relative_to(anchor).parts[:i]) for i in range(1,len(root.relative_to(anchor).parts)+1)]+[root/'source']
    for directory in directories:
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode&0o022:raise ValueError('untrusted executable parent')
    names=('oracle-read-adapter.py','offline-transport-v5.py','observe-release-frozen-4bbe.py','receipt-barrier-v5.py','management-agent-policy.py')
    for name in names:
        fd=os.open(root/'source'/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_mode&0o222 or info.st_size>65536:raise ValueError('untrusted executable module')
        finally:os.close(fd)
    # Verified immutable root directories prevent nonprivileged replacement
    # between checks and import. Coordinator still pins exact source hashes.
    spec=importlib.util.spec_from_file_location('adapter',root/'source/oracle-read-adapter.py')
    adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
    return adapter

ROOT=Path('/var/lib/ssh3-rs-management-read-20261025')

def invoke(request,exit_receipt,ports):
    if os.geteuid()!=0:raise ValueError('coordinator root dispatcher required')
    a=load_verified_adapter(ROOT)
    a.trusted_directory(ROOT)
    # All host inputs are immutable root files; fail BEFORE agent/SSH on absence.
    for path in (request,exit_receipt):
        a.trusted_directory(Path(path).parent)
        a.api.observer.read_owned(path,0)
    receipt=a.api.observer.read_owned(ROOT/'agent-approval.json',0)
    queried=receipt.get('queried_at_ns')
    if type(queried) is not int or not 0<=time.time_ns()-queried<=60_000_000_000:raise ValueError('fresh explicit agent approval missing')
    approval=receipt['approval']
    if approval.get('socket_path')!='/home/marcusmae/.ssh/agent/autossh-agents.sock' or approval.get('socket_uid')!=1000 or approval.get('public_identity_path')!='/home/marcusmae/.ssh/keys/id_rsa.oracle.pub' or approval.get('public_fingerprint')!='SHA256:UqyRn4K7PwXm3J2luXkyKxcmYSC5wz2a0mli+x4aERs':raise ValueError('approved identity policy mismatch')
    boot=a.api.observer.read_owned(ROOT/'oracle-boot.json',0)
    if type(boot.get('observed_at_ns')) is not int or not 0<=time.time_ns()-boot['observed_at_ns']<=300_000_000_000:raise ValueError('fresh Oracle boot receipt required')
    # Dedicated one-shot state: exclusive creation prevents overwriting prior run.
    state=ROOT/'collection-state';state.mkdir(mode=0o700)
    failed=[]
    ok=a.collect(request,exit_receipt,state,state/'host-receipt.json',ports,boot['boot_uuid'],lambda:failed.append('ROLLBACK_REQUIRED'),ssh_config=ROOT/'management.conf',agent_approval=approval)
    if not ok:
        print('ROLLBACK_REQUIRED: caller must invoke its exact admitted host rollback; no success receipt created')
        return 1
    print(str(state/'host-receipt.json'))
    return 0

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--host-exit',required=True);p.add_argument('--ports',nargs='+',required=True);x=p.parse_args()
    raise SystemExit(invoke(x.request,x.host_exit,x.ports))
