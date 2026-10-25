#!/usr/bin/env python3
"""Copy a validated immutable receipt locally; never invokes SSH or writes PASS."""
import argparse,importlib.util,os,time
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
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--request',required=True);p.add_argument('--destination',required=True);p.add_argument('--ports',nargs='+',required=True);x=p.parse_args()
    if os.geteuid()!=0:raise ValueError('root coordinator required')
    a=load_verified_adapter(ROOT)
    source=ROOT/'collection-state/host-receipt.json'
    for path in (source,Path(x.request),Path(x.destination)):a.trusted_directory(path.parent)
    request=a.api.observer.read_owned(x.request,0)
    if not a.api.barrier.validate(source,request,x.ports,time.time_ns(),0):raise ValueError('collected receipt does not match host transaction')
    receipt=a.api.observer.read_owned(source,0)
    a.api.observer.write_atomic(x.destination,receipt)
    print('VALIDATED_RECEIPT_COPIED_NOT_DEPLOYMENT_ACCEPTANCE')
