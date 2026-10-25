#!/usr/bin/env python3
"""LOCAL adapter only: no SSH collector or claim that synthetic facts are real.

Production callers must use the fixed trusted observer root and root ownership.
Tests explicitly inject an isolated root/current uid; observer logic is unchanged.
"""
import importlib.util,os,stat,time
from pathlib import Path
B=Path(__file__).parent

def load(name,file):
    s=importlib.util.spec_from_file_location(name,B/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
observer=load('frozen_observer','observe-release-frozen-4bbe.py')
barrier=load('v5_barrier','receipt-barrier-v5.py')

def check_root(root,owner):
    root=Path(root)
    if not root.is_absolute():raise ValueError('absolute trusted root required')
    # Every ancestor must reject symlinks/non-directories and uncontrolled writes.
    for p in [*reversed(root.parents),root]:
        st=p.lstat()
        if not stat.S_ISDIR(st.st_mode):raise ValueError('symlink/non-directory ancestor')
    st=root.lstat()
    if st.st_uid!=owner or st.st_mode&0o022:raise ValueError('untrusted adapter root')

def transfer(request,observation,root,output,ports,owner=0):
    root=Path(root);check_root(root,owner)
    req=observer.read_owned(request,owner)
    obs=observer.read_owned(observation,owner)
    # Re-serialize only already-validated immutable bounded JSON; no mode600
    # source is silently "laundered" into an accepted mode400 copy.
    observer.write_atomic(root/'request.json',req)
    observer.write_atomic(root/'observation.json',obs)
    copied_req=observer.read_owned(root/'request.json',owner)
    copied_obs=observer.read_owned(root/'observation.json',owner)
    receipt=observer.receipt(copied_req,copied_obs,ports,time.time_ns())
    observer.write_atomic(root/'receipt.json',receipt)
    receipt=observer.read_owned(root/'receipt.json',owner)
    observer.write_atomic(output,receipt)

def decide(request,observation,root,output,ports,rollback,owner=0):
    try:
        transfer(request,observation,root,output,ports,owner)
        req=observer.read_owned(request,owner)
        if not barrier.validate(output,req,ports,time.time_ns(),owner):raise ValueError('host barrier refused transferred receipt')
    except (OSError,ValueError,TypeError,KeyError):
        rollback();return False
    return True
