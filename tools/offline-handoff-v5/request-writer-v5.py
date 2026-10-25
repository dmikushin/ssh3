#!/usr/bin/env python3
"""Create a transaction request; local host operation, no network collection."""
import argparse,json,os,secrets,time
from pathlib import Path

def write_request(path,pid,start):
    path=Path(path)
    data=dict(nonce=secrets.token_hex(32),old_pid=pid,old_start=start,binary_sha256='d455dfda32d402972fc28951d1a17835eecb92f31c74f40fba9822dfaab7146d',go_exit_ns=time.time_ns())
    tmp=path.with_name(path.name+'.next')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(data,f);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
        os.link(tmp,path,follow_symlinks=False);tmp.unlink()
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if tmp.exists():tmp.unlink()
    return data

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('path');p.add_argument('old_pid',type=int);p.add_argument('old_start');a=p.parse_args()
    if os.geteuid()!=0:raise ValueError('production request writer requires root')
    if a.old_pid<=1 or not a.old_start.isascii() or not a.old_start.isdecimal() or int(a.old_start)<=0:raise ValueError('invalid old identity')
    write_request(a.path,a.old_pid,a.old_start)
