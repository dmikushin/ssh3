#!/usr/bin/env python3
"""Explicit delegated-agent admission primitives; no agent/SSH connection here."""
import base64,hashlib,os,re,stat
from pathlib import Path

def fingerprint(public_line):
    fields=public_line.split()
    if len(fields)<2 or fields[0] not in ('ssh-rsa','ssh-ed25519','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521'):raise ValueError('unsupported public identity')
    blob=base64.b64decode(fields[1],validate=True)
    if len(blob)<4 or len(blob)>16384:raise ValueError('invalid key blob')
    size=int.from_bytes(blob[:4],'big')
    if size<1 or 4+size>len(blob) or blob[4:4+size].decode('ascii')!=fields[0]:raise ValueError('public key type mismatch')
    return 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')

def match_agent_identity(public_line,agent_listing,approved):
    """Listing must come from a separate bounded query to the approved socket.

    Matching fingerprints is necessary, not proof of signing or agent provenance.
    This function accepts text only and NEVER queries a live agent itself.
    """
    fp=fingerprint(public_line)
    if fp!=approved or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',approved):raise ValueError('unapproved public fingerprint')
    if len(agent_listing)>65536:raise ValueError('agent identity listing overflow')
    found=[]
    for line in agent_listing.splitlines():
        parts=line.split()
        if len(parts)<3 or not parts[0].isdigit() or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',parts[1]):raise ValueError('malformed agent listing')
        found.append(parts[1])
    if fp not in found:raise ValueError('selected public key absent from approved agent')
    return fp

def socket_policy(path,owner,approved_exact,anchor=None):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or str(path)!=approved_exact:raise ValueError('socket not explicitly approved')
    if anchor is None:
        directories=[*reversed(path.parent.parents),path.parent]
    else:
        anchor=Path(anchor)
        if not path.is_relative_to(anchor):raise ValueError('outside fixture anchor')
        rel=path.parent.relative_to(anchor)
        directories=[anchor]+[anchor.joinpath(*rel.parts[:i]) for i in range(1,len(rel.parts)+1)]
    for d in directories:
        st=d.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0,owner) or st.st_mode&0o022:raise ValueError('untrusted agent socket parent')
    st=path.lstat()
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid!=owner or st.st_mode&0o077:raise ValueError('agent socket must be owner-only Unix socket')
    return dict(path=str(path),uid=st.st_uid,device=st.st_dev,inode=st.st_ino)
