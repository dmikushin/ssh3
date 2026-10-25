#!/usr/bin/env python3
"""Bounded SSH READ transport. No service mutations, no remote client-PID claim."""
import importlib.util,json,os,re,selectors,stat,subprocess,time
from pathlib import Path
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('offline',B/'offline-transport-v5.py');api=importlib.util.module_from_spec(s);s.loader.exec_module(api)

def parse_snapshot(data,ports,expected_boot):
    if len(data)>65536:raise ValueError('snapshot overflow')
    lines=data.decode('ascii').splitlines();i=0
    def take():
        nonlocal i
        if i>=len(lines):raise ValueError('truncated snapshot')
        line=lines[i];i+=1;return line
    if take()!='SSH3_PORT_SNAPSHOT_V1' or take()!='HOST glazomer.io':raise ValueError('host/protocol mismatch')
    if take()!='BOOT '+expected_boot:raise ValueError('Oracle boot changed')
    bound=[]
    for port in ports:
        if take()!='BEGIN '+port or take()!='RC 0':raise ValueError('failed/missing socket dump')
        count=0
        while True:
            line=take()
            if line=='END '+port:break
            count+=1
            if count>64:raise ValueError('socket row overflow')
            fields=line.split()
            if len(fields)<5 or fields[0] not in ('LISTEN','UNCONN'):raise ValueError('malformed ss row')
            if not fields[1].isdigit() or not fields[2].isdigit():raise ValueError('malformed queues')
            address=fields[3]
            if not address.endswith(':'+port[1:]):raise ValueError('unexpected ss port')
            if port[0]=='t' and fields[0]!='LISTEN':raise ValueError('wrong socket state')
            bound.append(port)
    if take()!='COMPLETE' or i!=len(lines):raise ValueError('incomplete/trailing snapshot')
    return sorted(set(bound))

def bounded_read(argv,script,seconds=5):
    p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        sel=selectors.DefaultSelector()
        for f in (p.stdout,p.stderr):os.set_blocking(f.fileno(),False);sel.register(f,selectors.EVENT_READ)
        os.set_blocking(p.stdin.fileno(),False);sel.register(p.stdin,selectors.EVENT_WRITE)
        sent=0
        streams={p.stdout:bytearray(),p.stderr:bytearray()};deadline=time.monotonic()+seconds
        while sel.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ValueError('SSH read deadline exceeded')
            for key,_ in sel.select(remaining):
                if key.fileobj is p.stdin:
                    if sent<len(script):sent+=os.write(p.stdin.fileno(),script[sent:sent+4096])
                    if sent==len(script):sel.unregister(p.stdin);p.stdin.close()
                    continue
                block=os.read(key.fileobj.fileno(),4096)
                if not block:sel.unregister(key.fileobj);continue
                streams[key.fileobj].extend(block)
                if len(streams[key.fileobj])>65536:raise ValueError('SSH output cap exceeded')
        if p.wait(timeout=max(.01,deadline-time.monotonic()))!=0:raise ValueError('SSH collector failed')
        return bytes(streams[p.stdout])
    finally:
        if p.poll() is None:p.kill();p.wait()
        for f in (p.stdin,p.stdout,p.stderr):f.close()
        sel.close()

def trusted_directory(path,owner=0,test_anchor=None):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('absolute normalized directory required')
    if owner!=0:
        if test_anchor is None:raise ValueError('test owner requires explicit isolated anchor')
        anchor=Path(test_anchor)
        if not anchor.is_absolute() or not path.is_relative_to(anchor):raise ValueError('path outside test anchor')
        directories=[anchor]+[anchor.joinpath(*path.relative_to(anchor).parts[:i]) for i in range(1,len(path.relative_to(anchor).parts)+1)]
    else:
        if test_anchor is not None:raise ValueError('production cannot override trusted root')
        directories=[*reversed(path.parents),path]
    for directory in directories:
        s=directory.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=owner or s.st_mode&0o022:raise ValueError('untrusted directory ancestor')

def trusted_ssh(config,owner=0,test_anchor=None):
    config=Path(config)
    if not config.is_absolute():raise ValueError('explicit absolute SSH config required')
    trusted_directory(config.parent,owner,test_anchor)
    fd=os.open(config,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=owner or st.st_mode&0o222 or st.st_size>16384:raise ValueError('immutable regular SSH config required')
        text=os.read(fd,16385).decode('ascii')
    finally:os.close(fd)
    fields={}
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        key,sep,value=line.partition(' ')
        if not sep or key.lower() in fields:raise ValueError('ambiguous SSH config')
        fields[key.lower()]=value.strip()
    required={'host':'oracle-management-read','hostname':'gateway.mikush.in','port':'2221','user':'marcusmae','batchmode':'yes','stricthostkeychecking':'yes','identityagent':'none','identitiesonly':'yes','proxycommand':'none','proxyjump':'none'}
    if any(fields.get(k)!=v for k,v in required.items()):raise ValueError('pinned management route missing')
    if set(fields)-set(required)-{'identityfile','userknownhostsfile'}:raise ValueError('unreviewed SSH directive')
    for key in ('identityfile','userknownhostsfile'):
        path=Path(fields.get(key,''))
        if not path.is_absolute():raise ValueError('explicit identity/pin file required')
        trusted_directory(path.parent,owner,test_anchor)
        st=path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=owner or st.st_mode&0o022:raise ValueError('untrusted identity/pin path')
        if key=='identityfile' and (path.suffix=='.pub' or st.st_mode&0o077):raise ValueError('private root identity required with IdentityAgent none')
    return ['/usr/bin/ssh','-F',str(config),'oracle-management-read']

def collect(request,host_exit,root,output,ports,expected_boot,rollback,owner=0,reader=None,ssh_config=None,test_anchor=None):
    """host_exit is independently signed-off immutable HOST evidence, not Oracle PID."""
    try:
        api.observer.port_set(ports)
        if not ports or len(ports)>16:raise ValueError('bounded explicit ports required')
        if not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',expected_boot):raise ValueError('canonical pinned Oracle boot required')
        for path in (request,host_exit,output):trusted_directory(Path(path).parent,owner,test_anchor)
        trusted_directory(root,owner,test_anchor)
        req=api.observer.read_owned(request,owner);api.observer.transaction(req)
        evidence=api.observer.read_owned(host_exit,owner)
        for k in ('nonce','old_pid','old_start','binary_sha256','go_exit_ns'):
            if type(evidence.get(k)) is not type(req[k]) or evidence[k]!=req[k]:raise ValueError('host exit belongs to another transaction')
        if evidence.get('host_verified_client_exit') is not True:raise ValueError('host client exit not verified')
        if ssh_config is None:raise ValueError('trusted SSH config missing')
        argv=trusted_ssh(ssh_config,owner,test_anchor)+['bash','-s','--',*ports]
        started=time.time_ns()
        if started<req['go_exit_ns']:raise ValueError('collection predates client exit')
        data=(reader or bounded_read)(argv,(B/'collect-oracle-ports.sh').read_bytes())
        ended=time.time_ns()
        bound=parse_snapshot(data,ports,expected_boot)
        obs=dict(req,oracle_host='glazomer.io',observed_at_ns=ended,collection_started_at_ns=started,collection_ended_at_ns=ended,old_process_state='exited_identity_verified',snapshot_complete=True,socket_command_rc=0,listening_ports=bound,covered_ports=ports)
        # old_process_state is supplied by validated HOST evidence above. The
        # remote collector supplies ONLY host/boot/socket inventory.
        root=Path(root);api.check_root(root,owner)
        observation=root/'collected-observation.json'
        api.observer.write_atomic(observation,obs)
        return api.decide(request,observation,root,output,ports,rollback,owner)
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):
        rollback();return False
