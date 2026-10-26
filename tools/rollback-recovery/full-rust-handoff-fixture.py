"""Finite LOCAL real-Rust forward + actual saved-controller rollback integration.
No production containers/routes/keys or external services are used.
"""
import pathlib,subprocess,time,select,hashlib,importlib.util,json,signal,os,pwd,socket,threading
B=pathlib.Path(__file__).parent
D=B/'full-rust-handoff-case';D.mkdir(exist_ok=False);D.chmod(0o755)
N='ssh3-consult-full-rust-handoff';NET=N+'-net'
IMAGE='sha256:d12354e0ce77f49e911084e77da10865fbaa4aac19129a2fab366dce15df37fc'
SERVER=B.parent/'rollout-build-20261025/dist/ssh3-server'
CLIENT=B.parent/'keyfmt2-wt/dist/ssh3'
assert hashlib.sha256(SERVER.read_bytes()).hexdigest()=='8c6f7e1d79d3ce6c49760fab78234d7d94724a9ba36c25afa825b1e1d40462b1'
assert hashlib.sha256(CLIENT.read_bytes()).hexdigest()=='22d7ae4e72da841cad92ca021d7230e3a97dbb9c0944169e22590e1d6b6f425d'
def run(*a):return subprocess.check_output(a,text=True).strip()
def wait(f,seconds=8):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=f()
  if value:return value
  select.select([],[],[],.03)
 raise RuntimeError('finite fixture condition not reached')
def stamp(pid):return pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
def freeport():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
processes=[];network_created=False;container_created=False
backend=None;events=[]
try:
 run('docker','network','create',NET);network_created=True
 network=json.loads(run('docker','network','inspect',NET))[0];gateway=network['IPAM']['Config'][0]['Gateway']
 print('FIXTURE_NETWORK',NET,gateway,flush=True)
 # Reused fixture key and configuration fields from discriminate.sh.
 for key in ('host_key','user_key'):subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','fixture','-f',str(D/key)],check=True)
 (D/'authorized_keys').write_text((D/'user_key.pub').read_text())
 config=f'''listen = "{gateway}:0"
host_key = "{D}/host_key"
endpoint_keys = "{D}/endpoint-keys"
authorized_keys = "{D}/authorized_keys"
stats_socket = "{D}/stats.sock"
[session]
set_env = {{ HOME = "{D}", XDG_CONFIG_HOME = "{D}/.config" }}
[limits]
login_grace = "5s"
'''
 (D/'server.toml').write_text(config)
 output=(D/'server.out').open('w');error=(D/'server.err').open('w')
 server=subprocess.Popen([str(SERVER),'-f',str(D/'server.toml')],stdout=output,stderr=error);processes.append(server)
 wait(lambda:'listening on' in (D/'server.out').read_text())
 port=int((D/'server.out').read_text().split('listening on')[-1].strip().split(':')[-1].split()[0])
 (D/'known_hosts').write_text(f'[{gateway}]:{port} '+(D/'host_key.pub').read_text())
 backend=socket.socket();backend.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);backend.bind((gateway,0));backend.listen(8);backend.settimeout(.5);backend_port=backend.getsockname()[1]
 stop=threading.Event();body=b'LOCAL_REAL_RUST_200_BODY';response=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
 def serve():
  while not stop.is_set():
   try:connection,address=backend.accept()
   except socket.timeout:continue
   except OSError:return
   request=b'';entry=dict(accepted_ns=time.time_ns(),peer=str(address));events.append(entry)
   try:
    connection.settimeout(3)
    while b'\r\n\r\n' not in request:
     chunk=connection.recv(4096)
     if not chunk:break
     request+=chunk
     if len(request)>16384:raise ValueError('request cap exceeded')
    entry.update(request_bytes=len(request),request_complete_ns=time.time_ns())
    connection.sendall(response);entry.update(response_bytes=len(response),response_sent_ns=time.time_ns())
   except Exception as e:entry['error']=type(e).__name__+': '+str(e)
   finally:connection.close();entry['close_ns']=time.time_ns();(D/'backend-events.json').write_text(json.dumps(events,indent=2))
 thread=threading.Thread(target=serve,daemon=True);thread.start()
 # Actual Go carrier is replaced only by the clean-exit synthetic service.
 source=(B/'fixture-ssh.c').read_text().replace('18180','3180').replace('#include <arpa/inet.h>','#include <arpa/inet.h>\n#include <signal.h>\n#include <unistd.h>\nstatic void done(int s){(void)s;_exit(0);}') .replace('int main(void) {','int main(void) { signal(SIGTERM,done);')
 (D/'go.c').write_text(source);subprocess.run(['cc','-O2','-o',str(D/'fake-go'),str(D/'go.c')],check=True)
 (D/'key').write_text('FIXTURE_NOT_A_REAL_KEY\n');(D/'key').chmod(0o600)
 user=pwd.getpwuid(os.getuid()).pw_name
 (D/'bridge.conf').write_text(f'''Host fixture
 HostName {gateway}
 Port {port}
 User {user}
 IdentityFile /fixture/user_key
 IdentitiesOnly yes
 IdentityAgent none
 UserKnownHostsFile /fixture/known_hosts
 GlobalKnownHostsFile none
 StrictHostKeyChecking yes
 ExitOnForwardFailure yes
''')
 gate=(B/'container-gate-cancel-fix.sh').read_text().replace('/opt/ssh3-rs-handoff-mux-20261026','/fixture')
 gate=gate[:gate.index('  exec "$S/ssh3-rs"')]+ '  exec "$S/ssh3-rs" -F "$S/bridge.conf" -N -L "0.0.0.0:3180:'+gateway+':'+str(backend_port)+'" fixture </dev/null\n  ;;\n *) exit 64;;\nesac\n'
 (D/'gate.sh').write_text(gate)
 subprocess.run(['cp',str(CLIENT),str(D/'ssh3-rs')],check=True)
 subprocess.run(['cp',str(B.parent/'primary-cutover-20261025/hosts/fsync-path'),str(D/'fsync-path')],check=True)
 (D/'artifacts.sha256').write_text(hashlib.sha256(CLIENT.read_bytes()).hexdigest()+'  ssh3-rs\n')
 published=freeport()
 run('docker','run','-d','--name',N,'--network',NET,'-p',f'127.0.0.1:{published}:3180','--mount',f'type=bind,src={D},dst=/fixture','--mount',f'type=bind,src={D}/fake-go,dst=/usr/local/bin/ssh-shim,readonly','-e','AUTOSSH_DEBUG=1','-e','SSH_REMOTE_USER=fixture','-e','SSH_REMOTE_HOST=127.0.0.1','-e','SSH_KEY_PATH=/fixture/key','-e','WATCHDOG_PROBE_ADDR=127.0.0.1:3180','-e','WATCHDOG_GRACE_PERIOD=60',IMAGE);container_created=True
 def rows():return [r.split(None,2) for r in run('docker','top',N,'-eo','pid,ppid,args').splitlines()[1:]]
 def find(text):return next((int(r[0]) for r in rows() if text in r[2]),None)
 init=int(run('docker','inspect','--format','{{.State.Pid}}',N));sup=wait(lambda:find('/usr/local/bin/autossh'));wd=wait(lambda:find('/usr/local/bin/tunnel-watchdog'));go=wait(lambda:find('/usr/local/bin/ssh-shim'))
 ip=run('docker','inspect','--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',N)
 ids={p:stamp(p) for p in (init,sup,wd,go)};print('FIXTURE_PID_START',json.dumps(ids),'published',published,'directIP',ip,flush=True)
 def fetch(host,port):
  proc=subprocess.run(['curl','--noproxy','*','--silent','--show-error','--dump-header',str(D/('headers-'+host.replace('.','_'))),'--max-time','4',f'http://{host}:{port}/health'],capture_output=True)
  (D/('curl-'+host.replace('.','_')+'.stderr')).write_bytes(proc.stderr)
  print('HTTP_OBSERVATION',host,port,'rc',proc.returncode,'body_bytes',len(proc.stdout),'ns',time.time_ns(),flush=True)
  if proc.returncode:raise RuntimeError('curl failure '+str(proc.returncode)+': '+proc.stderr.decode(errors='replace'))
  assert b'200 OK' in (D/('headers-'+host.replace('.','_'))).read_bytes()
  return proc.stdout
 def baseline_listening():
  return any(len(f:=line.split())>3 and f[1].endswith(':0C6C') and f[3]=='0A' for line in pathlib.Path(f'/proc/{init}/net/tcp').read_text().splitlines()[1:])
 wait(baseline_listening)
 print('BASELINE_LISTENER_READY',time.time_ns(),flush=True)
 assert fetch(ip,3180)==b'';assert fetch('127.0.0.1',published)==b''
 for pid in (sup,wd):assert stamp(pid)==ids[pid];print('OWN_STOP',pid,flush=True);os.kill(pid,signal.SIGSTOP)
 assert stamp(go)==ids[go];print('OWN_TERM_SYNTHETIC_GO_EXIT0',go,flush=True);os.kill(go,signal.SIGTERM)
 wait(lambda:pathlib.Path(f'/proc/{go}/stat').read_text().rsplit(') ',1)[1].split()[0]=='Z')
 run('docker','exec','-d',N,'bash','-c','bash /fixture/gate.sh launch > /fixture/rust.log 2>&1')
 wait(lambda:(D/'rust.pid').exists())
 # Gate record precedes exec/bind. Observe LISTEN in the same namespace without
 # opening a dummy forwarded connection or issuing retries to the HTTP backend.
 def listening():
  for line in pathlib.Path(f'/proc/{init}/net/tcp').read_text().splitlines()[1:]:
   f=line.split()
   if f[1].endswith(':0C6C') and f[3]=='0A':return True
  return False
 wait(listening)
 post=[]
 for host,p in [('127.0.0.1',published),(ip,3180)]:post.append(fetch(host,p))
 assert post==[body,body];assert len(events)==2 and all(e.get('response_bytes')==len(response) for e in events)
 print('REAL_RUST_FORWARD_PASS upstream_bytes',len(response),'delivered_body',len(body),'two_endpoints',flush=True)
 # Force a local failed postcheck AFTER observing the correct forwarding result.
 # Rollback is the actual merged MUX controller's cancel(), not a substitute.
 spec=importlib.util.spec_from_file_location('controller',B/'controller-mux-recovery.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
 c.ROOT=D;c.CONTAINER=N;c.S='/fixture'
 runtime=dict(roles={r:dict(pid=p,start=ids[p],exe_sha256=hashlib.sha256(pathlib.Path(f'/proc/{p}/exe').read_bytes()).hexdigest()) for r,p in [('init',init),('autossh',sup),('watchdog',wd)]},netns=str(pathlib.Path(f'/proc/{init}/ns/net').readlink()))
 runtime['roles']['go']=dict(pid=go,start=ids[go],exe_sha256=hashlib.sha256((D/'fake-go').read_bytes()).hexdigest());c.write('runtime.json',runtime)
 def fixture_parent(p):
  st=p.lstat();assert p==D and st.st_uid==0 and st.st_mode&0o022==0
 c.safe_directory=fixture_parent
 def identity(role):
  rec=runtime['roles'][role];assert stamp(rec['pid'])==rec['start'];assert pathlib.Path(f'/proc/{init}').exists();return rec,runtime
 c.identity=identity
 realkill=os.kill
 def ownkill(pid,sig):
  assert pid in (sup,wd) and stamp(pid)==ids[pid];print('OWN_CONTROLLER_SIGNAL',pid,signal.Signals(sig).name,flush=True);realkill(pid,sig)
 c.os.kill=ownkill
 try:
  print('CONTROLLED_POSTCHECK_FAILURE_TRIGGER',time.time_ns(),flush=True);c.cancel()
  child=wait(lambda:find('/usr/local/bin/ssh-shim'));child_start=stamp(child)
  c.cancel();assert find('/usr/local/bin/ssh-shim')==child and stamp(child)==child_start
 finally:c.os.kill=realkill
 assert pathlib.Path(f'/proc/{child}/stat').read_text().rsplit(') ',1)[1].split()[0] not in ('Z','X')
 assert thread.is_alive() and all('error' not in e for e in events)
 assert child!=go and int(run('docker','inspect','--format','{{.State.Pid}}',N))==init
 assert fetch('127.0.0.1',published)==b'';assert fetch(ip,3180)==b''
 assert len([r for r in rows() if '/usr/local/bin/ssh-shim' in r[2]])==1
 print('ROLLBACK_PASS SAME_INIT',init,'ONE_REPLACEMENT',child,'REPEAT_STABLE HTTP200_BOTH_ENDPOINTS',flush=True)
 print('RUST_CLOSE_LOG',(D/'rust.log').read_text(),flush=True)
 print('AUTOSSH_LOG',run('docker','logs',N),flush=True)
finally:
 if backend is not None:stop.set();backend.close()
 for process in processes:
  if process.poll() is None:print('OWN_PROCESS_TERMINATE',process.pid,flush=True);process.terminate();process.wait()
 if container_created:
  with (D/'container-final.log').open('w') as f:subprocess.run(['docker','logs',N],stdout=f,stderr=subprocess.STDOUT,check=False)
  with (D/'container-final-inspect.json').open('w') as f:subprocess.run(['docker','inspect',N],stdout=f,check=False)
  subprocess.run(['docker','rm','-f',N],check=False)
 if network_created:subprocess.run(['docker','network','rm',NET],check=False)
