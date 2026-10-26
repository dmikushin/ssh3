import pathlib,subprocess,time,select,hashlib,importlib.util,json,signal,os,sys
mode=sys.argv[1];assert mode in ("before-stop","only-autossh-stop","both-stop-go-alive","go-exited","autossh-resumed");code=0;iteration=sys.argv[2]
B=pathlib.Path(__file__).parent
D=B/('candidate-'+mode+'-'+iteration);D.mkdir(exist_ok=False);D.chmod(0o755)
N='ssh3-consult-candidate-'+mode+'-'+iteration
def run(*a):
 if os.geteuid()==0 and a[:2]==('sudo','-n'):a=a[2:]
 return subprocess.check_output(a,text=True).strip()
def wait(f,seconds=8):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=f()
  if v:return v
  select.select([],[],[],.03)
 raise RuntimeError('finite fixture condition not reached')
source=D/'go.c';source.write_text((B/'fixture-ssh.c').read_text().replace('#include <arpa/inet.h>','#include <arpa/inet.h>\n#include <signal.h>\n#include <unistd.h>\nstatic void done(int s){(void)s;_exit(0);}') .replace('int main(void) {','int main(void) { signal(SIGTERM,done);'))
subprocess.run(['cc','-O2','-o',str(D/'fake-go'),str(source)],check=True)
(D/'key').write_text('SYNTHETIC_FIXTURE_NOT_A_KEY\n');(D/'key').chmod(0o600)
# Actual entrypoint and watchdog from the cached image run unmodified. Only its
# transport executable is replaced; no network is available in this fixture.
gate=(B/'container-gate-cancel-fix.sh').read_text();sleepbin=D/'synthetic-rust';sleepbin.write_text('#!/bin/sh\nexec /usr/bin/sleep 60\n');sleepbin.chmod(0o755);sleep_sha=hashlib.sha256(sleepbin.read_bytes()).hexdigest()
gate=gate.replace('/opt/ssh3-rs-handoff-mux-20261026','/fixture').replace('22d7ae4e72da841cad92ca021d7230e3a97dbb9c0944169e22590e1d6b6f425d',sleep_sha)
gate=gate[:gate.index('  exec "$S/ssh3-rs"')]+ '  exec "$S/ssh3-rs" 60\n  ;;\n *) exit 64;;\nesac\n'
(D/'gate.sh').write_text(gate);subprocess.run(['cp',str(sleepbin),str(D/'ssh3-rs')],check=True)
subprocess.run(['cc','-O2','-o',str(D/'fsync-path'),str(B/'fsync-path.c')],check=True)
(D/'artifacts.sha256').write_text(sleep_sha+'  ssh3-rs\n')
try:
 run('docker','run','-d','--name',N,'--network=none','--mount',f'type=bind,src={D},dst=/fixture','--mount',f'type=bind,src={D}/fake-go,dst=/usr/local/bin/ssh-shim,readonly','-e','AUTOSSH_DEBUG=1','-e','SSH_REMOTE_USER=fixture','-e','SSH_REMOTE_HOST=127.0.0.1','-e','SSH_KEY_PATH=/fixture/key','-e','WATCHDOG_PROBE_ADDR=127.0.0.1:3180','-e','WATCHDOG_GRACE_PERIOD=60','sha256:d12354e0ce77f49e911084e77da10865fbaa4aac19129a2fab366dce15df37fc')
 def rows():return [x.split(None,2) for x in run('docker','top',N,'-eo','pid,ppid,args').splitlines()[1:]]
 def find(text):return next((int(x[0]) for x in rows() if text in x[2]),None)
 init=int(run('docker','inspect','--format','{{.State.Pid}}',N));sup=wait(lambda:find('/usr/local/bin/autossh'));wd=wait(lambda:find('/usr/local/bin/tunnel-watchdog'));child=wait(lambda:find('/usr/local/bin/ssh-shim'))
 def stamp(p):return pathlib.Path(f'/proc/{p}/stat').read_text().rsplit(') ',1)[1].split()[19]
 ids={p:stamp(p) for p in (init,sup,wd,child)}
 print('FIXTURE_IDENTITIES',json.dumps(ids),flush=True)
 for p in (() if mode=='before-stop' else (sup,) if mode=='only-autossh-stop' else (sup,wd)):
  assert stamp(p)==ids[p];print('OWN_STOP',p,flush=True);run('sudo','-n','kill','-STOP',str(p))
 if mode in ('go-exited','autossh-resumed'):
  assert stamp(child)==ids[child];run('sudo','-n','kill','-TERM',str(child))
  wait(lambda:pathlib.Path(f'/proc/{child}/stat').read_text().rsplit(') ',1)[1].split()[0]=='Z')
 if mode=='autossh-resumed':
  run('sudo','-n','kill','-USR1',str(sup));run('sudo','-n','kill','-CONT',str(sup))
  wait(lambda:find('/usr/local/bin/ssh-shim') not in (None,child))
 # Execute the unchanged controller cancel function with fixture path/identity
 # adapters only. It retains gate-cancel -> autossh CONT -> watchdog CONT.
 spec=importlib.util.spec_from_file_location('controller',B/'controller-partial-recovery.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
 c.ROOT=D;c.CONTAINER=N;c.S='/fixture'
 def identity(role):
  p={'init':init,'autossh':sup,'watchdog':wd}[role]
  assert stamp(p)==ids[p]
  assert pathlib.Path(f'/proc/{init}/stat').exists()
  return dict(pid=p,start=ids[p],exe_sha256='fixture'),{}
 c.identity=identity
 runtime=dict(roles={r:dict(pid=p,start=ids[p],exe_sha256=hashlib.sha256(pathlib.Path(f'/proc/{p}/exe').read_bytes()).hexdigest()) for r,p in [('init',init),('autossh',sup),('watchdog',wd)]},netns=str(pathlib.Path(f'/proc/{init}/ns/net').readlink()))
 runtime['roles']['go']=dict(pid=child,start=ids[child],exe_sha256=hashlib.sha256((D/'fake-go').read_bytes()).hexdigest())
 c.write('runtime.json',runtime)
 def fixture_parent(p):
  st=p.lstat();assert p==D and st.st_uid==0 and st.st_mode&0o022==0
 c.safe_directory=fixture_parent
 realkill=os.kill
 def owned_kill(p,s):
  assert p in (sup,wd) and stamp(p)==ids[p]
  print('OWN_CANDIDATE_SIGNAL',p,signal.Signals(s).name,flush=True)
  run('sudo','-n','kill','-'+signal.Signals(s).name[3:],str(p))
 c.os.kill=owned_kill
 try:
  c.cancel()
  first=wait(lambda:find('/usr/local/bin/ssh-shim'))
  first_stamp=stamp(first)
  c.cancel()
  assert find('/usr/local/bin/ssh-shim')==first and stamp(first)==first_stamp
 except Exception as e:print('CANCEL_RESULT',type(e).__name__,str(e),flush=True);raise
 finally:c.os.kill=realkill
 try:
  replacement=wait(lambda:find('/usr/local/bin/ssh-shim'))
  assert pathlib.Path(f'/proc/{replacement}/stat').read_text().rsplit(') ',1)[1].split()[0] not in ('Z','X')
  if mode in ('go-exited','autossh-resumed'):assert replacement!=child
  else:assert replacement==child
  assert int(run('docker','inspect','--format','{{.State.Pid}}',N))==init
  assert len([r for r in rows() if '/usr/local/bin/ssh-shim' in r[2]])==1
  health=run('docker','exec',N,'bash','-c','exec 3<>/dev/tcp/127.0.0.1/18180; IFS= read -r -t 1 line <&3; printf "%s" "$line"')
  assert '200 OK' in health
  print('RECOVERY_PASS',mode,'SAME_INIT',init,'ONE_CHILD',replacement,'HTTP200',flush=True)
 except Exception as error:
  print('RECOVERY_FAILED',mode,type(error).__name__,str(error),flush=True)
  raise
 print('CONTAINER_RESULT',run('docker','inspect','--format','status={{.State.Status}} exit={{.State.ExitCode}}',N),flush=True)
 print(run('docker','logs',N),flush=True)
finally:
 subprocess.run(['docker','rm','-f',N],check=False)
