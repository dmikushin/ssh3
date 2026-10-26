#!/usr/bin/env python3
"""Single first-gambetta transaction; root executor review required before use.

No automatic acceptance: timer remains armed until independent actual-caller
proof. This artifact is NOT run by its author against production.
"""
import argparse,contextlib,fcntl,hashlib,importlib.util,json,os,signal,stat,subprocess,time
from pathlib import Path
ROOT=Path('/var/lib/ssh3-rs-first-gambetta-mux-20261026')
MAN=Path('/var/lib/ssh3-rs-management-mux-20261026')
CONTAINER='autossh-ssh3'
S='/opt/ssh3-rs-handoff-mux-20261026'
PORTS=['t64070','t49167','t49160','u64443']
CLIENT='22d7ae4e72da841cad92ca021d7230e3a97dbb9c0944169e22590e1d6b6f425d'

def run(*argv):return subprocess.check_output(argv,text=True).strip()
def safe_directory(p):
 for parent in [*reversed(p.parents),p]:
  st=parent.lstat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise ValueError('unsafe root input parent')
def immutable(p):
 safe_directory(p.parent)
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o222 or st.st_size>64*1024*1024:raise ValueError('unsafe immutable source '+str(p))
 finally:os.close(fd)
def verify_inputs():
 immutable(ROOT/'controller.py');immutable(ROOT/'input.sha256')
 rows=(ROOT/'input.sha256').read_text().splitlines();seen=set()
 for row in rows:
  digest,name=row.split('  ',1)
  if not name or '/' in name or name in ('.','..') or name in seen:raise ValueError('unsafe manifest entry')
  seen.add(name);immutable(ROOT/name)
  if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:raise ValueError('input hash mismatch')
 required={'controller.py','runtime.json','container-gate.sh','bridge.conf','known_hosts','fsync-path','ssh3-rs','produce-host-exit.py','request-writer.py','provider-plan.json','management-source.sha256','postcheck.py','postcheck-source.sha256','provider-route-probe.py'}
 if seen!=required:raise ValueError('input manifest incomplete/unexpected')
 plan=json.loads((ROOT/'provider-plan.json').read_text())
 if plan.get('status')!='COORDINATOR_REVIEWED_ACTUAL_CALLER_PLAN' or not plan.get('observer_command') or plan.get('auto_accept') is not False:raise ValueError('actual provider observer plan missing')
def load(name,p):
 immutable(p);s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def write(name,data):
 p=ROOT/name;tmp=p.with_name(p.name+'.next')
 with tmp.open('x') as f:json.dump(data,f);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
 os.link(tmp,p);tmp.unlink();fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def identity(role):
 snapshot=json.loads((ROOT/'runtime.json').read_text());r=snapshot['roles'][role]
 if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=snapshot['boot_id']:raise ValueError('boot changed')
 if run('/usr/bin/docker','inspect','--format','{{.Id}}',CONTAINER)!=snapshot['container_id']:raise ValueError('container changed')
 init=snapshot['roles']['init']
 for rec in (init,r):
  p=Path('/proc')/str(rec['pid']);fields=(p/'stat').read_text().rsplit(') ',1)[1].split()
  if fields[19]!=rec['start'] or int(fields[1])!=rec['ppid'] or hashlib.sha256((p/'exe').read_bytes()).hexdigest()!=rec['exe_sha256']:raise ValueError('PID identity changed')
  if str((p/'ns/net').readlink())!=snapshot['netns']:raise ValueError('namespace changed')
 if role!='init' and r['pid']==init['pid']:raise ValueError('refusing init signal')
 return r,snapshot
@contextlib.contextmanager
def hostlock():
 fd=os.open(ROOT/'host.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:fcntl.flock(fd,fcntl.LOCK_EX);yield
 finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
def send(role,sig):
 with hostlock():
  if sig!=signal.SIGCONT and (ROOT/'rollback-begun.json').exists():raise ValueError('rollback already began')
  rec,_=identity(role)
  write('before-'+role+'-'+sig.name+'-'+str(time.time_ns())+'.json',dict(role=role,pid=rec['pid'],start=rec['start'],signal=sig.name,observed_at_ns=time.time_ns()))
  print('SIGNAL',role,rec['pid'],rec['start'],sig.name,flush=True);os.kill(rec['pid'],sig)
  completed=time.time_ns()
  write('operation-'+role+'-'+sig.name+'-'+str(completed)+'.json',dict(role=role,pid=rec['pid'],start=rec['start'],old_exe_sha256=rec['exe_sha256'],signal=sig.name,operation_returncode=0,attempted_at_ns=completed))
  return completed
def process_state(rec,allow_absent=False):
 try:fields=(Path('/proc')/str(rec['pid'])/'stat').read_text().rsplit(') ',1)[1].split()
 except FileNotFoundError:
  if allow_absent:return None
  raise
 if fields[19]!=rec['start']:raise ValueError('rollback process PID was reused')
 return fields[0]
def managed_child_alive(supervisor):
 old=runtime()['roles']['go']
 try:children=(Path('/proc')/str(supervisor['pid'])/'task'/str(supervisor['pid'])/'children').read_text().split()
 except FileNotFoundError:return False
 for pid in children:
  try:
   proc=Path('/proc')/pid;fields=(proc/'stat').read_text().rsplit(') ',1)[1].split()
   if fields[0] in ('Z','X') or int(fields[1])!=supervisor['pid']:continue
   if hashlib.sha256((proc/'exe').read_bytes()).hexdigest()!=old['exe_sha256']:continue
   if str((proc/'ns/net').readlink())!=runtime()['netns']:continue
   return True
  except FileNotFoundError:continue
 return False
def resume_verified(role,rec):
 identity(role)
 stamp=time.time_ns()
 write('before-'+role+'-SIGCONT-'+str(stamp)+'.json',dict(pid=rec['pid'],start=rec['start'],signal='SIGCONT',observed_at_ns=stamp))
 os.kill(rec['pid'],signal.SIGCONT)
 completed=time.time_ns()
 write('operation-'+role+'-SIGCONT-'+str(completed)+'.json',dict(pid=rec['pid'],start=rec['start'],signal='SIGCONT',operation_returncode=0,attempted_at_ns=completed))
def cancel():
 with hostlock():
  if (ROOT/'accepted.json').exists() and not (ROOT/'rollback-begun.json').exists():
   for name in ('accepted.json','postcheck-proof.json','request.json','postcheck-source.sha256'):immutable(ROOT/name)
   accepted=json.loads((ROOT/'accepted.json').read_text());proofpath=ROOT/'postcheck-proof.json';proof=json.loads(proofpath.read_text());request=json.loads((ROOT/'request.json').read_text())
   if accepted.get('nonce')==request.get('nonce')==proof.get('nonce') and proof.get('all_checks_passed') is True and proof.get('observer_source_sha256')==(ROOT/'postcheck-source.sha256').read_text().strip() and proof.get('reverse_ports')==['t64070','t49167','t49160','u64443'] and proof.get('provider_nonce')==request.get('nonce') and proof.get('provider',{}).get('phase')=='completed' and proof.get('provider',{}).get('http_status')==200 and proof.get('provider',{}).get('exact_nonce') is True and accepted.get('proof_sha256')==hashlib.sha256(proofpath.read_bytes()).hexdigest() and type(accepted.get('accepted_at_ns')) is int and accepted['accepted_at_ns']>=proof.get('observed_at_ns',0):
    print('ROLLBACK_SKIPPED_VALID_ACCEPTANCE',flush=True);return
   print('INVALID_ACCEPTANCE_PROOF_CONTINUING_ROLLBACK',flush=True)
  if not (ROOT/'rollback-begun.json').exists():write('rollback-begun.json',dict(at_ns=time.time_ns()))
 # Container gate serializes cancellation with delayed DockerExec launch.
 run('/usr/bin/docker','exec',CONTAINER,'bash',S+'/gate.sh','cancel')
 # Serialize partial rollback decisions, not only individual signals.
 with hostlock():
  rec,_=identity('autossh')
  state=process_state(rec)
  old_go=runtime()['roles']['go']
  child_state=process_state(old_go, allow_absent=True)
  if state=='T':
   if child_state in (None,'Z'):
    stamp=time.time_ns()
    write('before-autossh-SIGUSR1-'+str(stamp)+'.json',dict(pid=rec['pid'],start=rec['start'],signal='SIGUSR1',observed_at_ns=stamp))
    identity('autossh')
    if process_state(rec)!='T':raise ValueError('supervisor changed state before queued restart')
    os.kill(rec['pid'],signal.SIGUSR1)
    completed=time.time_ns()
    write('operation-autossh-SIGUSR1-'+str(completed)+'.json',dict(pid=rec['pid'],start=rec['start'],signal='SIGUSR1',operation_returncode=0,attempted_at_ns=completed))
   identity('autossh')
   resume_verified('autossh',rec)
  elif state not in ('S','R','D','I'):
   raise ValueError('unsupported autossh rollback state')
 # A running supervisor with a pending clean SIGCHLD is not yet recovery.
 # Require a verified managed child before releasing a stopped watchdog.
 deadline=time.monotonic()+3
 while not managed_child_alive(rec):
  identity('init');identity('autossh')
  if time.monotonic()>=deadline:raise ValueError('autossh has not restored a verified managed child')
  time.sleep(0.02)
 with hostlock():
  identity('init');identity('autossh')
  if not managed_child_alive(rec):raise ValueError('managed child disappeared before watchdog recovery')
  watch,_=identity('watchdog')
  state=process_state(watch)
  if state=='T':resume_verified('watchdog',watch)
  elif state not in ('S','R','D','I'):raise ValueError('unsupported watchdog rollback state')
 print('ROLLBACK_RESUMED_UNVERIFIED',flush=True)
def load_management():
 immutable(ROOT/'management-source.sha256')
 rows=(ROOT/'management-source.sha256').read_text().splitlines()
 expected={'invoke.py','copyback.py','source/oracle-read-adapter.py','source/offline-transport-v5.py','source/observe-release-frozen-4bbe.py','source/receipt-barrier-v5.py','source/management-agent-policy.py','source/direct-mux-argv.py'}
 seen=set()
 for row in rows:
  digest,name=row.split('  ',1)
  if name not in expected or name in seen:raise ValueError('management manifest unsafe/incomplete')
  seen.add(name);immutable(MAN/name)
  if hashlib.sha256((MAN/name).read_bytes()).hexdigest()!=digest:raise ValueError('management executable hash changed')
 if seen!=expected:raise ValueError('missing management executable pin')
 for name in ('oracle-read-adapter.py','offline-transport-v5.py','observe-release-frozen-4bbe.py','receipt-barrier-v5.py','management-agent-policy.py','direct-mux-argv.py'):immutable(MAN/'source'/name)
 return load('management_adapter',MAN/'source/oracle-read-adapter.py')
def stage():
 verify_inputs()
 for f in ('runtime.json','container-gate.sh','bridge.conf','known_hosts','fsync-path','ssh3-rs','produce-host-exit.py','request-writer.py','input.sha256'):immutable(ROOT/f)
 subprocess.run(['/usr/bin/sha256sum','--check','--strict','input.sha256'],cwd=ROOT,check=True)
 if hashlib.sha256((ROOT/'ssh3-rs').read_bytes()).hexdigest()!=CLIENT:raise ValueError('wrong Rust client')
 for role in ('init','autossh','watchdog','go'):identity(role)
 # Fresh container directory only. Never overwrite or copy the private /id_rsa.
 run('/usr/bin/docker','exec',CONTAINER,'bash','-c','test ! -e '+S+' && test ! -L '+S+' && install -d -m700 '+S)
 for source,dest in [('container-gate.sh','gate.sh'),('bridge.conf','bridge.conf'),('known_hosts','known_hosts'),('fsync-path','fsync-path'),('ssh3-rs','ssh3-rs')]:
  run('/usr/bin/docker','cp',str(ROOT/source),CONTAINER+':'+S+'/'+dest)
 run('/usr/bin/docker','exec',CONTAINER,'chmod','500',S+'/gate.sh',S+'/fsync-path',S+'/ssh3-rs')
 run('/usr/bin/docker','exec',CONTAINER,'chmod','400',S+'/bridge.conf',S+'/known_hosts')
 for source,dest in [('container-gate.sh','gate.sh'),('bridge.conf','bridge.conf'),('known_hosts','known_hosts'),('fsync-path','fsync-path'),('ssh3-rs','ssh3-rs')]:
  expected=hashlib.sha256((ROOT/source).read_bytes()).hexdigest()
  if run('/usr/bin/docker','exec',CONTAINER,'sha256sum',S+'/'+dest).split()[0]!=expected:raise ValueError('container copy hash mismatch')
 # Gate checks manifest from inside its namespace.
 content=''.join(hashlib.sha256((ROOT/src).read_bytes()).hexdigest()+'  '+dst+'\n' for src,dst in [('container-gate.sh','gate.sh'),('bridge.conf','bridge.conf'),('known_hosts','known_hosts'),('fsync-path','fsync-path'),('ssh3-rs','ssh3-rs')])
 p=ROOT/'container-artifacts.sha256';p.write_text(content);p.chmod(0o400)
 run('/usr/bin/docker','cp',str(p),CONTAINER+':'+S+'/artifacts.sha256')
 # Authentication check uses no stdin, cannot consume the controller script.
 # Use the reviewed transport's bounded pipe mechanism for exactly one auth read.
 transport=load_management()
 result=transport.bounded_read(['/usr/bin/docker','exec',CONTAINER,S+'/ssh3-rs','-F',S+'/bridge.conf','oracle-rs-cutover','id'],b'',5)
 if b'uid=1002(marcusmae)' not in result:raise ValueError('unexpected canary account identity')
 print('STAGED_UNACCEPTED',flush=True)
def execute():
 # Preconditions are checked BEFORE arming and before the first production signal.
 verify_inputs()
 immutable(ROOT/'input.sha256');subprocess.run(['/usr/bin/sha256sum','--check','--strict','input.sha256'],cwd=ROOT,check=True)
 for role in ('init','autossh','watchdog','go'):identity(role)
 for name in ('invoke.py','copyback.py'):immutable(MAN/name)
 # Coordinator must refresh actual auth/boot observations before review; refuse
 # stale facts before disturbing the existing Go client.
 for name in ('oracle-boot.json','management.conf'):immutable(MAN/name)
 boot=json.loads((MAN/'oracle-boot.json').read_text())
 transport=load_management()
 transport.trusted_ssh(MAN/'management.conf')
 now=time.time_ns()
 if not 0<=now-boot['observed_at_ns']<=300_000_000_000:raise ValueError('fresh real Oracle boot observation required')
 if (MAN/'collection-state').exists():raise ValueError('prior management run exists; inspect')
 subprocess.run(['/usr/bin/systemd-run','--unit=ssh3-first-gambetta-mux-rollback','--on-active=120s','/usr/bin/python3',str(ROOT/'controller.py'),'rollback'],check=True)
 subprocess.run(['/usr/bin/systemctl','is-active','--quiet','ssh3-first-gambetta-mux-rollback.timer'],check=True)
 # Exact container cancellation protects any late launch; timer survives this PID.
 try:
  send('autossh',signal.SIGSTOP);send('watchdog',signal.SIGSTOP)
  rec,snapshot=identity('go');verified=time.time_ns()
  nonce=os.urandom(32).hex()
  attempted=send('go',signal.SIGTERM)
  deadline=time.monotonic()+3
  while True:
   info=ROOT # no process signal in this loop
   try:fields=Path('/proc/'+str(rec['pid'])+'/stat').read_text().rsplit(') ',1)[1].split()
   except FileNotFoundError:break
   if fields[19]!=rec['start']:raise ValueError('old PID reused')
   if fields[0]=='Z':break
   if time.monotonic()>=deadline:raise ValueError('old Go failed to exit')
   time.sleep(.05)
  init,_=identity('init')
  if run('/usr/sbin/nsenter','--target',str(init['pid']),'--net','/usr/sbin/ss','-H','-tln','sport = :3180'):raise ValueError('container3180 still occupied')
  request=dict(nonce=nonce,old_pid=rec['pid'],old_start=rec['start'],binary_sha256=CLIENT,go_exit_ns=time.time_ns())
  write('request.json',request)
  write('prestop.json',dict(request,boot_id=snapshot['boot_id'],verified_before_stop_ns=verified))
  write('termination.json',dict(request,boot_id=snapshot['boot_id'],phase='AFTER_GO_TERM',signal='TERM',operation_returncode=0,attempted_at_ns=attempted))
  producer=load('producer',ROOT/'produce-host-exit.py')
  evidence=producer.evidence(request,json.loads((ROOT/'prestop.json').read_text()),snapshot['boot_id'],producer.proc_identity(rec['pid']),time.time_ns(),json.loads((ROOT/'termination.json').read_text()))
  write('host-exit.json',evidence)
  subprocess.run(['/usr/bin/python3',str(MAN/'invoke.py'),'--request',str(ROOT/'request.json'),'--host-exit',str(ROOT/'host-exit.json'),'--ports',*PORTS],check=True)
  subprocess.run(['/usr/bin/python3',str(MAN/'copyback.py'),'--request',str(ROOT/'request.json'),'--destination',str(ROOT/'remote-release-receipt.json'),'--ports',*PORTS],check=True)
  receipt=ROOT/'remote-release-receipt.json';immutable(receipt)
  if not transport.api.barrier.validate(receipt,request,PORTS,time.time_ns(),0):raise ValueError('copyback receipt mismatch')
  # Receipt is point-in-time; actual Rust bind failure must not be called success.
  with hostlock():
   if (ROOT/'rollback-begun.json').exists():raise ValueError('rollback won before launch')
   run('/usr/bin/docker','exec','-d',CONTAINER,'bash',S+'/gate.sh','launch')
  print('UNACCEPTED: timer armed; independent real provider request + every forward required',flush=True)
 except BaseException:
  cancel();raise
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['stage','execute','rollback']);a=p.parse_args()
 if os.geteuid()!=0:raise ValueError('root coordinator required')
 safe_directory(ROOT)
 if a.action=='stage':stage()
 elif a.action=='execute':execute()
 else:cancel()
