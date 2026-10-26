from pathlib import Path
import importlib.util,tempfile,contextlib,signal,json
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('candidate',B/'controller-partial-recovery.py');c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
@contextlib.contextmanager
def lock():yield
for case,ast,wst,gst,expected in [('before-stop','S','S','S',[]),('only-autossh-stop','T','S','S',[('autossh',signal.SIGCONT)]),('both-stop-go-alive','T','T','S',[('autossh',signal.SIGCONT),('watchdog',signal.SIGCONT)]),('go-exited','T','T',None,[('autossh',signal.SIGUSR1),('autossh',signal.SIGCONT),('watchdog',signal.SIGCONT)]),('autossh-resumed','S','T',None,[('watchdog',signal.SIGCONT)])]:
 with tempfile.TemporaryDirectory(dir=B,prefix='partial-') as d:
  c.ROOT=Path(d);c.hostlock=lock
  def fixture_parent(p):
   st=p.lstat();assert p==c.ROOT and st.st_uid==0 and st.st_mode&0o022==0
  c.safe_directory=fixture_parent
  records={r:dict(pid=i+101,start='fixture',exe_sha256='fixture',role=r) for i,r in enumerate(('init','autossh','watchdog','go'))}
  states={'init':'S','autossh':ast,'watchdog':wst,'go':gst};events=[];writes=[]
  (c.ROOT/'runtime.json').write_text(json.dumps(dict(roles=records,netns='fixture')));(c.ROOT/'runtime.json').chmod(0o400)
  c.identity=lambda r:(records[r],{})
  c.process_state=lambda rec,allow_absent=False:states[rec['role']]
  c.write=lambda name,data:(writes.append((name,data)),(c.ROOT/name).write_text(json.dumps(data)))
  c.run=lambda *args:''
  c.managed_child_alive=lambda rec:True
  real=c.os.kill
  def kill(pid,sig):
   role=next(r for r,v in records.items() if v['pid']==pid);events.append((role,sig))
   if sig==signal.SIGCONT:states[role]='S'
  c.os.kill=kill
  try:
   c.cancel();assert events==expected,(case,events,expected)
   before=list(events);c.cancel();assert events==before,(case,'repeated rollback signalled again')
   if any(sig==signal.SIGUSR1 for _,sig in events):assert any(n.startswith('operation-autossh-SIGUSR1-') and v['operation_returncode']==0 for n,v in writes)
   print('PASS',case,'and repeated rollback',[(r,s.name) for r,s in events])
  finally:c.os.kill=real
print('PASS five partial phase models and five repeat controls; no real signals')
