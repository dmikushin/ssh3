from pathlib import Path
import importlib.util,tempfile,os,json,time,threading
B=Path(__file__).parent

def load(name,file):
 s=importlib.util.spec_from_file_location(name,B/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
w=load('writer','request-writer-v5.py');a=load('adapter','offline-transport-v5.py')
for case in ('valid-delayed','request600','observation600','symlink','wrong-nonce','occupied-port'):
 with tempfile.TemporaryDirectory(dir=B,prefix='v5-') as d:
  p=Path(d);root=p/'trusted';root.mkdir(mode=0o700)
  request=p/'request';req=w.write_request(request,123,'77')
  assert request.stat().st_mode&0o777==0o400
  observation=p/'observation'
  def management():
   time.sleep(.02)
   obs=dict(req,oracle_host='glazomer.io',observed_at_ns=time.time_ns(),old_process_state='exited_identity_verified',snapshot_complete=True,socket_command_rc=0,listening_ports=['t64070'] if case=='occupied-port' else [],covered_ports=['t64070'])
   if case=='wrong-nonce':obs['nonce']='b'*64
   a.observer.write_atomic(observation,obs)
  t=threading.Thread(target=management);t.start();t.join()
  if case=='request600':request.chmod(0o600)
  if case=='observation600':observation.chmod(0o600)
  if case=='symlink':link=p/'linked';link.symlink_to(request);request=link
  callbacks=[]
  launch=a.decide(request,observation,root,p/'host-receipt',['t64070'],lambda:callbacks.append('rollback'),os.getuid())
  assert launch==(case=='valid-delayed')
  assert callbacks==([] if launch else ['rollback'])
  if launch:assert (p/'host-receipt').stat().st_mode&0o777==0o400
  print('PASS whole-interface',case,'launch',launch,'callbacks',callbacks)
print('PASS 6 cases writer->immutable-copy->observer->returned-receipt->hostbarrier')
