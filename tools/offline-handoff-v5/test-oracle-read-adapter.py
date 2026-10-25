from pathlib import Path
import importlib.util,tempfile,os,subprocess,json
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('collector',B/'oracle-read-adapter.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
s=importlib.util.spec_from_file_location('writer',B/'request-writer-v5.py');w=importlib.util.module_from_spec(s);s.loader.exec_module(w)
boot='a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12
valid=f'SSH3_PORT_SNAPSHOT_V1\nHOST glazomer.io\nBOOT {boot}\nBEGIN t64070\nRC 0\nEND t64070\nCOMPLETE\n'.encode()
for case in ('valid','truncated','nonzero','malformed','occupied','boot-race','oversize','wrong-host-exit'):
 with tempfile.TemporaryDirectory(dir=B,prefix='collector-') as d:
  p=Path(d);root=p/'trusted';root.mkdir(mode=0o700);req=w.write_request(p/'request',123,'77')
  evidence=dict(req,host_verified_client_exit=True)
  if case=='wrong-host-exit':evidence['old_pid']=124
  m.api.observer.write_atomic(p/'exit',evidence)
  data=valid
  if case=='truncated':data=data.replace(b'COMPLETE\n',b'')
  if case=='nonzero':data=data.replace(b'RC 0',b'RC 1')
  if case=='malformed':data=data.replace(b'END t64070',b'garbage\nEND t64070')
  if case=='occupied':data=data.replace(b'END t64070',b'LISTEN 0 128 127.0.0.1:64070 0.0.0.0:*\nEND t64070')
  if case=='boot-race':data=data.replace(boot.encode(),b'f'*36)
  if case=='oversize':data=b'x'*65537
  identity=p/'identity';identity.write_text('fixture-placeholder-NOT-a-real-key');identity.chmod(0o600)
  pin=p/'pin';pin.write_text('fixture-placeholder-NOT-a-real-pin');pin.chmod(0o400)
  config=p/'ssh-config';config.write_text(f'Host oracle-management-read\n HostName gateway.mikush.in\n Port 2221\n User marcusmae\n BatchMode yes\n StrictHostKeyChecking yes\n IdentityAgent none\n IdentitiesOnly yes\n ProxyCommand none\n ProxyJump none\n IdentityFile {identity}\n UserKnownHostsFile {pin}\n');config.chmod(0o400)
  calls=[];roll=[]
  def reader(argv,script):calls.append(argv);return data
  ok=m.collect(p/'request',p/'exit',root,p/'receipt',['t64070'],boot,lambda:roll.append('rollback'),os.getuid(),reader,config,p)
  assert ok==(case=='valid'),case
  assert roll==([] if ok else ['rollback']),case
  if case=='wrong-host-exit':assert not calls
  print('PASS adapter',case,'launch',ok)
# Execute actual collector with mocked ss/hostname. /proc boot read stays real.
for case in ('empty','occupied','nonzero','oversize'):
 with tempfile.TemporaryDirectory(dir=B,prefix='ss-') as d:
  p=Path(d);(p/'hostname').write_text('#!/bin/bash\nprintf "glazomer.io\\n"\n');(p/'hostname').chmod(0o700)
  body={'empty':'exit 0','occupied':'printf "LISTEN 0 128 127.0.0.1:64070 0.0.0.0:*\\n"','nonzero':'exit 2','oversize':'printf "%17000s" x'}[case]
  (p/'ss').write_text('#!/bin/bash\n'+body+'\n');(p/'ss').chmod(0o700)
  env=dict(os.environ,PATH=str(p)+':'+os.environ['PATH'])
  r=subprocess.run(['bash',str(B/'collect-oracle-ports.sh'),'t64070'],env=env,capture_output=True,timeout=3)
  if case in ('nonzero','oversize'):assert r.returncode!=0 and b'COMPLETE' not in r.stdout
  else:assert r.returncode==0 and b'COMPLETE' in r.stdout
  assert len(r.stdout)<17000
  print('PASS actual shell collector',case,'rc',r.returncode)
print('PASS 12 finite collector/adapter controls; no network')
