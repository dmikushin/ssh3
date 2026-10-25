from pathlib import Path
import importlib.util,tempfile,os,subprocess,hashlib
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('invoke',B/'invoke-management-read.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory(dir=B,prefix='bootstrap-') as d:
 p=Path(d);root=p/'root';root.mkdir(mode=0o700);src=root/'source';src.mkdir(mode=0o700);sentinel=p/'executed'
 names=('oracle-read-adapter.py','offline-transport-v5.py','observe-release-frozen-4bbe.py','receipt-barrier-v5.py','management-agent-policy.py')
 for n in names:(src/n).write_text('') ;(src/n).chmod(0o400)
 module=src/names[0];module.chmod(0o600);module.write_text('from pathlib import Path\nPath('+repr(str(sentinel))+').touch()\n');module.chmod(0o400)
 root.chmod(0o777)
 try:m.load_verified_adapter(root,os.getuid(),p)
 except ValueError:pass
 else:raise AssertionError('untrusted dir executed')
 assert not sentinel.exists();print('PASS untrusted executable parent refused before sentinel')
 root.chmod(0o700);m.load_verified_adapter(root,os.getuid(),p);assert sentinel.exists();print('PASS good owner fixture module imports after verification')
 # Actual staging preflight portion only, no root or install. Manifest lacks
 # copyback though source file exists: must fail before first install.
 script=(B/'stage-management-read.sh').read_text();block=script[script.index('for required in '):script.index('install -d ')]
 required=['oracle-read-adapter.py','offline-transport-v5.py','observe-release-frozen-4bbe.py','receipt-barrier-v5.py','management-agent-policy.py','collect-oracle-ports.sh','management-read.conf','invoke-management-read.py','copyback-management-receipt.py','tcp2221-known_hosts','agent-approval.json','oracle-boot.json']
 inp=p/'input';inp.mkdir()
 for n in required:(inp/n).write_text('fixture')
 def manifest(include):
  (inp/'STAGING.sha256').write_text(''.join(hashlib.sha256((inp/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in include))
 manifest([n for n in required if n!='copyback-management-receipt.py'])
 r=subprocess.run(['bash','-c','set -euo pipefail\nINPUT='+str(inp)+'\n'+block],capture_output=True);assert r.returncode!=0;print('PASS missing copyback manifest refused before staging')
 manifest(required);r=subprocess.run(['bash','-c','set -euo pipefail\nINPUT='+str(inp)+'\n'+block],capture_output=True);assert r.returncode==0,r.stderr;print('PASS complete source fixture staging preflight')
print('PASS4 bootstrap/staging controls no root/network')
