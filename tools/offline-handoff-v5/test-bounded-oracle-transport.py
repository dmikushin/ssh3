import importlib.util,sys,subprocess,tempfile,os,time
from pathlib import Path
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('a',B/'oracle-read-adapter.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory(dir=B,prefix='transport-') as d:
 p=Path(d)
 for case,code,payload in [('no-stdin',"import os,time;open(os.environ['PIDFILE'],'w').write(str(os.getpid()));time.sleep(30)",b'x'*1048576),('stdout-cap',"import os;open(os.environ['PIDFILE'],'w').write(str(os.getpid()));os.write(1,b'x'*70000)",b''),('stderr-cap',"import os;open(os.environ['PIDFILE'],'w').write(str(os.getpid()));os.write(2,b'x'*70000)",b'')]:
  pidfile=p/case;os.environ['PIDFILE']=str(pidfile);begin=time.monotonic()
  try:m.bounded_read([sys.executable,'-c',code],payload,.2)
  except (ValueError,subprocess.SubprocessError,OSError):pass
  else:raise AssertionError(case)
  assert time.monotonic()-begin<2
  pid=int(pidfile.read_text());assert not Path(f'/proc/{pid}').exists()
  print('PASS real bounded_read',case,'own child reaped',pid)
 out=m.bounded_read([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],b'valid',1)
 assert out==b'valid';print('PASS real bounded_read stdin/stdout completion')
 try:m.trusted_ssh(Path('relative-config'))
 except ValueError:print('PASS missing explicit trusted route rejected')
 else:raise AssertionError('relative')
print('PASS5 finite real transport controls no network')
