from pathlib import Path
import importlib.util,tempfile,os,time
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('a',B/'oracle-read-adapter.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory(dir=B,prefix='trust-') as d:
 p=Path(d);parent=p/'mutable';parent.mkdir(mode=0o700);leaf=parent/'leaf';leaf.mkdir(mode=0o700)
 m.trusted_directory(leaf,os.getuid(),p)
 parent.chmod(0o777)
 try:m.trusted_directory(leaf,os.getuid(),p)
 except ValueError:print('PASS safe leaf under mutable ancestor rejected')
 else:raise AssertionError('mutable parent')
 parent.chmod(0o700)
 # Current actual uid is not root: production mode must reject this tree even
 # though every leaf mode is root-like. No chown/sudo/production path used.
 if os.getuid()!=0:
  try:m.trusted_directory(leaf,0)
  except ValueError:print('PASS wrong owner ancestor rejected in production mode')
  else:raise AssertionError('wrongowner')
 fifo=p/'fifo';os.mkfifo(fifo,0o400);begin=time.monotonic()
 try:m.trusted_ssh(fifo,os.getuid(),p)
 except ValueError:print('PASS FIFO config nonblocking refusal')
 else:raise AssertionError('FIFO')
 assert time.monotonic()-begin<1
 calls=[]
 ok=m.collect(p/'missing',p/'exit',p,p/'output',['t64070'],'-'*36,lambda:calls.append('rollback'),os.getuid(),test_anchor=p)
 assert not ok and calls==['rollback'];print('PASS noncanonical boot UUID rejected before transport')
print('PASS4 path/FIFO/UUID controls; no network or privilege changes')
