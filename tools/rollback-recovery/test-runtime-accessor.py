from pathlib import Path
import importlib.util,tempfile,json,contextlib
B=Path(__file__).parent
for name,expected in [('controller-partial-missing-runtime.py','NameError'),('controller-partial-recovery.py','PASS')]:
 s=importlib.util.spec_from_file_location('case',B/name);c=importlib.util.module_from_spec(s);s.loader.exec_module(c)
 with tempfile.TemporaryDirectory(dir=B,prefix='runtime-') as d:
  c.ROOT=Path(d)
  def fixture_immutable(p):
   st=p.lstat();assert st.st_uid==0 and st.st_mode&0o222==0
  c.immutable=fixture_immutable
  if hasattr(c,'runtime'):
   c.write('runtime.json',dict(roles={'go':dict(pid=123,start='1')},netns='fixture'))
   assert c.runtime()['roles']['go']['pid']==123
  @contextlib.contextmanager
  def lock():yield
  c.hostlock=lock;c.run=lambda *a:'';c.identity=lambda r:(dict(pid=123,start='1'),{})
  c.process_state=lambda *a,**k:'S';c.managed_child_alive=lambda rec:True
  try:c.cancel()
  except NameError:
   assert expected=='NameError';print('OLD FAIL NameError without injected runtime')
  else:
   assert expected=='PASS';print('NEW PASS actual immutable runtime file, no runtime monkeypatch')
