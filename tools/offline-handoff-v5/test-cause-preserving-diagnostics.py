from pathlib import Path
import contextlib,importlib.util,io
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('adapter',B/'oracle-read-adapter.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
original=a.api.observer.port_set
try:
 a.api.observer.port_set=lambda p:(_ for _ in ()).throw(ValueError('approved agent socket identity changed'))
 output=io.StringIO();calls=[]
 with contextlib.redirect_stderr(output):
  ok=a.collect(None,None,None,None,['t1'],'fixture',lambda:calls.append('rollback'))
 assert ok is False and calls==['rollback']
 assert 'oracle_read_adapter.collect: ValueError: approved agent socket identity changed' in output.getvalue()
 print('PASS actual collect catch retains known cause and rollback exactly once')
finally:a.api.observer.port_set=original
for error in (ValueError('password=syntheticPrivate'),ValueError('True syntheticPrivate'),ValueError('-----BEGIN OPENSSH PRIVATE KEY----- syntheticPrivate')):
 result=a.api.failure_reason('fixture',error);assert 'syntheticPrivate' not in result
print('PASS unknown/private exception data withheld')
result=a.api.failure_reason('fixture',ValueError('bounded_read: child process exited with returncode=37; token=syntheticPrivate'))
assert 'returncode=37' in result and 'syntheticPrivate' not in result
print('PASS rc37 retained and credential marker redacted')
original=a.api.transfer
try:
 a.api.transfer=lambda *args:(_ for _ in ()).throw(ValueError('required port remains bound'))
 output=io.StringIO();calls=[]
 with contextlib.redirect_stderr(output):assert a.api.decide(None,None,None,None,[],lambda:calls.append('rollback')) is False
 assert calls==['rollback'] and 'required port remains bound' in output.getvalue()
 print('PASS actual decide catch retains cause and rollback exactly once')
finally:a.api.transfer=original
