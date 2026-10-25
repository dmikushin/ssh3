from pathlib import Path
import importlib.util,sys
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('a',B/'oracle-read-adapter.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
message='Host key verification failed.\nPermission denied (publickey).\nBad configuration option: fixture\n'
secret='syntheticCredentialValue'
unsafe=message+'https://user:'+secret+'@example.invalid/path\nAuthorization: Bearer '+secret+'\ntoken='+secret+'\n-----BEGIN OPENSSH PRIVATE KEY-----\n'+secret+'\n-----END OPENSSH PRIVATE KEY-----\n'
code='import sys;sys.stderr.write('+repr(unsafe)+');sys.stdout.write("never expose stdout");sys.exit(37)'
try:a.bounded_read([sys.executable,'-c',code],b'',1)
except ValueError as error:
 text=str(error)
 assert 'returncode=37' in text and 'bounded_read:' in text
 for line in message.splitlines():assert line in text
 assert secret not in text and 'never expose stdout' not in text
 assert '[REDACTED' in text
 print('PASS rc37 and exact host-key/auth/config diagnostics retained; credentials/stdout excluded')
else:raise AssertionError('missing diagnostic')
assert len(a.redacted_stderr(b'x'*10000))<4200
print('PASS diagnostic cap4096 without transport cap change')
