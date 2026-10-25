import importlib.util,os,socket,tempfile,base64
from pathlib import Path
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('policy',B/'management-agent-policy.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
# Synthetic public blob, no real identity/key material and no live agent query.
type_=b'ssh-ed25519';blob=len(type_).to_bytes(4,'big')+type_+(32).to_bytes(4,'big')+b'x'*32
public='ssh-ed25519 '+base64.b64encode(blob).decode();fp=m.fingerprint(public)
assert m.match_agent_identity(public,'256 '+fp+' fixture (ED25519)',fp)==fp
print('PASS explicit public identity matches fixture listing')
try:m.match_agent_identity(public,'256 SHA256:'+'a'*43+' other',fp)
except ValueError:print('PASS absent agent identity refused')
else:raise AssertionError('missing')
with tempfile.TemporaryDirectory(dir=Path.home()/'scratch',prefix='ap-') as d:
 root=Path(d);path=root/'agent';sock=socket.socket(socket.AF_UNIX);sock.bind(str(path));path.chmod(0o600)
 assert m.socket_policy(path,os.getuid(),str(path),root)['inode']==path.stat().st_ino
 print('PASS explicit owner-only fixture socket')
 for case in ('symlink','wrong-owner','mutable-parent','regular','ambient'):
  candidate=path;owner=os.getuid();approved=str(path)
  if case=='symlink':candidate=root/'link';candidate.symlink_to(path);approved=str(candidate)
  if case=='wrong-owner':owner=os.getuid()+1
  if case=='mutable-parent':root.chmod(0o777)
  if case=='regular':candidate=root/'file';candidate.write_text('not socket');approved=str(candidate)
  if case=='ambient':approved=str(root/'some-other-agent')
  try:m.socket_policy(candidate,owner,approved,root)
  except ValueError:print('PASS refused',case)
  else:raise AssertionError(case)
  root.chmod(0o700)
 sock.close()
assert 'ForwardAgent no' in (B/'oracle-management-agent.conf.in').read_text()
print('PASS no remote agent forwarding in template')
print('PASS9 known-answer controls; socket fixture only, no live agent/SSH')
