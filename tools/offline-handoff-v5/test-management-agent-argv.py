import importlib.util,os,socket,tempfile,base64
from pathlib import Path
B=Path(__file__).parent
s=importlib.util.spec_from_file_location('a',B/'oracle-read-adapter.py');a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
s=importlib.util.spec_from_file_location('p',B/'management-agent-policy.py');p=importlib.util.module_from_spec(s);s.loader.exec_module(p)
with tempfile.TemporaryDirectory(dir=Path.home()/'scratch',prefix='av-') as d:
 root=Path(d);sockpath=root/'agent';sock=socket.socket(socket.AF_UNIX);sock.bind(str(sockpath));sockpath.chmod(0o600)
 kind=b'ssh-ed25519';blob=len(kind).to_bytes(4,'big')+kind+(32).to_bytes(4,'big')+b'z'*32;public='ssh-ed25519 '+base64.b64encode(blob).decode();fp=p.fingerprint(public)
 pub=root/'identity.pub';pub.write_text(public);pub.chmod(0o400)
 pin=root/'known_hosts';pin.write_text('synthetic-placeholder');pin.chmod(0o400)
 config=root/'config';text=(B/'oracle-management-agent.conf.in').read_text().replace('/home/marcusmae/.ssh/keys/id_rsa.oracle.pub',str(pub)).replace('@EXISTING_APPROVED_AGENT_SOCKET@',str(sockpath)).replace('@ROOT_OWNED_TCP2221_KNOWN_HOSTS@',str(pin));config.write_text(text);config.chmod(0o400)
 st=sockpath.stat();approval=dict(socket_path=str(sockpath),socket_uid=os.getuid(),device=st.st_dev,inode=st.st_ino,public_identity_path=str(pub),public_fingerprint=fp,agent_listing='256 '+fp+' fixture (ED25519)')
 assert a.trusted_ssh(config,os.getuid(),root,approval)==['/usr/bin/ssh','-F',str(config),'oracle-management-read'];print('PASS actual trusted_ssh approved .pub/socket exact argv')
 for case in ('missing','inode','fingerprint','socket'):
  changed=None if case=='missing' else dict(approval)
  if case=='inode':changed['inode']+=1
  if case=='fingerprint':changed['public_fingerprint']='SHA256:'+'a'*43
  if case=='socket':changed['socket_path']=str(root/'other')
  try:a.trusted_ssh(config,os.getuid(),root,changed)
  except (ValueError,OSError):print('PASS actual trusted_ssh rejected',case)
  else:raise AssertionError(case)
 sock.close()
print('PASS5 argv controls no live agent/SSH')
