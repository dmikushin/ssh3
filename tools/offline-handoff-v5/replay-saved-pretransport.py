#!/usr/bin/env python3
"""READ ONLY saved pretransport validation; never calls collector/SSH/write APIs."""
import importlib.util,os,stat,time
from pathlib import Path
R=Path('/var/lib/ssh3-rs-first-gambetta-20261025')
M=Path('/var/lib/ssh3-rs-management-read-20261025')
phase='bootstrap'
try:
 if os.geteuid()!=0:raise ValueError('root read executor required')
 for directory in [*reversed((M/'source').parents),M/'source']:
  st=directory.lstat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise ValueError('unsafe executable parent')
 for name in ('oracle-read-adapter.py','offline-transport-v5.py','observe-release-frozen-4bbe.py','receipt-barrier-v5.py','management-agent-policy.py'):
  p=M/'source'/name;st=p.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o222 or st.st_size>65536:raise ValueError('unsafe executable source')
 spec=importlib.util.spec_from_file_location('saved_adapter',M/'source/oracle-read-adapter.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
 phase='request/root paths'
 for p in (R/'request.json',R/'host-exit.json',M/'collection-state/host-receipt.json'):a.trusted_directory(p.parent)
 a.trusted_directory(M/'collection-state')
 phase='request parsing'
 req=a.api.observer.read_owned(R/'request.json',0);a.api.observer.transaction(req)
 phase='host exit identity'
 evidence=a.api.observer.read_owned(R/'host-exit.json',0)
 for k in ('nonce','old_pid','old_start','binary_sha256','go_exit_ns'):
  if type(evidence.get(k)) is not type(req[k]) or evidence[k]!=req[k]:raise ValueError('host exit mismatch field '+k)
 if evidence.get('host_verified_client_exit') is not True:raise ValueError('host client exit not verified')
 phase='approval parsing'
 approval=a.api.observer.read_owned(M/'agent-approval.json',0)
 phase='trusted SSH config/public identity/socket validation'
 a.trusted_ssh(M/'management.conf',agent_approval=approval['approval'])
 phase='collection time ordering'
 if time.time_ns()<req['go_exit_ns']:raise ValueError('collection predates exit')
 print('PRETRANSPORT_REACHED: STOPPED BEFORE transport; NO SSH/collector/receipt writes')
 print('Current approval age seconds:',(time.time_ns()-approval['queried_at_ns'])/1e9,'(replay age is NOT historical failure evidence)')
except Exception as error:
 # Diagnostics are bounded/redacted by the already-loaded adapter when available.
 message=str(error)
 known=('approved agent socket identity changed','explicit existing agent approval required','host client exit not verified','collection predates exit','untrusted directory ancestor','pinned management route missing')
 if message not in known:message='unclassified failure; raw exception data withheld'
 if 'a' in globals() and hasattr(a.api,'failure_reason'):message=a.api.failure_reason('saved_replay',error)
 print('SAVED_VALIDATION_FAILURE phase='+phase+' type='+type(error).__name__+' reason='+message[:4096])
 raise SystemExit(1)
