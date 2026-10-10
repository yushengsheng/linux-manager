"""Finish the recorded SSH rollback fixture; never create another account."""
from pathlib import Path
import json
import sys
import time
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from linux_manager.models import Store,atomic_private
from linux_manager.controller import Controller
PRIVATE=Path('/private/tmp/linux-manager-development')

def main():
 state=json.loads((PRIVATE/'bundle-process.json').read_text());native=Store(Path(state['data']))
 old=json.loads((BASE/'scripts/.rename_account_gui_state.json').read_text())
 originals=[p for p in native.profiles() if p.host!=old['host']];assert len(originals)==1
 original=originals[0];store=Store(PRIVATE/'password-recovery-fixture');controller=Controller(store)
 fixtures=[p for p in store.profiles() if p.identifier!=original.identifier and p.username.startswith('lmcheck_') and p.remember];assert len(fixtures)==1
 fixture=fixtures[0]
 for attempt in range(80):
  tasks=controller.transport(original).call({'action':'tasks'})['tasks'];task=next(t for t in tasks if t['operation']=='ssh')
  if task['state']=='rolled_back':break
  assert task['state']=='awaiting_verification'
  time.sleep(3)
 else:raise RuntimeError('automatic_recovery_did_not_complete')
 controller.transport(original).call({'action':'ping'})
 store.record({'task_id':task['id'],'server_id':original.identifier,'operation':'ssh','state':'rolled_back','message':'真实端口保护恢复通过。'})
 print(json.dumps({'check':'blocked_new_ssh_port_automatic_rollback','result':'passed'}),flush=True)
 time.sleep(3);controller.execute(original,{'operation':'delete_user','username':fixture.username})
 report=Controller(native).inspect(original)
 assert not any(row['username']==fixture.username for row in report['accounts'])
 assert report['ssh']['passwordauthentication']==['no'] and report['ssh']['permitrootlogin']==['no']
 atomic_private(PRIVATE/'password-recovery-result.json',json.dumps({'password_and_connection_recovery_passed':True}))
 print(json.dumps({'check':'original_connection_and_fixture_cleanup','result':'passed'}),flush=True)

if __name__=='__main__':
 try:main()
 except Exception as error:
  atomic_private(PRIVATE/'password-recovery-error.txt',type(error).__name__+': '+str(error))
  print(json.dumps({'recovery_followup':'failed','failure_type':type(error).__name__}),flush=True);raise SystemExit(1)
