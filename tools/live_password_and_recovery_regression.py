"""Additional disposable-server checks for password and SSH port verification."""
from pathlib import Path
import json
import secrets
import sys
import time
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from linux_manager.models import Store,ManagerError,atomic_private
from linux_manager.controller import Controller
PRIVATE=Path('/private/tmp/linux-manager-development')


def main():
    state=json.loads((PRIVATE/'bundle-process.json').read_text());native=Store(Path(state['data']))
    old=json.loads((BASE/'scripts/.rename_account_gui_state.json').read_text())
    candidates=[p for p in native.profiles() if p.host!=old['host']];assert len(candidates)==1
    original=candidates[0];source=Controller(native)
    store=Store(PRIVATE/'password-recovery-fixture');controller=Controller(store)
    store.save([original]);atomic_private(controller.transport(original).known_hosts,source.transport(original).known_hosts.read_bytes())
    name='lmcheck_'+secrets.token_hex(4)
    result=controller.security_plan(original,{'mode':'create','username':name,'block_original':False,'fail2ban':False,'updates':False})
    assert result['complete'];conn=result['connection']
    value=secrets.token_urlsafe(32)
    status,conn=controller.execute(conn,{'operation':'password','username':name,'new_password':value});assert status['state']=='succeeded'
    assert controller.transport(conn).call({'action':'verify_password','username':name,'password':value})['verified']
    print(json.dumps({'check':'real_password_change_and_verification','result':'passed'}),flush=True)
    params={'operation':'ssh','username':name,'port':22222,'old_port':original.port,'allow_password':False,'allow_root':False}
    switched=False
    try:
        _,conn=controller.execute(conn,params);switched=True
        print(json.dumps({'check':'ssh_new_port_verified','result':'passed'}),flush=True)
    except ManagerError:
        controller.transport(original).call({'action':'ping'})
        tasks=controller.transport(original).call({'action':'tasks'})['tasks']
        target=next(t for t in tasks if t['operation']=='ssh')
        assert target['state']=='rolled_back'
        print(json.dumps({'check':'blocked_new_ssh_port_rolls_back','result':'passed'}),flush=True)
    if switched:
        _,conn=controller.execute(conn,{'operation':'ssh','username':name,'port':original.port,'old_port':conn.port,'allow_password':False,'allow_root':False})
    controller.transport(original).call({'action':'ping'})
    time.sleep(3)
    controller.execute(original,{'operation':'delete_user','username':name})
    report=source.inspect(original)
    assert not any(row['username']==name for row in report['accounts'])
    assert report['ssh']['passwordauthentication']==['no'] and report['ssh']['permitrootlogin']==['no']
    assert all(any(u.get('ActiveState')=='active' for u in report['services'][kind]) for kind in ['exchange','hysteria2','xui'])
    atomic_private(PRIVATE/'password-recovery-result.json',json.dumps({'password_and_connection_recovery_passed':True}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        atomic_private(PRIVATE/'password-recovery-error.txt',type(error).__name__+': '+str(error))
        print(json.dumps({'password_recovery_regression':'failed','failure_type':type(error).__name__}),flush=True)
        raise SystemExit(1)
