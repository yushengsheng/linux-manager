"""Drop the owned master after task submission; never resubmit the operation."""
from pathlib import Path
import json,sys,time
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from tools.live_redeployment_regression import Regression,PRIVATE
from linux_manager.models import atomic_private
r=None
try:
 r=Regression();transport=r.controller.transport;starts=[]
 def observed(connection, fresh=False):
  ssh=transport(connection,fresh=fresh);original=ssh.call
  def call(request,**kwargs):
   if request.get('action')=='start':starts.append(True)
   return original(request,**kwargs)
  ssh.call=call;return ssh
 r.controller.transport=observed
 killed=[]
 def progress(status):
  if status.get('state')=='queued' and not killed:
   session=r.controller.connections.sessions[r.c.identifier]
   session.process.terminate();killed.append(True)
 params=r.params('nginx');before=r.audit()['units']
 result,_=r.controller.execute(r.c,params,progress)
 assert result['state']=='succeeded' and result['result']['action']=='unchanged' and len(starts)==1 and killed
 assert before==r.audit()['units']
 deadline=time.monotonic()+25
 while r.controller.connection_status(r.c)['state']!='connected' and time.monotonic()<deadline:time.sleep(.2)
 assert r.controller.connection_status(r.c)['state']=='connected'
 r.controller.tasks(r.c)
 print(json.dumps({'check':'existing_task_read_after_transport_restart_without_resubmission','result':'passed'}),flush=True)
 atomic_private(PRIVATE/'task-connection-regression-result.json',json.dumps({'task_connection_recovery_passed':True}))
except Exception as error:
 import traceback
 atomic_private(PRIVATE/'task-connection-regression-error.txt',traceback.format_exc())
 print(json.dumps({'task_connection_regression':'failed','failure_type':type(error).__name__}),flush=True)
 raise SystemExit(1)
finally:
 if r:r.controller.close_connections()
