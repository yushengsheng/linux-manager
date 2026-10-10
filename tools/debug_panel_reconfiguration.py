"""Capture structural node differences on the disposable test alias only."""
from pathlib import Path
import sys,json
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from tools.live_redeployment_regression import Regression,PRIVATE
from linux_manager.models import atomic_private
r=None
try:
 r=Regression()
 source=(BASE/'linux_manager/remote_agent.py').read_text().split('if __name__ == "linux_manager_remote":')[0]
 source=source.replace('#LM_BUNDLED_REDEPLOYMENT#','LM_REDEPLOYMENT_SOURCE = '+repr((BASE/'linux_manager/redeployment.py').read_text()))
 result=r.remote('''import json,secrets
scope={"__name__":"panel_test"};exec(compile(REQUEST["agent"],"<panel-test>","exec"),scope)
params=REQUEST["params"];plan=scope["deployment_preflight"](params)
identifier=secrets.token_hex(12);scope["TASK"]=scope["ROOT"]/"tasks"/identifier;scope["TASK"].mkdir()
scope["write_json"](scope["TASK"]/"status.json",{"id":identifier,"operation":"deploy","state":"running","progress":0,"events":[],"created":scope["now"](),"updated":scope["now"](),"message":"测试节点比较"})
captured=[];original=scope["_deployment_state"]
def observe(kind,address):
 data=original(kind,address)
 if kind=="xui":captured.append(data.get("inbounds",[]))
 return data
scope["_deployment_state"]=observe
try:
 scope["_deployment_backup"]("xui","reconfigure")
 scope["_change_xui"](params,plan);result={"configuration_passed":True}
except Exception as error:
 scope["restore_deployment"](identifier);result={"configuration_passed":False,"failure_type":type(error).__name__}
file=scope["TASK"]/"status.json";state=json.loads(file.read_text());state.update(state="succeeded" if result["configuration_passed"] else "failed",message="独立诊断已完成，失败时恢复原项目");scope["write_json"](file,state)
result["capture_count"]=len(captured)
result["captured"]=captured
''',{'agent':source,'params':r.params('xui',port=r.saved['projects']['xui']['port'])})
 atomic_private(PRIVATE/'panel-node-captures.json',json.dumps(result))
 fields={'settings','stream_settings','clients','protocol','network','security','port','enable','remark','created_at','updated_at','totalGB','expiryTime','limitIp','reset','flow','email','id','subId'}
 differences=[]
 def compare(a,b,path=''):
  if isinstance(a,dict) and isinstance(b,dict):
   for k in set(a)|set(b):
    if a.get(k)!=b.get(k):compare(a.get(k),b.get(k),path+'.'+(k if k in fields else 'other_field'))
  elif isinstance(a,list) and isinstance(b,list):
   if len(a)!=len(b):differences.append(path+'.count')
   for x,y in zip(a,b):compare(x,y,path+'.item')
  elif a!=b:differences.append(path)
 if len(result['captured'])>=2:compare(result['captured'][-2],result['captured'][-1])
 print(json.dumps({k:v for k,v in result.items() if k!='captured'}|{'changed_fields':differences}))
except Exception as e:
 import traceback
 atomic_private(PRIVATE/'panel-debug-error.txt',traceback.format_exc())
 print(json.dumps({'failure_type':type(e).__name__}))
finally:
 if r:r.controller.close_connections()
