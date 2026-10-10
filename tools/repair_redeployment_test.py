"""Repair only a failed deployment in the disposable test alias and diagnose safely."""
from pathlib import Path
import json
import sys
BASE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from tools.live_redeployment_regression import Regression,PRIVATE
from linux_manager.models import Redactor,atomic_private
r=None
try:
    r=Regression()
    source=(BASE/'linux_manager/remote_agent.py').read_text().split('if __name__ == "linux_manager_remote":')[0]
    source=source.replace('#LM_BUNDLED_REDEPLOYMENT#','LM_REDEPLOYMENT_SOURCE = '+repr((BASE/'linux_manager/redeployment.py').read_text()))
    result=r.remote('''from pathlib import Path
import json,traceback
scope={"__name__":"deployment_test_repair"};exec(compile(REQUEST["agent"],"<repair>","exec"),scope)
files=sorted(Path("/var/lib/linux-server-manager/tasks").glob("*/status.json"),key=lambda p:p.stat().st_mtime,reverse=True)
file=next(f for f in files if json.loads(f.read_text()).get("state")=="recovery_failed")
try:
 manifest=file.parent/"backup/manifest.json"
 value=json.loads(manifest.read_text())
 for row in value["paths"]:
  if row["path"]=="/etc/x-ui":row["ownership"]=[item for item in row.get("ownership",[]) if item["name"] not in {"x-ui.db-wal","x-ui.db-shm"}]
 scope["write_json"](manifest,value)
 scope["restore_deployment"](file.parent.name)
 state=json.loads(file.read_text());state.update(state="failed",message="测试发现的问题已修复，原项目已恢复。")
 scope["write_json"](file,state);result={"restored":True}
except Exception as error:
 result={"restored":False,"diagnostic":type(error).__name__+": "+str(error),"trace":traceback.format_exc()}
''',{'agent':source})
    atomic_private(PRIVATE/'redeployment-repair-result.json',json.dumps(result))
    red=Redactor();red.add(str(BASE),r.c.host,r.c.username,r.c.password,r.c.sudo_password,r.c.key_path,r.c.key_passphrase)
    print(red.text(json.dumps({k:v for k,v in result.items() if k!='trace'})))
except Exception as error:
    import traceback
    atomic_private(PRIVATE/'redeployment-repair-error.txt',traceback.format_exc())
    print(json.dumps({'repair_failed':True,'failure_type':type(error).__name__}))
finally:
    if r:r.controller.close_connections()
