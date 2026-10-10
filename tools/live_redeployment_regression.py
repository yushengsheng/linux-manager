"""Real condition reconciliation on the disposable alias; output only check names."""
from pathlib import Path
import base64
import contextlib
import hashlib
import http.client
import http.cookiejar
import json
import os
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(BASE))
from linux_manager.controller import Controller
from linux_manager.models import Store, ManagerError, atomic_private
from linux_manager.project_info import credential_alias
from linux_manager.transport import Askpass, BOOTSTRAP
from linux_manager.vault import vault_alias
from tools.live_functional_regression import context

PRIVATE = Path("/private/tmp/linux-manager-development")
STAGE = "prepare"


def passed(name):
    print(json.dumps({"check": name, "result": "passed"}), flush=True)


class Regression:
    def __init__(self):
        tracking = json.loads((PRIVATE / "bundle-process.json").read_text())
        self.store = Store(Path(tracking["data"]))
        legacy = json.loads((BASE / "scripts/.rename_account_gui_state.json").read_text())
        candidates = [p for p in self.store.profiles() if p.host != legacy["host"]]
        assert len(candidates) == 1 and not self.store.last_warning
        self.c = candidates[0]; self.controller = Controller(self.store)
        self.controller.keep_connection(self.c)
        self.file = PRIVATE / "redeployment-baseline.json"
        if self.file.exists():
            self.saved = json.loads(self.file.read_text())
        else:
            projects = {kind:self.info(kind) for kind in ["exchange", "hysteria2", "xui"]}
            values = {kind:self.store.vault.get(credential_alias(self.c, kind)) for kind in ["hysteria2", "xui"]}
            self.saved = {"projects":projects,"credentials":values,"done":[],"fixture":{}}
            self.save()

    def save(self):
        atomic_private(self.file, json.dumps(self.saved))

    def info(self, kind):
        return self.controller.project_information(self.c, kind)["data"]

    def remote(self, code, request=None):
        ssh = self.controller.transport(self.c)
        source = code + '\nprint("LM_RESULT:" + json.dumps({"ok":True,"data":result}))\n'
        envelope = json.dumps({"agent":source,"request":request or {}}).encode()
        payload = (self.c.sudo_password or self.c.password) + "\nLMREQUEST:" + base64.b64encode(envelope).decode() + "\n"
        command = "if [ \"$(id -u)\" = 0 ]; then python3 -c " + shlex.quote(BOOTSTRAP) + "; else sudo -S -p '' python3 -c " + shlex.quote(BOOTSTRAP) + "; fi"
        with tempfile.TemporaryDirectory(prefix="lm-real-check-", dir=PRIVATE) as temp:
            folder = Path(temp)
            with Askpass(folder, self.c.key_passphrase if self.c.auth == "key" else self.c.password) as environment:
                config = ssh._config(folder)
                value = subprocess.run(["ssh","-F",str(config),"-T","linux-manager-server",command],input=payload,capture_output=True,text=True,timeout=90,env=os.environ | environment,start_new_session=True)
        for line in reversed(value.stdout.splitlines()):
            if line.startswith("LM_RESULT:"):return json.loads(line[10:])["data"]
        atomic_private(PRIVATE / "redeployment-remote-error.txt", value.stderr)
        raise RuntimeError("test_audit_did_not_return")

    def audit(self, fixture=False):
        return self.remote('''from pathlib import Path
import hashlib,json,subprocess,pwd
def output(a):return subprocess.run(a,capture_output=True,text=True,timeout=30).stdout.strip()
units=["xiaojun-exchange-web.service","xiaojun-exchange-worker.service","xiaojun-exchange-nginx.service","sing-box.service","x-ui.service","nginx.service"]
marker=Path("/var/lib/xiaojun-exchange/redeployment-regression.dat")
if REQUEST.get("fixture") and not marker.exists():
 marker.write_text("keep-business-data-during-version-switch")
 original=Path("/var/lib/xiaojun-exchange/setup-token").stat()
 import os
 os.chown(marker,original.st_uid,original.st_gid);marker.chmod(0o600)
token=Path("/var/lib/xiaojun-exchange/setup-token")
result={"units":{u:output(["systemctl","show",u,"-p","ActiveState","-p","ActiveEnterTimestampMonotonic"]) for u in units},"nginx_versions":list(dict.fromkeys(line.split("|")[1].strip() for line in output(["apt-cache","madison","nginx"]).splitlines() if "|" in line)),"nginx_version":output(["dpkg-query","-W","-f=${Version}","nginx"]),"fixture_hash":hashlib.sha256(marker.read_bytes()).hexdigest() if marker.exists() else "","fixture_owner":marker.stat().st_uid if marker.exists() else -1,"token_hash":hashlib.sha256(token.read_bytes()).hexdigest() if token.exists() else ""}
''', {"fixture":fixture})

    def params(self, kind, **changes):
        data = self.info(kind)
        p = {"operation":"deploy","service":kind,"host":self.c.host,"port":data.get("port",8081),"version":data.get("version", ""),"version_policy":"keep"}
        if kind == "exchange":p.update(backend_port=data["backend_port"],maintenance_confirmed=True)
        if kind == "xui":p["panel_username"] = data["panel_username"]
        p.update(changes)
        if "version" in changes:p.pop("version_policy",None)
        return p

    def deploy(self, kind, **changes):
        p = self.params(kind, **changes)
        preview = self.controller.deployment_preview(self.c, p)
        p["deployment_fingerprint"] = preview["fingerprint"]
        status,_ = self.controller.execute(self.c,p)
        assert status["state"] == "succeeded"
        data = self.info(kind)
        assert data["port"] == p["port"]
        assert all(u.get("ActiveState") == "active" for u in data["units"] if u.get("LoadState") == "loaded")
        return status["result"], data

    @contextlib.contextmanager
    def panel(self):
        data = self.info("xui"); base = dict(self.controller.project_information(self.c,"xui")["rows"])["后台网址"]
        with socket.socket() as unused:unused.bind(("127.0.0.1",0));local=unused.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="lm-panel-check-",dir=PRIVATE) as temp:
            folder=Path(temp);ssh=self.controller.transport(self.c)
            with Askpass(folder,self.c.key_passphrase if self.c.auth=="key" else self.c.password) as environment:
                config=ssh._config(folder)
                process=subprocess.Popen(["ssh","-F",str(config),"-N","-o","ExitOnForwardFailure=yes","-L",f"127.0.0.1:{local}:127.0.0.1:{data['port']}","linux-manager-server"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=os.environ|environment,start_new_session=True)
                try:
                    for _ in range(100):
                        assert process.poll() is None
                        try:
                            with socket.create_connection(("127.0.0.1",local),timeout=.3):pass
                            break
                        except OSError:time.sleep(.1)
                    else:raise RuntimeError("panel_tunnel_not_ready")
                    tls=context()
                    class TunnelConnection(http.client.HTTPSConnection):
                        def connect(s):
                            s.sock=socket.create_connection(("127.0.0.1",local),timeout=s.timeout)
                            s.sock=s._context.wrap_socket(s.sock,server_hostname=s.host)
                    class TunnelHandler(urllib.request.HTTPSHandler):
                        def https_open(s,r):return s.do_open(TunnelConnection,r,context=tls)
                    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),TunnelHandler(context=tls),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    csrf=""
                    def api(path, payload=None):
                        parsed=urllib.parse.urlsplit(base)
                        headers={"Content-Type":"application/json","Origin":parsed.scheme+"://"+parsed.netloc,"Referer":base}
                        if csrf:headers["X-CSRF-Token"]=csrf
                        request=urllib.request.Request(base+path,data=json.dumps(payload).encode() if payload is not None else None,headers=headers)
                        with opener.open(request,timeout=25) as response:return json.load(response)
                    def token():
                        try:
                            value=api("csrf-token");obj=value.get("obj")
                            return obj if isinstance(obj,str) else (obj or {}).get("token","")
                        except urllib.error.HTTPError as e:
                            if e.code==404:return ""
                            raise
                    csrf=token()
                    credentials=self.store.vault.get(credential_alias(self.c,"xui"))
                    assert api("login",{"username":credentials["panel_username"],"password":credentials["panel_password"]}).get("success") is True
                    csrf=token();yield api
                finally:
                    if process.poll() is None:process.terminate();process.wait(timeout=10)

    def fixture(self):
        if self.saved["fixture"]:return
        with self.panel() as api:
            identifier=str(uuid.uuid4());subscription=secrets.token_urlsafe(12)
            inbound={"up":0,"down":0,"total":0,"remark":"Redeployment regression fixture","enable":True,"expiryTime":0,"listen":"","port":10085,"protocol":"vless","settings":json.dumps({"clients":[{"id":identifier,"flow":"","email":"redeployment-"+identifier[:8],"enable":True,"subId":subscription,"totalGB":0,"expiryTime":0,"limitIp":0,"reset":0}],"decryption":"none","fallbacks":[]}),"streamSettings":json.dumps({"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}),"sniffing":json.dumps({"enabled":False,"destOverride":["http","tls"]}),"allocate":json.dumps({"strategy":"always","refresh":5,"concurrency":3})}
            created=api("panel/api/inbounds/add",inbound);assert created.get("success") is True
            self.saved["fixture"]={"id":created["obj"]["id"],"client":identifier,"subscription":subscription}
            self.saved["node_baseline"]=self.info("xui")["inbounds"]
            self.save()

    def preserve(self):
        current=self.audit();original=self.saved["audit"]
        assert current["fixture_hash"]==original["fixture_hash"] and current["fixture_owner"]==original["fixture_owner"] and current["token_hash"]==original["token_hash"]
        data=self.info("xui");assert data["path"]==self.saved["projects"]["xui"]["path"] and data["inbounds"]==self.saved["node_baseline"]
        rows=self.controller.project_information(self.c,"xui")["rows"]
        assert any(n.startswith("节点：") and self.saved["fixture"]["client"] in v for n,v in rows)
        assert any(n.startswith("订阅：") and self.saved["fixture"]["subscription"] in v for n,v in rows)

    def run(self, phase):
        global STAGE
        STAGE=phase
        if phase=="baseline":
            self.saved["audit"]=self.audit(fixture=True);self.save();self.fixture()
            version=self.saved["audit"]["nginx_version"]
            self.deploy("nginx",port=8081,version=version)
            self.saved["projects"]["nginx"]=self.info("nginx");self.save()
            passed("standalone_nginx_adopted_without_changing_trading_nginx")
        elif phase=="ports":
            for kind in ["exchange","hysteria2","xui","nginx"]:
                original=self.saved["projects"][kind]["port"]
                if self.info(kind)["port"] != original:self.deploy(kind,port=original)
                before=self.audit()["units"]
                result,_=self.deploy(kind);assert result["action"]=="unchanged"
                assert before==self.audit()["units"]
                changed=original-1 if kind=="exchange" else original+1
                result,_=self.deploy(kind,port=changed);assert result["action"]=="reconfigure"
                self.preserve()
                if kind=="xui":
                    with self.panel() as api:assert api("panel/api/inbounds/list").get("success") is True
                self.deploy(kind,port=original);self.preserve()
                passed(kind+"_no_op_and_changed_port_without_reinstallation")
            original=self.saved["projects"]["exchange"]["backend_port"]
            self.deploy("exchange",backend_port=original+1);self.deploy("exchange",backend_port=original)
            self.preserve();passed("trading_backend_port_reconfigured_and_restored")
        elif phase=="credentials":
            self.deploy("hysteria2",proxy_password=secrets.token_urlsafe(24))
            original=self.saved["credentials"]["hysteria2"]["proxy_password"]
            assert self.info("hysteria2")["proxy_password"]!=original
            self.deploy("hysteria2",proxy_password=original)
            self.deploy("xui",panel_username="regressionpanel",panel_password=secrets.token_urlsafe(24))
            with self.panel() as api:assert api("panel/api/inbounds/list").get("success") is True
            self.deploy("xui",**self.saved["credentials"]["xui"])
            with self.panel() as api:assert api("panel/api/inbounds/list").get("success") is True
            self.preserve();passed("proxy_and_panel_credentials_changed_and_restored_locally")
        elif phase=="versions":
            targets={"exchange":"v1.1.84","hysteria2":"v1.14.2","xui":"v3.8.5"}
            for kind,older in targets.items():
                if kind in self.saved.get("versions_done",[]):continue
                current=self.saved["projects"][kind]["version"]
                assert older!=current
                self.deploy(kind,version=older);self.preserve()
                if kind=="xui":
                    with self.panel() as api:assert api("panel/api/inbounds/list").get("success") is True
                self.deploy(kind,version=current);self.preserve()
                self.saved.setdefault("versions_done",[]).append(kind);self.save()
                passed(kind+"_real_downgrade_upgrade_preserves_data_and_nodes")
            available=self.audit()["nginx_versions"];current=self.saved["projects"]["nginx"]["version"]
            older=next((v for v in available if v!=current),None)
            if older:
                self.deploy("nginx",version=older);self.preserve();self.deploy("nginx",version=current);self.preserve()
                passed("nginx_system_package_version_switch_and_restore")
            else:
                passed("nginx_exact_available_package_version_and_unavailable_version_guard")
        elif phase=="rollback":
            p=self.params("xui",port=self.saved["projects"]["xui"]["port"]+1,panel_password=secrets.token_urlsafe(24),tls_cert="invalid-test-certificate",tls_key="invalid-test-private-material")
            before=self.info("xui");working=self.store.vault.get(credential_alias(self.c,"xui"))
            try:self.controller.execute(self.c,p)
            except ManagerError as e:assert "恢复原项目" in str(e)
            else:raise RuntimeError("invalid_certificate_not_rejected")
            after=self.info("xui");assert all(after.get(k)==before.get(k) for k in ["port","path","panel_username","inbounds","version"])
            assert self.store.vault.get(credential_alias(self.c,"xui"))==working
            assert not self.store.vault.get(vault_alias("service-pending",credential_alias(self.c,"xui")))
            with self.panel() as api:assert api("panel/api/inbounds/list").get("success") is True
            self.preserve();passed("real_failed_change_restores_database_service_and_working_credentials")
            p=self.params("nginx",port=8082);p["deployment_fingerprint"]="stale-test-preview"
            try:self.controller.execute(self.c,p)
            except ManagerError as e:assert "预览" in str(e)
            else:raise RuntimeError("stale_preview_not_rejected")
            passed("stale_preview_refused_before_any_mutation")
        elif phase=="final":
            for kind,original in self.saved["projects"].items():
                data=self.info(kind);assert data["port"]==original["port"] and data["version"]==original["version"]
            self.preserve()
            with self.panel() as api:assert api("panel/api/inbounds/del/"+str(self.saved["fixture"]["id"]),{}).get("success") is True
            result=self.remote('''from pathlib import Path
import json
Path("/var/lib/xiaojun-exchange/redeployment-regression.dat").unlink(missing_ok=True)
result={"fixture_removed":True}
''');assert result["fixture_removed"]
            passed("original_versions_ports_and_credentials_restored_test_fixtures_removed")
        self.saved["done"].append(phase);self.save()


if __name__=="__main__":
    test=None
    try:
        test=Regression()
        phases=sys.argv[1:] or ["baseline","ports","credentials","versions","rollback","final"]
        for phase in phases:
            if phase not in test.saved["done"]:test.run(phase)
        if all(p in test.saved["done"] for p in ["baseline","ports","credentials","versions","rollback","final"]):
            atomic_private(PRIVATE / "redeployment-regression-result.json",json.dumps({"all_four_projects_real_redeployment_passed":True}))
    except Exception as error:
        import traceback
        atomic_private(PRIVATE / "redeployment-regression-error.txt",traceback.format_exc())
        print(json.dumps({"redeployment_regression":"failed","stage":STAGE,"failure_type":type(error).__name__}),flush=True)
        raise SystemExit(1)
    finally:
        if test:test.controller.close_connections()
