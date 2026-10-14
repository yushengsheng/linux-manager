"""Synthetic protocol checks; run only with explicit --authorized-test-host.

Uses the existing saved SSH identity, appends one temporary local provider and
removes only that provider in finally. Never calls a paid upstream model.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linux_manager.controller import Controller
from linux_manager.models import Store, atomic_private
import tools.live_direct_download_regression as live

REMOTE_PROTOCOL_TEST = 'import json, pathlib, runpy, threading, time, subprocess, urllib.request, http.server, fcntl\nns=runpy.run_path(\'/var/lib/linux-server-manager/cliproxyapi/maintenance.py\',run_name=\'lm_fixture\');g=ns[\'cp_read\'].__globals__\nclass Handler(http.server.BaseHTTPRequestHandler):\n def log_message(self,*args):pass\n def do_POST(self):\n  request=json.loads(self.rfile.read(int(self.headers.get(\'Content-Length\',0))))\n  tool=bool(request.get(\'tools\')); stream=bool(request.get(\'stream\'))\n  self.send_response(200);self.send_header(\'Content-Type\',\'text/event-stream\' if stream else \'application/json\');self.end_headers()\n  if stream:\n   chunks=[{\'delta\':{\'role\':\'assistant\'},\'finish_reason\':None}]\n   if tool:\n    chunks+=[{\'delta\':{\'tool_calls\':[{\'index\':0,\'id\':\'call_fixture\',\'type\':\'function\',\'function\':{\'name\':\'fixture_tool\',\'arguments\':\'{"value":1}\'}}]},\'finish_reason\':None},{\'delta\':{},\'finish_reason\':\'tool_calls\'}]\n   else:chunks += [{\'delta\':{\'content\':\'fixture response\'},\'finish_reason\':None},{\'delta\':{},\'finish_reason\':\'stop\'}]\n   for choice in chunks:\n    obj={\'id\':\'chatcmpl-fixture\',\'object\':\'chat.completion.chunk\',\'created\':int(time.time()),\'model\':\'fixture-model\',\'choices\':[dict(index=0,**choice)]}\n    self.wfile.write((\'data: \'+json.dumps(obj)+\'\\n\\n\').encode());self.wfile.flush()\n   self.wfile.write(b\'data: [DONE]\\n\\n\')\n  else:\n   message={\'role\':\'assistant\',\'content\':\'fixture response\'}\n   if tool:message={\'role\':\'assistant\',\'content\':None,\'tool_calls\':[{\'id\':\'call_fixture\',\'type\':\'function\',\'function\':{\'name\':\'fixture_tool\',\'arguments\':\'{"value":1}\'}}]}\n   self.wfile.write(json.dumps({\'id\':\'chatcmpl-fixture\',\'object\':\'chat.completion\',\'created\':int(time.time()),\'model\':\'fixture-model\',\'choices\':[{\'index\':0,\'message\':message,\'finish_reason\':\'tool_calls\' if tool else \'stop\'}],\'usage\':{\'prompt_tokens\':1,\'completion_tokens\':1,\'total_tokens\':2}}).encode())\nserver=http.server.ThreadingHTTPServer((\'127.0.0.1\',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()\nconfig=g[\'cp_read\'](); assert not any(p.get(\'name\')==\'linux-manager-fixture\' for p in config.get(\'api-keys\',{}).get(\'openai-compatibility\',[]))\nproviders=config.setdefault(\'api-keys\',{}).setdefault(\'openai-compatibility\',[])\nproviders.append({\'name\':\'linux-manager-fixture\',\'base-url\':\'http://127.0.0.1:\'+str(server.server_port)+\'/v1\',\'keys\':[{\'api-key\':\'fixture-only-no-paid-api\'}],\'models\':[{\'name\':\'fixture-model\',\'alias\':\'fixture-model\'}]})\nresult={\'synthetic\':True,\'requests\':[]}\nwith pathlib.Path(\'/var/lib/linux-server-manager/operation.lock\').open(\'a\') as lock:\n fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)\n try:\n  g[\'command\']([\'systemctl\',\'stop\',g[\'CP_UNIT\']]);g[\'cp_save_config\'](config);g[\'command\']([\'systemctl\',\'start\',g[\'CP_UNIT\']]);time.sleep(2)\n  record=g[\'cp_records\']();base=\'https://\'+record[\'host\']+\':\'+str(record[\'port\'])\n  for endpoint in [\'chat/completions\',\'messages\',\'responses\']:\n   for stream in [False,True]:\n    for tool in [False,True]:\n     body={\'model\':\'fixture-model\',\'stream\':stream}\n     if endpoint==\'responses\':body[\'input\']=\'fixture prompt\'\n     else:body[\'messages\']=[{\'role\':\'user\',\'content\':\'fixture prompt\'}]\n     if endpoint==\'messages\':body[\'max_tokens\']=100\n     if tool:\n      schema={\'type\':\'object\',\'properties\':{\'value\':{\'type\':\'integer\'}}}\n      if endpoint==\'messages\':body[\'tools\']=[{\'name\':\'fixture_tool\',\'input_schema\':schema}]\n      elif endpoint==\'responses\':body[\'tools\']=[{\'type\':\'function\',\'name\':\'fixture_tool\',\'parameters\':schema}]\n      else:body[\'tools\']=[{\'type\':\'function\',\'function\':{\'name\':\'fixture_tool\',\'parameters\':schema}}]\n     req=urllib.request.Request(base+\'/v1/\'+endpoint,data=json.dumps(body).encode(),headers={\'Authorization\':\'Bearer \'+config[\'access\'][\'api-keys\'][0],\'Content-Type\':\'application/json\'})\n     opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n     try:\n      with opener.open(req,timeout=20) as response:\n       payload=response.read().decode();assert response.status==200\n     except urllib.error.HTTPError as error:raise RuntimeError(str((endpoint,stream,tool))+\': \'+error.read().decode()[:600])\n     assert (\'fixture_tool\' if tool else \'fixture response\') in payload,(endpoint,stream,tool,payload[:200])\n     if stream:assert \'data:\' in payload\n     result[\'requests\'].append({\'protocol\':endpoint,\'stream\':stream,\'tool\':tool,\'passed\':True})\n finally:\n  latest=g[\'cp_read\'](); latest[\'api-keys\'][\'openai-compatibility\']=[p for p in latest[\'api-keys\'][\'openai-compatibility\'] if p.get(\'name\')!=\'linux-manager-fixture\']\n  if not latest[\'api-keys\'][\'openai-compatibility\']:latest[\'api-keys\'].pop(\'openai-compatibility\')\n  if not latest[\'api-keys\']:latest.pop(\'api-keys\')\n  g[\'command\']([\'systemctl\',\'stop\',g[\'CP_UNIT\']]);g[\'cp_save_config\'](latest);g[\'command\']([\'systemctl\',\'start\',g[\'CP_UNIT\']]);server.shutdown();time.sleep(1)\n  g[\'cp_health\'](g[\'cp_read\'](),g[\'cp_records\']())\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--authorized-test-host', required=True)
    args = parser.parse_args()
    store = Store(Path.home() / 'Library/Application Support/linux服务器管理')
    targets = [p for p in store.profiles() if p.host == args.authorized_test_host]
    if len(targets) != 1 or store.last_warning: raise SystemExit('Saved test profile is ambiguous or credentials unavailable.')
    live.EVIDENCE = Path('/private/tmp/linux-manager-cliproxyapi-live')
    live.EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    ssh = Controller(store).transport(targets[0], fresh=True)
    result = live.remote_python(ssh, REMOTE_PROTOCOL_TEST, timeout=180)
    atomic_private(live.EVIDENCE / 'synthetic-protocols.json', json.dumps(result))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__': main()
