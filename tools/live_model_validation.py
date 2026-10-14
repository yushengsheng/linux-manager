"""Explicitly authorized inference checks using an existing saved test gateway.

Runs installed clients with isolated configuration; never replaces real client
settings, restarts services, or changes server authorization. Evidence is local.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from linux_manager.client_config import ClientConfigurator, PROVIDER, gateway_connection, gateway_models
from linux_manager.controller import Controller
from linux_manager.models import Store, ManagerError, atomic_private

CODEX = Path('/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex')
PI_NODE = Path.home() / '.local/share/pi-node/node-v22.23.2-darwin-arm64/bin/node'
PI_CLI = PI_NODE.parent.parent / 'lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js'
EVIDENCE = Path('/private/tmp/linux-manager-model-validation')


class AppServer:
    def __init__(self, codex_home, cwd):
        self.process = subprocess.Popen([str(CODEX), 'app-server', '--stdio'], cwd=cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=os.environ | {'CODEX_HOME': str(codex_home)}, text=True, bufsize=1)
        self.messages = queue.Queue()
        self.next_id = 0
        self.notifications = []
        self.errors = []
        def read_stdout():
            for line in self.process.stdout:
                try: self.messages.put(json.loads(line))
                except ValueError: pass
            self.messages.put({'closed': True})
        def read_stderr():
            for line in self.process.stderr:
                self.errors.append(line)
        threading.Thread(target=read_stdout, daemon=True).start()
        threading.Thread(target=read_stderr, daemon=True).start()
        self.request('initialize', {'clientInfo': {'name': 'linux_manager_validation', 'version': '0.3.12'},
                                    'capabilities': {'experimentalApi': True}})
        self.send({'method': 'initialized'})

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + '\n')
        self.process.stdin.flush()

    def next_message(self, timeout):
        try: message = self.messages.get(timeout=max(0.01, timeout))
        except queue.Empty: raise ManagerError('Codex 验证等待超时。') from None
        if message.get('closed'): raise ManagerError('Codex 验证进程提前退出。')
        return message

    def request(self, method, params, timeout=30):
        self.next_id += 1
        identifier = self.next_id
        self.send({'id': identifier, 'method': method, 'params': params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            message = self.next_message(deadline - time.monotonic())
            if message.get('id') == identifier:
                if 'error' in message:
                    raise ManagerError('Codex RPC 校验失败：' + str(message['error'].get('code')))
                return message['result']
            self.notifications.append(message)
        raise ManagerError('Codex 验证等待超时。')

    def turn(self, thread_id, text, model):
        params = {'threadId': thread_id, 'model': model, 'input': [{'type': 'text', 'text': text}]}
        if model.startswith('gpt-'): params['effort'] = 'low'
        result = self.request('turn/start', params)
        turn_id = result['turn']['id']
        deadline = time.monotonic() + 90
        text_parts = []
        commands = []
        events = []
        while time.monotonic() < deadline:
            message = self.notifications.pop(0) if self.notifications else self.next_message(deadline - time.monotonic())
            method = message.get('method', '')
            params = message.get('params', {})
            if params.get('threadId') != thread_id or params.get('turnId', turn_id) != turn_id:
                continue
            events.append(method)
            if method == 'item/agentMessage/delta': text_parts.append(params.get('delta', ''))
            if method == 'item/completed' and params.get('item', {}).get('type') == 'commandExecution':
                commands.append(params['item'].get('exitCode'))
            if method == 'turn/completed':
                return {'status': params['turn']['status'], 'text': ''.join(text_parts),
                        'command_exit_codes': commands, 'event_types': sorted(set(events))}
        raise ManagerError('Codex 模型调用等待超时。')

    def close(self):
        self.process.terminate()
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired: self.process.kill(); self.process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--authorized-profile', required=True)
    args = parser.parse_args()
    EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    store = Store(Path.home() / 'Library/Application Support/linux服务器管理')
    profiles = [p for p in store.profiles() if p.identifier == args.authorized_profile]
    if len(profiles) != 1 or store.last_warning:
        raise ManagerError('已授权测试档案不唯一或凭据不可用。')
    controller = Controller(store)
    ssh = controller.transport(profiles[0], fresh=True)
    if not ssh.trusted(): raise ManagerError('所选服务器身份未受信任。')
    info = controller.project_information(profiles[0], 'cliproxyapi')
    gateway = gateway_connection(info)
    models = gateway_models(gateway['base_url'], gateway['api_keys'][0])
    selected = [m for m in ('gpt-6.1-sol', 'gpt-6-sol') if m in models]
    if len(selected) != 2: raise ManagerError('预期的两个 GPT 测试模型不可用。')
    results = {}
    with tempfile.TemporaryDirectory(prefix='clients-live-', dir=EVIDENCE) as directory:
        root = Path(directory)
        configurator = ClientConfigurator(root / 'backups', root / 'home', {})
        cached_catalog = Path.home() / '.codex/models_cache.json'
        if cached_catalog.is_file():
            target = configurator.directories['codex'] / 'models_cache.json'
            target.parent.mkdir(parents=True)
            atomic_private(target, cached_catalog.read_bytes())
        for client in ('codex', 'pi'):
            configurator.configure(client, gateway['base_url'], gateway['api_keys'][0], selected[0], models)
        cwd = root / 'workspace'; cwd.mkdir()
        (cwd / 'validation.txt').write_text('tool-loop-ok\n')
        app = AppServer(configurator.directories['codex'], cwd)
        try:
            catalog = app.request('model/list', {'limit': 100, 'includeHidden': False})
            results['codex_models'] = [m['id'] for m in catalog['data']]
            thread = app.request('thread/start', {'cwd': str(cwd), 'model': selected[0], 'modelProvider': PROVIDER,
                'approvalPolicy': 'never', 'sandbox': 'read-only', 'ephemeral': True})['thread']['id']
            first = app.turn(thread, 'Remember this test code: gateway-472. Reply exactly: remembered. Do not use tools.', selected[0])
            results['codex_first_turn'] = {'status': first['status'], 'passed': first['status'] == 'completed' and 'remembered' in first['text']}
            print(json.dumps({'check': 'codex_first_turn', **results['codex_first_turn']}), flush=True)
            second = app.turn(thread, 'What test code did I give you? Reply only with it. Do not use tools.', selected[1])
            results['codex_model_switch_followup'] = {'status': second['status'], 'model': selected[1],
                'passed': second['status'] == 'completed' and 'gateway-472' in second['text']}
            print(json.dumps({'check': 'codex_model_switch_followup', **results['codex_model_switch_followup']}), flush=True)
            third = app.turn(thread, 'Use a local shell tool to read validation.txt in the current directory. Then reply exactly with its content. Do not modify any files.', selected[0])
            results['codex_tool_loop'] = {'status': third['status'], 'successful_commands': third['command_exit_codes'].count(0),
                'passed': third['status'] == 'completed' and 0 in third['command_exit_codes'] and 'tool-loop-ok' in third['text']}
            print(json.dumps({'check': 'codex_tool_loop', **results['codex_tool_loop']}), flush=True)
            for model in ('claude-sonnet-4-6', 'gemini-3.8-flash-high'):
                if model not in models: continue
                turn = app.turn(thread, 'Reply exactly: cross-model-ok. Do not use tools.', model)
                results['codex_' + model] = {'status': turn['status'], 'passed': turn['status'] == 'completed' and 'cross-model-ok' in turn['text']}
                print(json.dumps({'check': 'codex_cross_provider', 'model': model, **results['codex_' + model]}), flush=True)
        finally: app.close()
        if PI_NODE.is_file() and PI_CLI.is_file():
            env = os.environ | {'PI_CODING_AGENT_DIR': str(configurator.directories['pi']), 'PI_OFFLINE': '1'}
            listing = subprocess.run([str(PI_NODE), str(PI_CLI), '--offline', '--no-approve', '--list-models', PROVIDER],
                cwd=cwd, env=env, capture_output=True, text=True, timeout=30)
            results['pi_model_list'] = {'exit': listing.returncode, 'gpt_choices_visible': all(m in listing.stdout for m in selected)}
            for model in selected:
                process = subprocess.run([str(PI_NODE), str(PI_CLI), '--offline', '--no-approve', '--provider', PROVIDER,
                    '--model', model, '--thinking', 'low', '--no-tools', '-p', 'Reply exactly: pi-gateway-ok'],
                    cwd=cwd, env=env, capture_output=True, text=True, timeout=90)
                passed = process.returncode == 0 and 'pi-gateway-ok' in process.stdout
                results['pi_' + model] = {'exit': process.returncode, 'passed': passed}
                print(json.dumps({'check': 'pi_call', 'model': model, 'exit': process.returncode, 'passed': passed}), flush=True)
        atomic_private(EVIDENCE / 'client-real-results.json', json.dumps(results, ensure_ascii=False, indent=2))
    print(json.dumps(results, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    try: main()
    except ManagerError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
