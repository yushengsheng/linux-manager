"""Run each test in an isolated process; redact local connection values."""
import argparse
import contextlib
import io
from pathlib import Path
import json
import re
import subprocess
import sys
import time
import unittest

base = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(base))
sys.path.insert(0, str(base / 'tests'))
values = [str(base), str(Path.home())]


def redact(output):
    for value in sorted(values, key=len, reverse=True):
        output = output.replace(value, "[local-value]")
    return re.sub(r"(?:\d{1,3}\.){3}\d{1,3}", "[address]", output)


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item.id()


def main():
    parser = argparse.ArgumentParser(description='完整本地回归；各用例独立运行，避免 Tk 窗口间互相影响')
    parser.add_argument('--case', help=argparse.SUPPRESS)
    parser.add_argument('--report', type=Path, help='保存脱敏后的完整本机测试记录')
    args = parser.parse_args()
    if args.case:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            suite = unittest.defaultTestLoader.loadTestsFromName(args.case)
            result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
        print(redact(output.getvalue()), end='')
        print('LM_TEST_RESULT:' + json.dumps({'run': result.testsRun, 'failures': len(result.failures),
                                             'errors': len(result.errors), 'skipped': len(result.skipped)}))
        return not result.wasSuccessful()

    discovery = io.StringIO()
    with contextlib.redirect_stdout(discovery), contextlib.redirect_stderr(discovery):
        suite = unittest.defaultTestLoader.discover(str(base / 'tests'))
    if unittest.defaultTestLoader.errors:
        print(redact('\n'.join(unittest.defaultTestLoader.errors)))
        return 1
    targets = list(cases(suite))
    totals = dict(run=0, failures=0, errors=0, skipped=0)
    reports = [redact(discovery.getvalue())]
    started = time.monotonic()
    for index, target in enumerate(targets, 1):
        try:
            child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--case', target],
                                   cwd=base, capture_output=True, text=True, timeout=60)
            body, marker, packet = (child.stdout + child.stderr).rpartition('LM_TEST_RESULT:')
            result = json.loads(packet) if marker else None
            if not result or (child.returncode and not (result['failures'] or result['errors'])):
                raise ValueError('test process did not finish normally')
            body = redact(body)
        except (subprocess.TimeoutExpired, OSError, ValueError, KeyError, TypeError):
            body = '测试进程未完成或超时：' + target + '\n'
            result = dict(run=1, failures=0, errors=1, skipped=0)
        reports.append(body)
        for key in totals:
            totals[key] += result[key]
        if result['failures'] or result['errors']:
            print(body[-8000:], flush=True)
        if index % 25 == 0 or index == len(targets):
            print(json.dumps({'completed': index, 'total': len(targets), **totals}), flush=True)
    passed = totals['run'] - totals['failures'] - totals['errors'] - totals['skipped']
    summary = f"核对 {totals['run']} 项：{passed} 通过、{totals['skipped']} 跳过、{totals['failures']} 失败、{totals['errors']} 错误；耗时 {time.monotonic() - started:.1f} 秒。"
    print(summary, flush=True)
    if args.report:
        from linux_manager.models import atomic_private
        atomic_private(args.report, '\n'.join(reports) + '\n' + summary + '\n')
    return bool(totals['failures'] or totals['errors'])


if __name__ == '__main__':
    raise SystemExit(main())
