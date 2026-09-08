#!/usr/bin/env python3
"""Shipping-CLI conformance checks using synthetic credentials and local fixtures only.

Build Rust and Go first. See docs/reference-execution.md for the invocation.
No result is accepted without the expected process exit and observable effects.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def source_digest():
    digest = hashlib.sha256()
    files = []
    for folder in ('rust/src', 'python/toolclad', 'js/src', 'go/pkg', 'go/cmd', 'tests'):
        files.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for path in sorted(files):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


class LocalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, address):
        pass  # Timeout/output-limit cases deliberately close their sockets.


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.server.requests.append(dict(path=self.path, body=body.decode(), token=self.headers.get('X-Token')))
        if self.path.startswith('/slow'):
            time.sleep(2)
        if self.path.startswith('/redirect'):
            self.send_response(302)
            self.send_header('Location', self.server.destination + '/redirect-target')
            self.end_headers()
            return
        if self.path.startswith('/large'):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'x' * (5 * 1024 * 1024))
            return
        self.send_response(404 if self.path.startswith('/missing') else 206 if self.path.startswith('/partial') else 200)
        self.end_headers()
        self.wfile.write(json.dumps({'path': self.path, 'body': body.decode(), 'token': self.headers.get('X-Token')}).encode())

    do_POST = do_GET


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust-bin', required=True)
    parser.add_argument('--go-bin', required=True)
    parser.add_argument('--python', default='python3')
    parser.add_argument('--report', required=True)
    opts = parser.parse_args()
    runners = {
        'rust': [str(Path(opts.rust_bin).resolve())],
        'python': [shutil.which(opts.python) or opts.python, '-m', 'toolclad.cli'],
        'javascript': [shutil.which('node'), str(ROOT / 'js/src/cli.js')],
        'go': [str(Path(opts.go_bin).resolve())],
    }
    for runner in runners.values():
        if not runner[0] or not Path(runner[0]).is_file():
            raise RuntimeError(f'Missing CLI executable: {runner}')
    artifacts = {name: hashlib.sha256(Path(runner[0]).read_bytes()).hexdigest() for name, runner in runners.items()}
    before = source_digest()
    results = []
    server = LocalServer(('127.0.0.1', 0), Handler)
    trap = LocalServer(('127.0.0.1', 0), Handler)
    server.requests, trap.requests = [], []
    server.destination = trap.destination = f'http://127.0.0.1:{trap.server_port}'
    for item in (server, trap):
        threading.Thread(target=item.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{server.server_port}'
    token = 'synthetic-token-for-local-test'
    secret_body = 'synthetic "quoted" \\ value\nsecond line'
    try:
        with tempfile.TemporaryDirectory(prefix='toolclad-e2e-') as temp:
            directory = Path(temp)
            marker = directory / 'effect.json'
            child_pid = directory / 'child.pid'
            fixture = directory / 'fixture.py'
            fixture.write_text('''#!/usr/bin/python3
import json, os, subprocess, sys, time
from pathlib import Path
marker = Path(sys.argv[1]) if len(sys.argv)>1 else None
mode = sys.argv[2] if len(sys.argv)>2 else 'custom'
if mode == 'sleep': time.sleep(10)
if mode == 'large': print('x' * (5 * 1024 * 1024)); sys.exit(0)
if mode == 'descendant':
    child = subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(10)'])
    Path(sys.argv[3]).write_text(str(child.pid))
if mode == 'fail': sys.exit(7)
result = {'argv': sys.argv[3:], 'secret': os.environ.get('TOOLCLAD_SECRET_TOKEN'), 'canary': os.environ.get('TOOLCLAD_E2E_CANARY'), 'input': sys.stdin.read(), 'arg': os.environ.get('TOOLCLAD_ARG_VALUE'), 'scan': os.environ.get('TOOLCLAD_SCAN_ID')}
if marker: marker.write_text(json.dumps(result))
print(json.dumps(result))
''')
            fixture.chmod(0o700)
            (directory / '.curlrc').write_text('location\n')
            environment = {
                'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8',
                'HOME': temp, 'PYTHONPATH': str(ROOT / 'python'),
                'TOOLCLAD_EVIDENCE_DIR': str(directory / 'evidence'),
                'TOOLCLAD_SECRET_TOKEN': token, 'TOOLCLAD_SECRET_BODY': secret_body,
                'TOOLCLAD_E2E_CANARY': 'must-not-reach-child',
                'HTTP_PROXY': trap.destination, 'HTTPS_PROXY': trap.destination,
                'ALL_PROXY': trap.destination, 'http_proxy': trap.destination,
                'https_proxy': trap.destination, 'all_proxy': trap.destination,
                'NO_PROXY': '', 'no_proxy': '',
            }
            base = '[tool]\nname="e2e_fixture"\nversion="1.0.0"\nbinary="python3"\ndescription="Local execution fixture"\ntimeout_seconds=1\n'
            output = '[output]\nformat="text"\n'
            argdef = '[args.value]\ntype="string"\nrequired=true\n'
            def command(mode='ok', argument='{value}', exec_array=False):
                argv = ['/usr/bin/python3', str(fixture), str(marker), mode]
                if argument is not None:
                    argv.append(argument)
                if exec_array:
                    return '[command]\nexec=' + json.dumps(argv) + '\n'
                return '[command]\ntemplate=' + json.dumps(' '.join(argv)) + '\n'
            def manifest(backend=None, definitions=argdef, tool='', out=output):
                return base + tool + out + (backend or command()) + definitions
            def http(path='/ok', headers='', body='', definitions=''):
                result = f'[http]\nmethod="POST"\nurl="{origin}{path}"\n'
                if body:
                    result += 'body_template=' + json.dumps(body) + '\n'
                if headers:
                    result += '[http.headers]\n' + headers
                return manifest(result, definitions)
            def live(pid):
                try:
                    state = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0]
                    return state != 'Z'
                except FileNotFoundError:
                    return False
            def run_case(language, name, content, args=None, subcommand='run', success=False, effects=False, requests=0, check=None):
                marker.unlink(missing_ok=True)
                child_pid.unlink(missing_ok=True)
                server.requests.clear()
                trap.requests.clear()
                path = directory / 'case.clad.toml'
                path.write_text(content)
                invocation = runners[language] + [subcommand, str(path)]
                for arg in args or []:
                    invocation.extend(['--arg', arg])
                process = subprocess.Popen(invocation, env=environment, cwd=temp, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                start = time.monotonic()
                failed = None
                stdout = stderr = ''
                try:
                    out, err = process.communicate(timeout=6)
                    stdout, stderr = out.decode(errors='replace'), err.decode(errors='replace')
                    assert (process.returncode == 0) == success, f'exit={process.returncode}; {stderr[:500]}; {stdout[:500]}'
                    assert marker.exists() == effects, f'effect marker={marker.exists()}'
                    assert len(server.requests) == requests, f'requests={server.requests}'
                    assert not trap.requests, f'proxy/redirect trap reached: {trap.requests}'
                    if check:
                        check(stdout, stderr)
                    if child_pid.exists():
                        pid = int(child_pid.read_text())
                        for _ in range(20):
                            if not live(pid): break
                            time.sleep(.025)
                        assert not live(pid), f'descendant {pid} survived'
                except Exception as exc:
                    failed = str(exc)
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate(timeout=2)
                    if child_pid.exists():
                        try: os.kill(int(child_pid.read_text()), signal.SIGKILL)
                        except ProcessLookupError: pass
                result = {'language': language, 'case': name, 'passed': failed is None, 'duration_ms': int(1000*(time.monotonic()-start)), 'exit_code': process.returncode}
                if failed: result.update(error=failed, stdout=stdout[:2000], stderr=stderr[:2000])
                results.append(result)
                print(f'{language}: {name}: {"PASS" if failed is None else "FAIL " + failed}', flush=True)
            def assert_equal(actual, expected):
                assert actual == expected, f'{actual!r} != {expected!r}'
            def marker_check(value):
                def check(out, err):
                    data = json.loads(marker.read_text())
                    assert_equal(data['argv'], [value])
                    assert data['secret'] is None and data['canary'] is None and data['input'] == ''
                return check
            for language in runners:
                run_case(language,'literal_template_argv',manifest(),['value=alpha --extra'],success=True,effects=True,check=marker_check('alpha --extra'))
                run_case(language,'literal_exec_argv',manifest(command(exec_array=True)),['value=alpha --extra'],success=True,effects=True,check=marker_check('alpha --extra'))
                run_case(language,'clamped_default',manifest(definitions='[args.value]\ntype="integer"\nmax=10\nclamp=true\ndefault=99\n'),success=True,effects=True,check=marker_check('10'))
                run_case(language,'invalid_default',manifest(definitions='[args.value]\ntype="port"\ndefault=0\n'))
                run_case(language,'unknown_argument',manifest(),['value=ok','unknown=no'])
                run_case(language,'missing_required',manifest())
                run_case(language,'empty_required',manifest(),['value='])
                run_case(language,'duplicate_argument',manifest(),['value=ok','value=changed'])
                run_case(language,'empty_argument_name',manifest(),['value=ok',' =no'])
                run_case(language,'zero_timeout',manifest().replace('timeout_seconds=1','timeout_seconds=0'),['value=ok'])
                run_case(language,'fractional_timeout',manifest().replace('timeout_seconds=1','timeout_seconds=1.5'),['value=ok'])
                run_case(language,'boolean_timeout',manifest().replace('timeout_seconds=1','timeout_seconds=true'),['value=ok'])
                run_case(language,'empty_cedar_refused',manifest(tool='[tool.cedar]\nresource=""\naction=""\n'),['value=ok'])
                run_case(language,'approval_refused',manifest(tool='human_approval=true\n'),['value=ok'])
                run_case(language,'cedar_refused',manifest(tool='[tool.cedar]\nresource="Fixture"\naction="execute"\n'),['value=ok'])
                run_case(language,'scope_refused',manifest(definitions=argdef+'scope_check=true\n'),['value=ok'])
                run_case(language,'callback_refused',manifest(tool='dispatch="callback"\n'),['value=ok'])
                run_case(language,'approval_preview',manifest(tool='human_approval=true\n'),['value=ok'],subcommand='test',success=True)
                run_case(language,'ambiguous_backend',manifest(command()+'[http]\nurl="'+origin+'/ok"\n'),['value=ok'])
                run_case(language,'custom_parser_refused',manifest(out=output+'parser="./parser.py"\n'),['value=ok'])
                run_case(language,'command_failure',manifest(command('fail'),definitions=''))
                run_case(language,'command_timeout',manifest(command('sleep'),definitions=''))
                run_case(language,'command_output_limit',manifest(command('large'),definitions=''))
                # Success is not required when cleanup cuts off output from a detached background job.
                run_case(language,'descendant_cleanup',manifest(command('descendant',str(child_pid)),definitions=''),success=(language in ('rust','python')),effects=True)
                def custom_check(out, err):
                    envelope = json.loads(out)
                    data = envelope['results']
                    if 'raw_output' in data:
                        data = json.loads(data['raw_output'])
                    assert_equal(data['arg'], 'ok')
                    assert_equal(data['scan'], envelope['scan_id'])
                    assert data['secret'] is None and data['canary'] is None and data['input'] == ''
                run_case(language,'custom_executor',manifest('[command]\nexecutor='+json.dumps(str(fixture))+'\n'),['value=ok'],success=True,check=custom_check)
                run_case(language,'invocation_id',manifest(command(argument='{_scan_id}'),definitions=''),success=True,effects=True,
                         check=lambda out,err: assert_equal(json.loads(marker.read_text())['argv'],[json.loads(out)['scan_id']]))
                run_case(language,'http_default',http('/defaults',body='{"value":"{value}"}',definitions='[args.value]\ntype="port"\nrequired=true\ndefault=443\n'),success=True,requests=1,
                         check=lambda out,err: assert_equal(json.loads(server.requests[0]['body']),{'value':'443'}))
                run_case(language,'http_unknown',http(),['extra=no'])
                run_case(language,'http_approval',http().replace('timeout_seconds=1','timeout_seconds=1\nhuman_approval=true'))
                run_case(language,'http_no_proxy',http(headers='X-Token="{_secret:token}"\n'),success=True,requests=1,check=lambda out,err: assert_equal(server.requests[0]['token'],token))
                run_case(language,'http_no_redirect',http('/redirect',headers='X-Token="{_secret:token}"\n'),requests=1)
                run_case(language,'http_error_exit',http('/missing'),requests=1)
                run_case(language,'http_default_partial',http('/partial'),success=True,requests=1)
                run_case(language,'http_error_list_not_allowlist',http('/missing').replace('method="POST"','method="POST"\nerror_status=[500]'),requests=1)
                run_case(language,'http_timeout',http('/slow'),requests=1)
                run_case(language,'http_output_limit',http('/large'),requests=1)
                run_case(language,'http_literal_secret_token',http(body='{"value":"{value}","secret":"{_secret:body}"}',definitions="[args.value]\ntype='enum'\nallowed=['{_secret:token}']\n"),['value={_secret:token}'],success=True,requests=1,
                         check=lambda out,err: assert_equal(json.loads(server.requests[0]['body']),{'value':'{_secret:token}','secret':secret_body}))
                run_case(language,'http_secret_free_preview',http(headers='X-Token="{_secret:missing}"\n'),subcommand='test',success=True,
                         check=lambda out,err: assert_equal(token in out+err or secret_body in out+err,False))
                run_case(language,'http_dynamic_authority',http(definitions=argdef).replace(origin,'http://{value}'),['value=127.0.0.1'],success=False)
                run_case(language,'http_url_secret',http('/{_secret:token}'))
                run_case(language,'schema_closed_arguments',manifest(),subcommand='schema',success=True,
                         check=lambda out,err: assert_equal(json.loads(out)['inputSchema']['additionalProperties'],False))
                mcp = manifest('[mcp]\nserver="local-fixture"\ntool="preview"\n', definitions=argdef)
                run_case(language,'mcp_preview_not_success',mcp,['value=ok'])
                run_case(language,'mcp_unknown',mcp,['value=ok','extra=no'])
                run_case(language,'mcp_dry_run',mcp,['value=ok'],subcommand='test',success=True)
    finally:
        server.shutdown(); trap.shutdown(); server.server_close(); trap.server_close()
    after = source_digest()
    after_artifacts = {name: hashlib.sha256(Path(runner[0]).read_bytes()).hexdigest() for name, runner in runners.items()}
    expected = 44 * len(runners)
    report = dict(planned=expected, executed=len(results), passed=sum(r['passed'] for r in results),
                  failed=sum(not r['passed'] for r in results), source_before=before, source_after=after,
                  artifacts_before=artifacts, artifacts_after=after_artifacts, cases=results)
    Path(opts.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))
    return 0 if len(results)==expected and all(r['passed'] for r in results) and before==after and artifacts==after_artifacts else 1


if __name__ == '__main__':
    raise SystemExit(main())
