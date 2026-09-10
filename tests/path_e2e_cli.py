#!/usr/bin/env python3
"""Focused path-contract checks through all four shipping reference CLIs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from e2e_cli import ROOT, source_digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust-bin', required=True)
    parser.add_argument('--go-bin', required=True)
    parser.add_argument('--python', default='python3')
    parser.add_argument('--report', required=True)
    parser.add_argument('--languages', nargs='+', choices=['rust','python','javascript','go'])
    args = parser.parse_args()
    runners = {
        'rust': [str(Path(args.rust_bin).resolve())],
        'python': [shutil.which(args.python) or args.python, '-m', 'toolclad.cli'],
        'javascript': [shutil.which('node'), str(ROOT / 'js/src/cli.js')],
        'go': [str(Path(args.go_bin).resolve())],
    }
    if args.languages:
        runners = {name: command for name, command in runners.items() if name in args.languages}
    cases = json.loads((ROOT / 'tests/path_vectors.json').read_text())['cases']
    before = source_digest()
    hashes = {name: hashlib.sha256(Path(command[0]).read_bytes()).hexdigest() for name, command in runners.items()}
    results = []
    with tempfile.TemporaryDirectory(prefix='toolclad-path-e2e-') as temp:
        root = Path(temp)
        marker = root / 'effect.json'
        fixture = root / 'fixture.py'
        fixture.write_text('''import json,sys
from pathlib import Path
result={'argument':sys.argv[2]}
Path(sys.argv[1]).write_text(json.dumps(result))
result['content']=Path(sys.argv[2]).read_text()
print(json.dumps(result))
''')
        for case in cases:
            if not case['error']:
                file = root / case['value']
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('synthetic path fixture')
        os.mkfifo(root / 'credential.pipe', 0o600)
        env = {'PATH':os.environ.get('PATH','/usr/bin:/bin'), 'LANG':'C.UTF-8',
               'HOME':temp, 'PYTHONPATH':str(ROOT / 'python'),
               'TOOLCLAD_EVIDENCE_DIR':str(root / 'evidence')}
        plans = []
        for kind in ('path','credential_file'):
            for case in cases:
                plans.append((kind + '_' + case['name'],kind,case['value'],not case['error'],'run','default' if '\0' in case['value'] else 'supplied'))
        for value in ('input.txt','..','data/..'):
            plans.append(('preview_'+value,'path',value,value=='input.txt','test','supplied'))
        for value in ('input.txt','data/..'):
            plans.append(('default_'+value,'path',value,value=='input.txt','run','default'))
        plans.append(('credential_fifo','credential_file','credential.pipe',False,'run','supplied'))
        for language, runner in runners.items():
            for name, kind, value, allowed, mode, origin in plans:
                marker.unlink(missing_ok=True)
                path = root / 'case.clad.toml'
                content = '[tool]\nname="path_fixture"\nversion="1"\nbinary="python3"\ndescription="Synthetic path effect"\ntimeout_seconds=2\n[output]\nformat="json"\n'
                content += '[command]\nexec=' + json.dumps(['/usr/bin/python3', str(fixture),str(marker),'{value}']) + '\n'
                content += '[args.value]\ntype=' + json.dumps(kind) + '\nrequired=true\n'
                if origin=='default': content += 'default=' + json.dumps(value) + '\n'
                path.write_text(content)
                command = runner + [mode, str(path)]
                if origin=='supplied': command += ['--arg','value='+value]
                completed = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=8)
                expected_effect = allowed and mode=='run'
                passed = ((completed.returncode==0)==allowed and marker.exists()==expected_effect)
                if expected_effect and marker.exists():
                    expected_value = value.strip() if language=='rust' else value
                    passed = passed and json.loads(marker.read_text())['argument']==expected_value
                    passed = passed and 'synthetic path fixture' in completed.stdout
                result = dict(language=language,case=name,passed=passed,exit_code=completed.returncode,effect=marker.exists())
                if not passed: result.update(stdout=completed.stdout[-1000:],stderr=completed.stderr[-1000:])
                results.append(result)
    after = source_digest()
    after_hashes = {name: hashlib.sha256(Path(command[0]).read_bytes()).hexdigest() for name, command in runners.items()}
    report = dict(languages=list(runners),planned=len(plans)*len(runners),executed=len(results),passed=sum(row['passed'] for row in results),
                  source_before=before,source_after=after,artifacts_before=hashes,artifacts_after=after_hashes,cases=results)
    Path(args.report).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='cases'}))
    return 0 if len(results)==report['planned'] and all(row['passed'] for row in results) and before==after and hashes==after_hashes else 1


if __name__=='__main__':
    raise SystemExit(main())
