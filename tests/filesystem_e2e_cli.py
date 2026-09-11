#!/usr/bin/env python3
"""Verify that reference CLIs never silently execute declared file capabilities."""
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
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    runners = {
        'rust': [str(Path(args.rust_bin).resolve())],
        'python': [shutil.which('python3'), '-m', 'toolclad.cli'],
        'javascript': [shutil.which('node'), str(ROOT / 'js/src/cli.js')],
        'go': [str(Path(args.go_bin).resolve())],
    }
    before = source_digest()
    hashes = {name: hashlib.sha256(Path(command[0]).read_bytes()).hexdigest() for name, command in runners.items()}
    cases = []
    with tempfile.TemporaryDirectory(prefix='toolclad-files-e2e-') as temp:
        root = Path(temp)
        marker = root / 'effect.txt'
        script = root / 'effect.py'
        script.write_text('from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_text("useful result")\nprint("useful result")\n')
        base = '[tool]\nname="files_fixture"\nversion="1"\nbinary="python3"\ndescription="File contract fixture"\ntimeout_seconds=2\n[output]\nformat="text"\n'
        base += '[command]\nexec=' + json.dumps(['/usr/bin/python3', str(script), str(marker)]) + '\n'
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8', 'HOME': temp,
               'PYTHONPATH': str(ROOT / 'python'), 'TOOLCLAD_EVIDENCE_DIR': str(root / 'evidence')}
        for language, runner in runners.items():
            for name, declaration in [('ordinary', ''), ('empty', '[filesystem]\n'),
                    ('read', '[filesystem]\nread=["input.txt"]\n'),
                    ('create', '[filesystem]\ncreate=["result.txt"]\nmax_file_bytes=1024\n')]:
                for mode in ['run', 'test']:
                    marker.unlink(missing_ok=True)
                    manifest = root / 'fixture.clad.toml'
                    manifest.write_text(base + declaration)
                    completed = subprocess.run(runner + [mode, str(manifest)], cwd=root, env=env,
                        capture_output=True, text=True, timeout=8)
                    allowed = mode == 'test' or name == 'ordinary'
                    expected_effect = mode == 'run' and name == 'ordinary'
                    passed = (completed.returncode == 0) == allowed and marker.exists() == expected_effect
                    if expected_effect:
                        passed = passed and marker.read_text() == 'useful result'
                    if not allowed:
                        passed = passed and 'filesystem grants require an embedding runtime' in (completed.stdout + completed.stderr).lower()
                    cases.append(dict(language=language, case=name, mode=mode, passed=passed,
                        exit_code=completed.returncode, effect=marker.exists(), stdout=completed.stdout, stderr=completed.stderr))
    after = source_digest()
    after_hashes = {name: hashlib.sha256(Path(command[0]).read_bytes()).hexdigest() for name, command in runners.items()}
    passed = len(cases) == 32 and all(row['passed'] for row in cases) and before == after and hashes == after_hashes
    report = dict(passed=passed, source_before=before, source_after=after, binaries_before=hashes,
                  binaries_after=after_hashes, planned=32, executed=len(cases), cases=cases)
    Path(args.report).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=passed, cases=len(cases), report=args.report)))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
