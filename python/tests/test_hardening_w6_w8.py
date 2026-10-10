"""Spawn-path hardening (W6: TC-8, TC-18, TC-19, TC-21) and timeouts (W8: TC-11).

Every spawned tool is a local coreutils program (printenv, cat, pwd, echo,
touch, dd, sleep). Nothing here opens a socket.
"""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import toolclad.executor as executor
from toolclad.executor import (
    SAFE_PATH,
    child_env,
    execute,
    inject_template_vars,
    load_secrets_file,
)
from toolclad.manifest import load_manifest

_VECTORS = Path(__file__).resolve().parents[2] / "tests" / "injection_vectors.json"
_ALLOWED = {"PATH", "HOME", "LANG", "LC_ALL", "TZ", "TERM"}
_SCAN_ID_RE = re.compile(r"^[0-9]+-[0-9a-f]{32}$")

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX spawn path")


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    evidence = tmp_path / "evidence"
    monkeypatch.setenv("TOOLCLAD_EVIDENCE_DIR", str(evidence))
    monkeypatch.setenv("TOOLCLAD_KILL_GRACE_MS", "200")
    monkeypatch.delenv("TOOLCLAD_SECRETS_FILE", raising=False)
    monkeypatch.delenv("TOOLCLAD_SCOPE_FILE", raising=False)
    return evidence


def _load(tmp_path: Path, body: str, name: str = "t.clad.toml"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return load_manifest(str(path))


def _manifest(tmp_path: Path, binary: str, exec_: list, extra_tool: str = "", tail: str = ""):
    return _load(
        tmp_path,
        f"""\
        [tool]
        name = "t"
        version = "1.0.0"
        binary = "{binary}"
        description = "x"
        {extra_tool}

        [command]
        exec = {json.dumps(exec_)}

        [output]
        format = "text"
        {tail}
        """,
    )


def _env_names(stdout: str) -> dict:
    out = {}
    for line in stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def _sentinels(monkeypatch):
    monkeypatch.setenv("TOOLCLAD_SECRET_LEAK", "sentinel")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "sentinel2")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/x")


# ---------------------------------------------------------------------------
# F1: environment allowlist
# ---------------------------------------------------------------------------


@posix_only
class TestChildEnvironment:
    def test_oneshot_env_is_allowlisted(self, tmp_path, monkeypatch):
        _sentinels(monkeypatch)
        m = _manifest(tmp_path, "printenv", ["printenv"])
        env = execute(m, {})
        assert env["status"] == "success", env
        raw = env["results"]["raw_output"]
        names = _env_names(raw)
        assert set(names) <= _ALLOWED
        assert names["PATH"] == SAFE_PATH
        for sentinel in ("sentinel", "sentinel2", "/tmp/x"):
            assert sentinel not in raw

    def test_executor_hatch_env(self, tmp_path, monkeypatch):
        _sentinels(monkeypatch)
        m = _load(
            tmp_path,
            """\
            [tool]
            name = "t"
            version = "1.0.0"
            description = "x"

            [args.msg]
            position = 1
            required = true
            type = "string"
            description = "m"

            [command]
            executor = "printenv"

            [output]
            format = "text"
            """,
        )
        env = execute(m, {"msg": "hello"})
        assert env["status"] == "success", env
        raw = env["results"]["raw_output"]
        names = _env_names(raw)
        assert names["TOOLCLAD_ARG_MSG"] == "hello"
        assert names["PATH"] == SAFE_PATH
        assert names["TOOLCLAD_SCAN_ID"] == env["scan_id"]
        assert names["TOOLCLAD_TOOL_NAME"] == "t"
        assert names["TOOLCLAD_EVIDENCE_DIR"] == os.environ["TOOLCLAD_EVIDENCE_DIR"]
        assert names["TOOLCLAD_OUTPUT_DIR"].startswith(names["TOOLCLAD_EVIDENCE_DIR"])
        hatch = {
            "TOOLCLAD_ARG_MSG", "TOOLCLAD_SCAN_ID", "TOOLCLAD_TOOL_NAME",
            "TOOLCLAD_EVIDENCE_DIR", "TOOLCLAD_OUTPUT_DIR",
        }
        assert set(names) <= _ALLOWED | hatch
        assert not any(k.startswith("TOOLCLAD_SECRET") for k in names)
        for sentinel in ("sentinel", "sentinel2", "/tmp/x"):
            assert sentinel not in raw

    def test_secret_filter_survives_allowlist_edits(self, monkeypatch):
        # Even a secret name handed in as an extra variable never reaches a child.
        monkeypatch.setenv("TOOLCLAD_SECRET_X", "s")
        env = child_env({"TOOLCLAD_SECRET_Y": "s", "TOOLCLAD_SECRETS_FILE": "/f", "TOOLCLAD_ARG_A": "1"})
        assert env["TOOLCLAD_ARG_A"] == "1"
        assert not any(k.startswith("TOOLCLAD_SECRET") for k in env)

    def test_passthrough_only_when_set(self, monkeypatch):
        monkeypatch.delenv("TZ", raising=False)
        monkeypatch.setenv("LANG", "C.UTF-8")
        env = child_env()
        assert "TZ" not in env
        assert env["LANG"] == "C.UTF-8"


# ---------------------------------------------------------------------------
# F2: secrets file
# ---------------------------------------------------------------------------


class TestSecretsFile:
    def _write(self, tmp_path, mode, body='api_key = "from-file"\n'):
        path = tmp_path / "secrets.toml"
        path.write_text(body)
        os.chmod(path, mode)
        return path

    def test_file_value_used(self, tmp_path, monkeypatch):
        path = self._write(tmp_path, 0o600)
        monkeypatch.setenv("TOOLCLAD_SECRETS_FILE", str(path))
        assert inject_template_vars("Bearer {_secret:api_key}") == "Bearer from-file"

    def test_file_wins_over_env(self, tmp_path, monkeypatch):
        path = self._write(tmp_path, 0o600)
        monkeypatch.setenv("TOOLCLAD_SECRETS_FILE", str(path))
        monkeypatch.setenv("TOOLCLAD_SECRET_API_KEY", "from-env")
        assert inject_template_vars("{_secret:api_key}") == "from-file"

    def test_env_used_when_not_in_file(self, tmp_path, monkeypatch):
        path = self._write(tmp_path, 0o600)
        monkeypatch.setenv("TOOLCLAD_SECRETS_FILE", str(path))
        monkeypatch.setenv("TOOLCLAD_SECRET_OTHER", "from-env")
        assert inject_template_vars("{_secret:other}") == "from-env"

    @posix_only
    def test_group_readable_file_refused(self, tmp_path, monkeypatch):
        path = self._write(tmp_path, 0o644)
        monkeypatch.setenv("TOOLCLAD_SECRETS_FILE", str(path))
        with pytest.raises(RuntimeError, match=r"readable by group or others \(mode 0644\); chmod 600 it"):
            load_secrets_file()

    def test_missing_secret_is_error(self, tmp_path, monkeypatch):
        path = self._write(tmp_path, 0o600)
        monkeypatch.setenv("TOOLCLAD_SECRETS_FILE", str(path))
        monkeypatch.delenv("TOOLCLAD_SECRET_NOPE", raising=False)
        with pytest.raises(RuntimeError, match="Secret 'nope' not found"):
            inject_template_vars("{_secret:nope}")

    def test_file_read_once_per_call(self, tmp_path, monkeypatch):
        path = self._write(tmp_path, 0o600)
        monkeypatch.setenv("TOOLCLAD_SECRETS_FILE", str(path))
        calls = []
        real = executor.load_secrets_file

        def counting():
            calls.append(1)
            return real()

        monkeypatch.setattr(executor, "load_secrets_file", counting)
        m = _load(
            tmp_path,
            """\
            [tool]
            name = "h"
            version = "1.0.0"
            description = "x"

            [http]
            method = "POST"
            url = "https://api.example.com/{_secret:api_key}"
            headers = { Authorization = "Bearer {_secret:api_key}", X-Key = "{_secret:api_key}" }
            body_template = '{"k": "{_secret:api_key}"}'

            [output]
            format = "json"
            """,
        )
        env = execute(m, {}, dry_run=True)
        assert env["status"] == "dry_run"
        assert env["command"] == "POST https://api.example.com/from-file"
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# F3: argv[0] resolution and the interpreter denylist
# ---------------------------------------------------------------------------


@posix_only
class TestArgv0:
    def test_bare_echo_runs(self, tmp_path):
        m = _manifest(tmp_path, "echo", ["echo", "hi"])
        env = execute(m, {})
        assert env["status"] == "success", env
        assert env["results"]["raw_output"] == "hi\n"

    def test_basename_mismatch_rejected(self, tmp_path):
        with pytest.raises(ValueError, match=r"command argv\[0\] 'cat' does not match tool.binary 'echo'"):
            _manifest(tmp_path, "echo", ["cat", "/etc/hostname"])

    def test_full_path_matches_basename(self, tmp_path):
        m = _manifest(tmp_path, "echo", ["/bin/echo", "hi"])
        assert m.command.exec[0] == "/bin/echo"

    def test_interpreter_rejected_without_opt_in(self, tmp_path):
        with pytest.raises(
            ValueError,
            match=r"command argv\[0\] 'bash' is an interpreter; set allow_interpreter = true to permit it",
        ):
            _manifest(tmp_path, "bash", ["bash", "--version"])

    def test_interpreter_loads_with_opt_in(self, tmp_path):
        m = _manifest(tmp_path, "bash", ["bash", "--version"], extra_tool="allow_interpreter = true")
        assert m.tool.allow_interpreter is True

    def test_empty_binary_skips_basename_check(self, tmp_path):
        m = _manifest(tmp_path, "", ["echo", "hi"])
        assert m.command.exec[0] == "echo"

    def test_unresolvable_binary_is_execution_error(self, tmp_path):
        name = "toolclad-no-such-binary"
        m = _manifest(tmp_path, name, [name])
        env = execute(m, {})
        assert env["status"] == "error"
        assert name in env["results"]["error"]
        assert SAFE_PATH in env["results"]["error"]

    def test_vectors_from_shared_file(self, tmp_path):
        vectors = {v["id"]: v for v in json.loads(_VECTORS.read_text())["manifest_vectors"]}
        for vid in ("shell-as-binary", "binary-basename-mismatch", "zero-timeout"):
            assert vectors[vid]["expect"] == "reject"
            with pytest.raises(ValueError):
                _load(tmp_path, vectors[vid]["manifest"], name=f"{vid}.clad.toml")
        for vid in ("minimal-valid-exec", "minimal-valid-template"):
            assert vectors[vid]["expect"] == "accept"
            with pytest.warns(DeprecationWarning) if "template" in vid else _nullcontext():
                _load(tmp_path, vectors[vid]["manifest"], name=f"{vid}.clad.toml")


class _nullcontext:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# F4: stdin, cwd, umask, rlimits
# ---------------------------------------------------------------------------


@posix_only
class TestSpawnSettings:
    def test_stdin_is_dev_null(self, tmp_path):
        m = _manifest(tmp_path, "cat", ["cat"], extra_tool="timeout_seconds = 5")
        start = time.monotonic()
        env = execute(m, {})
        assert time.monotonic() - start < 3
        assert env["status"] == "success", env
        assert env["results"]["raw_output"] == ""

    def test_cwd_is_private_scratch_dir(self, tmp_path, monkeypatch, _isolated_env):
        kept = []
        monkeypatch.setattr(executor, "_remove_if_empty", lambda p: kept.append(p))
        m = _manifest(tmp_path, "pwd", ["pwd"])
        env = execute(m, {})
        assert env["status"] == "success", env
        work = env["results"]["raw_output"].strip()
        assert work == os.path.join(str(_isolated_env), f"{env['scan_id']}-work")
        assert kept == [work]
        assert stat.S_IMODE(os.stat(work).st_mode) == 0o700

    def test_empty_scratch_dir_removed(self, tmp_path):
        m = _manifest(tmp_path, "pwd", ["pwd"])
        env = execute(m, {})
        assert not os.path.exists(env["results"]["raw_output"].strip())

    def test_scratch_dir_kept_when_tool_writes(self, tmp_path):
        m = _manifest(tmp_path, "touch", ["touch", "left-behind"])
        env = execute(m, {})
        assert env["status"] == "success", env
        work = os.path.join(os.environ["TOOLCLAD_EVIDENCE_DIR"], f"{env['scan_id']}-work")
        created = os.path.join(work, "left-behind")
        assert os.path.isfile(created)
        # umask 0077 in the child: the file is private.
        assert stat.S_IMODE(os.stat(created).st_mode) == 0o600

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/self/limits")
    def test_default_rlimits_applied(self, tmp_path):
        m = _manifest(tmp_path, "cat", ["cat", "/proc/self/limits"])
        env = execute(m, {})
        assert env["status"] == "success", env
        limits = env["results"]["raw_output"]
        assert re.search(r"Max core file size\s+0\s+0\s", limits)
        assert re.search(r"Max file size\s+1073741824\s+1073741824\s", limits)
        assert re.search(r"Max open files\s+1024\s+1024\s", limits)
        # NPROC is opt-in: it is counted per user, not per tool tree.
        assert not re.search(r"Max processes\s+512\s", limits)

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/self/limits")
    def test_declared_rlimits_override(self, tmp_path):
        m = _manifest(
            tmp_path, "cat", ["cat", "/proc/self/limits"],
            tail="\n[tool.limits]\nnofile = 64\ncpu_seconds = 30\nnproc = 1000000\n",
        )
        assert (m.tool.limits.nofile, m.tool.limits.cpu_seconds) == (64, 30)
        env = execute(m, {})
        limits = env["results"]["raw_output"]
        assert re.search(r"Max open files\s+64\s+64\s", limits)
        assert re.search(r"Max cpu time\s+30\s+30\s", limits)
        assert re.search(r"Max processes\s+\d+\s", limits)

    def test_fsize_limit_enforced(self, tmp_path):
        m = _load(
            tmp_path,
            """\
            [tool]
            name = "t"
            version = "1.0.0"
            binary = "dd"
            description = "x"

            [tool.limits]
            fsize_bytes = 1000

            [command]
            exec = ["dd", "if=/dev/zero", "of=big", "bs=5000", "count=1"]

            [output]
            format = "text"
            """,
        )
        assert m.tool.limits.fsize_bytes == 1000
        env = execute(m, {})
        assert env["status"] == "error", env
        work = os.path.join(os.environ["TOOLCLAD_EVIDENCE_DIR"], f"{env['scan_id']}-work")
        assert os.path.getsize(os.path.join(work, "big")) <= 1000


# ---------------------------------------------------------------------------
# F5: evidence paths
# ---------------------------------------------------------------------------


@posix_only
class TestEvidencePaths:
    def test_output_file_matches_table(self, tmp_path, _isolated_env):
        m = _manifest(tmp_path, "echo", ["echo", "{_output_file}", "{_scan_id}", "{_evidence_dir}"])
        env = execute(m, {})
        assert env["status"] == "success", env
        expected = os.path.join(str(_isolated_env), f"{env['scan_id']}-t", "scan.txt")
        assert env["output_file"] == expected
        assert env["results"]["raw_output"].split() == [expected, env["scan_id"], str(_isolated_env)]
        assert stat.S_IMODE(os.stat(os.path.dirname(expected)).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(str(_isolated_env)).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(expected).st_mode) == 0o600

    def test_output_dir_exists_before_spawn(self, tmp_path):
        # The tool writes {_output_file} itself; that works only if the
        # directory was created before the spawn. Its file is kept.
        m = _manifest(tmp_path, "touch", ["touch", "{_output_file}"])
        env = execute(m, {})
        assert env["status"] == "success", env
        assert os.path.isfile(env["output_file"])
        assert stat.S_IMODE(os.stat(env["output_file"]).st_mode) == 0o600

    def test_output_dir_honored(self, tmp_path, _isolated_env):
        m = _manifest(
            tmp_path, "echo", ["echo", "{_output_file}"],
            extra_tool='\n[tool.evidence]\noutput_dir = "{evidence_dir}/custom-{scan_id}"\n',
        )
        env = execute(m, {})
        expected = os.path.join(str(_isolated_env), f"custom-{env['scan_id']}", "scan.txt")
        assert env["output_file"] == expected
        assert env["results"]["raw_output"].strip() == expected

    def test_extension_from_format(self, tmp_path):
        m = _manifest(tmp_path, "echo", ["echo", "x"])
        m.output.format = "json"
        env = execute(m, {})
        assert env["output_file"].endswith("/scan.json")

    def test_scan_ids_unique_and_random(self, tmp_path):
        m = _manifest(tmp_path, "echo", ["echo", "x"])
        a = execute(m, {}, dry_run=True)["scan_id"]
        b = execute(m, {}, dry_run=True)["scan_id"]
        assert a != b
        assert _SCAN_ID_RE.match(a) and _SCAN_ID_RE.match(b)

    def test_preplanted_symlink_refused(self, tmp_path, _isolated_env):
        target = tmp_path / "victim"
        target.write_text("untouched")
        fixed = _isolated_env / "fixed"
        fixed.mkdir(parents=True)
        os.symlink(str(target), str(fixed / "scan.txt"))
        m = _manifest(
            tmp_path, "echo", ["echo", "overwrite"],
            extra_tool='\n[tool.evidence]\noutput_dir = "{evidence_dir}/fixed"\n',
        )
        env = execute(m, {})
        assert env["status"] == "error"
        assert target.read_text() == "untouched"

    def test_private_write_refuses_symlink(self, tmp_path):
        target = tmp_path / "victim"
        target.write_text("untouched")
        link = tmp_path / "link"
        os.symlink(str(target), str(link))
        with pytest.raises(OSError):
            executor._write_private_file(str(link), "x")
        assert target.read_text() == "untouched"


# ---------------------------------------------------------------------------
# W8: timeouts
# ---------------------------------------------------------------------------


@posix_only
class TestTimeouts:
    def _record_popen(self, monkeypatch):
        procs = []
        real = subprocess.Popen

        class Recording(real):  # type: ignore[misc, valid-type]
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                procs.append(self)

        monkeypatch.setattr(executor.subprocess, "Popen", Recording)
        return procs

    def test_sleep_times_out_and_group_is_gone(self, tmp_path, monkeypatch):
        procs = self._record_popen(monkeypatch)
        m = _manifest(tmp_path, "sleep", ["sleep", "10"], extra_tool="timeout_seconds = 1")
        start = time.monotonic()
        env = execute(m, {})
        assert time.monotonic() - start < 5
        assert env["status"] == "timeout"
        assert env["exit_code"] == -1
        assert len(procs) == 1
        pid = procs[0].pid
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        with pytest.raises(ProcessLookupError):
            os.killpg(pid, 0)

    def test_partial_output_kept(self, tmp_path):
        # cat prints the file, then blocks opening a FIFO that has no writer:
        # output before a hang, without a shell or threads.
        log = tmp_path / "log.txt"
        log.write_text("partial-line\n")
        fifo = tmp_path / "never-written"
        os.mkfifo(str(fifo))
        m = _manifest(tmp_path, "cat", ["cat", str(log), str(fifo)], extra_tool="timeout_seconds = 1")
        env = execute(m, {})
        assert env["status"] == "timeout"
        assert env["exit_code"] == -1
        assert "partial-line" in env["results"]["raw_output"]

    def test_zero_timeout_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError, match="timeout_seconds must be greater than zero"):
            _manifest(tmp_path, "echo", ["echo", "x"], extra_tool="timeout_seconds = 0")

    def test_negative_timeout_refused_at_load(self, tmp_path):
        with pytest.raises(ValueError, match="timeout_seconds must be greater than zero"):
            _manifest(tmp_path, "echo", ["echo", "x"], extra_tool="timeout_seconds = -5")

    @pytest.mark.parametrize(
        "raw,expected",
        [(None, 2.0), ("200", 0.2), ("0", 0.0), ("-5", 2.0), ("abc", 2.0), ("", 2.0)],
    )
    def test_kill_grace_parsing(self, monkeypatch, raw, expected):
        if raw is None:
            monkeypatch.delenv("TOOLCLAD_KILL_GRACE_MS", raising=False)
        else:
            monkeypatch.setenv("TOOLCLAD_KILL_GRACE_MS", raw)
        assert executor._kill_grace_seconds() == expected

    def test_sigterm_sent_before_sigkill(self, tmp_path, monkeypatch):
        sent = []
        real = os.killpg

        def spy(pgid, sig):
            sent.append(sig)
            return real(pgid, sig)

        monkeypatch.setattr(executor.os, "killpg", spy)
        m = _manifest(tmp_path, "sleep", ["sleep", "10"], extra_tool="timeout_seconds = 1")
        env = execute(m, {})
        assert env["status"] == "timeout"
        assert sent[0] == signal.SIGTERM
        assert signal.SIGKILL in sent


def test_executor_hatch_interpreter_refused(tmp_path):
    from toolclad.manifest import load_manifest

    p = tmp_path / "hatch.clad.toml"
    body = (
        '[tool]\nname = "t"\nversion = "1.0.0"\nbinary = "wrapper"\ndescription = "x"\n\n'
        '[command]\nexecutor = "{exe}"\n\n[output]\nformat = "text"\n'
    )
    p.write_text(body.replace("{exe}", "/bin/sh"))
    with pytest.raises(ValueError, match="'/bin/sh' is an interpreter"):
        load_manifest(str(p))
    p.write_text(body.replace("{exe}", "scripts/wrapper.sh"))
    load_manifest(str(p))
