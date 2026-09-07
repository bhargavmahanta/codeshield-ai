from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest


def _events(text: str = "A safe answer") -> bytes:
    common = {"sessionID": "ses_test", "messageID": "msg_test"}
    events = [
        {
            "type": "step_start",
            "timestamp": 1,
            "sessionID": "ses_test",
            "part": {**common, "id": "prt_start", "type": "step-start"},
        },
        {
            "type": "text",
            "timestamp": 1,
            "sessionID": "ses_test",
            "part": {
                **common,
                "id": "prt_text",
                "type": "text",
                "text": text,
                "time": {"start": 1, "end": 2},
            },
        },
        {
            "type": "step_finish",
            "timestamp": 1,
            "sessionID": "ses_test",
            "part": {
                **common,
                "id": "prt_finish",
                "type": "step-finish",
                "reason": "stop",
                "cost": 0,
                "tokens": {
                    "input": 1,
                    "output": 2,
                    "reasoning": 0,
                    "cache": {"read": 0, "write": 0},
                },
            },
        },
    ]
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


class RecordingInput(io.BytesIO):
    recorded = b""

    def close(self) -> None:
        self.recorded = self.getvalue()
        super().close()


class FakeProcess:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes = b"",
        returncode: int = 0,
        *,
        timeout: bool = False,
    ) -> None:
        self.stdin = RecordingInput()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.pid = 4242
        self.returncode = None
        self._returncode = returncode
        self._timeout = timeout
        self._waits = 0

    def wait(self, timeout: float | None = None) -> int:
        self._waits += 1
        if self._timeout and self._waits == 1:
            raise subprocess.TimeoutExpired("opencode", timeout)
        self.returncode = self._returncode
        return self._returncode


class InterruptingProcess(FakeProcess):
    def wait(self, timeout: float | None = None) -> int:
        self._waits += 1
        if self._waits == 1:
            raise KeyboardInterrupt
        self.returncode = self._returncode
        return self._returncode


class FakePopen:
    def __init__(self, content: FakeProcess | None = None) -> None:
        self.content = content or FakeProcess(_events())
        self.calls: list[tuple[list[str], dict, FakeProcess]] = []

    def __call__(self, argv, **kwargs):
        command = list(argv)
        if command[-1] == "--version":
            process = FakeProcess(b"1.18.26\n")
        elif command[-1] == "--help":
            process = FakeProcess(
                b"", b"--pure --format --model --agent --title message stdin\n"
            )
        else:
            process = self.content
        self.calls.append((command, kwargs, process))
        return process


def test_interrupt_during_worker_setup_reaps_owned_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner

    process = FakeProcess(b"")
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *args, **kwargs: process)
    killed: list[int] = []
    monkeypatch.setattr(
        runner.os, "killpg", lambda pid, signal: killed.append(pid), raising=False
    )

    def interrupt() -> threading.Event:
        raise KeyboardInterrupt

    monkeypatch.setattr(runner.threading, "Event", interrupt)

    with pytest.raises(KeyboardInterrupt):
        runner._execute(
            ["opencode"],
            b"",
            cwd=Path.cwd(),
            environment={},
            timeout=1,
            stdout_limit=1,
            stderr_limit=1,
        )

    assert killed == [process.pid]
    assert process._waits >= 1
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    popen: FakePopen,
) -> Path:
    import codeshield.opencode.runner as runner

    executable = tmp_path / "opencode"
    executable.write_bytes(b"review-2-compatible-opencode-binary")
    monkeypatch.setenv("CODESHIELD_OPENCODE_EXECUTABLE", str(executable))
    monkeypatch.setenv("CODESHIELD_HOME", str(tmp_path / "codeshield-home"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(runner, "_supported_platform", lambda: True)
    monkeypatch.setattr(runner.subprocess, "Popen", popen)
    return executable


def _approve(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakePopen:
    from codeshield.opencode.runner import doctor

    popen = FakePopen()
    _configure(monkeypatch, tmp_path, popen)
    doctor()
    popen.calls.clear()
    return popen


def test_isolated_runtime_uses_only_fail_closed_configuration(tmp_path: Path) -> None:
    from codeshield.opencode.runner import isolated_runtime

    source = {
        "HOME": str(tmp_path / "home"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
        "OPENAI_API_KEY": "must-not-be-inherited",
        "OPENCODE_SERVER_PASSWORD": "must-not-be-inherited",
        "CODESHIELD_VAULT_KEY": "must-not-be-inherited",
        "UNRELATED": "must-not-be-inherited",
    }

    with isolated_runtime(source) as (cwd, environment):
        config = json.loads(environment["OPENCODE_CONFIG_CONTENT"])

        assert cwd != Path(source["HOME"])
        assert environment["HOME"] == source["HOME"]
        assert environment["XDG_DATA_HOME"] == source["XDG_DATA_HOME"]
        assert environment["XDG_CONFIG_HOME"] == str(cwd / "config")
        assert environment["XDG_CACHE_HOME"] == str(cwd / "cache")
        assert environment["XDG_STATE_HOME"] == str(cwd / "state")
        assert config["permission"] == {"*": "deny"}
        assert config["tools"] == {"*": False}
        assert config["agent"]["codeshield-review2"]["permission"] == {
            "*": "deny"
        }
        assert config["agent"]["codeshield-review2"]["tools"] == {"*": False}
        assert config["share"] == "disabled"
        assert config["autoupdate"] is False
        assert config["mcp"] == {}
        assert config["plugin"] == []
        assert config["instructions"] == []
        assert config["enabled_providers"] == ["openai"]
        assert environment["OPENCODE_DISABLE_PROJECT_CONFIG"] == "true"
        assert environment["OPENCODE_PURE"] == "true"
        assert environment["OPENCODE_DISABLE_EXTERNAL_SKILLS"] == "true"
        assert environment["OPENCODE_DISABLE_CLAUDE_CODE"] == "true"
        assert environment["OPENCODE_DISABLE_CLAUDE_CODE_PROMPT"] == "true"
        assert environment["OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"] == "true"
        assert environment["OPENCODE_DISABLE_AUTOUPDATE"] == "true"
        assert environment["OPENCODE_DISABLE_MODELS_FETCH"] == "true"
        assert "OPENCODE_DISABLE_DEFAULT_PLUGINS" not in environment
        assert not {
            "OPENAI_API_KEY",
            "OPENCODE_SERVER_PASSWORD",
            "CODESHIELD_VAULT_KEY",
            "UNRELATED",
        } & environment.keys()


def test_isolated_runtime_ignores_process_temp_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner

    project = tmp_path / "project"
    poisoned = project / "process-temp"
    trusted = tmp_path / "trusted-os-temp"
    poisoned.mkdir(parents=True)
    trusted.mkdir()
    (project / ".git").mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setenv("TMPDIR", str(poisoned))
    monkeypatch.setenv("TEMP", str(poisoned))
    monkeypatch.setattr(runner.tempfile, "tempdir", str(poisoned))
    monkeypatch.setattr(
        runner, "_trusted_temporary_root", lambda: trusted, raising=False
    )

    with runner.isolated_runtime({"HOME": str(tmp_path / "home")}) as (cwd, _):
        assert cwd.parent == trusted
        assert not cwd.is_relative_to(project)


@pytest.mark.parametrize("marker", ["AGENTS.md", ".opencode"])
def test_isolated_runtime_rejects_instruction_bearing_temp_ancestor(
    marker: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner
    from codeshield.opencode.errors import OpenCodeError

    marked = tmp_path / "marked"
    unsafe = marked / "temp"
    unsafe.mkdir(parents=True)
    target = marked / marker
    target.mkdir() if marker == ".opencode" else target.write_text("untrusted")
    monkeypatch.setattr(runner.tempfile, "tempdir", str(unsafe))
    monkeypatch.setattr(
        runner, "_trusted_temporary_root", lambda: unsafe, raising=False
    )

    with pytest.raises(OpenCodeError, match="^CS_OPENCODE_CONFIGURATION$"):
        with runner.isolated_runtime({"HOME": str(tmp_path / "home")}):
            pass


def test_isolated_runtime_rejects_temp_root_inside_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner
    from codeshield.opencode.errors import OpenCodeError

    project = tmp_path / "project"
    unsafe = project / "temp"
    unsafe.mkdir(parents=True)
    (project / ".git").mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setattr(runner.tempfile, "tempdir", str(unsafe))
    monkeypatch.setattr(
        runner, "_trusted_temporary_root", lambda: unsafe, raising=False
    )

    with pytest.raises(OpenCodeError, match="^CS_OPENCODE_CONFIGURATION$"):
        with runner.isolated_runtime({"HOME": str(tmp_path / "home")}):
            pass


def test_doctor_receipt_allows_one_canonical_stdin_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codeshield.opencode.runner import OpenCodeRunner

    popen = _approve(monkeypatch, tmp_path)

    answer = OpenCodeRunner().run("Explain list indexes briefly.", "openai/gpt-5.4-mini")

    assert answer == "A safe answer"
    assert len(popen.calls) == 1
    argv, options, process = popen.calls[0]
    assert argv == [
        str(tmp_path / "opencode"),
        "--pure",
        "run",
        "--format",
        "json",
        "--model",
        "openai/gpt-5.4-mini",
        "--agent",
        "codeshield-review2",
        "--title",
        "CodeShield-Review2",
    ]
    assert options["shell"] is False
    assert options["start_new_session"] is True
    assert Path(options["cwd"]) != tmp_path
    assert process.stdin.recorded == b"Explain list indexes briefly."


def test_doctor_invokes_only_version_and_run_help_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codeshield.opencode.runner import doctor

    popen = FakePopen()
    executable = _configure(monkeypatch, tmp_path, popen)

    doctor()

    assert [call[0] for call in popen.calls] == [
        [str(executable), "--version"],
        [str(executable), "--pure", "run", "--help"],
    ]
    assert all(call[2].stdin.recorded == b"" for call in popen.calls)


@pytest.mark.parametrize("link_part", ["parent", "target"])
def test_doctor_rejects_link_like_receipt_paths(
    link_part: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner
    from codeshield.opencode.errors import OpenCodeError

    popen = FakePopen()
    executable = _configure(monkeypatch, tmp_path, popen)
    digest = runner._binary_digest(executable)
    destination = runner._receipt_path(runner._compatibility_key(digest))
    destination.parent.mkdir(parents=True)
    if link_part == "target":
        destination.write_text("attacker-controlled")
        simulated_link = destination
    else:
        simulated_link = destination.parent
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == simulated_link or original_is_symlink(path),
    )

    with pytest.raises(OpenCodeError, match="^CS_OPENCODE_CONFIGURATION$"):
        runner.doctor()


def test_run_requires_current_binary_compatibility_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner
    from codeshield.opencode.errors import OpenCodeError

    popen = FakePopen()
    executable = _configure(monkeypatch, tmp_path, popen)
    executable.write_bytes(b"binary-without-a-doctor-receipt")

    with pytest.raises(OpenCodeError, match="^CS_OPENCODE_INCOMPATIBLE$"):
        runner.OpenCodeRunner().run("public prompt", "openai/gpt-5.4-mini")

    assert popen.calls == []


@pytest.mark.parametrize(
    "process",
    [
        FakeProcess(b"x" * 2_000_001),
        FakeProcess(b"", b"x" * 65_537),
    ],
)
def test_run_kills_owned_process_group_while_output_exceeds_limit(
    process: FakeProcess,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner
    from codeshield.opencode.errors import OpenCodeError

    popen = _approve(monkeypatch, tmp_path)
    popen.content = process
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        runner.os,
        "killpg",
        lambda pid, sig: killed.append((pid, sig)),
        raising=False,
    )

    with pytest.raises(OpenCodeError, match="^CS_OPENCODE_OUTPUT_LIMIT$"):
        runner.OpenCodeRunner().run("public prompt", "openai/gpt-5.4-mini")

    assert killed == [(process.pid, runner._KILL_SIGNAL)]


def test_run_timeout_kills_only_owned_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner
    from codeshield.opencode.errors import OpenCodeError

    process = FakeProcess(b"", timeout=True)
    popen = _approve(monkeypatch, tmp_path)
    popen.content = process
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        runner.os,
        "killpg",
        lambda pid, sig: killed.append((pid, sig)),
        raising=False,
    )

    with pytest.raises(OpenCodeError, match="^CS_OPENCODE_TIMEOUT$"):
        runner.OpenCodeRunner().run("public prompt", "openai/gpt-5.4-mini")

    assert killed == [(process.pid, runner._KILL_SIGNAL)]


def test_keyboard_interrupt_reaps_owned_process_group_and_closes_pipes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner

    process = InterruptingProcess(b"")
    popen = _approve(monkeypatch, tmp_path)
    popen.content = process
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        runner.os,
        "killpg",
        lambda pid, sig: killed.append((pid, sig)),
        raising=False,
    )

    with pytest.raises(KeyboardInterrupt):
        runner.OpenCodeRunner().run("public prompt", "openai/gpt-5.4-mini")

    assert killed == [(process.pid, runner._KILL_SIGNAL)]
    assert process._waits == 2
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed


def test_keyboard_interrupt_while_joining_reaps_owned_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import codeshield.opencode.runner as runner

    process = FakeProcess(_events())
    popen = _approve(monkeypatch, tmp_path)
    popen.content = process
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        runner.os,
        "killpg",
        lambda pid, sig: killed.append((pid, sig)),
        raising=False,
    )
    original_join = runner.threading.Thread.join
    interrupts = 0

    def interrupt_once(thread, timeout=None):
        nonlocal interrupts
        if interrupts == 0:
            interrupts += 1
            raise KeyboardInterrupt
        return original_join(thread, timeout)

    monkeypatch.setattr(runner.threading.Thread, "join", interrupt_once)

    with pytest.raises(KeyboardInterrupt):
        runner.OpenCodeRunner().run("public prompt", "openai/gpt-5.4-mini")

    assert killed == [(process.pid, runner._KILL_SIGNAL)]
    assert process.stdin.closed
    assert process.stdout.closed
    assert process.stderr.closed


def test_run_failure_never_exposes_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codeshield.opencode.errors import OpenCodeError
    from codeshield.opencode.runner import OpenCodeRunner

    private_error = "private upstream failure detail"
    popen = _approve(monkeypatch, tmp_path)
    popen.content = FakeProcess(b"", private_error.encode(), returncode=1)

    with pytest.raises(OpenCodeError) as captured:
        OpenCodeRunner().run("public prompt", "openai/gpt-5.4-mini")

    assert str(captured.value) == "CS_OPENCODE_FAILED"
    assert private_error not in str(captured.value)
