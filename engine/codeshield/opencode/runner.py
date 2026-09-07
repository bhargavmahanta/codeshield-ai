"""Bounded, isolated OpenCode 1.18.26 process adapter."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .errors import OpenCodeError
from .protocol import parse_response


OPENCODE_VERSION = "1.18.26"
_AGENT = "codeshield-review2"
_TITLE = "CodeShield-Review2"
_MAX_INPUT = 1_000_000
_MAX_STDOUT = 2_000_000
_MAX_STDERR = 65_536
_RUN_TIMEOUT = 120.0
_METADATA_TIMEOUT = 10.0
_RECEIPT_SCHEMA = 1
_KILL_SIGNAL = getattr(signal, "SIGKILL", 9)
_MODEL = re.compile(r"openai/[A-Za-z0-9][A-Za-z0-9._-]{0,100}")
_PASSTHROUGH_ENV = (
    "HOME",
    "XDG_DATA_HOME",
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
_ISOLATION_FLAGS = {
    "OPENCODE_DISABLE_PROJECT_CONFIG": "true",
    "OPENCODE_PURE": "true",
    "OPENCODE_DISABLE_EXTERNAL_SKILLS": "true",
    "OPENCODE_DISABLE_CLAUDE_CODE": "true",
    "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT": "true",
    "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS": "true",
    "OPENCODE_DISABLE_AUTOUPDATE": "true",
    "OPENCODE_DISABLE_MODELS_FETCH": "true",
}
_INLINE_CONFIG = {
    "agent": {
        _AGENT: {
            "description": "CodeShield Review 2 no-tool agent",
            "mode": "primary",
            "permission": {"*": "deny"},
            "tools": {"*": False},
        }
    },
    "autoupdate": False,
    "enabled_providers": ["openai"],
    "instructions": [],
    "mcp": {},
    "permission": {"*": "deny"},
    "plugin": [],
    "share": "disabled",
    "tools": {"*": False},
}
_REQUIRED_HELP_FLAGS = ("--pure", "--format", "--model", "--agent", "--title")


def _supported_platform() -> bool:
    return sys.platform.startswith("linux")


def _trusted_temporary_root() -> Path:
    if sys.platform.startswith("linux"):
        return Path("/tmp")
    return Path(tempfile.gettempdir())


def _path_is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _repository_root(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        try:
            if (candidate / ".git").exists():
                return candidate
        except OSError:
            raise OpenCodeError("CS_OPENCODE_CONFIGURATION") from None
    return None


def _validated_temporary_root() -> Path:
    try:
        root = _trusted_temporary_root()
        if not root.is_absolute() or ".." in root.parts:
            raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
        root = root.resolve(strict=True)
        if not root.is_dir() or _path_is_link_like(root):
            raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
        current = Path.cwd().resolve(strict=True)
        repository = _repository_root(current)
        if root == current or current in root.parents:
            raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
        if repository is not None and (root == repository or repository in root.parents):
            raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
        for ancestor in (root, *root.parents):
            if _path_is_link_like(ancestor):
                raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
            if (ancestor / "AGENTS.md").exists() or (ancestor / ".opencode").exists():
                raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
    except OpenCodeError:
        raise
    except (OSError, RuntimeError):
        raise OpenCodeError("CS_OPENCODE_CONFIGURATION") from None
    return root


@contextmanager
def isolated_runtime(environment: Mapping[str, str]) -> Iterator[tuple[Path, dict[str, str]]]:
    """Yield an empty working directory and a credential-free environment."""

    home = environment.get("HOME")
    if not home:
        raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
    data_home = environment.get("XDG_DATA_HOME") or str(Path(home) / ".local" / "share")
    temporary_root = _validated_temporary_root()
    with tempfile.TemporaryDirectory(
        prefix="codeshield-opencode-", dir=temporary_root
    ) as temporary:
        cwd = Path(temporary).resolve(strict=True)
        if cwd.parent != temporary_root:
            raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
        config = cwd / "config"
        cache = cwd / "cache"
        state = cwd / "state"
        process_temp = cwd / "tmp"
        for directory in (config, cache, state, process_temp):
            directory.mkdir()
        clean = {
            key: value
            for key in _PASSTHROUGH_ENV
            if (value := environment.get(key)) is not None
        }
        clean.update(
            {
                "HOME": home,
                "XDG_DATA_HOME": data_home,
                "XDG_CONFIG_HOME": str(config),
                "XDG_CACHE_HOME": str(cache),
                "XDG_STATE_HOME": str(state),
                "TMPDIR": str(process_temp),
                "OPENCODE_CONFIG_CONTENT": json.dumps(
                    _INLINE_CONFIG, separators=(",", ":"), sort_keys=True
                ),
                **_ISOLATION_FLAGS,
            }
        )
        yield cwd, clean


def _resolve_executable() -> Path:
    configured = os.environ.get("CODESHIELD_OPENCODE_EXECUTABLE")
    selected = configured or shutil.which("opencode")
    if not selected:
        raise OpenCodeError("CS_OPENCODE_MISSING")
    path = Path(selected)
    if not path.is_absolute():
        raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
    try:
        if not path.is_file():
            raise OpenCodeError("CS_OPENCODE_MISSING")
    except OSError:
        raise OpenCodeError("CS_OPENCODE_MISSING") from None
    return path


def _binary_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as binary:
            while chunk := binary.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        raise OpenCodeError("CS_OPENCODE_MISSING") from None
    return digest.hexdigest()


def _compatibility_key(binary_digest: str) -> str:
    value = f"{binary_digest}\0{OPENCODE_VERSION}".encode("ascii")
    return hashlib.sha256(value).hexdigest()


def _receipt_path(key: str) -> Path:
    configured = os.environ.get("CODESHIELD_HOME")
    root = Path(configured) if configured else Path.home() / ".codeshield"
    if not root.is_absolute():
        raise OpenCodeError("CS_OPENCODE_CONFIGURATION")
    return root / "compatibility" / f"opencode-{key}.json"


def _validate_receipt_location(path: Path, error_code: str) -> None:
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise OpenCodeError(error_code)
        for parent in (path.parent, *path.parent.parents):
            if _path_is_link_like(parent):
                raise OpenCodeError(error_code)
            if parent.exists() and not parent.is_dir():
                raise OpenCodeError(error_code)
        if _path_is_link_like(path):
            raise OpenCodeError(error_code)
        if path.exists() and not path.is_file():
            raise OpenCodeError(error_code)
    except OpenCodeError:
        raise
    except (OSError, RuntimeError):
        raise OpenCodeError(error_code) from None


def _receipt(binary_digest: str) -> dict[str, Any]:
    return {
        "binary_sha256": binary_digest,
        "compatibility_key": _compatibility_key(binary_digest),
        "opencode_version": OPENCODE_VERSION,
        "required_help_flags": list(_REQUIRED_HELP_FLAGS),
        "schema_version": _RECEIPT_SCHEMA,
        "source_tag": "v1.18.26",
    }


def _write_receipt(binary_digest: str) -> None:
    record = _receipt(binary_digest)
    destination = _receipt_path(record["compatibility_key"])
    try:
        _validate_receipt_location(destination, "CS_OPENCODE_CONFIGURATION")
        destination.parent.mkdir(parents=True, exist_ok=True)
        _validate_receipt_location(destination, "CS_OPENCODE_CONFIGURATION")
        handle, temporary = tempfile.mkstemp(
            prefix=".opencode-", suffix=".tmp", dir=destination.parent
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as output:
                json.dump(record, output, indent=2, sort_keys=True)
                output.write("\n")
            os.chmod(temporary, 0o600)
            _validate_receipt_location(destination, "CS_OPENCODE_CONFIGURATION")
            os.replace(temporary, destination)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except OSError:
        raise OpenCodeError("CS_OPENCODE_CONFIGURATION") from None


def _verify_receipt(binary_digest: str) -> None:
    expected = _receipt(binary_digest)
    path = _receipt_path(expected["compatibility_key"])
    try:
        _validate_receipt_location(path, "CS_OPENCODE_INCOMPATIBLE")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
                raise ValueError
            content = source.read(4097)
        if len(content) > 4096:
            raise ValueError
        actual = json.loads(content.decode("utf-8", errors="strict"))
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        raise OpenCodeError("CS_OPENCODE_INCOMPATIBLE") from None
    if actual != expected:
        raise OpenCodeError("CS_OPENCODE_INCOMPATIBLE")


class _ProcessGroup:
    def __init__(self, process: Any) -> None:
        self.process = process
        self._lock = threading.Lock()
        self._killed = False

    def kill(self) -> None:
        with self._lock:
            if self._killed:
                return
            self._killed = True
            try:
                os.killpg(self.process.pid, _KILL_SIGNAL)
            except (OSError, ProcessLookupError):
                pass


def _consume(
    stream: Any,
    limit: int,
    output: bytearray,
    exceeded: threading.Event,
    group: _ProcessGroup,
    failed: threading.Event,
) -> None:
    try:
        while True:
            remaining = limit - len(output)
            chunk = stream.read(min(65_536, remaining + 1))
            if not chunk:
                return
            if len(chunk) > remaining:
                exceeded.set()
                group.kill()
                return
            output.extend(chunk)
    except (OSError, ValueError):
        failed.set()
        group.kill()


def _send_input(
    stream: Any,
    payload: bytes,
    failed: threading.Event,
    group: _ProcessGroup,
) -> None:
    try:
        stream.write(payload)
        stream.flush()
    except (OSError, ValueError):
        failed.set()
        group.kill()
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            failed.set()


def _close_pipe_safely(stream: Any) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except BaseException:
        pass


def _join_threads(
    threads: list[threading.Thread], *, suppress_exceptions: bool = False
) -> None:
    for thread in threads:
        try:
            thread.join(timeout=1)
        except BaseException:
            if not suppress_exceptions:
                raise


def _close_stopped_pipes(
    bindings: list[tuple[threading.Thread, Any]],
) -> None:
    for thread, stream in bindings:
        if not thread.is_alive():
            _close_pipe_safely(stream)


def _cleanup_process(
    process: Any,
    group: _ProcessGroup,
    threads: list[threading.Thread],
    bindings: list[tuple[threading.Thread, Any]],
) -> None:
    group.kill()
    try:
        process.wait(timeout=5)
    except BaseException:
        pass
    _join_threads(threads, suppress_exceptions=True)
    _close_stopped_pipes(bindings)


def _execute(
    argv: list[str],
    payload: bytes,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
) -> tuple[bytes, bytes]:
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=dict(environment),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except FileNotFoundError:
        raise OpenCodeError("CS_OPENCODE_MISSING") from None
    except OSError:
        raise OpenCodeError("CS_OPENCODE_FAILED") from None
    group = _ProcessGroup(process)
    started: list[threading.Thread] = []
    bindings: list[tuple[threading.Thread, Any]] = []
    streams = (process.stdin, process.stdout, process.stderr)
    try:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise OpenCodeError("CS_OPENCODE_FAILED")
        exceeded = threading.Event()
        failed = threading.Event()
        stdout = bytearray()
        stderr = bytearray()
        threads = [
            threading.Thread(
                target=_consume,
                args=(process.stdout, stdout_limit, stdout, exceeded, group, failed),
                daemon=True,
            ),
            threading.Thread(
                target=_consume,
                args=(process.stderr, stderr_limit, stderr, exceeded, group, failed),
                daemon=True,
            ),
            threading.Thread(
                target=_send_input,
                args=(process.stdin, payload, failed, group),
                daemon=True,
            ),
        ]
        bindings = [
            (threads[0], process.stdout),
            (threads[1], process.stderr),
            (threads[2], process.stdin),
        ]
        for thread in threads:
            thread.start()
            started.append(thread)
        returncode = process.wait(timeout=timeout)
        _join_threads(started)
    except subprocess.TimeoutExpired:
        _cleanup_process(process, group, started, bindings)
        if not bindings:
            for stream in streams:
                _close_pipe_safely(stream)
        raise OpenCodeError("CS_OPENCODE_TIMEOUT") from None
    except BaseException:
        _cleanup_process(process, group, started, bindings)
        if not bindings:
            for stream in streams:
                _close_pipe_safely(stream)
        raise
    if exceeded.is_set():
        _cleanup_process(process, group, started, bindings)
        raise OpenCodeError("CS_OPENCODE_OUTPUT_LIMIT")
    if any(thread.is_alive() for thread in threads) or failed.is_set():
        _cleanup_process(process, group, started, bindings)
        raise OpenCodeError("CS_OPENCODE_FAILED")
    _close_stopped_pipes(bindings)
    if returncode != 0:
        raise OpenCodeError("CS_OPENCODE_FAILED")
    return bytes(stdout), bytes(stderr)


def _ensure_supported() -> None:
    if not _supported_platform():
        raise OpenCodeError("CS_OPENCODE_INCOMPATIBLE")


class OpenCodeRunner:
    """Run one authorized prompt using a previously verified OpenCode binary."""

    def run(self, text: str, model: str) -> str:
        _ensure_supported()
        if not isinstance(text, str) or not text.strip() or "\x00" in text:
            raise OpenCodeError("CS_OPENCODE_INVALID_INPUT")
        if not isinstance(model, str) or _MODEL.fullmatch(model) is None:
            raise OpenCodeError("CS_OPENCODE_INVALID_INPUT")
        try:
            payload = text.encode("utf-8")
        except UnicodeError:
            raise OpenCodeError("CS_OPENCODE_INVALID_INPUT") from None
        if len(payload) > _MAX_INPUT:
            raise OpenCodeError("CS_OPENCODE_INVALID_INPUT")

        executable = _resolve_executable()
        _verify_receipt(_binary_digest(executable))
        argv = [
            str(executable),
            "--pure",
            "run",
            "--format",
            "json",
            "--model",
            model,
            "--agent",
            _AGENT,
            "--title",
            _TITLE,
        ]
        with isolated_runtime(os.environ) as (cwd, environment):
            response, _ = _execute(
                argv,
                payload,
                cwd=cwd,
                environment=environment,
                timeout=_RUN_TIMEOUT,
                stdout_limit=_MAX_STDOUT,
                stderr_limit=_MAX_STDERR,
            )
        return parse_response(response)


def doctor() -> str:
    """Verify only binary version/help metadata and persist compatibility."""

    _ensure_supported()
    executable = _resolve_executable()
    before = _binary_digest(executable)
    with isolated_runtime(os.environ) as (cwd, environment):
        version_output, _ = _execute(
            [str(executable), "--version"],
            b"",
            cwd=cwd,
            environment=environment,
            timeout=_METADATA_TIMEOUT,
            stdout_limit=_MAX_STDERR,
            stderr_limit=_MAX_STDERR,
        )
        help_output, help_error = _execute(
            [str(executable), "--pure", "run", "--help"],
            b"",
            cwd=cwd,
            environment=environment,
            timeout=_METADATA_TIMEOUT,
            stdout_limit=_MAX_STDERR,
            stderr_limit=_MAX_STDERR,
        )
    try:
        version = version_output.decode("utf-8", errors="strict").strip()
        help_text = (help_output + b"\n" + help_error).decode(
            "utf-8", errors="strict"
        )
    except UnicodeError:
        raise OpenCodeError("CS_OPENCODE_INCOMPATIBLE") from None
    if version != OPENCODE_VERSION or not all(
        flag in help_text for flag in _REQUIRED_HELP_FLAGS
    ):
        raise OpenCodeError("CS_OPENCODE_INCOMPATIBLE")
    after = _binary_digest(executable)
    if before != after:
        raise OpenCodeError("CS_OPENCODE_INCOMPATIBLE")
    _write_receipt(after)
    return _compatibility_key(after)
