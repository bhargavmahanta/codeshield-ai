"""Offline integration against real OS pipes; never contacts a provider."""

import os
import sys

import pytest

from codeshield.opencode.protocol import parse_response
from codeshield.opencode.runner import _execute, isolated_runtime
from codeshield.opencode.errors import OpenCodeError


@pytest.mark.skipif(sys.platform != "linux", reason="Real process adapter targets the WSL/Linux demo")
def test_real_offline_stub_receives_stdin_and_returns_complete_protocol():
    # This is executable stub code, not prompt content. The prompt only goes
    # into _execute's stdin payload, never into the argv program below.
    program = """
import sys,json
assert len(sys.stdin.buffer.read()) == 30
common={'sessionID':'ses_stub','messageID':'msg_stub'}
for kind,part in [
 ('step_start',{'id':'p1','type':'step-start'}),
 ('text',{'id':'p2','type':'text','text':'A safe answer','time':{'start':1,'end':2}}),
 ('step_finish',{'id':'p3','type':'step-finish','reason':'stop','cost':0,'tokens':{'input':1,'output':2,'reasoning':0,'cache':{'read':0,'write':0}}})
]:
 print(json.dumps({'type':kind,'timestamp':1,'sessionID':'ses_stub','part':{**common,**part}}))
"""
    payload = b"Review2 safe stdin-only input."
    argv = [sys.executable, "-c", program]
    assert payload.decode() not in str(argv)
    with isolated_runtime(os.environ) as (cwd, environment):
        assert payload.decode() not in str(environment)
        output, error = _execute(argv, payload, cwd=cwd, environment=environment,
                                 timeout=5, stdout_limit=2_000_000, stderr_limit=65_536)
    assert error == b""
    assert parse_response(output) == "A safe answer"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process-group integration")
@pytest.mark.parametrize("channel", ["stdout", "stderr"])
def test_real_offline_output_overflow_is_bounded(channel):
    program = f"import sys\nwhile True:\n sys.{channel}.buffer.write(b'x'*4096)\n sys.{channel}.flush()"
    with isolated_runtime(os.environ) as (cwd, environment):
        with pytest.raises(OpenCodeError, match="^CS_OPENCODE_OUTPUT_LIMIT$"):
            _execute([sys.executable, "-c", program], b"", cwd=cwd, environment=environment,
                     timeout=5, stdout_limit=1024, stderr_limit=1024)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process-group integration")
def test_real_offline_timeout_is_sanitized():
    with isolated_runtime(os.environ) as (cwd, environment):
        with pytest.raises(OpenCodeError, match="^CS_OPENCODE_TIMEOUT$"):
            _execute([sys.executable, "-c", "import time; time.sleep(10)"], b"", cwd=cwd,
                     environment=environment, timeout=0.1, stdout_limit=1024, stderr_limit=1024)
