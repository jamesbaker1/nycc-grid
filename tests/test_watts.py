"""pygrid.watts: one meter, nvidia-smi, and a hard rule that failure reads as None.

every test here fakes the subprocess. the one test that really shells out asserts only
the type, because the machine running the suite may or may not have a gpu.
"""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from pygrid import watts


class _Proc:
    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


@pytest.fixture
def smi(monkeypatch):
    """pretend nvidia-smi exists, and capture the call it is asked to make."""
    calls: list[tuple] = []

    def fake_which(name):
        return "/usr/bin/" + name if name == watts.NVIDIA_SMI else None

    monkeypatch.setattr(watts.shutil, "which", fake_which)

    def install(result):
        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if isinstance(result, Exception):
                raise result
            return result

        monkeypatch.setattr(watts.subprocess, "run", fake_run)
        return calls

    return install


def test_no_nvidia_smi_is_none_not_zero(monkeypatch):
    # None means "no reading". zero would tell the grid this box draws nothing.
    monkeypatch.setattr(watts.shutil, "which", lambda name: None)
    monkeypatch.setattr(watts.subprocess, "run", _never_called)
    assert watts.measure() is None


def test_single_gpu_reading(smi):
    smi(_Proc("64.53\n"))
    assert watts.measure() == pytest.approx(64.53)


def test_multi_gpu_readings_are_summed(smi):
    smi(_Proc("100.0\n35.5\n0.25\n"))
    assert watts.measure() == pytest.approx(135.75)


def test_blank_lines_and_whitespace_are_tolerated(smi):
    smi(_Proc("\n  120.5  \n\n 9.5\n\n"))
    assert watts.measure() == pytest.approx(130.0)


def test_the_command_is_the_pinned_query(smi):
    calls = smi(_Proc("1.0"))
    watts.measure()
    (cmd, kwargs), = calls
    assert Path(cmd[0]).stem == "nvidia-smi"
    assert cmd[1:] == ["--query-gpu=power.draw", "--format=csv,noheader,nounits"]
    assert kwargs["timeout"] == 3.0
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    # a non-zero exit is handled here, not raised out of the heartbeat path
    assert kwargs.get("check") is False


def test_nonzero_exit_is_none(smi):
    smi(_Proc("99.9\n", returncode=9))
    assert watts.measure() is None


def test_timeout_is_none(smi):
    smi(subprocess.TimeoutExpired(cmd="nvidia-smi", timeout=watts.TIMEOUT_S))
    assert watts.measure() is None


def test_unexecutable_binary_is_none(smi):
    smi(OSError("Exec format error"))
    assert watts.measure() is None


def test_empty_output_is_none(smi):
    # no gpus listed is not zero watts, it is no reading
    smi(_Proc("\n  \n"))
    assert watts.measure() is None


@pytest.mark.parametrize("stdout", ["[N/A]\n", "100.0\n[N/A]\n", "not a number", "nan\n", "-5.0\n", "inf\n"])
def test_unreadable_line_discards_the_whole_reading(smi, stdout):
    # a partial sum would under-report and still look like a real measurement
    smi(_Proc(stdout))
    assert watts.measure() is None


def test_none_stdout_is_none(smi):
    smi(_Proc(None))
    assert watts.measure() is None


def test_measure_never_raises(smi):
    smi(subprocess.SubprocessError("boom"))
    assert watts.measure() is None


def test_stdlib_only():
    # the spec bans psutil and vendor sdks: a node needs one binary dependency, and
    # this module has to import on a box with nothing but python and pynacl.
    tree = ast.parse(Path(watts.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= set(sys.stdlib_module_names), imported
    assert "psutil" not in imported


def test_real_call_returns_a_float_or_none():
    reading = watts.measure()
    assert reading is None or (isinstance(reading, float) and reading >= 0.0)


def _never_called(*args, **kwargs):
    raise AssertionError("subprocess.run must not be reached without nvidia-smi on PATH")
