"""measured power draw, when the box can actually measure it.

one source, nvidia-smi, and nothing else. no psutil, no vendor sdk, no wall-plug
guesswork: stdlib only, because a node should not need twenty packages to say how much
it is drawing. a machine with no nvidia gpu gets None and the node falls back to the
number its operator typed in.

what a "measured" reading is: what the driver reports for the local gpus, right now,
summed. what it is not: an attested measurement. the node signs the number it sends,
so the signature says which node said it, not that the number is true.
"""

from __future__ import annotations

import shutil
import subprocess

NVIDIA_SMI = "nvidia-smi"
QUERY_ARGS = ["--query-gpu=power.draw", "--format=csv,noheader,nounits"]

# a heartbeat is due every 30s. a meter that has not answered in three is not a meter.
TIMEOUT_S = 3.0

__all__ = ["measure", "NVIDIA_SMI", "QUERY_ARGS", "TIMEOUT_S"]


def measure() -> float | None:
    """total watts across the local nvidia gpus, or None when it cannot be read.

    None means "no reading", never 0.0: a caller must not read a missing meter as an
    idle machine. every failure lands here, including nvidia-smi missing, a non-zero
    exit, the 3s timeout, a driver that answers [N/A], and no gpus at all.

    a partial sum is a lie, so one unparseable line discards the whole reading rather
    than reporting the gpus that did answer.
    """
    exe = shutil.which(NVIDIA_SMI)
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, *QUERY_ARGS],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        # SubprocessError covers TimeoutExpired; OSError covers a binary that is on
        # PATH but will not execute.
        return None
    if proc.returncode != 0:
        return None

    total = 0.0
    seen = 0
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            watts = float(line)
        except ValueError:
            return None
        if watts != watts or watts in (float("inf"), float("-inf")) or watts < 0:
            return None  # nan/inf/negative watts are a broken driver, not a reading
        total += watts
        seen += 1
    if seen == 0:
        return None
    return total
