import logging
import shlex
import threading
import time
import uuid
import re

import lbr_testsuite.executable as lb_exec
from lbr_testsuite.executable import Executor, Tool

from src.common.utils import duplicate_executor


_LOCK = threading.Lock()
_STATE = {
    "initialized": False,
    "backend": "none",  # systemd | cgroup2 | none
    "name": None,
    "slice": None,
    "path": None,
    "mem_limit": None,
    "cpu_limit": None,
}


def _tool_ok(executor: Executor, cmd: str, sudo: bool) -> bool:
    try:
        Tool(cmd, executor=executor, sudo=sudo, failure_verbosity="silent").run()
        return True
    except Exception:
        return False


def _get_memtotal_kib(executor: Executor, sudo: bool) -> int:
    output, _ = Tool(
        "bash -c \"awk '/MemTotal:/ {print \\\$2}' /proc/meminfo\"",
        executor=executor,
        sudo=sudo,
    ).run()
    return int(output.strip())


def _limit_to_bytes(limit, executor: Executor, sudo: bool) -> int | None:
    if limit is None:
        return None

    if isinstance(limit, int):
        return int(limit)

    s = str(limit).strip().lower()
    if not s:
        return None

    if s.endswith("%"):
        percent = float(s[:-1]) / 100.0
        memtotal_kib = _get_memtotal_kib(executor, sudo)
        return int(memtotal_kib * 1024 * percent)

    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([kmgt]?)", s)
    if not match:
        raise ValueError(f"Unsupported memory limit format: {limit}")

    value = float(match.group(1))
    unit = match.group(2)
    units = {
        "": 1,
        "k": 1024,
        "m": 1024**2,
        "g": 1024**3,
        "t": 1024**4,
    }
    return int(value * units[unit])


def _memory_high_from_limit(mem_limit, executor: Executor, sudo: bool) -> str | None:
    limit_bytes = _limit_to_bytes(mem_limit, executor, sudo)
    if limit_bytes is None:
        return None

    # Keep some headroom below MemoryMax to trigger reclaim before hard OOM.
    memory_high = int(limit_bytes * 0.9)
    if memory_high <= 0:
        return None

    return str(memory_high)


def _init_systemd_group(
    executor: Executor, sudo: bool, base_name: str, mem_limit, cpu_limit
):
    base_name = f"{base_name}.slice"

    props = []
    if mem_limit is not None:
        props.extend(["MemorySwapMax=0", "MemoryZSwapMax=0"])
        props.append(f"MemoryMax={mem_limit}")
        mem_high = _memory_high_from_limit(mem_limit, executor, sudo)
        if mem_high is not None:
            props.append(f"MemoryHigh={mem_high}")
            props.append(f"MemoryLimit={mem_high}")
    else:
        props.extend(
            [
                "MemoryMax=",
                "MemoryLimit=",
                "MemoryHigh=",
                "MemorySwapMax=",
                "MemoryZSwapMax=",
            ]
        )
    if cpu_limit is not None:
        props.append(f"CPUQuota={cpu_limit}")
    else:
        props.append("CPUQuota=")

    if props:
        cmd = (
            "systemctl set-property --runtime "
            + shlex.quote(base_name)
            + " "
            + " ".join(props)
        )
        Tool(cmd, executor=executor, sudo=sudo, failure_verbosity="silent").run()

    _STATE["backend"] = "systemd"
    _STATE["name"] = base_name
    _STATE["slice"] = base_name
    _STATE["mem_limit"] = mem_limit
    _STATE["cpu_limit"] = cpu_limit
    _STATE["initialized"] = True


def _init_cgroup2_group(
    executor: Executor, sudo: bool, base_name: str, mem_limit, cpu_limit
):
    unique_name = f"{base_name}-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    group_path = f"/sys/fs/cgroup/{unique_name}"

    Tool(f"mkdir -p {shlex.quote(group_path)}", executor=executor, sudo=sudo).run()

    mem_bytes = _limit_to_bytes(mem_limit, executor, sudo)
    if mem_bytes is not None:
        mem = str(mem_bytes)
        Tool(
            f"sh -lc 'echo {shlex.quote(mem)} > {shlex.quote(group_path)}/memory.max'",
            executor=executor,
            sudo=sudo,
        ).run()
        mem_high = _memory_high_from_limit(mem_limit, executor, sudo)
        if mem_high is not None:
            Tool(
                f"sh -lc 'echo {shlex.quote(mem_high)} > {shlex.quote(group_path)}/memory.high'",
                executor=executor,
                sudo=sudo,
                failure_verbosity="silent",
            ).run()

    # Optional CPU limit mapping can be added later.
    _ = cpu_limit

    Tool(
        f"sh -lc 'echo 1 > {shlex.quote(group_path)}/memory.oom.group'",
        executor=executor,
        sudo=sudo,
        failure_verbosity="silent",
    ).run()

    _STATE["backend"] = "cgroup2"
    _STATE["name"] = unique_name
    _STATE["path"] = group_path
    _STATE["mem_limit"] = mem_limit
    _STATE["cpu_limit"] = cpu_limit
    _STATE["initialized"] = True


def _init_group_once(
    executor: Executor, sudo: bool, group_name: str, mem_limit=None, cpu_limit=None
):
    if _STATE["initialized"]:
        return

    setup_exec = duplicate_executor(executor, 1)[0]

    has_systemd = (
        _tool_ok(setup_exec, "command -v systemd-run >/dev/null 2>&1", sudo)
        and _tool_ok(setup_exec, "command -v systemctl >/dev/null 2>&1", sudo)
        and _tool_ok(setup_exec, "test -d /run/systemd/system", sudo)
    )

    if has_systemd:
        _init_systemd_group(setup_exec, sudo, group_name, mem_limit, cpu_limit)
        return

    has_cgroup2 = _tool_ok(
        setup_exec, "test -f /sys/fs/cgroup/cgroup.controllers", sudo
    )
    if has_cgroup2:
        _init_cgroup2_group(setup_exec, sudo, group_name, mem_limit, cpu_limit)
        return

    logging.getLogger().warning(
        "Neither systemd-run nor writable cgroup v2 available. Process limits disabled."
    )
    _STATE["backend"] = "none"
    _STATE["name"] = group_name
    _STATE["mem_limit"] = mem_limit
    _STATE["cpu_limit"] = cpu_limit
    _STATE["initialized"] = True


def _wrap_command(command: str, env: list) -> str:
    backend = _STATE["backend"]

    if backend == "systemd":
        args = [
            "systemd-run",
            "--scope",
            "--quiet",
            "--slice",
            shlex.quote(_STATE["slice"]),
        ]
        for e in env:
            args.append(f"--setenv={e}")
        return " ".join(
            args
            + [
                "sh",
                "-lc",
                shlex.quote("exec " + command),
            ]
        )

    if backend == "cgroup2":
        path = _STATE["path"]
        shell = f"echo $$ > {path}/cgroup.procs; exec {command}"
        return " ".join([e for e in env]) + " sh -lc " + shlex.quote(shell)

    return command


class Daemon(lb_exec.Daemon):
    def __init__(
        self,
        command,
        executor,
        *args,
        sudo=False,
        mem_limit=None,
        cpu_limit=None,
        process_group_name="flowtest-exporter",
        env=[],
        **kwargs,
    ):
        with _LOCK:
            _init_group_once(
                executor=executor,
                sudo=sudo,
                group_name=process_group_name,
                mem_limit=mem_limit,
                cpu_limit=cpu_limit,
            )
            wrapped_command = _wrap_command(command, env)

        super().__init__(wrapped_command, *args, executor=executor, sudo=sudo, **kwargs)
