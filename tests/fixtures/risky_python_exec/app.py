"""Positive fixture for Python dynamic execution and unsafe subprocess usage."""

import os
import pickle
import subprocess


def dynamic(expr: str):
    # PY-EVAL-EXEC-001: dynamic evaluation of a string.
    return eval(expr)  # noqa: S307


def run_shell(cmd: str) -> int:
    # PY-SUBPROCESS-SHELL-001: shell=True.
    return subprocess.run(cmd, shell=True, check=False).returncode


def run_system(cmd: str) -> int:
    # PY-OS-SYSTEM-001.
    return os.system(cmd)


def load(blob: bytes):
    # PY-PICKLE-LOAD-001.
    return pickle.loads(blob)


def safe_add(a: int, b: int) -> int:
    # Negative: ordinary code, no findings.
    return a + b
