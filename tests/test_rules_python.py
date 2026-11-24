"""Tests for Python rules (AST analysis and regex fallback)."""

from __future__ import annotations

from pathlib import Path

from sncheck.config import ScanConfig
from sncheck.file_inventory import FileKind, InventoryFile
from sncheck.models import Target, TargetType
from sncheck.scanner import scan_path

from .conftest import assert_has_finding, assert_no_finding, scan_fixture


def test_detects_eval_exec_subprocess_ossystem_pickle() -> None:
    result = scan_fixture("risky_python_exec")
    for rule_id in (
        "PY-EVAL-EXEC-001",
        "PY-SUBPROCESS-SHELL-001",
        "PY-OS-SYSTEM-001",
        "PY-PICKLE-LOAD-001",
    ):
        assert_has_finding(result, rule_id)


def test_safe_subprocess_not_flagged() -> None:
    result = scan_fixture("safe_repo")
    assert_no_finding(result, "PY-SUBPROCESS-SHELL-001")
    assert_no_finding(result, "PY-EVAL-EXEC-001")


def test_regex_fallback_on_unparseable_python(tmp_path: Path) -> None:
    # Invalid Python so ast.parse raises; the regex fallback should still fire.
    bad = tmp_path / "broken.py"
    bad.write_text("def f(:\n    os.system('x')\n")
    target = Target(type=TargetType.LOCAL, raw=str(tmp_path), path=str(tmp_path))
    result = scan_path(tmp_path, target, ScanConfig(rules=("python",)))
    assert_has_finding(result, "PY-OS-SYSTEM-001")


def _eval_lines(result) -> list[int]:
    return sorted(f.line for f in result.findings if f.id == "PY-EVAL-EXEC-001")


def test_eval_method_on_call_result_or_subscript_not_flagged(tmp_path: Path) -> None:
    # PyTorch's Module.eval() is ubiquitous in subnet code. Called on a call
    # result or subscript it must not be mistaken for the eval() builtin, while
    # a real eval() in the same file is still reported.
    (tmp_path / "model.py").write_text(
        "model = AutoModelForCausalLM.from_pretrained('gpt2').eval()\n"
        "layers[0].eval()\n"
        "self.model.eval()\n"
        "eval(payload)\n"
    )
    target = Target(type=TargetType.LOCAL, raw=str(tmp_path), path=str(tmp_path))
    result = scan_path(tmp_path, target, ScanConfig(rules=("python",)))
    assert _eval_lines(result) == [4]


def test_eval_method_not_flagged_by_regex_fallback(tmp_path: Path) -> None:
    # Same as above when the file cannot be parsed and the regex fallback runs.
    (tmp_path / "broken.py").write_text("def f(:\n    model.eval()\n    exec(code)\n")
    target = Target(type=TargetType.LOCAL, raw=str(tmp_path), path=str(tmp_path))
    result = scan_path(tmp_path, target, ScanConfig(rules=("python",)))
    assert _eval_lines(result) == [3]


def test_call_name_handles_plain_name() -> None:
    # Sanity check the InventoryFile model is usable in isolation.
    inv = InventoryFile(path=Path("x.py"), relative="x.py", kind=FileKind.PYTHON, size=1)
    assert inv.kind == FileKind.PYTHON
