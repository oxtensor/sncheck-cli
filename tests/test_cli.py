"""Tests for the CLI surface and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sncheck.cli import app

from .conftest import FIXTURES

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "sncheck" in result.stdout


def test_rules_list() -> None:
    result = runner.invoke(app, ["rules", "list"])
    assert result.exit_code == 0
    assert "SH-CURL-BASH-001" in result.stdout


def test_rules_explain_known() -> None:
    result = runner.invoke(app, ["rules", "explain", "SH-CURL-BASH-001"])
    assert result.exit_code == 0
    assert "Remote script piped to shell" in result.stdout


def test_rules_explain_unknown() -> None:
    result = runner.invoke(app, ["rules", "explain", "NOPE-000"])
    assert result.exit_code == 2


def test_check_local_text_default_exit_zero() -> None:
    result = runner.invoke(app, ["check", str(FIXTURES / "risky_curl_bash")])
    assert result.exit_code == 0
    assert "SH-CURL-BASH-001" in result.stdout


def test_check_fail_on_high() -> None:
    result = runner.invoke(app, ["check", str(FIXTURES / "risky_curl_bash"), "--fail-on", "high"])
    assert result.exit_code == 1


def test_check_fail_on_high_clean_repo_exit_zero() -> None:
    result = runner.invoke(app, ["check", str(FIXTURES / "safe_repo"), "--fail-on", "high"])
    assert result.exit_code == 0


def test_check_fail_on_high_ignores_torch_eval_method(tmp_path: Path) -> None:
    # A benign model.eval() on a call result must not trip --fail-on high.
    (tmp_path / "miner.py").write_text("model = load_model().eval()\n")
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 0, result.stdout


def test_check_json_format() -> None:
    result = runner.invoke(app, ["check", str(FIXTURES / "risky_python_exec"), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["tool"] == "sncheck"
    assert any(f["id"] == "PY-EVAL-EXEC-001" for f in payload["findings"])


def test_check_min_severity_filters_low_findings() -> None:
    # risky_python_exec has high findings; at --min-severity high the medium
    # os.system finding should be filtered out of the JSON findings list, while
    # the summary still counts it.
    result = runner.invoke(
        app,
        [
            "check",
            str(FIXTURES / "risky_python_exec"),
            "--format",
            "json",
            "--min-severity",
            "high",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    severities = {f["severity"] for f in payload["findings"]}
    assert severities <= {"high", "critical"}
    # Summary is unfiltered, so medium count is preserved.
    assert payload["summary"]["medium"] >= 1


def test_check_unknown_rule_group_is_usage_error() -> None:
    result = runner.invoke(app, ["check", str(FIXTURES / "safe_repo"), "--rules", "bogus"])
    assert result.exit_code == 2


def test_check_unresolvable_target_exit_three() -> None:
    result = runner.invoke(app, ["check", "this is not a valid target!!"])
    assert result.exit_code == 3


@pytest.mark.parametrize("raw", ["./missing-miner", "~sncheck-no-such-user/miner"])
def test_check_missing_local_path_exit_three(
    raw: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["check", raw, "--format", "json"])
    assert result.exit_code == 3
    assert json.loads(result.stdout)["error"] == f"Local path does not exist: {raw}"
