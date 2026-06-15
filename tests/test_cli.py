"""Tests for the CLI surface and exit codes."""

from __future__ import annotations

import json

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


def test_check_json_format() -> None:
    result = runner.invoke(app, ["check", str(FIXTURES / "risky_python_exec"), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["tool"] == "sncheck"
    assert any(f["id"] == "PY-EVAL-EXEC-001" for f in payload["findings"])


def test_check_unknown_rule_group_is_usage_error() -> None:
    result = runner.invoke(app, ["check", str(FIXTURES / "safe_repo"), "--rules", "bogus"])
    assert result.exit_code == 2


def test_check_unresolvable_target_exit_three() -> None:
    result = runner.invoke(app, ["check", "this is not a valid target!!"])
    assert result.exit_code == 3
