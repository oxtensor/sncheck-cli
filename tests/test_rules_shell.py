"""Tests for shell rules."""

from __future__ import annotations

from .conftest import assert_has_finding, assert_no_finding, scan_fixture


def test_curl_bash_rule_detects_remote_script() -> None:
    result = scan_fixture("risky_curl_bash")
    assert_has_finding(result, "SH-CURL-BASH-001")


def test_safe_repo_has_no_curl_bash() -> None:
    result = scan_fixture("safe_repo")
    assert_no_finding(result, "SH-CURL-BASH-001")
