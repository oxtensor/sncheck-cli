"""Tests for shell rules."""

from __future__ import annotations

from pathlib import Path

from sncheck.config import ScanConfig
from sncheck.models import Severity, Target, TargetType
from sncheck.scanner import scan_path

from .conftest import assert_has_finding, assert_no_finding, scan_fixture


def _scan_dir(path: Path, config: ScanConfig | None = None):
    target = Target(type=TargetType.LOCAL, raw=str(path), path=str(path))
    return scan_path(path, target, config or ScanConfig())


def test_curl_bash_rule_detects_remote_script() -> None:
    result = scan_fixture("risky_curl_bash")
    assert_has_finding(result, "SH-CURL-BASH-001")


def test_safe_repo_has_no_curl_bash() -> None:
    result = scan_fixture("safe_repo")
    assert_no_finding(result, "SH-CURL-BASH-001")


def test_apt_cache_cleanup_is_not_flagged(tmp_path: Path) -> None:
    # The standard Docker cleanup must not produce a destructive-removal finding.
    (tmp_path / "Dockerfile").write_text(
        "RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
    )
    result = _scan_dir(tmp_path, ScanConfig(rules=("shell",)))
    assert_no_finding(result, "SH-RM-RF-001")


def test_rm_rf_of_wallet_dir_is_high(tmp_path: Path) -> None:
    (tmp_path / "wipe.sh").write_text("#!/bin/bash\nrm -rf ~/.bittensor/wallets\n")
    result = _scan_dir(tmp_path, ScanConfig(rules=("shell",)))
    assert_has_finding(result, "SH-RM-RF-001")
    finding = next(f for f in result.findings if f.id == "SH-RM-RF-001")
    assert finding.severity == Severity.HIGH
