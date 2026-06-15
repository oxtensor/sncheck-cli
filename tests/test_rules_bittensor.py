"""Tests for Bittensor-specific rules."""

from __future__ import annotations

from sncheck.config import ScanConfig
from sncheck.models import Severity

from .conftest import assert_has_finding, assert_no_finding, scan_fixture


def test_wallet_path_detected_in_code() -> None:
    result = scan_fixture("risky_wallet_access")
    assert_has_finding(result, "BT-WALLET-PATH-001")
    # In code, the wallet path is high severity.
    wallet = next(f for f in result.findings if f.id == "BT-WALLET-PATH-001")
    assert wallet.severity == Severity.HIGH


def test_safe_repo_has_no_wallet_path_finding() -> None:
    result = scan_fixture("safe_repo")
    assert_no_finding(result, "BT-WALLET-PATH-001")


def test_wallet_name_in_docs_is_not_high() -> None:
    # The safe repo README mentions --wallet.name but never the wallet *path*.
    result = scan_fixture("safe_repo", ScanConfig(rules=("bittensor",)))
    assert not any(f.severity == Severity.HIGH for f in result.findings)
