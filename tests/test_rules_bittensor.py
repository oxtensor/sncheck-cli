"""Tests for Bittensor-specific rules."""

from __future__ import annotations

from pathlib import Path

from sncheck.config import ScanConfig
from sncheck.models import Severity, Target, TargetType
from sncheck.scanner import scan_path

from .conftest import assert_has_finding, assert_no_finding, scan_fixture


def _scan_dir(path: Path, config: ScanConfig | None = None):
    target = Target(type=TargetType.LOCAL, raw=str(path), path=str(path))
    return scan_path(path, target, config or ScanConfig())


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


def test_hotkey_references_collapse_to_one_info_finding(tmp_path: Path) -> None:
    # A file that references 'hotkey' on many lines (as nearly every subnet repo
    # does) must produce exactly one informational finding, not one per line.
    code = "\n".join(f"hotkey_{i} = wallet.hotkey  # line {i}" for i in range(40))
    (tmp_path / "miner.py").write_text(code + "\n")

    result = _scan_dir(tmp_path, ScanConfig(rules=("bittensor",)))
    hotkeys = [f for f in result.findings if f.id == "BT-HOTKEY-REF-001"]
    assert len(hotkeys) == 1
    assert hotkeys[0].severity == Severity.INFO
    assert "more references in this file" in hotkeys[0].evidence


def test_coldkey_references_collapse_per_file(tmp_path: Path) -> None:
    code = "\n".join(f"coldkey_{i} = wallet.coldkey" for i in range(10))
    (tmp_path / "wallet.py").write_text(code + "\n")

    result = _scan_dir(tmp_path, ScanConfig(rules=("bittensor",)))
    coldkeys = [f for f in result.findings if f.id == "BT-COLDKEY-REF-001"]
    assert len(coldkeys) == 1
