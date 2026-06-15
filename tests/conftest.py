"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

from sncheck.config import ScanConfig
from sncheck.models import ScanResult, Target, TargetType
from sncheck.scanner import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def scan_fixture(name: str, config: ScanConfig | None = None) -> ScanResult:
    """Scan a fixture repository by directory name."""
    root = FIXTURES / name
    target = Target(type=TargetType.LOCAL, raw=str(root), path=str(root))
    return scan_path(root, target, config or ScanConfig())


def finding_ids(result: ScanResult) -> set[str]:
    return {f.id for f in result.findings}


def assert_has_finding(result: ScanResult, rule_id: str) -> None:
    assert rule_id in finding_ids(result), (
        f"expected finding {rule_id}; got {sorted(finding_ids(result))}"
    )


def assert_no_finding(result: ScanResult, rule_id: str) -> None:
    assert rule_id not in finding_ids(result), f"did not expect finding {rule_id}"
