"""Tests for the text and JSON reporters."""

from __future__ import annotations

import json

from rich.console import Console

from sncheck.reporters import json as json_reporter
from sncheck.reporters import text as text_reporter

from .conftest import scan_fixture


def _render_text(name: str) -> str:
    result = scan_fixture(name)
    console = Console(record=True, width=100, force_terminal=False)
    text_reporter.render(result, console=console)
    return console.export_text()


def test_text_report_groups_by_level_and_type() -> None:
    out = _render_text("risky_wallet_exfil")
    # Level section headers and a type sub-header are present.
    assert "── CRITICAL (1) ──" in out
    assert "[bittensor]" in out
    # The critical wallet-exfil finding appears, and the bottom summary too.
    assert "BT-WALLET-EXFIL-001" in out
    assert "Summary" in out
    # Critical section is printed before the LOW section (worst-first).
    assert out.index("── CRITICAL") < out.index("── LOW")


def test_text_report_does_not_repeat_impact_per_occurrence() -> None:
    # BT-WALLET-PATH-001 fires more than once in this fixture; its Impact and
    # Recommendation must be printed once for the rule, with the hits listed as
    # locations rather than repeating the whole block.
    out = _render_text("risky_wallet_exfil")
    assert out.count("Referencing the wallet directory") == 1
    assert "Locations:" in out


def test_json_report_has_stable_schema() -> None:
    result = scan_fixture("risky_curl_bash")
    payload = json.loads(json_reporter.render(result))

    assert payload["schema_version"] == "0.1"
    assert payload["tool"] == "sncheck"
    assert payload["overall_risk"] == "high"
    assert set(payload["summary"]) == {"critical", "high", "medium", "low", "info"}
    assert any(f["id"] == "SH-CURL-BASH-001" for f in payload["findings"])

    # Every finding carries the documented fields.
    for finding in payload["findings"]:
        for field in (
            "id",
            "title",
            "severity",
            "category",
            "impact",
            "recommendation",
            "file",
            "evidence",
            "confidence",
        ):
            assert field in finding


def test_json_report_clean_repo() -> None:
    result = scan_fixture("safe_repo")
    payload = json.loads(json_reporter.render(result))
    assert payload["overall_risk"] in {"clean", "low"}
