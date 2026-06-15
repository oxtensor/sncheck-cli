"""Tests for the text and JSON reporters."""

from __future__ import annotations

import json

from sncheck.reporters import json as json_reporter

from .conftest import scan_fixture


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
