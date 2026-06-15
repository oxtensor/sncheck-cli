"""Tests for scoring and risk derivation."""

from __future__ import annotations

from sncheck.models import Category, Confidence, Finding, RiskLevel, Severity
from sncheck.scoring import overall_risk, reaches_threshold, summarize


def _finding(sev: Severity) -> Finding:
    return Finding(
        id="X",
        title="t",
        severity=sev,
        category=Category.SHELL,
        description="d",
        impact="i",
        recommendation="r",
        file="f",
        evidence="e",
        confidence=Confidence.LOW,
    )


def test_overall_risk_empty_is_clean() -> None:
    assert overall_risk([]) == RiskLevel.CLEAN


def test_overall_risk_picks_worst() -> None:
    findings = [_finding(Severity.LOW), _finding(Severity.HIGH), _finding(Severity.MEDIUM)]
    assert overall_risk(findings) == RiskLevel.HIGH


def test_overall_risk_low_only() -> None:
    assert overall_risk([_finding(Severity.LOW), _finding(Severity.INFO)]) == RiskLevel.LOW


def test_summary_counts() -> None:
    findings = [_finding(Severity.HIGH), _finding(Severity.HIGH), _finding(Severity.LOW)]
    summary = summarize(findings)
    assert (summary.high, summary.low, summary.critical) == (2, 1, 0)


def test_reaches_threshold() -> None:
    findings = [_finding(Severity.MEDIUM)]
    assert reaches_threshold(findings, Severity.MEDIUM)
    assert not reaches_threshold(findings, Severity.HIGH)
