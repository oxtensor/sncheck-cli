"""Turn a list of findings into a summary and an overall risk level."""

from __future__ import annotations

from sncheck.models import Finding, RiskLevel, Severity, Summary


def summarize(findings: list[Finding]) -> Summary:
    """Count findings by severity."""
    summary = Summary()
    for finding in findings:
        match finding.severity:
            case Severity.CRITICAL:
                summary.critical += 1
            case Severity.HIGH:
                summary.high += 1
            case Severity.MEDIUM:
                summary.medium += 1
            case Severity.LOW:
                summary.low += 1
            case Severity.INFO:
                summary.info += 1
    return summary


def overall_risk(findings: list[Finding]) -> RiskLevel:
    """Derive the overall risk level from the worst finding present.

    - critical -> any critical finding
    - high -> any high finding
    - medium -> any medium finding
    - low -> only low/info findings
    - clean -> no findings at all
    """
    if not findings:
        return RiskLevel.CLEAN

    worst = max(f.severity.rank for f in findings)
    if worst == Severity.CRITICAL.rank:
        return RiskLevel.CRITICAL
    if worst == Severity.HIGH.rank:
        return RiskLevel.HIGH
    if worst == Severity.MEDIUM.rank:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def reaches_threshold(findings: list[Finding], fail_on: Severity) -> bool:
    """Whether any finding is at least as severe as ``fail_on``."""
    return any(f.severity.rank >= fail_on.rank for f in findings)
