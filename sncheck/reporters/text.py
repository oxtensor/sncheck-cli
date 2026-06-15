"""Text reporter: human-readable terminal output via Rich."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from sncheck.models import RiskLevel, ScanResult, Severity

_RISK_STYLE = {
    RiskLevel.CRITICAL: "bold white on red",
    RiskLevel.HIGH: "bold red",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.LOW: "cyan",
    RiskLevel.CLEAN: "bold green",
    RiskLevel.UNKNOWN: "dim",
}

_RISK_LABEL = {
    RiskLevel.CRITICAL: "Critical",
    RiskLevel.HIGH: "High",
    RiskLevel.MEDIUM: "Medium",
    RiskLevel.LOW: "Low",
    RiskLevel.CLEAN: "No high-risk findings detected",
    RiskLevel.UNKNOWN: "Unknown",
}

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

# Worst-first ordering for the findings list.
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def render(result: ScanResult, console: Console | None = None) -> None:
    """Print a human-readable report to ``console`` (or a fresh stdout console)."""
    console = console or Console()

    console.print(Text("SNCheck report", style="bold"))
    console.print()

    target_label = result.target.url or result.target.path or result.target.raw
    console.print(f"Target: {target_label}")
    if result.commit:
        console.print(f"Commit: {result.commit}")

    risk = result.overall_risk
    console.print(
        Text("Overall risk: ", style="bold") + Text(_RISK_LABEL[risk], style=_RISK_STYLE[risk])
    )

    if result.error:
        console.print()
        console.print(Text(f"Scan error: {result.error}", style="bold red"))
        return

    if not result.findings:
        console.print()
        console.print("No findings at the selected severity.")
        _print_summary(console, result)
        return

    console.print()
    console.print(Text("Findings:", style="bold"))

    # Group findings by severity level, then by category (type), then by rule.
    # All occurrences of one rule share a single Impact/Recommendation block and
    # are listed as locations underneath, so identical text is never repeated.
    by_level = _group_by_level_and_type(result.findings)

    for severity in _SEVERITY_ORDER:
        by_type = by_level.get(severity)
        if not by_type:
            continue
        count = sum(
            len(rule_findings) for rules in by_type.values() for rule_findings in rules.values()
        )
        console.print()
        console.print(
            Text(f"── {severity.value.upper()} ", style=_SEVERITY_STYLE[severity])
            + Text(f"({count}) ──", style="dim")
        )
        for category in sorted(by_type):
            console.print(Text(f"  [{category}]", style="bold"))
            for rule_id in sorted(by_type[category]):
                _print_rule_group(console, by_type[category][rule_id])

    _print_summary(console, result)


# Maximum number of locations listed per rule before truncating.
_MAX_LOCATIONS = 15


def _group_by_level_and_type(findings) -> dict:
    """Bucket findings into {severity: {category: {rule_id: [findings]}}}."""
    by_level: dict = {}
    for finding in findings:
        by_type = by_level.setdefault(finding.severity, {})
        by_rule = by_type.setdefault(finding.category.value, {})
        by_rule.setdefault(finding.id, []).append(finding)

    # Stable ordering of occurrences within each rule: by file then line.
    for by_type in by_level.values():
        for by_rule in by_type.values():
            for rule_findings in by_rule.values():
                rule_findings.sort(key=lambda f: (f.file, f.line or 0))
    return by_level


def _location(finding) -> str:
    loc = finding.file
    if finding.line is not None:
        loc += f":{finding.line}"
    return loc


def _print_rule_group(console: Console, findings: list) -> None:
    """Print all occurrences of one rule, sharing a single impact/recommendation."""
    first = findings[0]
    sev = first.severity
    console.print()

    header = Text("    ")
    header.append(f"[{sev.value.upper()}] ", style=_SEVERITY_STYLE[sev])
    header.append(f"{first.id}: {first.title}")
    if len(findings) > 1:
        header.append(f"  ({len(findings)} occurrences)", style="dim")
    console.print(header)

    # Shared explanation, printed once for the whole rule.
    console.print(f"    Impact: {first.impact}")
    console.print(f"    Recommendation: {first.recommendation}")
    console.print(f"    Confidence: {first.confidence.value}")

    if len(findings) == 1:
        console.print(f"    Location: {_location(first)}")
        console.print(f"    Evidence: {first.evidence}")
        return

    console.print("    Locations:")
    for finding in findings[:_MAX_LOCATIONS]:
        console.print(f"      {_location(finding)} — {finding.evidence}")
    if len(findings) > _MAX_LOCATIONS:
        console.print(f"      … (+{len(findings) - _MAX_LOCATIONS} more)")


def _print_summary(console: Console, result: ScanResult) -> None:
    """Print the severity summary at the bottom of the report."""
    s = result.summary
    total = s.critical + s.high + s.medium + s.low + s.info
    hidden = total - len(result.findings)
    risk = result.overall_risk

    console.print()
    console.print(Text("Summary", style="bold"))
    console.print(
        Text("  Overall risk: ", style="bold") + Text(_RISK_LABEL[risk], style=_RISK_STYLE[risk])
    )
    console.print(
        f"  {s.critical} critical, {s.high} high, {s.medium} medium, "
        f"{s.low} low, {s.info} info  ({total} total)"
    )
    if hidden > 0:
        console.print(
            Text(
                f"  {hidden} lower-severity finding(s) hidden "
                "— use --min-severity info to show all",
                style="dim",
            )
        )
