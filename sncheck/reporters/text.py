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

    s = result.summary
    console.print(
        f"Summary: {s.critical} critical, {s.high} high, {s.medium} medium, "
        f"{s.low} low, {s.info} info"
    )

    if not result.findings:
        console.print()
        console.print("No findings.")
        return

    console.print()
    console.print(Text("Findings:", style="bold"))

    ordered = sorted(
        result.findings,
        key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.file, f.line or 0, f.id),
    )
    for finding in ordered:
        console.print()
        sev = finding.severity
        header = Text()
        header.append(f"[{sev.value.upper()}] ", style=_SEVERITY_STYLE[sev])
        header.append(f"{finding.id}: {finding.title}")
        console.print(header)

        location = finding.file
        if finding.line is not None:
            location += f":{finding.line}"
        console.print(f"File: {location}")
        console.print(f"Evidence: {finding.evidence}")
        console.print(f"Impact: {finding.impact}")
        console.print(f"Recommendation: {finding.recommendation}")
        console.print(f"Confidence: {finding.confidence.value}")
