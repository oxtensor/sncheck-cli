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

    # Group findings first by severity level, then by category (type). Within a
    # level+type, repeated hits of the same rule in the same file collapse into
    # one block (e.g. a "hotkey" reference on 60 lines -> one block).
    by_level = _group_by_level_and_type(result.findings)

    for severity in _SEVERITY_ORDER:
        by_type = by_level.get(severity)
        if not by_type:
            continue
        count = sum(len(groups) for groups in by_type.values())
        console.print()
        console.print(
            Text(f"── {severity.value.upper()} ", style=_SEVERITY_STYLE[severity])
            + Text(f"({count}) ──", style="dim")
        )
        for category in sorted(by_type):
            console.print(Text(f"  [{category}]", style="bold"))
            for group in by_type[category]:
                _print_group(console, group)

    _print_summary(console, result)


def _group_by_level_and_type(findings) -> dict:
    """Bucket findings into {severity: {category: [ (rule,file) groups ]}}."""
    # First collapse identical rule+file hits into one group each.
    collapsed: dict[tuple[str, str], list] = {}
    for finding in findings:
        collapsed.setdefault((finding.id, finding.file), []).append(finding)

    by_level: dict = {}
    for group in collapsed.values():
        first = group[0]
        by_type = by_level.setdefault(first.severity, {})
        by_type.setdefault(first.category.value, []).append(group)

    # Stable ordering of the groups within each category: by file then rule id.
    for by_type in by_level.values():
        for groups in by_type.values():
            groups.sort(key=lambda g: (g[0].file, g[0].id))
    return by_level


def _print_group(console: Console, group: list) -> None:
    """Print one collapsed finding block, indented under its category."""
    first = group[0]
    sev = first.severity
    console.print()
    header = Text("    ")
    header.append(f"[{sev.value.upper()}] ", style=_SEVERITY_STYLE[sev])
    header.append(f"{first.id}: {first.title}")
    if len(group) > 1:
        header.append(f"  (×{len(group)})", style="dim")
    console.print(header)

    if len(group) == 1:
        location = first.file
        if first.line is not None:
            location += f":{first.line}"
        console.print(f"    File: {location}")
        console.print(f"    Evidence: {first.evidence}")
    else:
        lines = [f.line for f in group if f.line is not None]
        shown = ", ".join(str(n) for n in lines[:10])
        if len(lines) > 10:
            shown += f", … (+{len(lines) - 10} more)"
        console.print(f"    File: {first.file} ({len(group)} occurrences)")
        console.print(f"    Lines: {shown}")
        console.print(f"    Evidence (first): {first.evidence}")

    console.print(f"    Impact: {first.impact}")
    console.print(f"    Recommendation: {first.recommendation}")
    console.print(f"    Confidence: {first.confidence.value}")


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
