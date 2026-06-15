"""SNCheck command-line interface."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from sncheck import __version__
from sncheck.config import ALL_RULE_GROUPS, ScanConfig
from sncheck.models import ScanResult, Severity
from sncheck.reporters import json as json_reporter
from sncheck.reporters import text as text_reporter
from sncheck.rules import all_rules
from sncheck.scanner import scan
from sncheck.scoring import reaches_threshold

app = typer.Typer(
    name="sncheck",
    help="Security scanner for Bittensor subnet repositories. Inspect before you run.",
    add_completion=False,
    no_args_is_help=True,
)
rules_app = typer.Typer(help="Inspect the built-in rule set.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

# Exit codes (see development guide section 15).
EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_USAGE = 2
EXIT_TARGET = 3
EXIT_INTERNAL = 4


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


class FailOn(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NEVER = "never"


def _parse_rules(rules: str | None) -> tuple[str, ...]:
    if not rules:
        return ALL_RULE_GROUPS
    groups = tuple(g.strip() for g in rules.split(",") if g.strip())
    unknown = [g for g in groups if g not in ALL_RULE_GROUPS]
    if unknown:
        raise typer.BadParameter(
            f"Unknown rule group(s): {', '.join(unknown)}. Available: {', '.join(ALL_RULE_GROUPS)}."
        )
    return groups


@app.command()
def check(
    target: str = typer.Argument(..., help="GitHub URL, owner/repo, or local path."),
    format: OutputFormat = typer.Option(OutputFormat.TEXT, "--format", "-f", help="Output format."),
    fail_on: FailOn = typer.Option(
        FailOn.NEVER,
        "--fail-on",
        help="Exit non-zero if a finding reaches this severity.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the report to a file instead of stdout."
    ),
    rules: str | None = typer.Option(None, "--rules", help="Comma-separated rule groups to run."),
    include_experimental: bool = typer.Option(
        False, "--include-experimental", help="Include experimental rules."
    ),
    min_severity: Severity = typer.Option(
        Severity.INFO,
        "--min-severity",
        help="Only show findings at this severity or above (counts still reflect all).",
    ),
    no_clone_cleanup: bool = typer.Option(
        False, "--no-clone-cleanup", help="Keep the temporary clone directory."
    ),
) -> None:
    """Scan a subnet repository for security and trust risks."""
    config = ScanConfig(
        rules=_parse_rules(rules),
        include_experimental=include_experimental,
    )

    try:
        result = scan(target, config, cleanup_clone=not no_clone_cleanup)
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        Console(stderr=True).print(f"[bold red]Internal error:[/] {exc}")
        raise typer.Exit(EXIT_INTERNAL) from exc

    _emit(_filter_for_display(result, min_severity), format, output)

    if result.error is not None:
        raise typer.Exit(EXIT_TARGET)

    if fail_on != FailOn.NEVER:
        threshold = Severity(fail_on.value)
        if reaches_threshold(result.findings, threshold):
            raise typer.Exit(EXIT_THRESHOLD)

    raise typer.Exit(EXIT_OK)


def _filter_for_display(result: ScanResult, min_severity: Severity) -> ScanResult:
    """Return a copy of the result whose findings are filtered for display.

    The summary counts are left untouched so the headline numbers always reflect
    every finding, even when the detailed list is filtered.
    """
    if min_severity == Severity.INFO:
        return result
    kept = [f for f in result.findings if f.severity.rank >= min_severity.rank]
    return result.model_copy(update={"findings": kept})


def _emit(result: ScanResult, format: OutputFormat, output: Path | None) -> None:
    if format == OutputFormat.JSON:
        text = json_reporter.render(result)
        if output is not None:
            output.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        return

    # Text format.
    if output is not None:
        with output.open("w", encoding="utf-8") as fh:
            console = Console(file=fh)
            text_reporter.render(result, console=console)
    else:
        text_reporter.render(result, console=Console())


@rules_app.command("list")
def rules_list() -> None:
    """List all built-in rules."""
    console = Console()
    for rule in all_rules():
        console.print(
            f"[bold]{rule.id}[/]  [dim]{rule.severity.value}/{rule.group}[/]  {rule.title}"
        )


@rules_app.command("explain")
def rules_explain(
    rule_id: str = typer.Argument(..., help="Rule ID, e.g. SH-CURL-BASH-001."),
) -> None:
    """Explain a single rule in detail."""
    console = Console()
    match = next((r for r in all_rules() if r.id.lower() == rule_id.lower()), None)
    if match is None:
        Console(stderr=True).print(f"[bold red]Unknown rule:[/] {rule_id}")
        raise typer.Exit(EXIT_USAGE)

    console.print(f"[bold]{match.id}[/]: {match.title}")
    console.print(f"Severity: {match.severity.value}")
    console.print(f"Confidence: {match.confidence.value}")
    console.print(f"Category: {match.category.value}")
    console.print(f"Group: {match.group}")
    console.print()
    console.print(f"What it detects: {match.description}")
    console.print(f"Why it matters: {match.impact}")
    console.print(f"Recommendation: {match.recommendation}")


@app.command()
def version() -> None:
    """Print the SNCheck version."""
    print(f"sncheck {__version__}")


def main() -> None:  # pragma: no cover - thin wrapper
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
