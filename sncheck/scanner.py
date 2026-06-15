"""The scan pipeline: resolve -> fetch -> inventory -> rules -> scoring.

This module never executes repository code. Files are only ever read as text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sncheck import __version__
from sncheck.config import ScanConfig
from sncheck.file_inventory import InventoryFile, build_inventory
from sncheck.models import Finding, RiskLevel, ScanResult, Target
from sncheck.rules import all_rules
from sncheck.rules.base import FileContext, Rule
from sncheck.scoring import overall_risk, summarize
from sncheck.target import FetchedRepo, TargetError, cleanup, fetch_target, resolve_target


def _now() -> datetime:
    return datetime.now(timezone.utc)


def scan_path(
    root: Path, target: Target, config: ScanConfig, commit: str | None = None
) -> ScanResult:
    """Run all enabled rules over an already-available repository on disk."""
    started = _now()
    inventory = build_inventory(root, max_file_size=config.max_file_size)
    rules = _selected_rules(config)

    findings = run_rules(rules, inventory, root)

    result = ScanResult(
        tool_version=__version__,
        target=target,
        commit=commit,
        started_at=started,
        finished_at=_now(),
        overall_risk=overall_risk(findings),
        summary=summarize(findings),
        findings=findings,
    )
    return result


def run_rules(rules: list[Rule], inventory: list[InventoryFile], root: Path) -> list[Finding]:
    """Execute file-level and repo-level rules, returning all findings."""
    findings: list[Finding] = []

    # Repo-level rules run once over the whole inventory.
    for rule in rules:
        if rule.is_repo_rule:
            assert rule.repo_check is not None
            findings.extend(rule.repo_check(inventory, root))

    # File-level rules run per applicable file.
    file_rules = [r for r in rules if not r.is_repo_rule]
    for inv in inventory:
        applicable = [r for r in file_rules if r.applies_to(inv.kind)]
        if not applicable:
            continue
        text = _read_text(inv.path)
        if text is None:
            continue
        ctx = FileContext(inv=inv, text=text)
        for rule in applicable:
            assert rule.check is not None
            findings.extend(rule.check(ctx))

    return findings


def _selected_rules(config: ScanConfig) -> list[Rule]:
    selected: list[Rule] = []
    for rule in all_rules():
        if not config.is_group_enabled(rule.group):
            continue
        if not config.is_rule_enabled(rule.id):
            continue
        if rule.experimental and not config.include_experimental:
            continue
        selected.append(rule)
    return selected


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan(raw_target: str, config: ScanConfig, *, cleanup_clone: bool = True) -> ScanResult:
    """Full pipeline entry point: resolve, fetch, scan, and clean up.

    On a target-resolution or fetch failure, returns a ScanResult with
    ``overall_risk = unknown`` and an ``error`` message rather than raising, so
    callers can map it to a clean exit code.
    """
    try:
        target = resolve_target(raw_target)
    except TargetError as exc:
        return _error_result(raw_target, str(exc))

    fetched: FetchedRepo | None = None
    try:
        fetched = fetch_target(target)
    except TargetError as exc:
        return _error_result(raw_target, str(exc), target=target)

    try:
        return scan_path(fetched.path, target, config, commit=fetched.commit)
    finally:
        if cleanup_clone:
            cleanup(fetched)


def _error_result(raw_target: str, message: str, target: Target | None = None) -> ScanResult:
    from sncheck.models import TargetType

    tgt = target or Target(type=TargetType.LOCAL, raw=raw_target)
    return ScanResult(
        tool_version=__version__,
        target=tgt,
        started_at=_now(),
        finished_at=_now(),
        overall_risk=RiskLevel.UNKNOWN,
        error=message,
    )
