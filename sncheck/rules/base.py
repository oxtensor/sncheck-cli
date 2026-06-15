"""Rule engine primitives.

A *rule* is a small unit that inspects a single file and yields zero or more
:class:`Finding` objects. Rules register themselves with :data:`REGISTRY` so the
scanner can enumerate them, filter by group, and expose them to ``sncheck rules``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from re import Pattern

from sncheck.file_inventory import FileKind, InventoryFile
from sncheck.models import Category, Confidence, Finding, Severity


@dataclass
class FileContext:
    """The information a rule receives about one file."""

    inv: InventoryFile
    text: str

    @property
    def relative(self) -> str:
        return self.inv.relative

    @property
    def kind(self) -> FileKind:
        return self.inv.kind

    @property
    def path(self) -> Path:
        return self.inv.path

    def lines(self) -> list[str]:
        return self.text.splitlines()


# A file check takes a FileContext and yields Findings.
CheckFn = Callable[["FileContext"], Iterable[Finding]]
# A repo check takes the full inventory + root and yields Findings. Used by
# rules that reason about the repository as a whole (e.g. a missing lockfile).
RepoCheckFn = Callable[[list[InventoryFile], Path], Iterable[Finding]]


@dataclass
class Rule:
    """Metadata plus the check function for a single rule."""

    id: str
    title: str
    severity: Severity
    category: Category
    confidence: Confidence
    description: str
    impact: str
    recommendation: str
    group: str
    check: CheckFn | None = None
    repo_check: RepoCheckFn | None = None
    kinds: frozenset[FileKind] = field(default_factory=frozenset)
    experimental: bool = False

    @property
    def is_repo_rule(self) -> bool:
        return self.repo_check is not None

    def applies_to(self, kind: FileKind) -> bool:
        return not self.kinds or kind in self.kinds

    def make_finding(
        self,
        *,
        file: str,
        evidence: str,
        line: int | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> Finding:
        """Build a Finding from this rule's metadata, overriding per-match fields."""
        return Finding(
            id=self.id,
            title=self.title,
            severity=severity or self.severity,
            category=self.category,
            description=self.description,
            impact=self.impact,
            recommendation=self.recommendation,
            file=file,
            line=line,
            evidence=evidence,
            confidence=confidence or self.confidence,
        )


REGISTRY: dict[str, Rule] = {}


def register(rule: Rule) -> Rule:
    """Register a rule, guarding against duplicate IDs."""
    if rule.id in REGISTRY:
        raise ValueError(f"Duplicate rule id: {rule.id}")
    REGISTRY[rule.id] = rule
    return rule


def all_rules() -> list[Rule]:
    """Return all registered rules sorted by ID for stable output."""
    return sorted(REGISTRY.values(), key=lambda r: r.id)


def strip_evidence(line: str, limit: int = 200) -> str:
    """Trim and truncate a matched line for display as evidence."""
    snippet = line.strip()
    if len(snippet) > limit:
        snippet = snippet[: limit - 1] + "…"
    return snippet


def regex_line_rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    category: Category,
    confidence: Confidence,
    description: str,
    impact: str,
    recommendation: str,
    group: str,
    patterns: Iterable[str | Pattern[str]],
    kinds: Iterable[FileKind] = (),
    experimental: bool = False,
    flags: int = 0,
    per_file_once: bool = False,
) -> Rule:
    """Create and register a rule that flags lines matching any pattern.

    This covers the common case of "if a line looks like X, raise a finding".
    More nuanced rules (AST analysis, multi-line context) define their own
    check function instead.

    When ``per_file_once`` is set, the rule reports a single finding per file at
    the first match, with the total occurrence count noted in the evidence. Use
    this for references that are common and expected (e.g. ``hotkey``) so the
    rule provides awareness without one finding per line.
    """
    compiled: list[Pattern[str]] = [
        p if isinstance(p, re.Pattern) else re.compile(p, flags) for p in patterns
    ]

    def check(ctx: FileContext) -> Iterable[Finding]:
        matches: list[tuple[int, str]] = []
        for lineno, line in enumerate(ctx.lines(), start=1):
            if any(pat.search(line) for pat in compiled):
                matches.append((lineno, line))
                if not per_file_once:
                    yield rule.make_finding(
                        file=ctx.relative,
                        line=lineno,
                        evidence=strip_evidence(line),
                    )
        if per_file_once and matches:
            first_line, first_text = matches[0]
            evidence = strip_evidence(first_text)
            if len(matches) > 1:
                evidence += f"  (+{len(matches) - 1} more references in this file)"
            yield rule.make_finding(
                file=ctx.relative,
                line=first_line,
                evidence=evidence,
            )

    rule = Rule(
        id=id,
        title=title,
        severity=severity,
        category=category,
        confidence=confidence,
        description=description,
        impact=impact,
        recommendation=recommendation,
        group=group,
        check=check,
        kinds=frozenset(kinds),
        experimental=experimental,
    )
    return register(rule)
