"""Dependency hygiene rules.

For v0.1 these are lightweight: identify dependency files, warn when no lockfile
is present, and flag unpinned, git, or remote-archive requirements. Real CVE
matching (OSV / Trivy) is left to a later milestone.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from sncheck.file_inventory import FileKind, InventoryFile
from sncheck.models import Category, Confidence, Finding, Severity
from sncheck.rules.base import FileContext, Rule, register, strip_evidence

GROUP = "dependencies"
_DEP = (FileKind.DEPENDENCY,)

_LOCKFILES = {"poetry.lock", "pipfile.lock", "requirements.lock", "uv.lock", "pdm.lock"}
_MANIFESTS = {"requirements.txt", "pyproject.toml", "pipfile", "setup.py", "setup.cfg"}


# -- DEP-NO-LOCKFILE-001 (repo-level) ----------------------------------------


def _no_lockfile_check(inventory: list[InventoryFile], root: Path) -> Iterable[Finding]:
    names = {f.path.name.lower() for f in inventory}
    has_manifest = bool(names & _MANIFESTS)
    has_lockfile = bool(names & _LOCKFILES)
    if has_manifest and not has_lockfile:
        manifest = next(
            (f.relative for f in inventory if f.path.name.lower() in _MANIFESTS),
            "requirements.txt",
        )
        yield _no_lockfile_rule.make_finding(
            file=manifest,
            evidence="no lockfile found alongside dependency manifest",
        )


_no_lockfile_rule = Rule(
    id="DEP-NO-LOCKFILE-001",
    title="No dependency lockfile",
    severity=Severity.LOW,
    category=Category.DEPENDENCY,
    confidence=Confidence.MEDIUM,
    description="The repo declares dependencies but ships no lockfile.",
    impact="Without a lockfile, installs can resolve to different (possibly malicious) "
    "package versions over time.",
    recommendation="Commit a lockfile (poetry.lock, Pipfile.lock, uv.lock, ...) so installs "
    "are reproducible.",
    group=GROUP,
    repo_check=_no_lockfile_check,
)
register(_no_lockfile_rule)


# -- Per-line requirements rules ---------------------------------------------

_GIT_DEP_RE = re.compile(r"\bgit\+(?:https?|ssh|git)://", re.IGNORECASE)
_ARCHIVE_RE = re.compile(r"https?://\S+\.(?:tar\.gz|tgz|zip|whl)\b", re.IGNORECASE)
# A bare or unpinned requirement line in requirements.txt.
_REQ_LINE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_PINNED_RE = re.compile(r"==|@")


def _is_requirements_txt(ctx: FileContext) -> bool:
    return ctx.inv.path.name.lower() == "requirements.txt"


def _unpinned_check(ctx: FileContext) -> Iterable[Finding]:
    if ctx.kind != FileKind.DEPENDENCY or not _is_requirements_txt(ctx):
        return
    for lineno, raw in enumerate(ctx.lines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if _GIT_DEP_RE.search(line) or _ARCHIVE_RE.search(line):
            continue  # handled by dedicated rules below
        if not _REQ_LINE_RE.match(line):
            continue
        if not _PINNED_RE.search(line):
            yield _unpinned_rule.make_finding(
                file=ctx.relative, line=lineno, evidence=strip_evidence(raw)
            )


_unpinned_rule = Rule(
    id="DEP-UNPINNED-REQ-001",
    title="Unpinned dependency",
    severity=Severity.LOW,
    category=Category.DEPENDENCY,
    confidence=Confidence.LOW,
    description="A requirement is not pinned to an exact version.",
    impact="Unpinned dependencies can silently upgrade to a compromised release.",
    recommendation="Pin dependencies to exact versions (package==x.y.z) and use a lockfile.",
    group=GROUP,
    check=_unpinned_check,
    kinds=frozenset(_DEP),
)
register(_unpinned_rule)


def _make_pattern_dep_rule(rule: Rule, pattern: re.Pattern[str]) -> None:
    def check(ctx: FileContext) -> Iterable[Finding]:
        if ctx.kind != FileKind.DEPENDENCY:
            return
        for lineno, raw in enumerate(ctx.lines(), start=1):
            if pattern.search(raw):
                yield rule.make_finding(
                    file=ctx.relative, line=lineno, evidence=strip_evidence(raw)
                )

    rule.check = check
    register(rule)


_make_pattern_dep_rule(
    Rule(
        id="DEP-GIT-DEPENDENCY-001",
        title="Git URL dependency",
        severity=Severity.MEDIUM,
        category=Category.DEPENDENCY,
        confidence=Confidence.MEDIUM,
        description="A dependency is installed directly from a git repository.",
        impact="Git dependencies are mutable; the referenced code can change after review.",
        recommendation="Pin to a released version on an index, or pin the git ref to a commit "
        "hash you have reviewed.",
        group=GROUP,
        kinds=frozenset(_DEP),
    ),
    _GIT_DEP_RE,
)

_make_pattern_dep_rule(
    Rule(
        id="DEP-REMOTE-ARCHIVE-001",
        title="Remote archive dependency",
        severity=Severity.MEDIUM,
        category=Category.DEPENDENCY,
        confidence=Confidence.MEDIUM,
        description="A dependency is installed from a remote archive URL.",
        impact="Remote archives can be swapped out and are not verified against an index.",
        recommendation="Install from a trusted package index with a pinned version and hash.",
        group=GROUP,
        kinds=frozenset(_DEP),
    ),
    _ARCHIVE_RE,
)
