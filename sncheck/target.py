"""Target resolution and repository fetching.

Resolves a user-provided target string into normalized :class:`Target` metadata
and, for remote GitHub repos, shallow-clones it into a temporary directory.

Security note: this module never executes repository code. Cloning uses ``git``
with no checkout hooks beyond what git itself performs.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sncheck.models import Target, TargetType

# https://github.com/owner/repo(.git)(/...) or owner/repo shorthand.
_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)
_GH_SHORTHAND_RE = re.compile(r"^gh:(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$")
_BARE_SHORTHAND_RE = re.compile(r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$")


class TargetError(Exception):
    """Raised when a target cannot be resolved or fetched."""


def resolve_target(raw: str) -> Target:
    """Resolve a raw target string into normalized metadata.

    Recognizes GitHub URLs, ``gh:owner/repo`` shorthand, bare ``owner/repo``
    shorthand, and local filesystem paths. A target that can only be a path
    (``./x``, ``../x``, ``~/x``, ``/x``) but does not exist is reported as a
    missing path rather than tried as GitHub shorthand.
    """
    raw = raw.strip()
    if not raw:
        raise TargetError("Empty target.")

    # Local path takes priority if it actually exists on disk.
    try:
        candidate: Path | None = Path(raw).expanduser()
    except RuntimeError:  # "~user/..." for an unknown user
        candidate = None
    if candidate is not None and candidate.exists():
        if not candidate.is_dir():
            raise TargetError(f"Local target is not a directory: {raw}")
        return Target(
            type=TargetType.LOCAL,
            raw=raw,
            path=str(candidate.resolve()),
        )

    if _is_path_like(raw):
        raise TargetError(f"Local path does not exist: {raw}")

    owner_repo = _match_github(raw)
    if owner_repo is not None:
        owner, repo = owner_repo
        return Target(
            type=TargetType.GITHUB,
            raw=raw,
            owner=owner,
            repo=repo,
            url=f"https://github.com/{owner}/{repo}",
        )

    raise TargetError(
        f"Could not resolve target {raw!r}. Expected a local path, a GitHub URL, "
        "or 'owner/repo' shorthand."
    )


def _is_path_like(raw: str) -> bool:
    """Whether ``raw`` can only be a filesystem path, never a GitHub target.

    True for home-relative and absolute paths, and for paths whose first
    component is ``.`` or ``..``, which the bare ``owner/repo`` pattern would
    otherwise accept as an owner (``./miner`` -> ``github.com/./miner``).
    """
    if raw.startswith("~") or Path(raw).is_absolute():
        return True
    return re.split(r"[\\/]", raw, maxsplit=1)[0] in {".", ".."}


def _match_github(raw: str) -> tuple[str, str] | None:
    for pattern in (_GITHUB_URL_RE, _GH_SHORTHAND_RE, _BARE_SHORTHAND_RE):
        m = pattern.match(raw)
        if m:
            return m.group("owner"), m.group("repo")
    return None


@dataclass
class FetchedRepo:
    """A repository ready to scan on the local filesystem."""

    path: Path
    commit: str | None
    # Temp dir to clean up, or None for local targets we should not delete.
    cleanup_dir: Path | None


def fetch_target(target: Target) -> FetchedRepo:
    """Make ``target`` available on the local filesystem for scanning."""
    if target.type == TargetType.LOCAL:
        assert target.path is not None
        return FetchedRepo(
            path=Path(target.path), commit=_read_commit(Path(target.path)), cleanup_dir=None
        )
    return _clone_github(target)


def _clone_github(target: Target) -> FetchedRepo:
    if shutil.which("git") is None:
        raise TargetError("git is required to clone remote repositories but was not found.")

    tmp = Path(tempfile.mkdtemp(prefix="sncheck-"))
    dest = tmp / "repo"
    assert target.url is not None
    try:
        _run_git(["clone", "--depth", "1", target.url, str(dest)])
    except TargetError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return FetchedRepo(path=dest, commit=_read_commit(dest), cleanup_dir=tmp)


def _read_commit(repo: Path) -> str | None:
    if not (repo / ".git").exists():
        return None
    try:
        out = _run_git(["-C", str(repo), "rev-parse", "HEAD"])
    except TargetError:
        return None
    return out.strip() or None


def _run_git(args: list[str]) -> str:
    """Run a git command with a hardened environment.

    We disable interactive prompts and any ``GIT_*`` hooks/askpass that could
    cause git to run external programs while fetching untrusted repos.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    env["GCM_INTERACTIVE"] = "never"
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - env dependent
        raise TargetError(f"git command failed: {exc}") from exc
    if proc.returncode != 0:
        raise TargetError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def cleanup(fetched: FetchedRepo) -> None:
    """Remove any temporary directory created for a remote clone."""
    if fetched.cleanup_dir is not None:
        shutil.rmtree(fetched.cleanup_dir, ignore_errors=True)
