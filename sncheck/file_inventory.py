"""Walk a repository and classify the files worth scanning.

The inventory deliberately skips VCS metadata, virtual environments, vendored
dependencies, binaries, and oversized text files so that rules only ever see a
bounded amount of plain-text input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from sncheck.config import DEFAULT_MAX_FILE_SIZE


class FileKind(str, Enum):
    """Coarse classification used by rules to decide what to inspect."""

    PYTHON = "python"
    SHELL = "shell"
    DOCKER = "docker"
    DEPENDENCY = "dependency"
    WORKFLOW = "workflow"
    DOCS = "docs"
    OTHER = "other"


# Directory names to skip entirely, anywhere in the tree.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        ".tox",
        "dist",
        "build",
        ".eggs",
    }
)

_PY_EXTS = {".py"}
_SHELL_EXTS = {".sh", ".bash", ".zsh"}
_DEP_FILES = {"requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "setup.cfg"}
_DOC_EXTS = {".md", ".rst", ".txt"}

# pip requirement/constraint files other than the canonical requirements.txt:
# requirements-dev.txt, requirements_test.txt, dev-requirements.txt,
# constraints.txt, pip-tools inputs (*.in), and anything in a requirements/ dir.
# These share the .txt extension with docs, so they need an explicit match.
_REQ_EXTS = {".txt", ".in"}
_REQ_STEM_RE = re.compile(
    r"^(?:requirements|constraints)(?:[-_.].*)?$|[-_.](?:requirements|constraints)$"
)


@dataclass
class InventoryFile:
    """A single classified file in the inventory."""

    path: Path
    relative: str
    kind: FileKind
    size: int


def _is_requirements_file(path: Path) -> bool:
    if path.suffix.lower() not in _REQ_EXTS:
        return False
    if path.parent.name.lower() == "requirements":
        return True
    return _REQ_STEM_RE.search(path.stem.lower()) is not None


def classify(path: Path) -> FileKind:
    """Classify a single file by name, extension, and parent directory.

    Pass the path relative to the repository root so the parent-directory check
    never sees directories above the repo.
    """
    name = path.name.lower()
    suffix = path.suffix.lower()

    if suffix in _PY_EXTS:
        return FileKind.PYTHON
    if suffix in _SHELL_EXTS:
        return FileKind.SHELL
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return FileKind.DOCKER
    if name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return FileKind.DOCKER
    if name in _DEP_FILES or name == "requirements.txt" or name.endswith(".lock"):
        return FileKind.DEPENDENCY
    if _is_requirements_file(path):
        return FileKind.DEPENDENCY
    if suffix in _DOC_EXTS:
        return FileKind.DOCS
    return FileKind.OTHER


def _is_workflow(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    parts = rel.parts
    return (
        len(parts) >= 3
        and parts[0] == ".github"
        and parts[1] == "workflows"
        and path.suffix.lower() in {".yml", ".yaml"}
    )


def _looks_binary(path: Path) -> bool:
    """Heuristic: a file is binary if its first chunk contains a NUL byte."""
    try:
        with path.open("rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return True
    return b"\x00" in chunk


def build_inventory(root: Path, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> list[InventoryFile]:
    """Walk ``root`` and return the files that rules should inspect."""
    inventory: list[InventoryFile] = []
    root = root.resolve()

    for path in _walk(root):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_file_size:
            continue

        relative = path.relative_to(root)
        kind = FileKind.WORKFLOW if _is_workflow(path, root) else classify(relative)

        # Only skip-binary check for files we might actually read as text.
        if _looks_binary(path):
            continue

        inventory.append(
            InventoryFile(
                path=path,
                relative=str(relative),
                kind=kind,
                size=size,
            )
        )

    inventory.sort(key=lambda f: f.relative)
    return inventory


def _walk(root: Path):
    """Yield files under ``root``, pruning skipped directories."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                # Do not follow symlinks; they can escape the repo tree.
                continue
            if entry.is_dir():
                if entry.name in SKIP_DIRS:
                    continue
                stack.append(entry)
            elif entry.is_file():
                yield entry
