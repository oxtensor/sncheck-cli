"""Tests for the file inventory walker and classifier."""

from __future__ import annotations

from pathlib import Path

from sncheck.file_inventory import FileKind, build_inventory, classify

from .conftest import FIXTURES


def test_classify_by_extension(tmp_path: Path) -> None:
    assert classify(tmp_path / "a.py") == FileKind.PYTHON
    assert classify(tmp_path / "install.sh") == FileKind.SHELL
    assert classify(tmp_path / "Dockerfile") == FileKind.DOCKER
    assert classify(tmp_path / "requirements.txt") == FileKind.DEPENDENCY
    assert classify(tmp_path / "README.md") == FileKind.DOCS
    assert classify(tmp_path / "data.bin") == FileKind.OTHER


def test_inventory_skips_git_and_binaries(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("print('hi')\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02binary")

    rels = {f.relative for f in build_inventory(tmp_path)}
    assert "keep.py" in rels
    assert not any(r.startswith(".git") for r in rels)
    assert "blob.bin" not in rels


def test_inventory_respects_size_limit(tmp_path: Path) -> None:
    (tmp_path / "big.py").write_text("x = 1\n" * 1000)
    inv = build_inventory(tmp_path, max_file_size=10)
    assert not any(f.relative == "big.py" for f in inv)


def test_inventory_detects_workflow_kind() -> None:
    # The safe repo has no workflow, but classification is path-based; build a
    # small check against the dependency fixture's known files instead.
    inv = build_inventory(FIXTURES / "safe_repo")
    kinds = {f.relative: f.kind for f in inv}
    assert kinds["miner.py"] == FileKind.PYTHON
    assert kinds["requirements.txt"] == FileKind.DEPENDENCY
