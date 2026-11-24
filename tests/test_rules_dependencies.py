"""Tests for dependency rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from sncheck.config import ScanConfig
from sncheck.models import Target, TargetType
from sncheck.scanner import scan_path


def _scan_dir(path: Path):
    target = Target(type=TargetType.LOCAL, raw=str(path), path=str(path))
    return scan_path(path, target, ScanConfig(rules=("dependencies",)))


@pytest.mark.parametrize("relative", ["requirements-dev.txt", "requirements/base.txt"])
def test_git_and_archive_deps_reported_in_secondary_requirements_files(
    tmp_path: Path, relative: str
) -> None:
    req = tmp_path / relative
    req.parent.mkdir(parents=True, exist_ok=True)
    req.write_text(
        "numpy==1.26.4\n"
        "git+https://github.com/attacker/bittensor.git@main#egg=bittensor\n"
        "https://example.com/pkgs/helper-0.1.tar.gz\n"
    )
    result = _scan_dir(tmp_path)
    found = {(f.id, f.file, f.line) for f in result.findings}
    assert ("DEP-GIT-DEPENDENCY-001", relative, 2) in found
    assert ("DEP-REMOTE-ARCHIVE-001", relative, 3) in found
