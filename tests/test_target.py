"""Tests for target resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from sncheck.models import TargetType
from sncheck.target import TargetError, resolve_target


def test_resolve_local_path(tmp_path: Path) -> None:
    target = resolve_target(str(tmp_path))
    assert target.type == TargetType.LOCAL
    assert target.path == str(tmp_path.resolve())


def test_resolve_github_url() -> None:
    target = resolve_target("https://github.com/example/subnet")
    assert target.type == TargetType.GITHUB
    assert (target.owner, target.repo) == ("example", "subnet")
    assert target.url == "https://github.com/example/subnet"


def test_resolve_github_url_with_git_suffix() -> None:
    target = resolve_target("https://github.com/example/subnet.git")
    assert (target.owner, target.repo) == ("example", "subnet")


def test_resolve_gh_shorthand() -> None:
    target = resolve_target("gh:example/subnet")
    assert target.type == TargetType.GITHUB
    assert (target.owner, target.repo) == ("example", "subnet")


def test_resolve_bare_shorthand() -> None:
    target = resolve_target("example/subnet")
    assert target.type == TargetType.GITHUB


@pytest.mark.parametrize(
    "raw",
    [
        "./miner",
        "../miner",
        "../../subnets/miner",
        "./src/miner",
        "~/miner",
        "~sncheck-no-such-user/miner",
        "/sncheck-does-not-exist/miner",
    ],
)
def test_missing_local_path_is_not_github_shorthand(
    raw: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Path-like targets that do not exist must fail with a clear error instead
    # of resolving to e.g. https://github.com/./miner and cloning that.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(TargetError, match=r"^Local path does not exist: "):
        resolve_target(raw)


def test_existing_dot_relative_path_resolves_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "miner").mkdir()
    monkeypatch.chdir(tmp_path)
    target = resolve_target("./miner")
    assert target.type == TargetType.LOCAL
    assert target.path == str((tmp_path / "miner").resolve())


@pytest.mark.parametrize("raw", ["opentensor/bittensor", "src/miner", "gh:example/subnet"])
def test_missing_owner_repo_still_resolves_to_github(
    raw: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert resolve_target(raw).type == TargetType.GITHUB


def test_resolve_rejects_garbage() -> None:
    with pytest.raises(TargetError):
        resolve_target("not a target!!")


def test_resolve_rejects_empty() -> None:
    with pytest.raises(TargetError):
        resolve_target("   ")
