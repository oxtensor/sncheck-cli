"""Scan configuration.

For v0.1, configuration is driven by CLI flags. This module centralizes the
defaults and the small set of options the pipeline reads so that file-based
config (``sncheck.toml``) can be layered on later without touching call sites.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# All built-in rule modules, by their category name.
ALL_RULE_GROUPS: tuple[str, ...] = (
    "bittensor",
    "shell",
    "python",
    "docker",
    "dependencies",
)

# Default maximum size for a text file we will read and scan (1 MB).
DEFAULT_MAX_FILE_SIZE = 1_000_000


@dataclass
class ScanConfig:
    """Options that control how a scan runs."""

    rules: tuple[str, ...] = ALL_RULE_GROUPS
    include_experimental: bool = False
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    disabled_rule_ids: frozenset[str] = field(default_factory=frozenset)

    def is_group_enabled(self, group: str) -> bool:
        return group in self.rules

    def is_rule_enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disabled_rule_ids
