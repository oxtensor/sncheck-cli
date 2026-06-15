"""Built-in rule set.

Importing this package registers every built-in rule via side effect, so the
registry is fully populated as soon as ``sncheck.rules`` is imported.
"""

from __future__ import annotations

from sncheck.rules import bittensor, dependencies, docker, python, shell  # noqa: F401
from sncheck.rules.base import REGISTRY, Rule, all_rules

__all__ = ["REGISTRY", "Rule", "all_rules"]
