"""JSON reporter.

Emits the stable machine-readable report described in the development guide.
Field order and the ``schema_version`` are part of the contract for downstream
platform ingestion.
"""

from __future__ import annotations

import json

from sncheck.models import ScanResult


def render(result: ScanResult) -> str:
    """Render a scan result as a pretty-printed JSON document."""
    payload = result.model_dump(mode="json", exclude_none=False)
    return json.dumps(payload, indent=2, ensure_ascii=False)
