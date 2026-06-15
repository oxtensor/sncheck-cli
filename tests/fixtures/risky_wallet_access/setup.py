"""Positive fixture for reading Bittensor wallet key files."""

import os


def load_wallet() -> bytes:
    # PY-WALLET-FILE-OPEN-001: opens a coldkey file under the wallet directory.
    with open(os.path.expanduser("~/.bittensor/wallets/default/coldkey"), "rb") as fh:
        return fh.read()


def safe_helper() -> str:
    # Negative line: no wallet access here.
    return "ok"
