"""Positive fixture for Bittensor wallet path access."""

import os


def load_wallet() -> bytes:
    # BT-WALLET-PATH-001 / PY-WALLET-FILE-OPEN-001: reads wallet key material.
    wallet_dir = os.path.expanduser("~/.bittensor/wallets/default/coldkey")
    with open(wallet_dir, "rb") as fh:
        return fh.read()


def safe_helper() -> str:
    # Negative line: no wallet access here.
    return "ok"
