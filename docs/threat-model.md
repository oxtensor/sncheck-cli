# Threat Model

SNCheck focuses on risks a miner faces when cloning, installing, or running a
Bittensor subnet repository.

## Miner machine and wallet risks (v0.1 focus)

- **Wallet file theft** — code that reads `~/.bittensor/wallets`.
- **Hotkey / coldkey compromise** — references to key material in code.
- **Mnemonic exposure** — seed phrases handled, logged, or transmitted.
- **Remote code execution during setup** — `curl | bash`, base64-decoded payloads.
- **Malicious dependency installation** — unpinned, git, or remote-archive deps.
- **Docker host escape** — privileged containers, Docker socket or wallet mounts.
- **Dynamic execution** — `eval`, `exec`, `os.system`, `subprocess(shell=True)`, `pickle.load`.
- **Fund-moving commands** — `btcli transfer` / `btcli stake` run automatically.

## Repo-owner / incentive risks (later milestones)

- Hidden scoring advantages.
- Validation bypasses.
- Miner spoofing.
- Undisclosed centralized allowlists.
- Code paths that treat owner-controlled miners differently.

For v0.1, SNCheck targets the miner-machine and wallet-safety surface. Incentive
integrity checks are planned for a later milestone.

## What SNCheck does NOT do

- It does not execute repository code.
- It does not prove a repository is safe — only that known risky patterns are or
  are not present.
- It does not collect wallet data, mnemonics, or secrets.
