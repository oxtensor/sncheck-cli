# SNCheck CLI

SNCheck helps miners inspect Bittensor subnet repositories before cloning, installing, or running them.

SNCheck does **not** certify that a repository is safe. It reports suspicious patterns and
Bittensor-specific risk signals so users can review them before running code.

## Install

```bash
pipx install sncheck
```

Or from source:

```bash
git clone https://github.com/sncheck/sncheck-cli
cd sncheck-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
sncheck check https://github.com/example/subnet
sncheck check ./local-subnet-repo
sncheck check https://github.com/example/subnet --format json
sncheck check ./local-subnet-repo --fail-on high
```

Other commands:

```bash
sncheck rules list
sncheck rules explain SH-CURL-BASH-001
sncheck version
```

### Reducing noise

Some patterns (like `hotkey`) appear throughout normal subnet code. SNCheck keeps
these quiet: `hotkey`/`coldkey` references produce at most one finding per file,
and `hotkey` is reported as `info` (context, not risk). By default the report
shows findings at `low` and above; the summary at the bottom always reflects the
full counts.

```bash
sncheck check <target>                      # default: low and above
sncheck check <target> --min-severity medium  # only medium+ (cut more noise)
sncheck check <target> --min-severity info    # show everything, including hotkey context
sncheck check <target> --rules shell,python   # only run specific groups
```

## What It Detects

High-signal wallet risks (the operations that actually steal keys):

- **Wallet exfiltration** — reading a coldkey/mnemonic and sending it over the network (critical)
- **Wallet directory copy** — `cp`/`tar`/`scp` of `~/.bittensor` off the machine (high)
- **Reading wallet key files** — opening coldkey/wallet files (high)
- **Fund-moving commands** — `btcli transfer` / `btcli stake` (critical/medium)

Other risks:

- Remote scripts piped to shell (`curl ... | bash`), base64-decoded payloads
- Python dynamic execution (`eval`, `exec`, `os.system`, `subprocess(shell=True)`, `pickle.load`)
- Docker install risks (root user, privileged, host mounts)
- Dependency hygiene issues (missing lockfiles, unpinned/remote dependencies)

Referencing the wallet directory, a hotkey, or a coldkey is **expected** in nearly
every subnet repo, so SNCheck treats a plain reference as low/info context — not a
risk. The high/critical severities are reserved for code that *does* something
dangerous with wallet material.

## Example Output

```text
Overall risk: High

[HIGH] SH-CURL-BASH-001 Remote script piped to shell
File: setup.sh:12
Evidence: curl https://example.com/install.sh | bash
```

## Limitations

- SNCheck performs **static** analysis only. It never executes scanned repository code.
- A clean report does not guarantee a repository is safe. Rules detect *known* risky
  patterns, not every possible threat.
- Some findings are context-dependent and require manual review. SNCheck uses neutral,
  evidence-first wording and points you to the file and line so you can decide.

## Security

Do not report live exploit details for active subnet repositories in public issues before
maintainers have had a chance to respond. See [SECURITY.md](SECURITY.md).

## License

Apache-2.0
