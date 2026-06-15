# Development

## Setup

```bash
git clone https://github.com/sncheck/sncheck-cli
cd sncheck-cli
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running checks

```bash
ruff check .
ruff format --check .
pytest
```

## Architecture

SNCheck is a small pipeline:

```text
target -> resolve -> fetch (clone or local) -> file inventory -> rule engine -> scoring -> reporter
```

| Module | Responsibility |
| --- | --- |
| `sncheck/target.py` | Resolve a target string; shallow-clone remote repos (never executes repo code). |
| `sncheck/file_inventory.py` | Walk and classify files; skip VCS dirs, venvs, binaries, oversized files. |
| `sncheck/rules/` | The rule engine (`base.py`) and built-in rule groups. |
| `sncheck/scoring.py` | Summary counts and overall risk level. |
| `sncheck/reporters/` | Text (Rich) and JSON renderers. |
| `sncheck/scanner.py` | Glue: runs the full pipeline. |
| `sncheck/cli.py` | Typer CLI and exit codes. |

## Safety invariant

SNCheck must never execute scanned repository code. Files are only read as text,
clones are shallow with hardened git environment variables, and symlinks are not
followed during inventory.
