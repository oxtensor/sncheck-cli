# Contributing to SNCheck

Thanks for helping make Bittensor subnet repositories safer to run.

## Development setup

```bash
git clone https://github.com/sncheck/sncheck-cli
cd sncheck-cli
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the checks locally before opening a pull request:

```bash
ruff check .
ruff format --check .
pytest
```

## Writing a new rule

Every rule should include:

- A stable rule ID (for example `SH-CURL-BASH-001`).
- A clear title.
- A severity (`critical`, `high`, `medium`, `low`, `info`).
- A confidence (`low`, `medium`, `high`).
- What it detects.
- Why it matters for miners.
- A recommended fix or review action.
- A test fixture with at least one positive and one negative case.

Use neutral, evidence-first wording. Report risks, not accusations. See `docs/rule-authoring.md`.

## Principles

- **Miner-first:** output should help a miner decide what to do next.
- **Evidence-first:** show file, line, and pattern.
- **No secret collection:** never ask for wallet data.
- **No default execution:** treat every scanned repo as hostile input.
- **Open rules:** users should understand why a finding exists.

## Reporting bugs and false positives

Use the issue templates under `.github/ISSUE_TEMPLATE/`. False positives are valuable
feedback — please include the rule ID, the matched evidence, and why it should not fire.
