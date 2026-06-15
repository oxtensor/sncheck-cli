# Rule Authoring

Every rule lives in a group module under `sncheck/rules/` and registers itself
with the rule registry on import.

## Required metadata

Each rule must define:

- A stable rule ID (e.g. `SH-CURL-BASH-001`). Never reuse or renumber an ID.
- A clear title (e.g. "Bittensor wallet path access", not "Bad code found").
- A severity: `critical`, `high`, `medium`, `low`, or `info`.
- A confidence: `low`, `medium`, or `high`.
- What it detects (`description`).
- Why it matters for miners (`impact`).
- A recommended fix or review action (`recommendation`).
- At least one positive and one negative test fixture.

## Two ways to write a rule

### 1. Line-based regex rule

Use `regex_line_rule(...)` for "if a line looks like X, raise a finding":

```python
regex_line_rule(
    id="SH-CURL-BASH-001",
    title="Remote script piped to shell",
    severity=Severity.HIGH,
    category=Category.SHELL,
    confidence=Confidence.HIGH,
    description="...",
    impact="...",
    recommendation="...",
    group="shell",
    kinds=(FileKind.SHELL, FileKind.DOCKER),
    patterns=[r"curl\s[^|]*\|\s*(?:bash|sh)\b"],
)
```

### 2. Custom check function

For AST analysis, multi-line context, or severity that depends on file kind,
build a `Rule` with your own `check` function and call `register(rule)`. The
Python rules use `ast` to match real call sites; the wallet-path rule raises a
different severity in docs versus code.

### 3. Repo-level rule

Set `repo_check` instead of `check` to reason about the whole inventory (for
example, "a dependency manifest exists but no lockfile").

## Wording

Report risks, not accusations. Prefer "high risk finding" and "manual review
recommended" over "scam" or "malicious owner".

## Recommendation quality

Good: "Review why this script reads `~/.bittensor/wallets`. Do not run it on a
machine with real wallets until the access is explained."

Poor: "Delete this repo."
