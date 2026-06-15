# Scoring

## Severity levels

| Severity | Meaning |
| --- | --- |
| `critical` | Likely direct key theft, remote code execution, or destructive wallet action. |
| `high` | Dangerous behavior that could compromise miner machines or wallet material. |
| `medium` | Risky behavior needing manual review. |
| `low` | Weak practice or unusual behavior. |
| `info` | Useful context, not necessarily risky. |

## Overall risk

The overall risk is derived from the worst finding present:

- **Critical** if any critical finding exists.
- **High** if any high finding exists.
- **Medium** if any medium finding exists.
- **Low** if only low/info findings exist.
- **Clean** if there are no findings.
- **Unknown** if the scan failed or the target could not be inspected.

SNCheck avoids the word "Safe". A clean scan is reported as
"No high-risk findings detected".

## Confidence

Confidence (`low`/`medium`/`high`) is independent of severity. It reflects how
sure the rule is that a match is a true signal rather than incidental text. A
high-severity, low-confidence finding still deserves a look but is more likely a
false positive.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed; no finding reached the fail threshold. |
| 1 | Scan completed; a finding reached the `--fail-on` threshold. |
| 2 | Invalid CLI usage. |
| 3 | Target could not be fetched or inspected. |
| 4 | Internal error. |

Without `--fail-on`, `sncheck check` exits 0 unless the scan fails internally.
