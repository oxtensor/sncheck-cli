"""Bittensor-specific rules: wallet, hotkey, coldkey, mnemonic, and btcli usage.

Not every match is malicious. Severity is tuned by *where* the match appears:
documentation that mentions ``--wallet.name`` is informational, while Python or
shell code that opens files under ``~/.bittensor/wallets`` is high risk.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sncheck.file_inventory import FileKind
from sncheck.models import Category, Confidence, Finding, Severity
from sncheck.rules.base import FileContext, Rule, regex_line_rule, register, strip_evidence

GROUP = "bittensor"

_CODE_KINDS = (FileKind.PYTHON, FileKind.SHELL, FileKind.DOCKER, FileKind.WORKFLOW)

# Wallet directory path. In docs this is info; in code it is high risk.
_WALLET_PATH_RE = re.compile(r"(?:~|\$HOME|[\w./-]*)?[./]bittensor[\\/]wallets", re.IGNORECASE)


def _wallet_path_check(ctx: FileContext) -> Iterable[Finding]:
    in_docs = ctx.kind == FileKind.DOCS
    for lineno, line in enumerate(ctx.lines(), start=1):
        if _WALLET_PATH_RE.search(line):
            if in_docs:
                severity, confidence = Severity.LOW, Confidence.LOW
            else:
                severity, confidence = Severity.HIGH, Confidence.HIGH
            yield _wallet_path_rule.make_finding(
                file=ctx.relative,
                line=lineno,
                evidence=strip_evidence(line),
                severity=severity,
                confidence=confidence,
            )


_wallet_path_rule = Rule(
    id="BT-WALLET-PATH-001",
    title="Bittensor wallet path access",
    severity=Severity.HIGH,
    category=Category.BITTENSOR,
    confidence=Confidence.HIGH,
    description="Code references the default Bittensor wallet directory.",
    impact="Miner wallet files may be read, copied, modified, or exfiltrated.",
    recommendation="Review why this code accesses ~/.bittensor/wallets before running it on a "
    "machine with real wallets.",
    group=GROUP,
    check=_wallet_path_check,
    kinds=frozenset(),  # inspect every text file; severity depends on kind
)
register(_wallet_path_rule)


regex_line_rule(
    id="BT-MNEMONIC-REF-001",
    title="Mnemonic / seed phrase reference",
    severity=Severity.HIGH,
    category=Category.BITTENSOR,
    confidence=Confidence.MEDIUM,
    description="Code references a mnemonic or seed phrase.",
    impact="Mnemonics fully control a wallet. Handling them in code is a serious exposure risk.",
    recommendation="Confirm the mnemonic is never logged, transmitted, or written to disk.",
    group=GROUP,
    kinds=_CODE_KINDS,
    patterns=[r"\bmnemonic\b", r"\bseed[_\s-]?phrase\b"],
    flags=re.IGNORECASE,
)

regex_line_rule(
    id="BT-COLDKEY-REF-001",
    title="Coldkey reference in code",
    severity=Severity.MEDIUM,
    category=Category.BITTENSOR,
    confidence=Confidence.LOW,
    description="Code references a coldkey.",
    impact="The coldkey controls funds. Code that reads or moves it warrants review.",
    recommendation="Check whether this code reads, copies, or transmits coldkey material.",
    group=GROUP,
    kinds=_CODE_KINDS,
    patterns=[r"\bcoldkey\b"],
    flags=re.IGNORECASE,
    # Coldkey appears throughout normal wallet code; one awareness finding per
    # file is enough. The dedicated wallet-path / mnemonic rules carry the real
    # high-severity signal.
    per_file_once=True,
)

regex_line_rule(
    id="BT-HOTKEY-REF-001",
    title="Hotkey reference in code",
    severity=Severity.INFO,
    category=Category.BITTENSOR,
    confidence=Confidence.LOW,
    description="Code references a hotkey.",
    impact="Hotkeys are required by virtually every subnet (miners and validators sign with "
    "them). This is informational context, not a risk on its own.",
    recommendation="No action needed unless the hotkey is exported, written to disk, or sent "
    "over the network. Those cases are covered by higher-severity rules.",
    group=GROUP,
    kinds=_CODE_KINDS,
    patterns=[r"\bhotkey\b"],
    flags=re.IGNORECASE,
    # 'hotkey' is ubiquitous in subnet code. Emit at most one informational
    # finding per file instead of one per line.
    per_file_once=True,
)

regex_line_rule(
    id="BT-BTCLI-TRANSFER-001",
    title="btcli transfer command",
    severity=Severity.CRITICAL,
    category=Category.BITTENSOR,
    confidence=Confidence.HIGH,
    description="Code invokes 'btcli wallet transfer', which moves funds.",
    impact="An automated transfer can move TAO out of a miner's wallet.",
    recommendation="Do not run this until you understand the destination and amount of any "
    "transfer.",
    group=GROUP,
    kinds=_CODE_KINDS + (FileKind.DOCS,),
    patterns=[r"btcli\s+(?:wallet\s+)?transfer\b"],
)

regex_line_rule(
    id="BT-BTCLI-STAKE-001",
    title="btcli stake command",
    severity=Severity.MEDIUM,
    category=Category.BITTENSOR,
    confidence=Confidence.MEDIUM,
    description="Code invokes a 'btcli stake' command.",
    impact="Staking moves wallet balance into stake; automated staking should be intentional.",
    recommendation="Confirm any automated staking is expected and uses the correct hotkey.",
    group=GROUP,
    kinds=_CODE_KINDS + (FileKind.DOCS,),
    patterns=[r"btcli\s+stake\b", r"btcli\s+root\b"],
)

regex_line_rule(
    id="BT-BTCLI-WALLET-001",
    title="btcli wallet command",
    severity=Severity.LOW,
    category=Category.BITTENSOR,
    confidence=Confidence.LOW,
    description="Code or docs invoke a general 'btcli wallet' command.",
    impact="Wallet management commands are normal during setup but worth noting.",
    recommendation="Review which wallet operation is performed and on which wallet.",
    group=GROUP,
    kinds=_CODE_KINDS + (FileKind.DOCS,),
    patterns=[r"btcli\s+wallet\s+(?:create|new|regen|list|overview)\b"],
)
