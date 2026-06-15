"""Bittensor-specific rules: wallet, hotkey, coldkey, mnemonic, and btcli usage.

Referencing the wallet directory, a hotkey, or a coldkey is *expected* in nearly
every subnet repo, so a plain reference is treated as low/info context. The real
risk is what code *does* with wallet material: reading the coldkey/mnemonic and
sending it over the network (BT-WALLET-EXFIL-001), or copying the wallet
directory off the machine (BT-WALLET-COPY-001). Those carry the high/critical
severities.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sncheck.file_inventory import FileKind
from sncheck.models import Category, Confidence, Finding, Severity
from sncheck.rules.base import FileContext, Rule, regex_line_rule, register, strip_evidence

GROUP = "bittensor"

_CODE_KINDS = (FileKind.PYTHON, FileKind.SHELL, FileKind.DOCKER, FileKind.WORKFLOW)
_DOC_AND_CODE = _CODE_KINDS + (FileKind.DOCS,)


# -- BT-WALLET-PATH-001: a plain reference to the wallet directory ------------
# Expected in essentially every subnet repo (config defaults, env vars, docs),
# so this is informational context, not a risk on its own.
regex_line_rule(
    id="BT-WALLET-PATH-001",
    title="Bittensor wallet directory reference",
    severity=Severity.LOW,
    category=Category.BITTENSOR,
    confidence=Confidence.LOW,
    description="Code or config references the default Bittensor wallet directory.",
    impact="Referencing the wallet directory is normal in subnet repos. It only becomes a risk "
    "if wallet files are read and their contents then leave the machine.",
    recommendation="No action needed for a plain path reference. Review only if wallet files "
    "are read and copied or transmitted (see BT-WALLET-EXFIL-001, BT-WALLET-COPY-001).",
    group=GROUP,
    kinds=_DOC_AND_CODE,
    patterns=[r"(?:~|\$HOME|[\w./-]*)?[./]bittensor[\\/]wallets"],
    flags=re.IGNORECASE,
    per_file_once=True,
)


# -- BT-WALLET-EXFIL-001: read key material AND send it over the network ------
# This is the actual wallet-theft pattern. We only treat *key material* as a
# secret (opening a wallet file, a coldkey file, or a mnemonic) -- not a plain
# path or a hotkey, since subnet code legitimately signs and makes network
# calls. A finding requires both a secret read and a network sink in one file.
_WALLET_SECRET_RE = re.compile(
    r"open\s*\([^)]*\.bittensor[\\/]wallets"  # opening a wallet file
    r"|\.bittensor[\\/]wallets[\\/][^\s'\"]*coldkey"  # path to a coldkey file
    r"|\bcoldkey\b[^\n]*\.(?:read|load|export|save|dump)"  # reading/exporting a coldkey
    r"|\bmnemonic\b",  # any mnemonic handling
    re.IGNORECASE,
)
_NET_SINK_RE = re.compile(
    r"requests\.(?:get|post|put|patch)\s*\("
    r"|httpx\."
    r"|urllib\.request"
    r"|aiohttp\."
    r"|socket\.socket"
    r"|smtplib\.|ftplib\.|paramiko\.|boto3"
    r"|api\.telegram\.org"
    r"|discord(?:app)?\.com/api/webhooks"
    r"|hooks\.slack\.com"
    r"|pastebin\.com"
    r"|\bcurl\b|\bwget\b|\bscp\b|\bnc\b",
    re.IGNORECASE,
)


def _wallet_exfil_check(ctx: FileContext) -> Iterable[Finding]:
    if ctx.kind not in (FileKind.PYTHON, FileKind.SHELL):
        return
    secret: tuple[int, str] | None = None
    has_sink = False
    for lineno, line in enumerate(ctx.lines(), start=1):
        if secret is None and _WALLET_SECRET_RE.search(line):
            secret = (lineno, line)
        if _NET_SINK_RE.search(line):
            has_sink = True
    if secret is not None and has_sink:
        yield _wallet_exfil_rule.make_finding(
            file=ctx.relative, line=secret[0], evidence=strip_evidence(secret[1])
        )


_wallet_exfil_rule = Rule(
    id="BT-WALLET-EXFIL-001",
    title="Wallet key material read alongside a network sink",
    severity=Severity.CRITICAL,
    category=Category.BITTENSOR,
    confidence=Confidence.MEDIUM,
    description="A file reads wallet key material (a wallet file, coldkey, or mnemonic) and "
    "also contains code that sends data over the network.",
    impact="This is the pattern used to steal wallets: read the key or mnemonic, then upload "
    "it to a remote server.",
    recommendation="Verify the key material is never included in any outbound request. Do not "
    "run this on a machine with real wallets until you have confirmed it is safe.",
    group=GROUP,
    check=_wallet_exfil_check,
    kinds=frozenset((FileKind.PYTHON, FileKind.SHELL)),
)
register(_wallet_exfil_rule)


# -- BT-WALLET-COPY-001: copy/archive/stream the wallet directory ------------
regex_line_rule(
    id="BT-WALLET-COPY-001",
    title="Wallet directory copied or archived",
    severity=Severity.HIGH,
    category=Category.BITTENSOR,
    confidence=Confidence.MEDIUM,
    description="A shell command copies, archives, or streams the Bittensor wallet directory.",
    impact="Copying the wallet directory is a common step in stealing keys, especially to /tmp "
    "or a remote host.",
    recommendation="Confirm why the wallet directory is copied. Treat copies to /tmp or a "
    "remote host as key theft until proven otherwise.",
    group=GROUP,
    kinds=(FileKind.SHELL, FileKind.DOCKER, FileKind.WORKFLOW),
    patterns=[
        r"\b(?:cp|mv|rsync|scp|sftp|tar|zip)\b[^\n]*\.bittensor",
        r"\bcat\b[^\n]*\.bittensor[\\/]wallets",
        r"\.bittensor[\\/]?[^\n|]*\|\s*(?:nc|ncat|curl|wget)\b",
    ],
    flags=re.IGNORECASE,
)


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
    severity=Severity.LOW,
    category=Category.BITTENSOR,
    confidence=Confidence.LOW,
    description="Code references a coldkey.",
    impact="The coldkey controls funds, but referencing it (type fields, config, comments) is "
    "normal. The risk is reading and transmitting it, which BT-WALLET-EXFIL-001 covers.",
    recommendation="No action for a plain reference. Review only if the coldkey file is read "
    "and its contents leave the machine.",
    group=GROUP,
    kinds=_CODE_KINDS,
    patterns=[r"\bcoldkey\b"],
    flags=re.IGNORECASE,
    # Coldkey appears throughout normal wallet code; one awareness finding per
    # file is enough.
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
