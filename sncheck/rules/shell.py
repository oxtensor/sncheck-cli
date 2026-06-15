"""Shell rules: remote execution and other dangerous install behavior."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sncheck.file_inventory import FileKind
from sncheck.models import Category, Confidence, Finding, Severity
from sncheck.rules.base import FileContext, Rule, regex_line_rule, register, strip_evidence

GROUP = "shell"

# Files where shell commands realistically appear.
_SHELL_KINDS = (FileKind.SHELL, FileKind.DOCKER, FileKind.WORKFLOW, FileKind.DOCS)

regex_line_rule(
    id="SH-CURL-BASH-001",
    title="Remote script piped to shell",
    severity=Severity.HIGH,
    category=Category.SHELL,
    confidence=Confidence.HIGH,
    description="A remote script is downloaded with curl and piped directly into a shell.",
    impact="Remote code can execute during installation with no chance to inspect it first.",
    recommendation="Download the script, read it, and run it explicitly instead of piping "
    "curl output into bash/sh.",
    group=GROUP,
    kinds=_SHELL_KINDS,
    patterns=[r"curl\s[^|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b"],
)

regex_line_rule(
    id="SH-WGET-SH-001",
    title="Remote script piped to shell via wget",
    severity=Severity.HIGH,
    category=Category.SHELL,
    confidence=Confidence.HIGH,
    description="A remote script is downloaded with wget and piped directly into a shell.",
    impact="Remote code can execute during installation with no chance to inspect it first.",
    recommendation="Download the script, read it, and run it explicitly instead of piping "
    "wget output into bash/sh.",
    group=GROUP,
    kinds=_SHELL_KINDS,
    patterns=[r"wget\s[^|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b"],
)

regex_line_rule(
    id="SH-BASE64-EXEC-001",
    title="Base64-decoded content piped to shell",
    severity=Severity.CRITICAL,
    category=Category.SHELL,
    confidence=Confidence.HIGH,
    description="Base64-encoded data is decoded and piped into a shell.",
    impact="Hidden, obfuscated code can execute. This is a common way to disguise payloads.",
    recommendation="Decode the payload and inspect it. Do not run obfuscated install steps "
    "on a machine with wallets.",
    group=GROUP,
    kinds=_SHELL_KINDS,
    patterns=[r"base64\s+(?:-d|--decode)\b[^|]*\|\s*(?:bash|sh)\b"],
)

regex_line_rule(
    id="SH-EVAL-001",
    title="Shell eval of command substitution",
    severity=Severity.MEDIUM,
    category=Category.SHELL,
    confidence=Confidence.MEDIUM,
    description="A shell script evaluates the output of a command substitution.",
    impact="Dynamically generated commands run with the script's privileges.",
    recommendation="Confirm what is being evaluated. Avoid eval of remote or generated input.",
    group=GROUP,
    kinds=_SHELL_KINDS,
    patterns=[r"\beval\s+[\"']?\$\("],
)

regex_line_rule(
    id="SH-REMOTE-SCRIPT-001",
    title="Remote script downloaded then executed",
    severity=Severity.HIGH,
    category=Category.SHELL,
    confidence=Confidence.MEDIUM,
    description="A file is made executable and run on the same line, often after download.",
    impact="A freshly fetched script may run without review.",
    recommendation="Inspect the downloaded script before making it executable and running it.",
    group=GROUP,
    kinds=_SHELL_KINDS,
    patterns=[r"chmod\s+\+x\s+\S+\s*&&\s*\./"],
)

regex_line_rule(
    id="SH-SUDO-INSTALL-001",
    title="Privileged package installation",
    severity=Severity.LOW,
    category=Category.SHELL,
    confidence=Confidence.MEDIUM,
    description="The installer runs a package manager with sudo.",
    impact="System-wide changes are made with root privileges during setup.",
    recommendation="Review which packages are installed and why root is required.",
    group=GROUP,
    kinds=_SHELL_KINDS,
    patterns=[r"sudo\s+(?:apt|apt-get|yum|dnf|pip|pip3)\s+install\b"],
)

# SH-RM-RF-001 needs a little context: a forced recursive delete of a build or
# package cache (the standard 'rm -rf /var/lib/apt/lists/*' Docker cleanup) is
# benign, while one targeting the wallet/home directory is a real risk.
_RM_RF_RE = re.compile(r"\brm\s+-rf\b|\brm\s+-fr\b")
_RM_BENIGN_RE = re.compile(
    r"/var/lib/apt/lists|/var/cache/|/tmp/|node_modules|__pycache__|\.cache|"
    r"\bbuild\b|\bdist\b|\.egg-info|\*\.pyc",
    re.IGNORECASE,
)
_RM_WALLET_RE = re.compile(r"\.bittensor|~|\$HOME|/root\b|/home/", re.IGNORECASE)


def _rm_rf_check(ctx: FileContext) -> Iterable[Finding]:
    if ctx.kind not in _SHELL_KINDS:
        return
    for lineno, line in enumerate(ctx.lines(), start=1):
        if not _RM_RF_RE.search(line):
            continue
        if _RM_BENIGN_RE.search(line):
            continue  # standard cache/build cleanup, not a risk
        if _RM_WALLET_RE.search(line):
            severity, confidence = Severity.HIGH, Confidence.HIGH
        else:
            severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        yield _rm_rf_rule.make_finding(
            file=ctx.relative,
            line=lineno,
            evidence=strip_evidence(line),
            severity=severity,
            confidence=confidence,
        )


_rm_rf_rule = Rule(
    id="SH-RM-RF-001",
    title="Destructive recursive removal",
    severity=Severity.MEDIUM,
    category=Category.SHELL,
    confidence=Confidence.MEDIUM,
    description="The script performs a forced recursive delete outside the usual build/package "
    "caches.",
    impact="Files can be destroyed irreversibly. Targeting a home or wallet path can wipe "
    "wallet data.",
    recommendation="Confirm the target path. Be especially cautious of 'rm -rf' on home or "
    "wallet directories.",
    group=GROUP,
    check=_rm_rf_check,
    kinds=frozenset(_SHELL_KINDS),
)
register(_rm_rf_rule)
