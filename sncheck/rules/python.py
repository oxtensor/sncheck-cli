"""Python rules: dynamic execution and unsafe subprocess / deserialization usage.

These rules prefer AST analysis so that they match real call sites rather than
incidental text. When a file cannot be parsed (invalid or partial Python), each
rule falls back to a regex scan so coverage degrades gracefully.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from sncheck.file_inventory import FileKind
from sncheck.models import Category, Confidence, Finding, Severity
from sncheck.rules.base import FileContext, Rule, regex_line_rule, register, strip_evidence

GROUP = "python"
_PY = (FileKind.PYTHON,)


def _evidence_at(ctx: FileContext, line: int | None) -> str:
    if line is None:
        return ""
    lines = ctx.lines()
    if 1 <= line <= len(lines):
        return strip_evidence(lines[line - 1])
    return ""


def _call_name(node: ast.Call) -> str | None:
    """Return a dotted call target like 'os.system' or 'eval'.

    Returns None unless the callee is a plain name or an attribute chain rooted
    at a name. A method on a call result or subscript (``load().eval()``,
    ``layers[0].eval()``) has no static dotted name, and reducing it to the bare
    method name would make it indistinguishable from the ``eval`` builtin.
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = [func.attr]
        cur: ast.expr = func.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            return None
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _ast_rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    category: Category,
    confidence: Confidence,
    description: str,
    impact: str,
    recommendation: str,
    matcher,
    fallback_patterns: list[str],
) -> Rule:
    """Register a rule that walks the AST, with a regex fallback on parse failure."""
    import re

    compiled = [re.compile(p) for p in fallback_patterns]

    def check(ctx: FileContext) -> Iterable[Finding]:
        if ctx.kind != FileKind.PYTHON:
            return
        try:
            tree = ast.parse(ctx.text)
        except SyntaxError:
            for lineno, line in enumerate(ctx.lines(), start=1):
                if any(p.search(line) for p in compiled):
                    yield rule.make_finding(
                        file=ctx.relative, line=lineno, evidence=strip_evidence(line)
                    )
            return
        for node in ast.walk(tree):
            line = matcher(node)
            if line is not None:
                yield rule.make_finding(
                    file=ctx.relative, line=line, evidence=_evidence_at(ctx, line)
                )

    rule = Rule(
        id=id,
        title=title,
        severity=severity,
        category=category,
        confidence=confidence,
        description=description,
        impact=impact,
        recommendation=recommendation,
        group=GROUP,
        check=check,
        kinds=frozenset(_PY),
    )
    return register(rule)


def _match_subprocess_shell(node: ast.AST) -> int | None:
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        } and _has_shell_true(node):
            return node.lineno
    return None


def _match_os_system(node: ast.AST) -> int | None:
    if isinstance(node, ast.Call) and _call_name(node) in {"os.system", "os.popen"}:
        return node.lineno
    return None


def _match_eval_exec(node: ast.AST) -> int | None:
    if isinstance(node, ast.Call) and _call_name(node) in {"eval", "exec"}:
        return node.lineno
    return None


def _match_pickle_load(node: ast.AST) -> int | None:
    if isinstance(node, ast.Call) and _call_name(node) in {"pickle.load", "pickle.loads"}:
        return node.lineno
    return None


_ast_rule(
    id="PY-SUBPROCESS-SHELL-001",
    title="subprocess called with shell=True",
    severity=Severity.MEDIUM,
    category=Category.PYTHON,
    confidence=Confidence.HIGH,
    description="A subprocess call uses shell=True.",
    impact="If any argument is attacker-influenced, this enables shell command injection.",
    recommendation="Pass arguments as a list and avoid shell=True, or sanitize all inputs.",
    matcher=_match_subprocess_shell,
    fallback_patterns=[r"subprocess\.\w+\([^)]*shell\s*=\s*True"],
)

_ast_rule(
    id="PY-OS-SYSTEM-001",
    title="os.system / os.popen call",
    severity=Severity.MEDIUM,
    category=Category.PYTHON,
    confidence=Confidence.HIGH,
    description="Code runs a shell command through os.system or os.popen.",
    impact="Shell commands run with the process privileges and can be injection-prone.",
    recommendation="Prefer subprocess with an argument list. Validate any dynamic input.",
    matcher=_match_os_system,
    fallback_patterns=[r"\bos\.system\s*\(", r"\bos\.popen\s*\("],
)

_ast_rule(
    id="PY-EVAL-EXEC-001",
    title="Use of eval() or exec()",
    severity=Severity.HIGH,
    category=Category.PYTHON,
    confidence=Confidence.HIGH,
    description="Code dynamically evaluates or executes a string.",
    impact="If the evaluated string is influenced by remote data, this is remote code execution.",
    recommendation="Remove eval/exec or replace with explicit, safe parsing.",
    matcher=_match_eval_exec,
    # The lookbehind skips methods of the same name, e.g. PyTorch's model.eval().
    fallback_patterns=[r"(?<!\.)\beval\s*\(", r"(?<!\.)\bexec\s*\("],
)

_ast_rule(
    id="PY-PICKLE-LOAD-001",
    title="Unsafe pickle deserialization",
    severity=Severity.HIGH,
    category=Category.PYTHON,
    confidence=Confidence.MEDIUM,
    description="Code deserializes data with pickle.",
    impact="Loading a pickle from an untrusted source can execute arbitrary code.",
    recommendation="Do not unpickle untrusted data. Use a safe format such as JSON.",
    matcher=_match_pickle_load,
    fallback_patterns=[r"\bpickle\.loads?\s*\("],
)


# Wallet file opens are a Bittensor concern but only meaningful in Python code.
regex_line_rule(
    id="PY-WALLET-FILE-OPEN-001",
    title="Opening a Bittensor wallet file",
    severity=Severity.HIGH,
    category=Category.PYTHON,
    confidence=Confidence.MEDIUM,
    description="Python code opens a path under the Bittensor wallet directory.",
    impact="Reading wallet files can expose key material.",
    recommendation="Review why wallet files are opened and ensure key material is never copied "
    "or transmitted.",
    group=GROUP,
    kinds=_PY,
    patterns=[
        r"open\s*\([^)]*\.bittensor[\\/]wallets",
        r"open\s*\([^)]*coldkey(?!pub)",
        r"(?:read_text|read_bytes)\s*\([^)]*\.bittensor[\\/]wallets",
    ],
)
