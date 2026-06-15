"""Docker rules: root user, privileged mode, and host mounts."""

from __future__ import annotations

import re
from typing import Iterable

from sncheck.file_inventory import FileKind
from sncheck.models import Category, Confidence, Finding, Severity
from sncheck.rules.base import FileContext, Rule, register, regex_line_rule, strip_evidence

GROUP = "docker"
_DOCKER = (FileKind.DOCKER,)

# USER root, but only when root is the *last* USER directive, is what really
# matters. For v0.1 we flag any explicit "USER root" and let the reader judge.
_USER_ROOT_RE = re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE)


def _user_root_check(ctx: FileContext) -> Iterable[Finding]:
    if ctx.kind != FileKind.DOCKER:
        return
    for lineno, line in enumerate(ctx.lines(), start=1):
        if _USER_ROOT_RE.match(line):
            yield _user_root_rule.make_finding(
                file=ctx.relative, line=lineno, evidence=strip_evidence(line)
            )


_user_root_rule = Rule(
    id="DOCKER-ROOT-USER-001",
    title="Container runs as root",
    severity=Severity.LOW,
    category=Category.DOCKER,
    confidence=Confidence.MEDIUM,
    description="The Dockerfile sets the container user to root.",
    impact="Running as root widens the blast radius if the container is compromised.",
    recommendation="Create and switch to a non-root user before running the application.",
    group=GROUP,
    check=_user_root_check,
    kinds=frozenset(_DOCKER),
)
register(_user_root_rule)


regex_line_rule(
    id="DOCKER-CURL-BASH-001",
    title="Remote script piped to shell in Dockerfile",
    severity=Severity.HIGH,
    category=Category.DOCKER,
    confidence=Confidence.HIGH,
    description="A Dockerfile RUN step downloads and pipes a script into a shell.",
    impact="Image builds execute remote code that is not pinned or inspected.",
    recommendation="Copy a pinned, reviewed script into the image and run it explicitly.",
    group=GROUP,
    kinds=_DOCKER,
    patterns=[r"(?:curl|wget)\s[^|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b"],
)

regex_line_rule(
    id="DOCKER-PRIVILEGED-001",
    title="Privileged container",
    severity=Severity.HIGH,
    category=Category.DOCKER,
    confidence=Confidence.HIGH,
    description="A compose file or run configuration requests privileged mode.",
    impact="Privileged containers can largely bypass isolation from the host.",
    recommendation="Avoid privileged mode. Grant only the specific capabilities required.",
    group=GROUP,
    kinds=_DOCKER,
    patterns=[r"privileged\s*:\s*true", r"--privileged\b"],
)

regex_line_rule(
    id="DOCKER-HOST-MOUNT-001",
    title="Sensitive host path mounted into container",
    severity=Severity.HIGH,
    category=Category.DOCKER,
    confidence=Confidence.MEDIUM,
    description="A container mounts the Docker socket or the host Bittensor directory.",
    impact="Mounting the Docker socket grants host control; mounting wallets exposes keys.",
    recommendation="Remove host mounts of /var/run/docker.sock and ~/.bittensor unless "
    "absolutely required and understood.",
    group=GROUP,
    kinds=_DOCKER,
    patterns=[r"/var/run/docker\.sock", r"\.bittensor\s*:\s*/", r":/root/\.bittensor"],
)
