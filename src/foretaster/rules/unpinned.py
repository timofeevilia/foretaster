import re
from collections.abc import Iterator

from foretaster.commandline import PackageRef, package_ref
from foretaster.models import Finding, Severity
from foretaster.redact import truncate
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

_EXACT_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.+-]+)?$")
_COMMIT = re.compile(r"[#@][0-9a-f]{7,40}$")


class UnpinnedPackage(Rule):
    meta = RuleMeta(
        id="FT-C002",
        title="Server package is not pinned to a version",
        severity=Severity.MEDIUM,
        description=(
            "The launcher downloads whatever the registry serves at start-up. If the "
            "package is hijacked or its maintainer turns hostile, the new code runs on "
            "the next launch with no review: the supply-chain form of a rug pull."
        ),
        remediation=(
            "Pin an exact version (npm `name@1.2.3`, PyPI `name==1.2.3`, a commit hash "
            "for git sources) or an image digest (`image@sha256:...`)."
        ),
        references=(OWASP_MCP["MCP04"],),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        for config, server in target.servers():
            ref = package_ref(server)
            if ref is None:
                continue
            problem = _unpinned_reason(ref)
            if problem:
                yield self.finding(
                    config,
                    f"{_ECOSYSTEM[ref.ecosystem]} {problem}.",
                    server=server,
                    evidence=truncate(ref.spec),
                )


_ECOSYSTEM = {"npm": "npm package", "pypi": "PyPI package", "docker": "Container image"}


def _unpinned_reason(ref: PackageRef) -> str | None:
    if ref.remote:
        return None if _COMMIT.search(ref.spec) else "is fetched from a URL without a commit hash"
    if ref.version is None:
        return "has no version"
    if ref.ecosystem == "docker":
        if ref.version == "latest":
            return "uses the mutable `latest` tag"
        return None
    if not _EXACT_VERSION.match(ref.version):
        return f"uses the floating version `{truncate(ref.version, 30)}`"
    return None
