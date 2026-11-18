"""Built-in rules."""

from foretaster.rules.base import Rule, RuleMeta, ScanTarget
from foretaster.rules.cleartext import CleartextTransport
from foretaster.rules.filesystem import BroadFilesystemAccess
from foretaster.rules.parse_problems import ParseProblems
from foretaster.rules.secrets import PlaintextSecret
from foretaster.rules.shell import ShellCommand
from foretaster.rules.typosquat import TyposquattedPackage
from foretaster.rules.unpinned import UnpinnedPackage

ALL_RULES: tuple[type[Rule], ...] = (
    ParseProblems,
    PlaintextSecret,
    UnpinnedPackage,
    CleartextTransport,
    ShellCommand,
    TyposquattedPackage,
    BroadFilesystemAccess,
)

__all__ = ["ALL_RULES", "Rule", "RuleMeta", "ScanTarget"]
