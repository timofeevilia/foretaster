"""Built-in rules."""

from foretaster.rules.base import Rule, RuleMeta, ScanTarget
from foretaster.rules.cleartext import CleartextTransport
from foretaster.rules.combos import LethalTrifecta, OpenRemoteServer
from foretaster.rules.drift import ChangedSinceBaseline, ToolNameCollision
from foretaster.rules.filesystem import BroadFilesystemAccess
from foretaster.rules.llm_review import LlmReview
from foretaster.rules.parse_problems import ParseProblems
from foretaster.rules.secrets import PlaintextSecret
from foretaster.rules.shell import ShellCommand
from foretaster.rules.tool_params import ExfiltrationParameter
from foretaster.rules.tool_shadowing import ToolShadowing
from foretaster.rules.tool_shape import AbnormalLength, EncodedPayload
from foretaster.rules.tool_text import Concealment, HiddenInstructions, SensitiveFileReference
from foretaster.rules.tool_unicode import InvisibleCharacters
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
    HiddenInstructions,
    InvisibleCharacters,
    SensitiveFileReference,
    Concealment,
    ExfiltrationParameter,
    ToolShadowing,
    EncodedPayload,
    AbnormalLength,
    ChangedSinceBaseline,
    ToolNameCollision,
    OpenRemoteServer,
    LethalTrifecta,
)

OPTIONAL_RULES: tuple[type[Rule], ...] = (LlmReview,)
"""Rules that run only on request and need something supplied to them."""

__all__ = ["ALL_RULES", "OPTIONAL_RULES", "LlmReview", "Rule", "RuleMeta", "ScanTarget"]
