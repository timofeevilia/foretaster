"""FT-L001: a language model judged a tool definition to be steering the agent.

Unlike every other rule this one is optional and not deterministic: it runs
only when the user asks for it and needs a reviewer to be supplied.
"""

from collections.abc import Iterator

from foretaster.llm.review import Category, Reviewer, VerdictKind
from foretaster.models import Finding, Severity
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget

_WHAT = {
    Category.NONE: "The text was judged to steer the agent.",
    Category.HIDDEN_INSTRUCTION: "The text instructs the agent instead of describing the tool.",
    Category.DATA_EXFILTRATION: "The text makes the agent pass data to where it does not belong.",
    Category.CREDENTIAL_ACCESS: "The text makes the agent read keys, tokens or other credentials.",
    Category.CROSS_TOOL_MANIPULATION: "The text sets rules for tools that are not this server's.",
    Category.CONCEALMENT: "The text tells the agent to keep something from the user.",
    Category.DESTRUCTIVE_ACTION: "The text causes a destructive action as a side effect.",
    Category.OTHER: "The text was judged to steer the agent.",
}


class ReviewIncompleteError(Exception):
    """Some items could not be reviewed, so their absence from the findings means nothing."""


class LlmReview(Rule):
    meta = RuleMeta(
        id="FT-L001",
        title="A language model judged the tool text to steer the agent",
        severity=Severity.HIGH,
        description=(
            "With --llm, every tool definition is read by a language model, which reports "
            "text that directs the agent rather than describing the tool. It catches attacks "
            "written in ordinary language that no pattern matches. The verdict is a model's "
            "opinion, quoted with its reasoning; it is not deterministic."
        ),
        remediation=(
            "Read the quoted text yourself. If it tells the agent to do anything the tool's "
            "purpose does not explain, do not connect the server."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP06"]),
    )

    def __init__(self, reviewer: Reviewer) -> None:
        self.reviewer = reviewer

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        outcome = self.reviewer.review(target.inventories)
        for item, verdict in outcome.verdicts:
            if verdict.verdict is VerdictKind.BENIGN:
                continue
            inventory = target.inventories[item.inventory]
            definite = verdict.verdict is VerdictKind.MALICIOUS
            yield self.make(
                inventory.origin.path,
                f"{_WHAT[verdict.category]} Model's reasoning: {verdict.reason}",
                pointer=item.pointer,
                line=inventory.origin.line,
                server=inventory.server,
                tool=item.tool,
                evidence=verdict.quote or None,
                severity=Severity.HIGH if definite else Severity.MEDIUM,
            )
        if outcome.failures:
            first = outcome.failures[0]
            subject = first.item.tool or "server instructions"
            raise ReviewIncompleteError(
                f"{len(outcome.failures)} item(s) were not reviewed by the model; "
                f"first: {subject}: {first.reason}"
            )
