import re
from collections.abc import Iterator

from foretaster.models import Finding, Severity
from foretaster.rules.base import OWASP_MCP, Rule, RuleMeta, ScanTarget, TextItem
from foretaster.textscan import normalise, parameters, snippet

_OTHER_TOOLS = re.compile(
    r"\b(?:when(?:ever)?|before|after|instead\s+of|every\s+time|each\s+time|always|never)\b"
    r"[^.]{0,60}\b(?:any|all|other|another|every)\s+(?:mcp\s+)?(?:tools?|servers?)\b"
    r"|\bthis\s+(?:tool|server)\b[^.]{0,40}"
    r"\b(?:overrides?|takes?\s+(?:precedence|priority)|replaces?|supersedes?)\b",
    re.IGNORECASE,
)
# An identifier that looks like a tool name. Kebab-case counts only inside quotes,
# because unquoted it is indistinguishable from an ordinary compound word.
_BARE = r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+|[a-z][a-z0-9]*(?:[A-Z][a-z0-9]+)+"
_QUOTED = r"[`'\"][A-Za-z][\w-]*(?:[_-][A-Za-z0-9]+|[A-Z][a-z0-9]+)[\w-]*[`'\"]"
_NAME = rf"(?:{_QUOTED}|{_BARE})"
# A tool-shaped name counts as a reference to a tool when it follows a verb of
# calling or precedes the word "tool". Keywords match in any case; names stay
# case-sensitive so camelCase can be recognised.
_TOOL_REFERENCE = re.compile(
    r"(?i:\b(?:calls?|calling|called|use|uses|using|used|via|invoke|invokes|invoking|run|runs"
    rf"|running|execute|executing|with|checking|through)\s+(?:the\s+)?)(?P<a>{_NAME})"
    rf"|(?P<b>{_NAME})(?i:\s+(?:tool|function|requests?|calls?|invocations?)\b)"
    rf"|(?i:\bwhen(?:ever)?\s+(?:the\s+)?)(?P<c>{_NAME})(?i:\s+is\b)"
)
# Only mandatory phrasing counts. "If unsure, use X" is advice; "before Y, use X" and
# "you must call X" are orders.
_MANDATORY = re.compile(
    r"\b(?:must|shall|should|always|never|mandatory|required|before|when(?:ever)?|instead"
    r"|all|any|every|each)\b",
    re.IGNORECASE,
)
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_QUOTE = r"[`'\"]"
_ARGUMENT_DIRECTIVE = re.compile(
    r"\b(?:change|modify|set|replace|override|rewrite|append|prepend|alter)\b[^.]{0,40}?"
    rf"{_QUOTE}?(?P<name>[A-Za-z_][\w-]*){_QUOTE}?\s+(?:parameter|argument|param|arg|field)\b",
    re.IGNORECASE,
)
_NOT_A_NAME = frozenset({"the", "a", "an", "this", "that", "each", "every", "any", "its", "your"})
_MIN_NAME_LENGTH = 5


class ToolShadowing(Rule):
    meta = RuleMeta(
        id="FT-T006",
        title="Tool text tries to control other tools",
        severity=Severity.HIGH,
        description=(
            "The text gives orders about tools that are not its own: it names a tool of "
            "another server, tells the model to call a tool this server does not provide, "
            "dictates the arguments of someone else's call, or sets rules for tools in "
            "general. A server should describe only its own tools. This pattern, called "
            "tool shadowing, lets a harmless-looking server change how the model uses a "
            "trusted one, for example by redirecting every e-mail."
        ),
        remediation=(
            "Do not run this server next to servers that handle anything sensitive, or remove it."
        ),
        references=(OWASP_MCP["MCP03"], OWASP_MCP["MCP06"]),
    )

    def check(self, target: ScanTarget) -> Iterator[Finding]:
        owners: dict[str, set[str]] = {}
        own: dict[str, set[str]] = {}
        for inventory in target.inventories:
            for tool in inventory.tools:
                owners.setdefault(tool.name, set()).add(inventory.server)
                own.setdefault(inventory.server, set()).add(_key(tool.name))

        for item in target.texts():
            text = normalise(item.text)
            foreign = sorted(
                name
                for name, servers in owners.items()
                if item.inventory.server not in servers and _distinctive(name)
            )
            named = next(
                (
                    (name, match)
                    for name in foreign
                    if (match := re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text))
                ),
                None,
            )
            if named:
                name, match = named
                other = ", ".join(sorted(owners[name]))
                yield self.text_finding(
                    item,
                    f"The {item.label} mentions the tool {name!r}, which belongs to "
                    f"another server ({other}).",
                    evidence=snippet(text, match.start(), match.end()),
                )
                continue
            local = self._local_evidence(item, text, own.get(item.inventory.server, set()))
            if local:
                message, start, end = local
                yield self.text_finding(
                    item,
                    message,
                    evidence=snippet(text, start, end),
                    severity=Severity.MEDIUM,
                )

    def _local_evidence(
        self, item: TextItem, text: str, own_tools: set[str]
    ) -> tuple[str, int, int] | None:
        """Look for control over foreign tools using only this server's own inventory."""
        own_parameters = (
            {_key(name) for name in parameters(item.tool.input_schema)} if item.tool else set()
        )
        family = _name_prefixes(item)
        offset = 0
        for sentence in _SENTENCE_END.split(text):
            start = text.index(sentence, offset)
            offset = start + len(sentence)
            if not _MANDATORY.search(sentence):
                continue
            for match in _TOOL_REFERENCE.finditer(sentence):
                name = next(group for group in match.groups() if group).strip("`'\"")
                if (
                    _key(name) in own_tools
                    or _key(name) in own_parameters
                    or _prefix(name) in family
                ):
                    continue
                return (
                    f"The {item.label} gives orders about the tool {name!r}, which this "
                    "server does not provide.",
                    start + match.start(),
                    start + match.end(),
                )
        if item.tool is not None:
            for match in _ARGUMENT_DIRECTIVE.finditer(text):
                name = match.group("name")
                if name.lower() in _NOT_A_NAME or _key(name) in own_parameters:
                    continue
                return (
                    f"The {item.label} dictates the value of {name!r}, which is not a "
                    "parameter of this tool.",
                    match.start(),
                    match.end(),
                )
        generic = _OTHER_TOOLS.search(text)
        if generic:
            return (
                f"The {item.label} sets rules for tools it does not own.",
                generic.start(),
                generic.end(),
            )
        return None


def _prefix(name: str) -> str:
    """The leading segment of a tool name, such as ``github`` in ``github_create_issue``."""
    head = re.split(r"[_-]", name, maxsplit=1)[0].lower()
    return head if head != name.lower() else ""


def _name_prefixes(item: TextItem) -> set[str]:
    """Prefixes shared by at least two of the server's own tools.

    A name carrying the server's own prefix is treated as one of its tools even
    when it is missing from the list, since servers often mention sibling tools.
    """
    counts: dict[str, int] = {}
    for tool in item.inventory.tools:
        prefix = _prefix(tool.name)
        if prefix:
            counts[prefix] = counts.get(prefix, 0) + 1
    return {prefix for prefix, count in counts.items() if count >= 2}


def _key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _distinctive(name: str) -> bool:
    """Skip names that are ordinary words and would match innocent prose."""
    return len(name) >= _MIN_NAME_LENGTH and (
        "_" in name or "-" in name or name != name.lower() or len(name) >= 12
    )
