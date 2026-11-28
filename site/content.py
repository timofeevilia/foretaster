"""Page text. Plain text only: the builder escapes every value."""

REPOSITORY = "https://github.com/timofeevilia/foretaster"
COMMAND = "uvx --from git+https://github.com/timofeevilia/foretaster foretaster scan"

CONTENT: dict[str, str] = {
    "title": "Foretaster: check the tools connected to an AI assistant",
    "description": "An open-source scanner that checks AI agent configurations and MCP tool "
    "descriptions for hidden commands. The check on this page runs in your browser.",
    "nav_how": "How the attack works",
    "nav_try": "Try it",
    "nav_measured": "Measurements",
    "hero_eyebrow": "Open-source scanner for AI agents",
    "hero_title": "Foretaster checks the tools connected to an AI assistant for hidden "
    "commands before the assistant reads them",
    "hero_lead": "It reads agent configuration files and the descriptions of connected "
    "tools, and reports poisoned descriptions, exposed keys and risky settings. The check "
    "on this page runs entirely in your browser, so nothing you paste leaves your computer.",
    "hero_try": "Try it on this page",
    "hero_code": "Code on GitHub",
    "how_eyebrow": "How the attack works",
    "how_title": "A tool's description is read by the model, not by a person",
    "how_intro": "Connecting a tool to an assistant looks like installing a plug-in, and it "
    "carries a risk that is easy to miss.",
    "how_1": "A tool is connected to the assistant and gives it access to, for example, "
    "mail, files or a calendar.",
    "how_2": "The tool arrives with a text saying what it can do, and the model reads that "
    "text in full as an instruction.",
    "how_3": "If a command is hidden in the text, such as reading the file with the keys "
    "and not reporting it, the assistant may carry it out.",
    "try_eyebrow": "Try it",
    "try_title": "Paste an agent configuration or a tool list and see what the scanner reports",
    "try_intro": "The field accepts the configuration file of Claude Desktop, Claude Code, "
    "Cursor, VS Code or Windsurf, or a saved list of a server's tools. Two examples with "
    "typical problems are provided.",
    "try_example_config": "Example: risky configuration",
    "try_example_tools": "Example: poisoned tool",
    "try_run": "Check",
    "try_placeholder": "Paste JSON here",
    "try_privacy": "The scanner is downloaded once, about 15 MB, and then runs on your "
    "device. This page is not allowed to connect to any other site, and it stores nothing.",
    "ui_loading": "Loading the scanner, about 15 MB, which is needed only once.",
    "ui_scanning": "Checking.",
    "ui_done": "Done.",
    "ui_failed": "The scanner could not be started:",
    "ui_empty": "The field is empty. Paste a configuration or load an example.",
    "ui_unreadable": "The text could not be read:",
    "ui_scanned": "Checked {servers} server(s) and {tools} tool(s). Findings:",
    "ui_clean": "none.",
    "ui_line": "line",
    "ui_server": "server",
    "ui_tool": "tool",
    "ui_fix": "Fix:",
    "finds_eyebrow": "What it looks for",
    "finds_title": "Nineteen checks in three groups",
    "finds_1_title": "Tool descriptions",
    "finds_1": "Instructions addressed to the model, invisible characters, references to "
    "key files, requests to hide an action from the user, parameters built to carry data "
    "out, and attempts to control the tools of another server.",
    "finds_2_title": "Configuration",
    "finds_2": "Keys and tokens stored in plain text, packages downloaded without a fixed "
    "version, connections without encryption, servers started through a shell script, "
    "look-alike package names and access to the whole disk.",
    "finds_3_title": "Changes and combinations",
    "finds_3": "A description that changed after it was approved, identical tool names on "
    "different servers, and an assistant that can at once read private data, take in "
    "outside content and send data out.",
    "measured_eyebrow": "Measurements",
    "measured_title": "A high result is obtained on attacks whose devices were already known",
    "measured_intro": "The scanner was measured on two public collections of attacks. The "
    "figures differ almost threefold, and both are shown because either one alone would "
    "mislead.",
    "chart_1_title": "First collection",
    "chart_1_text": "Attacks from the collection on which the rules were improved; the "
    "figures are for the part set aside and not looked at.",
    "chart_2_title": "Second collection",
    "chart_2_text": "Attacks by three other authors, never used for tuning.",
    "bar_before": "before tuning",
    "bar_after": "after tuning",
    "bar_devices": "recognisable devices",
    "bar_plain": "plain language",
    "bar_all": "all attacks",
    "of": "of",
    "caveat_1": "Rules based on patterns find attacks whose wording someone has already "
    "seen. Attacks written in ordinary business language mostly pass.",
    "caveat_2": "On the first collection {fp_hits} of {fp_total} genuine tools was flagged "
    "by mistake. In the second, {trap_hits} of {trap_total} harmless tool lists were "
    "flagged; they were written as traps, such as a manager of SSH keys.",
    "caveat_3": "An automatic check supplements caution about what is connected to an "
    "assistant and does not replace it.",
    "measured_link": "Method, limits and full tables",
    "run_eyebrow": "On your own machine",
    "run_title": "One command checks every agent configuration found on the computer",
    "run_intro": "It needs the free uv tool and installs nothing permanently. The scanner "
    "only reads files, it does not start or contact any server unless asked to, and its "
    "reports can be read by GitHub code scanning.",
    "footer_license": "Open source under the Apache-2.0 licence.",
    "footer_code": "Source code",
    "footer_security": "Report a vulnerability",
    "footer_benchmark": "Benchmark",
}
