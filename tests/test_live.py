import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from foretaster import live
from foretaster.cli import app
from foretaster.config_loader import parse_config
from foretaster.live import ConnectUnavailableError, collect
from foretaster.models import AgentConfig

pytest.importorskip("mcp")

FAKE_SERVER = str(Path(__file__).parent / "fixtures" / "fake_server.py")
runner = CliRunner()


def servers(call_log: Path, **modes: str) -> dict[str, object]:
    return {
        "mcpServers": {
            name: {
                "command": sys.executable,
                "args": [FAKE_SERVER, mode],
                "env": {"CALL_LOG": str(call_log)},
            }
            for name, mode in modes.items()
        }
    }


def config(call_log: Path, **modes: str) -> AgentConfig:
    return parse_config(json.dumps(servers(call_log, **modes)), path=Path("mcp.json"))


def test_lists_all_pages_and_never_calls_a_tool(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.log"
    result = collect([config(call_log, math="poisoned")], timeout=30)

    assert result.failures == ()
    (inventory,) = result.inventories
    assert inventory.server == "math"
    assert inventory.instructions == "Use the math tools."
    assert [tool.name for tool in inventory.tools] == ["add", "multiply"]
    assert inventory.origin.pointer == "/mcpServers/math"
    assert not call_log.exists()


def test_one_broken_server_does_not_stop_the_others(tmp_path: Path) -> None:
    result = collect(
        [config(tmp_path / "calls.log", down="crash", up="poisoned", slow="hang")], timeout=2
    )
    assert [inventory.server for inventory in result.inventories] == ["up"]
    failures = dict(result.failures)
    assert set(failures) == {"down", "slow"}
    assert failures["slow"] == "no answer within 2 seconds"
    assert failures["down"].isprintable()


def test_endless_pagination_is_cut_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "MAX_PAGES", 5)
    result = collect([config(tmp_path / "calls.log", s="endless")], timeout=30)
    assert len(result.inventories[0].tools) == 5

    monkeypatch.setattr(live, "MAX_TOOLS", 3)
    result = collect([config(tmp_path / "calls.log", s="endless")], timeout=30)
    assert len(result.inventories[0].tools) == 3


def test_disabled_and_unusable_servers(tmp_path: Path) -> None:
    text = json.dumps(
        {
            "mcpServers": {
                "off": {"command": sys.executable, "args": [FAKE_SERVER], "disabled": True},
                "empty": {},
                "sse": {"type": "sse", "url": "http://127.0.0.1:9/sse"},
                "http": {"url": "http://127.0.0.1:9/mcp"},
            }
        }
    )
    result = collect([parse_config(text, path=Path("mcp.json"))], timeout=10)
    assert result.inventories == ()
    failures = dict(result.failures)
    assert set(failures) == {"empty", "sse", "http"}
    assert failures["empty"] == "ValueError: server has no usable command or URL"


def test_missing_client_library(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "mcp", None)
    with pytest.raises(ConnectUnavailableError, match="foretaster\\[connect\\]"):
        collect([])

    result = runner.invoke(app, ["scan", "--tools", __file__, "--connect"])
    assert result.exit_code == 2
    assert "foretaster[connect]" in result.output


def test_error_descriptions_are_single_safe_lines() -> None:
    group = ExceptionGroup("outer", [RuntimeError("bad\x1b[2J\nnews")])
    assert live._describe(group) == "RuntimeError: bad\\u001b[2J news"
    assert live._describe(KeyError()) == "KeyError"
    assert len(live._describe(RuntimeError("x" * 500))) == 200


def test_scan_connect_reports_live_findings(tmp_path: Path) -> None:
    call_log = tmp_path / "calls.log"
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(servers(call_log, math="poisoned", down="crash"), indent=2))

    result = runner.invoke(app, ["scan", str(path), "--connect", "--format", "json"])

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["summary"]["servers"] == 2
    assert payload["summary"]["tools"] == 2
    live_findings = [finding for finding in payload["findings"] if finding["tool"]]
    assert {finding["rule_id"] for finding in live_findings} == {"FT-T001", "FT-T003", "FT-T004"}
    assert {finding["location"]["path"] for finding in live_findings} == {str(path)}
    assert all(finding["location"]["line"] == 3 for finding in live_findings)
    assert [(error["kind"], error["subject"]) for error in payload["errors"]] == [
        ("server", "down")
    ]
    assert not call_log.exists()

    text = runner.invoke(app, ["scan", str(path), "--connect"]).output
    assert "Could not connect to server down" in text
