import json
from pathlib import Path
from typing import Any

import pytest

from foretaster import config_loader
from foretaster.config_loader import ConfigLoadError, guess_client, load_config, parse_config
from foretaster.models import AgentConfig, Client, Scope, Transport

PATH = Path("mcp.json")


def parse(data: Any, **kwargs: Any) -> AgentConfig:
    return parse_config(json.dumps(data), path=kwargs.pop("path", PATH), **kwargs)


def test_stdio_server() -> None:
    config = parse(
        {
            "mcpServers": {
                "files": {
                    "command": "npx",
                    "args": ["-y", "@scope/server", 8080, True],
                    "env": {"TOKEN": "abc", "PORT": 1, "DEBUG": False},
                }
            }
        }
    )
    (server,) = config.servers
    assert server.name == "files"
    assert server.transport is Transport.STDIO
    assert server.command == "npx"
    assert server.args == ("-y", "@scope/server", "8080", "true")
    assert server.env == {"TOKEN": "abc", "PORT": "1", "DEBUG": "false"}
    assert server.enabled
    assert server.pointer == "/mcpServers/files"
    assert server.raw["command"] == "npx"
    assert config.problems == ()
    assert config.scope is Scope.USER


@pytest.mark.parametrize(
    ("entry", "transport"),
    [
        ({"url": "https://example.com/mcp"}, Transport.HTTP),
        ({"serverUrl": "https://example.com/mcp"}, Transport.HTTP),
        ({"httpUrl": "https://example.com/mcp"}, Transport.HTTP),
        ({"type": "sse", "url": "https://example.com/sse"}, Transport.SSE),
        ({"type": "Streamable-HTTP", "url": "https://example.com/mcp"}, Transport.HTTP),
        ({"transport": "stdio", "command": "x"}, Transport.STDIO),
    ],
)
def test_transport_detection(entry: dict[str, Any], transport: Transport) -> None:
    (server,) = parse({"mcpServers": {"s": entry}}).servers
    assert server.transport is transport
    if "command" not in entry:
        assert server.url is not None
        assert server.url.startswith("https://example.com/")


def test_headers_are_kept() -> None:
    (server,) = parse(
        {"mcpServers": {"s": {"url": "https://x", "headers": {"Authorization": "Bearer t"}}}}
    ).servers
    assert server.headers == {"Authorization": "Bearer t"}


@pytest.mark.parametrize("flag", [{"disabled": True}, {"enabled": False}])
def test_disabled_server(flag: dict[str, bool]) -> None:
    (server,) = parse({"mcpServers": {"s": {"command": "x", **flag}}}).servers
    assert not server.enabled


def test_vscode_layouts() -> None:
    project = parse({"servers": {"a": {"command": "x"}}})
    assert project.client is Client.VSCODE
    assert project.servers[0].pointer == "/servers/a"

    settings = parse({"mcp": {"servers": {"b": {"command": "y"}}}})
    assert settings.servers[0].pointer == "/mcp/servers/b"


def test_jsonc_input() -> None:
    text = '{\n  // my servers\n  "servers": {\n    "a": {"command": "x",},\n  },\n}'
    config = parse_config(text, path=Path(".vscode/mcp.json"))
    assert config.client is Client.VSCODE
    assert config.servers[0].line == 4


def test_claude_code_project_servers() -> None:
    config = parse(
        {
            "mcpServers": {"global": {"command": "g"}},
            "projects": {
                "/home/u/app": {"mcpServers": {"local": {"command": "l"}}},
                "/home/u/other": {"history": []},
                "/broken": "nope",
            },
        },
        path=Path(".claude.json"),
    )
    assert config.client is Client.CLAUDE_CODE
    assert [server.name for server in config.servers] == ["global", "local"]
    assert config.servers[1].pointer == "/projects/~1home~1u~1app/mcpServers/local"


def test_projects_key_ignored_for_other_clients() -> None:
    config = parse(
        {"projects": {"/p": {"mcpServers": {"local": {"command": "l"}}}}}, client=Client.CURSOR
    )
    assert config.servers == ()


def test_malformed_entries_become_problems() -> None:
    config = parse(
        {
            "mcpServers": {
                "not-object": "npx server",
                "empty": {},
                "bad-type": {"type": "carrier-pigeon", "command": "x"},
                "bad-fields": {
                    "command": ["x"],
                    "url": 5,
                    "args": "one two",
                    "env": ["A=1"],
                    "headers": {"H": None},
                },
                "bad-items": {"command": "x", "args": ["ok", {"no": 1}]},
            }
        }
    )
    assert [server.name for server in config.servers] == [
        "empty",
        "bad-type",
        "bad-fields",
        "bad-items",
    ]
    assert all(
        server.transport is Transport.UNKNOWN
        for server in config.servers
        if server.name != "bad-items"
    )
    assert config.servers[3].args == ("ok",)
    pointers = {problem.pointer for problem in config.problems}
    assert pointers == {
        "/mcpServers/not-object",
        "/mcpServers/empty",
        "/mcpServers/bad-type/type",
        "/mcpServers/bad-fields",
        "/mcpServers/bad-fields/command",
        "/mcpServers/bad-fields/url",
        "/mcpServers/bad-fields/args",
        "/mcpServers/bad-fields/env",
        "/mcpServers/bad-fields/headers/H",
        "/mcpServers/bad-items/args/1",
    }


def test_container_must_be_object() -> None:
    config = parse({"mcpServers": ["a"]})
    assert config.servers == ()
    assert config.problems[0].pointer == "/mcpServers"


def test_duplicate_keys_are_reported() -> None:
    text = '{"mcpServers": {"a": {"command": "safe"}, "a": {"command": "evil"}}}'
    config = parse_config(text, path=PATH)
    assert len(config.servers) == 1
    assert any("duplicate key 'a'" in problem.message for problem in config.problems)


def test_line_lookup() -> None:
    text = (
        '{\n  "mcpServers": {\n    "first": {"command": "x"},\n'
        '    "sec\\"ond": {"command": "y"}\n  }\n}'
    )
    config = parse_config(text, path=PATH)
    assert [server.line for server in config.servers] == [3, 4]
    assert config_loader._find_line(text, "absent") is None


@pytest.mark.parametrize("text", ["", "{", "[]", '"text"', "[" * 100_000])
def test_invalid_documents(text: str) -> None:
    with pytest.raises(ConfigLoadError) as excinfo:
        parse_config(text, path=PATH)
    assert excinfo.value.path == PATH
    assert str(PATH) in str(excinfo.value)


@pytest.mark.parametrize(
    ("path", "data", "client"),
    [
        ("Claude/claude_desktop_config.json", {}, Client.CLAUDE_DESKTOP),
        ("home/.claude.json", {}, Client.CLAUDE_CODE),
        ("repo/.mcp.json", {}, Client.CLAUDE_CODE),
        ("windsurf/mcp_config.json", {}, Client.WINDSURF),
        ("repo/.cursor/mcp.json", {}, Client.CURSOR),
        ("repo/.vscode/mcp.json", {}, Client.VSCODE),
        ("x/mcp.json", {"servers": {}}, Client.VSCODE),
        ("x/mcp.json", {"servers": {}, "mcpServers": {}}, Client.GENERIC),
        ("x/anything.json", {"mcpServers": {}}, Client.GENERIC),
    ],
)
def test_guess_client(path: str, data: dict[str, Any], client: Client) -> None:
    assert guess_client(Path(path), data) is client


def test_load_config_reads_file_with_bom(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"mcpServers": {"a": {"command": "x"}}}')
    config = load_config(path, client=Client.CURSOR, scope=Scope.PROJECT)
    assert config.path == path
    assert config.client is Client.CURSOR
    assert config.scope is Scope.PROJECT
    assert config.servers[0].name == "a"


def test_load_config_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigLoadError, match="not a regular file"):
        load_config(tmp_path / "missing.json")
    with pytest.raises(ConfigLoadError, match="not a regular file"):
        load_config(tmp_path)

    binary = tmp_path / "binary.json"
    binary.write_bytes(b"\xff\xfe\x00{")
    with pytest.raises(ConfigLoadError, match="not valid UTF-8"):
        load_config(binary)

    big = tmp_path / "big.json"
    big.write_text("{}")
    monkeypatch.setattr(config_loader, "MAX_CONFIG_BYTES", 1)
    with pytest.raises(ConfigLoadError, match="limit is 1"):
        load_config(big)


def test_load_config_os_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "mcp.json"
    path.write_text("{}")

    def deny(*args: object, **kwargs: object) -> str:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", deny)
    with pytest.raises(ConfigLoadError, match="cannot read file: Permission denied"):
        load_config(path)
