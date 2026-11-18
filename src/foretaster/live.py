"""Ask running MCP servers what they advertise.

This is the only part of Foretaster that executes or contacts anything, and it
runs only when the user asks for it. Starting a stdio server means running the
command from the configuration file, so the caller must have opted in.

The exchange is limited to ``initialize`` and ``tools/list``. No tool is ever
called.
"""

import os
from collections.abc import Sequence
from typing import Any, NamedTuple

from foretaster.models import AgentConfig, Location, ServerDefinition, ServerInventory, Transport
from foretaster.textscan import printable
from foretaster.tool_manifest import inventory_from_tools

DEFAULT_TIMEOUT = 30.0
MAX_PAGES = 50
MAX_TOOLS = 2000


class ConnectionFailure(NamedTuple):
    server: str
    reason: str


class LiveResult(NamedTuple):
    inventories: tuple[ServerInventory, ...]
    failures: tuple[ConnectionFailure, ...]


class ConnectUnavailableError(Exception):
    """The optional MCP client library is not installed."""


def collect(configs: Sequence[AgentConfig], *, timeout: float = DEFAULT_TIMEOUT) -> LiveResult:
    """Connect to every enabled server in ``configs`` and list its tools."""
    try:
        import anyio
        import mcp  # noqa: F401
    except ImportError as exc:
        raise ConnectUnavailableError(
            "connecting to servers needs the MCP client library: "
            "install it with `pip install 'foretaster[connect]'`"
        ) from exc

    async def run() -> LiveResult:
        inventories: list[ServerInventory] = []
        failures: list[ConnectionFailure] = []
        for config in configs:
            for server in config.servers:
                if not server.enabled:
                    continue
                try:
                    with anyio.fail_after(timeout):
                        instructions, tools = await _fetch(server)
                except TimeoutError:
                    failures.append(
                        ConnectionFailure(server.name, f"no answer within {timeout:g} seconds")
                    )
                except Exception as exc:
                    failures.append(ConnectionFailure(server.name, _describe(exc)))
                else:
                    origin = Location(path=config.path, pointer=server.pointer, line=server.line)
                    inventories.append(
                        inventory_from_tools(server.name, origin, tools, instructions)
                    )
        return LiveResult(tuple(inventories), tuple(failures))

    return anyio.run(run)


async def _fetch(server: ServerDefinition) -> tuple[str | None, list[dict[str, Any]]]:
    from contextlib import AsyncExitStack

    import httpx2
    from mcp import ClientSession, StdioServerParameters, types
    from mcp.client.sse import sse_client
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamable_http_client

    async with AsyncExitStack() as stack:
        if server.transport is Transport.STDIO and server.command:
            # The server's stderr is discarded: it is untrusted output that could
            # otherwise write escape sequences straight to the user's terminal.
            errlog = stack.enter_context(open(os.devnull, "w", encoding="utf-8"))  # noqa: SIM115
            parameters = StdioServerParameters(
                command=server.command, args=list(server.args), env=server.env or None
            )
            streams = await stack.enter_async_context(stdio_client(parameters, errlog=errlog))
        elif server.transport is Transport.SSE and server.url:
            streams = await stack.enter_async_context(
                sse_client(server.url, headers=server.headers or None)
            )
        elif server.transport is Transport.HTTP and server.url:
            client = await stack.enter_async_context(
                httpx2.AsyncClient(headers=server.headers or None, timeout=httpx2.Timeout(30.0))
            )
            streams = await stack.enter_async_context(
                streamable_http_client(server.url, http_client=client)
            )
        else:
            raise ValueError("server has no usable command or URL")

        session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        initialized = await session.initialize()

        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            page = await session.list_tools(params=params)
            for tool in page.tools:
                tools.append(
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.input_schema,
                    }
                )
            cursor = page.next_cursor
            if not cursor or len(tools) >= MAX_TOOLS:
                break
        return initialized.instructions, tools[:MAX_TOOLS]


def _describe(exc: BaseException) -> str:
    """Summarise an error from an untrusted server in one safe line."""
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    text = printable(str(exc)).strip()
    summary = f"{type(exc).__name__}: {text}" if text else type(exc).__name__
    return summary if len(summary) <= 200 else summary[:199] + "…"
