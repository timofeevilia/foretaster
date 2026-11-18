"""Interpret the command line of a stdio server without running it."""

import re
from collections.abc import Sequence
from typing import NamedTuple

from foretaster.models import ServerDefinition

_VALUE_FLAGS: dict[str, frozenset[str]] = {
    "npm": frozenset({"-p", "--package", "-c", "--call", "--registry", "--cache"}),
    "pypi": frozenset(
        {
            "--from",
            "--with",
            "--spec",
            "-p",
            "--python",
            "--index",
            "--index-url",
            "--extra-index-url",
            "--pip-args",
            "--directory",
        }
    ),
    "docker": frozenset(
        {
            "-e",
            "--env",
            "--env-file",
            "-v",
            "--volume",
            "--mount",
            "-p",
            "--publish",
            "-w",
            "--workdir",
            "-u",
            "--user",
            "--name",
            "--network",
            "--entrypoint",
            "-l",
            "--label",
            "--platform",
            "--add-host",
            "--cap-add",
            "--cap-drop",
            "--memory",
            "-m",
            "--cpus",
            "--pull",
            "--security-opt",
            "--tmpfs",
            "-h",
            "--hostname",
        }
    ),
}
_PACKAGE_FLAGS = {"npm": ("--package", "-p"), "pypi": ("--from", "--spec"), "docker": ()}
_REMOTE_SPEC = re.compile(
    r"^(?:[a-z+]+://|git\+|github:|gitlab:|bitbucket:|file:|\.{0,2}/|~)", re.I
)
_PYPI_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(.*)$")


class Invocation(NamedTuple):
    """A program and its arguments, with platform wrappers removed."""

    program: str
    args: tuple[str, ...]


class PackageRef(NamedTuple):
    """A package or image that a launcher fetches before running it."""

    ecosystem: str
    """``npm``, ``pypi`` or ``docker``."""
    name: str
    version: str | None
    """Version, tag or digest as written; ``None`` when absent."""
    remote: bool
    """True when the spec is a URL, git reference or path rather than a registry name."""
    spec: str


def program_name(command: str) -> str:
    """Normalise a command to a bare lowercase program name."""
    name = re.split(r"[\\/]", command.strip())[-1].lower()
    return re.sub(r"\.(exe|cmd|bat|ps1)$", "", name)


def invocation(server: ServerDefinition) -> Invocation | None:
    """Return what the server actually runs, unwrapping ``cmd /c`` and ``env``."""
    if not server.command:
        return None
    program = program_name(server.command)
    args = list(server.args)
    if program == "cmd" and len(args) >= 2 and args[0].lower() in {"/c", "/k"}:
        program, args = program_name(args[1]), args[2:]
    elif program == "env":
        while args and "=" in args[0] and not args[0].startswith("-"):
            args.pop(0)
        if not args:
            return None
        program, args = program_name(args[0]), args[1:]
    return Invocation(program, tuple(args))


def package_ref(server: ServerDefinition) -> PackageRef | None:
    """Identify the package a launcher such as ``npx`` or ``uvx`` would fetch."""
    inv = invocation(server)
    if inv is None:
        return None
    program, args = inv
    if program in {"npx", "bunx"}:
        return _from_launcher("npm", args)
    if program in {"pnpm", "yarn"} and args[:1] == ("dlx",):
        return _from_launcher("npm", args[1:])
    if program in {"npm", "bun"} and args[:1] in {("exec",), ("x",)}:
        return _from_launcher("npm", args[1:])
    if program == "uvx":
        return _from_launcher("pypi", args)
    if program == "uv" and args[:2] == ("tool", "run"):
        return _from_launcher("pypi", args[2:])
    if program == "pipx" and args[:1] == ("run",):
        return _from_launcher("pypi", args[1:])
    if program in {"docker", "podman", "nerdctl"} and "run" in args:
        return _from_launcher("docker", args[args.index("run") + 1 :])
    return None


def _from_launcher(ecosystem: str, args: Sequence[str]) -> PackageRef | None:
    spec = _package_spec(args, _VALUE_FLAGS[ecosystem], _PACKAGE_FLAGS[ecosystem])
    if not spec:
        return None
    if ecosystem == "docker":
        return _parse_image(spec)
    if _REMOTE_SPEC.match(spec) or (
        ecosystem == "npm" and "/" in spec and not spec.startswith("@")
    ):
        return PackageRef(ecosystem, spec, None, True, spec)
    if ecosystem == "npm":
        at = spec.find("@", 1)
        name, version = (spec, None) if at == -1 else (spec[:at], spec[at + 1 :])
        return PackageRef("npm", name, version or None, False, spec)
    match = _PYPI_SPEC.match(spec)
    if match is None:
        return None
    constraint = match.group(2).strip()
    if constraint.startswith("=="):
        constraint = constraint[2:].strip()
    elif constraint.startswith("@"):
        constraint = constraint[1:].strip()
    return PackageRef("pypi", match.group(1), constraint or None, False, spec)


def _package_spec(
    args: Sequence[str], value_flags: frozenset[str], package_flags: Sequence[str]
) -> str | None:
    """Return the explicit package flag's value, else the first positional argument."""
    positional: str | None = None
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            if positional is None and index + 1 < len(args):
                positional = args[index + 1]
            break
        if arg.startswith("-") and len(arg) > 1:
            flag, _, inline = arg.partition("=")
            if flag in package_flags:
                value = inline or (args[index + 1] if index + 1 < len(args) else "")
                if value:
                    return value
            if flag in value_flags and not inline:
                index += 1
        elif positional is None:
            positional = arg
        index += 1
    return positional


def _parse_image(spec: str) -> PackageRef:
    name, _, digest = spec.partition("@")
    tag: str | None = None
    colon = name.rfind(":")
    if colon > name.rfind("/"):
        name, tag = name[:colon], name[colon + 1 :]
    return PackageRef("docker", name, digest or tag or None, False, spec)
