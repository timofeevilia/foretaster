"""Benchmark suites."""

from collections.abc import Callable
from pathlib import Path

from benchmark.cases import Suite
from benchmark.suites import mcptox

LOADERS: dict[str, Callable[[Path], Suite]] = {"mcptox": mcptox.load}
