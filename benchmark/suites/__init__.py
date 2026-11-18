"""Benchmark suites."""

from collections.abc import Callable
from pathlib import Path

from benchmark.cases import Suite
from benchmark.suites import mcptox, wild
from benchmark.suites.wild import CaseSuite

LOADERS: dict[str, Callable[[Path], Suite]] = {"mcptox": mcptox.load}
CASE_LOADERS: dict[str, Callable[[Path], CaseSuite]] = {"wild": wild.load}
