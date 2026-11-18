"""Scanners that can be put through the benchmark."""

from benchmark.scanners.base import Flag, Scanner, Servers, Verdicts
from benchmark.scanners.cisco import CiscoYaraScanner
from benchmark.scanners.foretaster import ForetasterScanner

__all__ = ["CiscoYaraScanner", "Flag", "ForetasterScanner", "Scanner", "Servers", "Verdicts"]
