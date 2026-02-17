# PRD: Guardian Module - Local Machine Protection
# Reference: docs/PRD.md v0.2.2, Section: Guardian
#
# Guardian is Citadel Archer's local machine protection agent.
# It monitors files, processes, and network activity in real-time,
# using AI to detect and respond to threats proactively.

from .file_monitor import FileMonitor, SuspiciousFilePatterns
from .process_monitor import ProcessMonitor, SuspiciousProcessPatterns
from .extension_scanner import ExtensionScanner

__all__ = [
    "FileMonitor",
    "SuspiciousFilePatterns",
    "ProcessMonitor",
    "SuspiciousProcessPatterns",
    "ExtensionScanner",
]
