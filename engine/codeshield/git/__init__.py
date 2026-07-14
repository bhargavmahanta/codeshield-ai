"""Git staged-diff scanning and hook management."""

from codeshield.git.hooks import HookManager, HookStatus
from codeshield.git.repository import (
    GitIntegrationError,
    GitRepository,
    StagedTextBlock,
)
from codeshield.git.scanner import StagedGitScanner

__all__ = [
    "GitIntegrationError",
    "GitRepository",
    "HookManager",
    "HookStatus",
    "StagedGitScanner",
    "StagedTextBlock",
]
