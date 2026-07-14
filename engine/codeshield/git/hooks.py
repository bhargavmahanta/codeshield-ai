"""Safe lifecycle management for the native Git pre-commit hook."""

from __future__ import annotations

import os
from enum import StrEnum

from codeshield.git.repository import GitIntegrationError, GitRepository

HOOK_MARKER = "# CodeShield AI managed pre-commit hook v1"
HOOK_SCRIPT = f"""#!/bin/sh
{HOOK_MARKER}
if command -v codeshield >/dev/null 2>&1; then
  codeshield check-staged
else
  repository_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 3
  local_codeshield="$repository_root/.venv312/Scripts/codeshield.exe"
  if [ ! -x "$local_codeshield" ]; then
    echo "CodeShield setup error: install the engine or create .venv312." >&2
    exit 3
  fi
  "$local_codeshield" check-staged
fi
status=$?
if [ "$status" -eq 0 ]; then
  exit 0
fi
exit "$status"
"""


class HookStatus(StrEnum):
    NOT_INSTALLED = "not_installed"
    MANAGED = "managed"
    UNMANAGED = "unmanaged"


class HookManager:
    def __init__(self, repository: GitRepository) -> None:
        self.repository = repository
        self.path = repository.git_path("hooks/pre-commit")

    def status(self) -> HookStatus:
        if not self.path.exists():
            return HookStatus.NOT_INSTALLED
        content = self.path.read_text(encoding="utf-8", errors="replace")
        return HookStatus.MANAGED if HOOK_MARKER in content else HookStatus.UNMANAGED

    def install(self) -> HookStatus:
        current = self.status()
        if current is HookStatus.UNMANAGED:
            raise GitIntegrationError(
                "an unmanaged pre-commit hook already exists; it was not overwritten"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(HOOK_SCRIPT, encoding="utf-8", newline="\n")
        try:
            self.path.chmod(self.path.stat().st_mode | 0o111)
        except OSError as exc:
            if os.name != "nt":
                raise GitIntegrationError("unable to mark hook executable") from exc
        return HookStatus.MANAGED

    def uninstall(self) -> HookStatus:
        current = self.status()
        if current is HookStatus.UNMANAGED:
            raise GitIntegrationError("refusing to remove an unmanaged pre-commit hook")
        if current is HookStatus.MANAGED:
            self.path.unlink()
        return HookStatus.NOT_INSTALLED
