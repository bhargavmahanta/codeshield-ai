"""Detector protocol and shared helpers."""

from __future__ import annotations

from typing import Protocol

from codeshield.models.finding import Finding


class SensitiveDataDetector(Protocol):
    name: str

    def detect(self, text: str) -> list[Finding]:
        """Return safe, masked findings for the supplied untrusted text."""

