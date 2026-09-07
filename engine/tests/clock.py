"""Scoped clock control for date-dependent tests."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import date
from typing import Iterator
from unittest.mock import patch


@contextmanager
def controlled_clock(current_date: date) -> Iterator[None]:
    """Patch modules that own policy and provider date comparisons."""

    class ControlledDate(date):
        @classmethod
        def today(cls) -> date:
            return current_date

    with ExitStack() as stack:
        for module in (
            "codeshield.cli",
            "codeshield.providers.registry",
            "codeshield.policies.engine",
        ):
            stack.enter_context(patch(f"{module}.date", ControlledDate))
        yield
