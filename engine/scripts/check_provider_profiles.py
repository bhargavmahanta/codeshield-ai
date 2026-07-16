from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeshield.providers import ProviderRegistry, ProviderRegistryError


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--as-of", type=date.fromisoformat, default=date.today())
    arguments = parser.parse_args()
    try:
        errors = ProviderRegistry().verify(today=arguments.as_of)
    except ProviderRegistryError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        raise SystemExit(1)
    print("Provider profiles are current and internally consistent.")


if __name__ == "__main__":
    main()
