from __future__ import annotations

import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root.parents[1] / "engine"))

from codeshield_management_api.main import app


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: export_openapi.py OUTPUT_PATH")
    destination = Path(sys.argv[1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
