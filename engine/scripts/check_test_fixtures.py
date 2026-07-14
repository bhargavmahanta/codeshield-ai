from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeshield.models.enums import ContextLabel, Destination
from codeshield.scanner import CodeShieldScanner


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    targets = [root / "engine/tests", root / "packages"]
    unsafe_paths: set[str] = set()
    scanner = CodeShieldScanner()
    for target in targets:
        result = scanner.scan_path(
            target,
            destination=Destination.PRIVATE_GIT,
            excludes=["dist/**", "node_modules/**"],
            timeout_seconds=30.0,
        )
        for finding in result.findings:
            if (
                finding.context is not None
                and finding.context.label is ContextLabel.PROBABLE_REAL_SECRET
                and finding.file_path is not None
            ):
                unsafe_paths.add(str(Path(finding.file_path).relative_to(root)))
    if unsafe_paths:
        print("Unsafe non-test fixture context detected in:", file=sys.stderr)
        for path in sorted(unsafe_paths):
            print(f"- {path}", file=sys.stderr)
        raise SystemExit(1)
    print("Synthetic fixture contexts are safely classified.")


if __name__ == "__main__":
    main()
