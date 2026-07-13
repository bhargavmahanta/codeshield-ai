from __future__ import annotations

from pathlib import Path

from codeshield.models.enums import Destination


def test_scanner_skips_binary_oversized_and_excluded_files(tmp_path: Path, scanner) -> None:
    include = tmp_path / "include.txt"
    include.write_text('api_key = "sk_live_51SyntheticTokenValue999"', encoding="utf-8")
    binary = tmp_path / "binary.bin"
    binary.write_bytes(b"\x00\x01\x02")
    oversized = tmp_path / "large.txt"
    oversized.write_text("x" * 200, encoding="utf-8")
    excluded = tmp_path / "excluded.txt"
    excluded.write_text('password = "CorrectHorseBattery999"', encoding="utf-8")
    (tmp_path / ".codeshieldignore").write_text("excluded.txt\n", encoding="utf-8")

    result = scanner.scan_path(
        tmp_path,
        destination=Destination.PUBLIC_GIT,
        max_file_size=128,
        excludes=["*.ignored"],
    )

    assert result.files_scanned == 1
    assert len(result.findings) == 1
    reasons = {item.reason for item in result.files_skipped}
    assert {"binary", "file too large", "excluded"} <= reasons
