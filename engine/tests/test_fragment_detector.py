from __future__ import annotations

import pytest

from codeshield.detectors.fragments import FragmentDetector
from codeshield.models.context import FileContext
from codeshield.models.enums import DataCategory, DetectionSource
from codeshield.pseudonymization import ProtectionError, TextProtector
from codeshield.models.enums import ProtectionMode, RecommendedAction


SUFFIX = "SyntheticFragmentValue93628471"


@pytest.mark.parametrize(
    ("suffix", "text"),
    [
        (".py", f'token = "sk_" + "live_51{SUFFIX}"'),
        (".py", f'token = ("sk_" "live_51{SUFFIX}")'),
        (".ts", f'const token = "sk_" + "live_51{SUFFIX}";'),
        (".js", f"const token = 'sk_' + 'live_51{SUFFIX}';"),
        (
            ".json",
            f'{{"api_key_parts": ["sk_", "live_51{SUFFIX}"]}}',
        ),
    ],
)
def test_fragment_detector_reconstructs_supported_literals(
    suffix: str, text: str
) -> None:
    findings = FragmentDetector().detect(
        text, file_context=FileContext(suffix=suffix)
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.data_category is DataCategory.API_KEY
    assert finding.detection_source is DetectionSource.FRAGMENT
    assert len(finding.fragment_spans) == 2
    assert text[finding.start : finding.end]
    assert "static fragment reconstruction" in finding.explanation


@pytest.mark.parametrize(
    ("suffix", "text"),
    [
        (
            ".py",
            f'part_1 = "sk_"\npart_2 = "live_51{SUFFIX}"\ntoken = part_1 + part_2',
        ),
        (
            ".ts",
            f'const part1 = "sk_";\nconst part2 = "live_51{SUFFIX}";\n'
            "const token = part1 + part2;",
        ),
        (
            ".ts",
            f'const part1 = "sk_";\nconst part2 = "live_51{SUFFIX}";\n'
            "const token = `${part1}${part2}`;",
        ),
        (
            ".py",
            f'part = "live_51{SUFFIX}"\ntoken = f"sk_{{part}}"',
        ),
    ],
)
def test_fragment_detector_resolves_prior_constants_and_templates(
    suffix: str, text: str
) -> None:
    findings = FragmentDetector().detect(
        text, file_context=FileContext(suffix=suffix)
    )

    assert len(findings) == 1
    assert len(findings[0].fragment_spans) >= 2


@pytest.mark.parametrize(
    ("suffix", "text"),
    [
        (".py", 'token = load_prefix() + "synthetic"'),
        (".py", 'token = object.prefix + "synthetic"'),
        (".py", 'part = "sk_"\npart = user_input\ntoken = part + "live_value"'),
        (
            ".py",
            f'part = "sk_"\ntoken = part + "live_51{SUFFIX}"\npart = "changed"',
        ),
        (".py", f'token = part + "live_51{SUFFIX}"\npart = "sk_"'),
        (".py", f'parts = ["sk_"]\ntoken = parts[0] + "live_51{SUFFIX}"'),
        (".py", f'token = "sk_" * 2 + "live_51{SUFFIX}"'),
        (".py", 'first = second\nsecond = first\ntoken = first + "synthetic"'),
        (".py", 'token = "sk_" +'),
        (".ts", 'const token = getPrefix() + "synthetic";'),
        (".ts", 'const token = config.prefix + "synthetic";'),
        (
            ".ts",
            f'const part = "sk_";\nconst token = part + "live_51{SUFFIX}";\n'
            'part = "changed";',
        ),
        (".ts", f'const token = part + "live_51{SUFFIX}";\nconst part = "sk_";'),
        (".ts", f'const token = parts[0] + "live_51{SUFFIX}";'),
        (".ts", f'const token = "sk_".repeat(2) + "live_51{SUFFIX}";'),
        (".ts", 'const first = second;\nconst second = first;\nconst token = first + "x";'),
        (".ts", 'const token = "sk_" + ;'),
        (".ts", '// const token = "sk_" + "live_51SyntheticCommentValue999";'),
        (".json", '{"ordinary_parts": ["sk_", "live_51SyntheticDecoyValue999"]}'),
    ],
)
def test_fragment_detector_rejects_runtime_and_decoy_expressions(
    suffix: str, text: str
) -> None:
    assert (
        FragmentDetector().detect(text, file_context=FileContext(suffix=suffix))
        == []
    )


def test_fragment_detector_enforces_fragment_and_length_limits() -> None:
    text = (
        'token = "sk_" + "live_" + "51" + "Synthetic" + "Fragment" + '
        '"Value" + "93628471"'
    )
    assert (
        FragmentDetector(max_fragments=4).detect(
            text, file_context=FileContext(suffix=".py")
        )
        == []
    )
    with pytest.raises(ValueError, match="max_reconstructed_length"):
        FragmentDetector(max_reconstructed_length=16)


def test_fragmented_nonblocking_protection_fails_closed() -> None:
    text = f'token = "sk_" + "live_51{SUFFIX}"'
    finding = FragmentDetector().detect(
        text, file_context=FileContext(suffix=".py")
    )[0].model_copy(update={"recommended_action": RecommendedAction.WARN})

    with pytest.raises(
        ProtectionError, match="fragmented findings require manual source refactoring"
    ):
        TextProtector().protect(
            text, [finding], mode=ProtectionMode.TYPE_PLACEHOLDER
        )
