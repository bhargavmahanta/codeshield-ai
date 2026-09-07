"""Synthetic Phase 5 case generators; generated values never enter Git reports."""

from __future__ import annotations

import json
import random
from collections.abc import Iterable
from hashlib import sha256
from pathlib import Path

from codeshield.evaluation.models import EvaluationCase, ExpectedSpan
from codeshield.models.enums import DataCategory, Destination, RecommendedAction


SUITE_VERSION = "1.0.0"


def generate_phase5(seed: int = 42) -> dict[str, list[EvaluationCase]]:
    return {
        "codeshield-synthetic": _secret_cases(seed),
        "presidio-research-synthetic": _pii_cases(seed),
        "workflow-synthetic": _workflow_cases(seed),
    }


def generate_phase6(seed: int = 42) -> dict[str, list[EvaluationCase]]:
    generated = generate_phase5(seed)
    generated["fragment-synthetic"] = _fragment_cases(seed)
    return generated


def generate_phase8(seed: int = 42) -> dict[str, list[EvaluationCase]]:
    generated = generate_phase6(seed)
    generated["proxy-synthetic"] = _proxy_cases(seed)
    return generated


def generate_phase9(seed: int = 42) -> dict[str, list[EvaluationCase]]:
    generated = generate_phase8(seed)
    identifiers = [
        ("management-signature-tamper", "management-verification"),
        ("management-unknown-key", "management-verification"),
        ("management-expired", "management-verification"),
        ("management-rollback", "management-verification"),
        ("management-extra-prompt", "management-prohibited"),
        ("management-extra-response", "management-prohibited"),
        ("management-extra-path", "management-prohibited"),
        ("management-invalid-identifier", "management-prohibited"),
        ("management-invalid-counts", "management-prohibited"),
        ("management-safe-audit-one", "management-negative"),
        ("management-safe-audit-two", "management-negative"),
        ("management-safe-audit-three", "management-negative"),
    ]
    generated["management-synthetic"] = [
        EvaluationCase(case_id=case_id, suite=suite, text="metadata-only")
        for case_id, suite in identifiers
    ]
    return generated


def write_jsonl(path: Path, cases: Iterable[EvaluationCase]) -> str:
    def safe_record(case: EvaluationCase) -> dict[str, object]:
        record = case.model_dump(mode="json")
        if record.get("file_path") is None:
            record.pop("file_path", None)
        return record

    payload = "".join(
        json.dumps(
            safe_record(case),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for case in cases
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    return sha256(payload.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[EvaluationCase]:
    return [
        EvaluationCase.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _case(
    case_id: str,
    suite: str,
    text: str,
    values: list[tuple[DataCategory, str]],
    *,
    destination: Destination = Destination.LOCAL_FILE,
    action: RecommendedAction | None = None,
) -> EvaluationCase:
    expected: list[ExpectedSpan] = []
    cursor = 0
    for category, value in values:
        start = text.index(value, cursor)
        expected.append(ExpectedSpan(category=category, start=start, end=start + len(value)))
        cursor = start + len(value)
    return EvaluationCase(
        case_id=case_id,
        suite=suite,
        text=text,
        expected=expected,
        destination=destination,
        expected_action=action,
    )


def _secret_cases(seed: int) -> list[EvaluationCase]:
    randomizer = random.Random(seed)
    suffix = "".join(randomizer.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(18))
    api_key = "sk_" + f"live_51PhaseFive{suffix}"
    jwt = ".".join(
        (
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiJzeW50aGV0aWMifQ",
            "c2lnbmF0dXJlUGhhc2VGaXZl",
        )
    )
    database = "postgresql" + "://phase5_user:synthetic_password@db.example.test/review"
    email = "phase5.reviewer@example.test"
    phone = "+1 202-555-0147"
    cases = [
        _case("secret-api-python", "codeshield-synthetic", f"api_key = '{api_key}'", [(DataCategory.API_KEY, api_key)]),
        _case("secret-api-json", "codeshield-synthetic", json.dumps({"api_key": api_key}), [(DataCategory.API_KEY, api_key)]),
        _case("secret-jwt", "codeshield-synthetic", f"authorization: Bearer {jwt}", [(DataCategory.JWT, jwt)]),
        _case("secret-database", "codeshield-synthetic", f"DATABASE_URL={database}", [(DataCategory.DATABASE_CONNECTION_STRING, database)]),
        _case("pii-email-unicode", "codeshield-synthetic", f"Reviewer contact: {email} \u2014 synthetic only", [(DataCategory.EMAIL, email)]),
        _case("pii-phone", "codeshield-synthetic", f"Call the test desk at {phone}.", [(DataCategory.PHONE_NUMBER, phone)]),
        _case("public-git-block", "codeshield-synthetic", f"api_key = '{api_key}'", [(DataCategory.API_KEY, api_key)], destination=Destination.PUBLIC_GIT, action=RecommendedAction.BLOCK),
        _case("external-llm-block", "codeshield-synthetic", f"api_key = '{api_key}'", [(DataCategory.API_KEY, api_key)], destination=Destination.EXTERNAL_LLM, action=RecommendedAction.BLOCK),
        _case("placeholder-detected", "codeshield-synthetic", "password = 'changeme'", [(DataCategory.PASSWORD, "changeme")]),
    ]
    negatives = [
        "The documentation uses a short illustrative value.",
        "https://example.test/docs/getting-started",
        "const enabled = true;",
        "AABBCCDDEEAABBCCDDEEAABBCCDD",
        "This_is_a_readable_placeholder_example_value",
        "127.0.0.1 is the loopback interface.",
        "The build identifier is release-2026-09-02.",
        "No credential is present in this sentence.",
    ]
    cases.extend(
        EvaluationCase(case_id=f"negative-{index:02d}", suite="codeshield-synthetic", text=value)
        for index, value in enumerate(negatives, start=1)
    )
    # Deliberately difficult split-string case records a known false negative.
    cases.append(
        _case(
            "adversarial-split-secret",
            "codeshield-adversarial",
            "token = 'sk_' + 'live_51PhaseFiveSplitValue93628471'",
            [(DataCategory.API_KEY, "sk_' + 'live_51PhaseFiveSplitValue93628471")],
        )
    )
    return cases


def _fragment_cases(seed: int) -> list[EvaluationCase]:
    randomizer = random.Random(seed + 6)
    suffix = "".join(
        randomizer.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(18)
    )
    tail = f"live_51PhaseSix{suffix}"
    positives = [
        (
            "fragment-python-plus",
            f'token = "sk_" + "{tail}"',
            ".py",
            '"sk_" + "' + tail + '"',
        ),
        (
            "fragment-python-adjacent",
            f'token = ("sk_" "{tail}")',
            ".py",
            '"sk_" "' + tail + '"',
        ),
        (
            "fragment-python-names",
            f'left = "sk_"\nright = "{tail}"\ntoken = left + right',
            ".py",
            "left + right",
        ),
        (
            "fragment-python-template",
            f'right = "{tail}"\ntoken = f"sk_{{right}}"',
            ".py",
            'f"sk_{right}"',
        ),
        (
            "fragment-typescript-plus",
            f'const token = "sk_" + "{tail}";',
            ".ts",
            '"sk_" + "' + tail + '"',
        ),
        (
            "fragment-typescript-names",
            f'const left = "sk_";\nconst right = "{tail}";\n'
            "const token = left + right;",
            ".ts",
            "left + right",
        ),
        (
            "fragment-typescript-template",
            f'const left = "sk_";\nconst right = "{tail}";\n'
            "const token = `${left}${right}`;",
            ".ts",
            "`${left}${right}`",
        ),
        (
            "fragment-json-parts",
            f'{{"api_key_parts": ["sk_", "{tail}"]}}',
            ".json",
            f'["sk_", "{tail}"]',
        ),
    ]
    cases: list[EvaluationCase] = []
    for case_id, text, suffix_value, expression in positives:
        start = text.index(expression)
        cases.append(
            EvaluationCase(
                case_id=case_id,
                suite="fragment-positive",
                text=text,
                expected=[
                    ExpectedSpan(
                        category=DataCategory.API_KEY,
                        start=start,
                        end=start + len(expression),
                    )
                ],
                file_path=f"synthetic/example{suffix_value}",
            )
        )

    negatives = [
        (".py", 'token = load_prefix() + "synthetic"'),
        (".py", 'token = config.prefix + "synthetic"'),
        (".py", 'part = "sk_"\npart = user_input\ntoken = part + "live_value"'),
        (".py", 'message = "ordinary" + "documentation"'),
        (".ts", 'const token = getPrefix() + "synthetic";'),
        (".ts", 'const token = config.prefix + "synthetic";'),
        (".ts", '// const token = "sk_" + "live_51SyntheticCommentValue999";'),
        (".ts", 'const message = "ordinary" + "documentation";'),
        (".json", '{"ordinary_parts": ["sk_", "live_51SyntheticDecoyValue999"]}'),
        (".json", '{"token_parts": ["short", "example"]}'),
        (".txt", "The plus sign joins ideas in this documentation."),
        (".txt", "No credential fragments are present."),
    ]
    cases.extend(
        EvaluationCase(
            case_id=f"fragment-negative-{index:02d}",
            suite="fragment-negative",
            text=text,
            file_path=f"synthetic/negative-{index:02d}{suffix_value}",
        )
        for index, (suffix_value, text) in enumerate(negatives, start=1)
    )
    return cases


def _proxy_cases(seed: int) -> list[EvaluationCase]:
    randomizer = random.Random(seed + 8)
    suffix = "".join(
        randomizer.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(18)
    )
    api_key = _runtime_text("s", "k", "_", "li", "ve_51PhaseEight", suffix)
    database = _runtime_text(
        "postgres",
        "ql",
        "://proxy_user:",
        "synthetic_password",
        "@db.example.test/",
        "proxy_review",
    )
    jwt = ".".join(
        (
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiJwaGFzZTgifQ",
            "c3ludGhldGljUHJveHlTaWduYXR1cmU",
        )
    )
    cases = [
        _case(
            "proxy-api-key",
            "proxy-positive",
            f"credential={api_key}",
            [(DataCategory.API_KEY, api_key)],
            destination=Destination.EXTERNAL_LLM,
            action=RecommendedAction.BLOCK,
        ),
        _case(
            "proxy-database",
            "proxy-positive",
            f"database={database}",
            [(DataCategory.DATABASE_CONNECTION_STRING, database)],
            destination=Destination.EXTERNAL_LLM,
            action=RecommendedAction.BLOCK,
        ),
        _case(
            "proxy-jwt",
            "proxy-positive",
            f"authorization=Bearer {jwt}",
            [(DataCategory.JWT, jwt)],
            destination=Destination.EXTERNAL_LLM,
            action=RecommendedAction.BLOCK,
        ),
    ]
    negatives = [
        "Summarize this local design review.",
        "Explain why loopback binding reduces exposure.",
        "Return a JSON object with status and count.",
        "The model identifier is model-safe.",
        "Function tools are inspected before forwarding.",
        "No private content is present.",
        "A response is buffered before local release.",
        "Use deterministic synthetic test data.",
    ]
    cases.extend(
        EvaluationCase(
            case_id=f"proxy-negative-{index:02d}",
            suite="proxy-negative",
            text=text,
            destination=Destination.EXTERNAL_LLM,
        )
        for index, text in enumerate(negatives, start=1)
    )
    return cases


def _runtime_text(*parts: str) -> str:
    """Assemble deterministic fixtures without storing credential signatures."""

    return "".join(parts)


def _pii_cases(seed: int) -> list[EvaluationCase]:
    from faker import Faker
    from presidio_evaluator.data_generator.faker_extensions import SentenceFaker

    templates = [
        "In case of my child's account, we need to add {{person}} as guardian",
        "I'm originally from {{country}}",
        "Who's coming to {{country}} with me?",
        "{{country}} was super fun to visit!",
    ]
    records = [
        {"person": "Ada Lovelace", "country": "India"},
        {"person": "Grace Hopper", "country": "United Kingdom"},
        {"person": "Alan Turing", "country": "Canada"},
        {"person": "Katherine Johnson", "country": "Australia"},
    ]
    Faker.seed(seed + 1)
    random.seed(seed + 1)
    faker = SentenceFaker(records=records, locale="en_US", lower_case_ratio=0)
    cases: list[EvaluationCase] = []
    for index in range(16):
        template = templates[index % len(templates)]
        generated = faker.parse(template, index % len(templates))
        span = generated.spans[0]
        category = (
            DataCategory.PERSON
            if span.entity_type == "person"
            else DataCategory.LOCATION
        )
        cases.append(
            EvaluationCase(
                case_id=f"presidio-{index + 1:02d}",
                suite="presidio-research-synthetic",
                text=generated.full_text,
                expected=[
                    ExpectedSpan(
                        category=category,
                        start=span.start_position,
                        end=span.end_position,
                    )
                ],
            )
        )
    return cases


def _workflow_cases(seed: int) -> list[EvaluationCase]:
    del seed
    api_key = "sk_" + "live_51WorkflowSynthetic93628471"
    email = "workflow.person@example.test"
    return [
        _case("workflow-public-key", "workflow-synthetic", f"api_key='{api_key}'", [(DataCategory.API_KEY, api_key)], destination=Destination.PUBLIC_GIT, action=RecommendedAction.BLOCK),
        _case("workflow-private-key", "workflow-synthetic", f"api_key='{api_key}'", [(DataCategory.API_KEY, api_key)], destination=Destination.PRIVATE_GIT, action=RecommendedAction.BLOCK),
        _case("workflow-email-llm", "workflow-synthetic", f"contact={email}", [(DataCategory.EMAIL, email)], destination=Destination.EXTERNAL_LLM, action=RecommendedAction.PSEUDONYMIZE),
    ]
