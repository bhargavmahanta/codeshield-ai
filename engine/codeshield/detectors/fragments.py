"""Conservative static reconstruction of fragmented secret literals."""

from __future__ import annotations

import ast
from collections import Counter
import json
import re
import tokenize
from dataclasses import dataclass
from io import StringIO

from codeshield.detectors.masking import mask_value
from codeshield.detectors.regex import RegexDetector
from codeshield.models.context import FileContext
from codeshield.models.enums import DetectionSource
from codeshield.models.finding import Finding, SourceSpan, build_finding_id


PYTHON_SUFFIXES = {".py", ".pyi"}
JAVASCRIPT_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
JSON_SUFFIXES = {".json", ".jsonc"}
PARTS_KEY = re.compile(
    r"^(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|credential|token)[_-]?parts?$",
    re.IGNORECASE,
)
JS_ASSIGNMENT = re.compile(
    r"(?m)^[ \t]*(?:(const)[ \t]+)?([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*(.+?)[ \t]*;?[ \t]*$"
)
JSON_PARTS = re.compile(
    r'"(?P<key>[^"\\]+)"\s*:\s*(?P<array>\[(?P<body>(?:\s*"(?:\\.|[^"\\])*"\s*,?)+)\])',
    re.MULTILINE,
)
JS_TOKEN = re.compile(
    r"\s*(?:(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
    r"(?P<template>`(?:\\.|[^`\\])*`)|"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)|(?P<plus>\+))"
)


@dataclass(frozen=True)
class _StaticValue:
    value: str
    start: int
    end: int
    spans: tuple[SourceSpan, ...]


class FragmentDetector:
    """Detect secrets assembled only from statically known string fragments."""

    name = "fragment"

    def __init__(
        self,
        *,
        max_fragments: int = 8,
        max_reconstructed_length: int = 512,
    ) -> None:
        if not 2 <= max_fragments <= 16:
            raise ValueError("max_fragments must be between 2 and 16")
        if not 32 <= max_reconstructed_length <= 4096:
            raise ValueError("max_reconstructed_length must be between 32 and 4096")
        self.max_fragments = max_fragments
        self.max_reconstructed_length = max_reconstructed_length
        self.regex = RegexDetector()

    def detect(
        self, text: str, *, file_context: FileContext | None = None
    ) -> list[Finding]:
        suffix = (file_context or FileContext()).suffix
        candidates: list[_StaticValue] = []
        if suffix in PYTHON_SUFFIXES:
            candidates.extend(self._python_candidates(text))
        elif suffix in JAVASCRIPT_SUFFIXES:
            candidates.extend(self._javascript_candidates(text))
        elif suffix in JSON_SUFFIXES:
            candidates.extend(self._json_candidates(text))
        else:
            candidates.extend(self._python_candidates(text))
            candidates.extend(self._javascript_candidates(text))
            candidates.extend(self._json_candidates(text))

        findings: list[Finding] = []
        seen: set[tuple[int, int, str]] = set()
        for candidate in candidates:
            spans = _unique_spans(candidate.spans)
            if (
                len(spans) < 2
                or len(spans) > self.max_fragments
                or len(candidate.value) > self.max_reconstructed_length
            ):
                continue
            for nested in self.regex.detect(candidate.value):
                key = (candidate.start, candidate.end, nested.data_category.value)
                if key in seen:
                    continue
                seen.add(key)
                raw_value = candidate.value[nested.start : nested.end]
                findings.append(
                    Finding(
                        finding_id=build_finding_id(
                            category=nested.data_category,
                            source=DetectionSource.FRAGMENT,
                            start=candidate.start,
                            end=candidate.end,
                            raw_value=raw_value,
                        ),
                        data_category=nested.data_category,
                        start=candidate.start,
                        end=candidate.end,
                        masked_preview=mask_value(raw_value, nested.data_category),
                        detection_source=DetectionSource.FRAGMENT,
                        confidence_score=round(nested.confidence_score * 0.97, 3),
                        severity=nested.severity,
                        explanation=(
                            "Secret-like value detected through safe static fragment "
                            "reconstruction."
                        ),
                        recommended_action=nested.recommended_action,
                        fragment_spans=list(spans),
                    )
                )
        return findings

    def _python_candidates(self, text: str) -> list[_StaticValue]:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, MemoryError):
            return []
        lines = text.splitlines(keepends=True)
        offsets = _line_offsets(lines)
        candidates: list[_StaticValue] = []
        self._python_scope(tree.body, text, lines, offsets, candidates)
        return candidates

    def _python_scope(
        self,
        statements: list[ast.stmt],
        text: str,
        lines: list[str],
        offsets: list[int],
        candidates: list[_StaticValue],
    ) -> None:
        environment: dict[str, str] = {}
        assigned: set[str] = set()
        assignment_counts = Counter(
            target.id
            for statement in statements
            for target in _python_assignment_targets(statement)
        )
        reassigned = {
            name for name, count in assignment_counts.items() if count > 1
        }
        for statement in statements:
            expression: ast.expr | None = None
            target_name: str | None = None
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                expression = statement.value
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    target_name = targets[0].id
            elif isinstance(statement, ast.Expr):
                expression = statement.value
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._python_scope(
                    statement.body, text, lines, offsets, candidates
                )
                continue

            resolved = (
                self._resolve_python(expression, environment, text, lines, offsets)
                if expression is not None
                else None
            )
            if resolved is not None and len(_unique_spans(resolved.spans)) >= 2:
                candidates.append(resolved)
            if target_name is not None:
                if (
                    target_name in reassigned
                    or target_name in assigned
                    or resolved is None
                ):
                    environment.pop(target_name, None)
                else:
                    environment[target_name] = resolved.value
                assigned.add(target_name)

    def _resolve_python(
        self,
        node: ast.expr,
        environment: dict[str, str],
        text: str,
        lines: list[str],
        offsets: list[int],
    ) -> _StaticValue | None:
        bounds = _node_bounds(node, lines, offsets)
        if bounds is None:
            return None
        start, end = bounds
        if isinstance(node, ast.Name) and node.id in environment:
            return _StaticValue(
                environment[node.id],
                start,
                end,
                (SourceSpan(start=start, end=end),),
            )
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            spans = _python_string_spans(text[start:end], start)
            if not spans:
                spans = (SourceSpan(start=start, end=end),)
            return _StaticValue(node.value, start, end, spans)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_python(
                node.left, environment, text, lines, offsets
            )
            right = self._resolve_python(
                node.right, environment, text, lines, offsets
            )
            if left is None or right is None:
                return None
            value = left.value + right.value
            if len(value) > self.max_reconstructed_length:
                return None
            return _StaticValue(value, start, end, left.spans + right.spans)
        if isinstance(node, ast.JoinedStr):
            values: list[str] = []
            spans: list[SourceSpan] = []
            for item in node.values:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    values.append(item.value)
                    spans.append(SourceSpan(start=start, end=end))
                elif (
                    isinstance(item, ast.FormattedValue)
                    and isinstance(item.value, ast.Name)
                    and item.value.id in environment
                    and item.conversion == -1
                    and item.format_spec is None
                ):
                    item_bounds = _node_bounds(item.value, lines, offsets)
                    if item_bounds is None:
                        return None
                    values.append(environment[item.value.id])
                    spans.append(SourceSpan(start=item_bounds[0], end=item_bounds[1]))
                else:
                    return None
            value = "".join(values)
            if len(value) > self.max_reconstructed_length:
                return None
            return _StaticValue(value, start, end, tuple(spans))
        return None

    def _javascript_candidates(self, text: str) -> list[_StaticValue]:
        environment: dict[str, str] = {}
        assigned: set[str] = set()
        candidates: list[_StaticValue] = []
        matches = list(JS_ASSIGNMENT.finditer(_without_js_comments(text)))
        assignment_counts = Counter(match.group(2) for match in matches)
        for match in matches:
            is_const, name, expression = match.groups()
            expression_start = match.start(3)
            resolved = self._resolve_javascript(
                expression, expression_start, environment
            )
            if resolved is not None and len(_unique_spans(resolved.spans)) >= 2:
                candidates.append(resolved)
            if (
                is_const
                and assignment_counts[name] == 1
                and name not in assigned
                and resolved is not None
            ):
                environment[name] = resolved.value
            else:
                environment.pop(name, None)
            assigned.add(name)
        return candidates

    def _resolve_javascript(
        self,
        expression: str,
        base: int,
        environment: dict[str, str],
    ) -> _StaticValue | None:
        position = 0
        expect_value = True
        values: list[str] = []
        spans: list[SourceSpan] = []
        expression_start: int | None = None
        expression_end: int | None = None
        while position < len(expression):
            match = JS_TOKEN.match(expression, position)
            if match is None:
                if expression[position:].strip() in {"", ";"}:
                    break
                return None
            position = match.end()
            if match.group("plus"):
                if expect_value:
                    return None
                expect_value = True
                continue
            if not expect_value:
                return None
            token_start = base + match.start()
            token_end = base + match.end()
            if expression_start is None:
                expression_start = token_start
            expression_end = token_end
            if match.group("string"):
                value = _decode_js_string(match.group("string"))
                token_spans = [SourceSpan(start=token_start, end=token_end)]
            elif match.group("template"):
                resolved = _decode_js_template(
                    match.group("template"), token_start, environment
                )
                if resolved is None:
                    return None
                value, token_spans = resolved
            else:
                name = match.group("name")
                if name not in environment:
                    return None
                value = environment[name]
                token_spans = [SourceSpan(start=token_start, end=token_end)]
            values.append(value)
            spans.extend(token_spans)
            expect_value = False
            if len(values) > self.max_fragments:
                return None
        if expect_value or not values:
            return None
        value = "".join(values)
        if len(value) > self.max_reconstructed_length:
            return None
        return _StaticValue(
            value,
            expression_start if expression_start is not None else spans[0].start,
            expression_end if expression_end is not None else spans[-1].end,
            tuple(spans),
        )

    def _json_candidates(self, text: str) -> list[_StaticValue]:
        candidates: list[_StaticValue] = []
        for match in JSON_PARTS.finditer(text):
            if not PARTS_KEY.fullmatch(match.group("key")):
                continue
            values: list[str] = []
            spans: list[SourceSpan] = []
            body = match.group("body")
            body_start = match.start("body")
            position = 0
            valid = True
            for token in re.finditer(r'"(?:\\.|[^"\\])*"', body):
                gap = body[position : token.start()]
                if gap.strip().strip(","):
                    valid = False
                    break
                try:
                    values.append(json.loads(token.group(0)))
                except json.JSONDecodeError:
                    valid = False
                    break
                spans.append(
                    SourceSpan(
                        start=body_start + token.start(),
                        end=body_start + token.end(),
                    )
                )
                position = token.end()
            if body[position:].strip().strip(","):
                valid = False
            value = "".join(values)
            if (
                valid
                and 2 <= len(spans) <= self.max_fragments
                and len(value) <= self.max_reconstructed_length
            ):
                candidates.append(
                    _StaticValue(
                        value,
                        match.start("array"),
                        match.end("array"),
                        tuple(spans),
                    )
                )
        return candidates


def _without_js_comments(text: str) -> str:
    """Blank comments without changing offsets; quoted comment markers are retained."""

    result = list(text)
    index = 0
    quote: str | None = None
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            for current in range(index, end):
                result[current] = " "
            index = end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end == -1 else end + 2
            for current in range(index, end):
                if result[current] not in {"\r", "\n"}:
                    result[current] = " "
            index = end
            continue
        index += 1
    return "".join(result)


def _python_assignment_targets(statement: ast.stmt) -> list[ast.Name]:
    if isinstance(statement, ast.Assign):
        return [target for target in statement.targets if isinstance(target, ast.Name)]
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return [statement.target]
    return []


def _decode_js_string(token: str) -> str:
    body = token[1:-1]
    output: list[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'", '"': '"'}
    while index < len(body):
        if body[index] != "\\":
            output.append(body[index])
            index += 1
            continue
        if index + 1 >= len(body):
            return ""
        marker = body[index + 1]
        if marker == "u" and index + 5 < len(body):
            try:
                output.append(chr(int(body[index + 2 : index + 6], 16)))
            except ValueError:
                return ""
            index += 6
        elif marker == "x" and index + 3 < len(body):
            try:
                output.append(chr(int(body[index + 2 : index + 4], 16)))
            except ValueError:
                return ""
            index += 4
        elif marker in escapes:
            output.append(escapes[marker])
            index += 2
        else:
            return ""
    return "".join(output)


def _decode_js_template(
    token: str, base: int, environment: dict[str, str]
) -> tuple[str, list[SourceSpan]] | None:
    body = token[1:-1]
    output: list[str] = []
    spans: list[SourceSpan] = []
    position = 0
    for match in re.finditer(r"\$\{([A-Za-z_$][A-Za-z0-9_$]*)\}", body):
        literal = body[position : match.start()]
        if literal:
            output.append(literal)
            spans.append(
                SourceSpan(start=base + 1 + position, end=base + 1 + match.start())
            )
        name = match.group(1)
        if name not in environment:
            return None
        output.append(environment[name])
        spans.append(
            SourceSpan(
                start=base + 1 + match.start(1),
                end=base + 1 + match.end(1),
            )
        )
        position = match.end()
    remainder = body[position:]
    if "${" in remainder:
        return None
    if remainder:
        output.append(remainder)
        spans.append(
            SourceSpan(start=base + 1 + position, end=base + 1 + len(body))
        )
    return "".join(output), spans


def _line_offsets(lines: list[str]) -> list[int]:
    values = [0]
    for line in lines:
        values.append(values[-1] + len(line))
    return values


def _node_bounds(
    node: ast.AST, lines: list[str], offsets: list[int]
) -> tuple[int, int] | None:
    if not all(
        hasattr(node, name)
        for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ):
        return None
    start_line = int(node.lineno) - 1  # type: ignore[attr-defined]
    end_line = int(node.end_lineno) - 1  # type: ignore[attr-defined]
    start_column = _byte_to_character_column(
        lines[start_line], int(node.col_offset)  # type: ignore[attr-defined]
    )
    end_column = _byte_to_character_column(
        lines[end_line], int(node.end_col_offset)  # type: ignore[attr-defined]
    )
    return offsets[start_line] + start_column, offsets[end_line] + end_column


def _byte_to_character_column(line: str, byte_column: int) -> int:
    return len(line.encode("utf-8")[:byte_column].decode("utf-8", errors="ignore"))


def _python_string_spans(segment: str, base: int) -> tuple[SourceSpan, ...]:
    offsets = _line_offsets(segment.splitlines(keepends=True))
    spans: list[SourceSpan] = []
    try:
        tokens = tokenize.generate_tokens(StringIO(segment).readline)
        for token in tokens:
            if token.type != tokenize.STRING:
                continue
            start = base + offsets[token.start[0] - 1] + token.start[1]
            end = base + offsets[token.end[0] - 1] + token.end[1]
            spans.append(SourceSpan(start=start, end=end))
    except (tokenize.TokenError, IndentationError):
        return ()
    return tuple(spans)


def _unique_spans(spans: tuple[SourceSpan, ...]) -> tuple[SourceSpan, ...]:
    values = {(span.start, span.end): span for span in spans}
    return tuple(values[key] for key in sorted(values))
