"""Map supported proxy payloads to inspected CodeShield segments."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from codeshield.models.enums import SegmentKind, SegmentProvenance
from codeshield.models.llm import ContentSegment, ProtectedSegment
from codeshield.proxy.models import ChatRequest, ChatResponse, ResponsesRequest, ResponsesResponse


class ProxyMappingError(ValueError):
    """Raised when a validated payload cannot be transformed exactly."""


@dataclass(frozen=True)
class SegmentBinding:
    segment: ContentSegment
    path: tuple[str | int, ...]
    json_encoded: bool = False
    transformable: bool = True


def outbound_chat(request: ChatRequest) -> tuple[dict[str, Any], list[SegmentBinding]]:
    payload = request.model_dump(mode="json", exclude_none=True, by_alias=True)
    bindings: list[SegmentBinding] = []
    for index, message in enumerate(payload["messages"]):
        role = message["role"]
        kind, provenance = _role_security(role)
        content = message.get("content")
        if isinstance(content, str):
            _append(bindings, content, ("messages", index, "content"), kind, provenance)
        elif isinstance(content, list):
            for part_index, part in enumerate(content):
                _append(
                    bindings,
                    part["text"],
                    ("messages", index, "content", part_index, "text"),
                    kind,
                    provenance,
                )
        for call_index, call in enumerate(message.get("tool_calls") or []):
            _append(
                bindings,
                call["function"]["name"],
                ("messages", index, "tool_calls", call_index, "function", "name"),
                SegmentKind.TOOL_OUTPUT,
                SegmentProvenance.UNTRUSTED,
                transformable=False,
            )
            _append(
                bindings,
                call["function"]["arguments"],
                ("messages", index, "tool_calls", call_index, "function", "arguments"),
                SegmentKind.TOOL_OUTPUT,
                SegmentProvenance.UNTRUSTED,
            )
        if message.get("name"):
            _append(
                bindings,
                message["name"],
                ("messages", index, "name"),
                kind,
                provenance,
                transformable=False,
            )
    stop = payload.get("stop")
    if isinstance(stop, str):
        _append(
            bindings,
            stop,
            ("stop",),
            SegmentKind.USER,
            SegmentProvenance.TRUSTED,
        )
    elif isinstance(stop, list):
        for index, value in enumerate(stop):
            _append(
                bindings,
                value,
                ("stop", index),
                SegmentKind.USER,
                SegmentProvenance.TRUSTED,
            )
    if payload.get("response_format"):
        _append_json(
            bindings,
            payload["response_format"],
            ("response_format",),
        )
    if isinstance(payload.get("tool_choice"), dict):
        _append_json(
            bindings,
            payload["tool_choice"],
            ("tool_choice",),
            transformable=False,
        )
    for index, tool in enumerate(payload.get("tools") or []):
        function = tool["function"]
        _append(
            bindings,
            function["name"],
            ("tools", index, "function", "name"),
            SegmentKind.SOURCE_CODE,
            SegmentProvenance.TRUSTED,
            transformable=False,
        )
        if function.get("description"):
            _append(
                bindings,
                function["description"],
                ("tools", index, "function", "description"),
                SegmentKind.SOURCE_CODE,
                SegmentProvenance.TRUSTED,
            )
        _append_json(
            bindings,
            function["parameters"],
            ("tools", index, "function", "parameters"),
        )
    return payload, bindings


def outbound_responses(
    request: ResponsesRequest,
) -> tuple[dict[str, Any], list[SegmentBinding]]:
    payload = request.model_dump(mode="json", exclude_none=True, by_alias=True)
    bindings: list[SegmentBinding] = []
    if request.instructions is not None:
        _append(
            bindings,
            request.instructions,
            ("instructions",),
            SegmentKind.SYSTEM,
            SegmentProvenance.TRUSTED,
        )
    input_value = payload["input"]
    if isinstance(input_value, str):
        _append(
            bindings,
            input_value,
            ("input",),
            SegmentKind.USER,
            SegmentProvenance.TRUSTED,
        )
    else:
        for index, item in enumerate(input_value):
            if item["type"] == "function_call_output":
                _append(
                    bindings,
                    item["output"],
                    ("input", index, "output"),
                    SegmentKind.TOOL_OUTPUT,
                    SegmentProvenance.UNTRUSTED,
                )
                continue
            kind, provenance = _role_security(item["role"])
            content = item["content"]
            if isinstance(content, str):
                _append(bindings, content, ("input", index, "content"), kind, provenance)
            else:
                for part_index, part in enumerate(content):
                    _append(
                        bindings,
                        part["text"],
                        ("input", index, "content", part_index, "text"),
                        kind,
                        provenance,
                    )
    for index, tool in enumerate(payload.get("tools") or []):
        _append(
            bindings,
            tool["name"],
            ("tools", index, "name"),
            SegmentKind.SOURCE_CODE,
            SegmentProvenance.TRUSTED,
            transformable=False,
        )
        if tool.get("description"):
            _append(
                bindings,
                tool["description"],
                ("tools", index, "description"),
                SegmentKind.SOURCE_CODE,
                SegmentProvenance.TRUSTED,
            )
        _append_json(bindings, tool["parameters"], ("tools", index, "parameters"))
    if payload.get("text"):
        _append_json(bindings, payload["text"], ("text",))
    if isinstance(payload.get("tool_choice"), dict):
        _append_json(
            bindings,
            payload["tool_choice"],
            ("tool_choice",),
            transformable=False,
        )
    return payload, bindings


def inbound_chat(response: ChatResponse) -> tuple[dict[str, Any], list[SegmentBinding]]:
    payload = response.model_dump(mode="json", exclude_none=True, by_alias=True)
    bindings: list[SegmentBinding] = []
    for choice_index, choice in enumerate(payload["choices"]):
        message = choice["message"]
        if message.get("content") is not None:
            _append(
                bindings,
                message["content"],
                ("choices", choice_index, "message", "content"),
                SegmentKind.RETRIEVED,
                SegmentProvenance.UNTRUSTED,
            )
        if message.get("refusal") is not None:
            _append(
                bindings,
                message["refusal"],
                ("choices", choice_index, "message", "refusal"),
                SegmentKind.RETRIEVED,
                SegmentProvenance.UNTRUSTED,
            )
        for call_index, call in enumerate(message.get("tool_calls") or []):
            _append(
                bindings,
                call["function"]["arguments"],
                (
                    "choices",
                    choice_index,
                    "message",
                    "tool_calls",
                    call_index,
                    "function",
                    "arguments",
                ),
                SegmentKind.TOOL_OUTPUT,
                SegmentProvenance.UNTRUSTED,
            )
    return payload, bindings


def inbound_responses(
    response: ResponsesResponse,
) -> tuple[dict[str, Any], list[SegmentBinding]]:
    payload = response.model_dump(mode="json", exclude_none=True, by_alias=True)
    bindings: list[SegmentBinding] = []
    for output_index, item in enumerate(payload["output"]):
        if item["type"] == "function_call":
            _append(
                bindings,
                item["arguments"],
                ("output", output_index, "arguments"),
                SegmentKind.TOOL_OUTPUT,
                SegmentProvenance.UNTRUSTED,
            )
            continue
        for content_index, content in enumerate(item["content"]):
            field = "text" if content["type"] == "output_text" else "refusal"
            _append(
                bindings,
                content[field],
                ("output", output_index, "content", content_index, field),
                SegmentKind.RETRIEVED,
                SegmentProvenance.UNTRUSTED,
            )
    return payload, bindings


def apply_protected(
    payload: dict[str, Any],
    bindings: list[SegmentBinding],
    protected: list[ProtectedSegment],
) -> dict[str, Any]:
    by_id = {item.segment_id: item.protected_content for item in protected}
    if set(by_id) != {binding.segment.segment_id for binding in bindings}:
        raise ProxyMappingError("protected segment set is incomplete")
    result = copy.deepcopy(payload)
    for binding in bindings:
        protected_value = by_id[binding.segment.segment_id]
        if (
            not binding.transformable
            and protected_value != binding.segment.content
        ):
            raise ProxyMappingError("protected structural text is unsafe")
        value: Any = protected_value
        if binding.json_encoded:
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ProxyMappingError("protected function schema is invalid") from exc
        _set_path(result, binding.path, value)
    return result


def restore_known(
    payload: dict[str, Any],
    bindings: list[SegmentBinding],
    *,
    restore: Any,
) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    for binding in bindings:
        current = _get_path(result, binding.path)
        if not isinstance(current, str):
            raise ProxyMappingError("response text mapping is invalid")
        _set_path(result, binding.path, restore(current))
    return result


def _append(
    bindings: list[SegmentBinding],
    content: str,
    path: tuple[str | int, ...],
    kind: SegmentKind,
    provenance: SegmentProvenance,
    *,
    transformable: bool = True,
) -> None:
    bindings.append(
        SegmentBinding(
            segment=ContentSegment(
                segment_id=f"proxy-{len(bindings) + 1:04d}",
                kind=kind,
                content=content,
                provenance=provenance,
                path="proxy/content",
            ),
            path=path,
            transformable=transformable,
        )
    )


def _append_json(
    bindings: list[SegmentBinding],
    value: dict[str, Any],
    path: tuple[str | int, ...],
    *,
    transformable: bool = True,
) -> None:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    _append(
        bindings,
        encoded,
        path,
        SegmentKind.SOURCE_CODE,
        SegmentProvenance.TRUSTED,
        transformable=transformable,
    )
    binding = bindings[-1]
    bindings[-1] = SegmentBinding(
        segment=binding.segment,
        path=binding.path,
        json_encoded=True,
        transformable=transformable,
    )


def _role_security(role: str) -> tuple[SegmentKind, SegmentProvenance]:
    if role == "system":
        return SegmentKind.SYSTEM, SegmentProvenance.TRUSTED
    if role == "developer":
        return SegmentKind.SYSTEM, SegmentProvenance.TRUSTED
    if role == "user":
        return SegmentKind.USER, SegmentProvenance.TRUSTED
    if role == "tool":
        return SegmentKind.TOOL_OUTPUT, SegmentProvenance.UNTRUSTED
    return SegmentKind.RETRIEVED, SegmentProvenance.UNTRUSTED


def _set_path(root: Any, path: tuple[str | int, ...], value: Any) -> None:
    target = root
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def _get_path(root: Any, path: tuple[str | int, ...]) -> Any:
    target = root
    for part in path:
        target = target[part]
    return target
