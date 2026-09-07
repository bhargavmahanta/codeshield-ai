"""Decode only a complete, text-only OpenCode JSON event stream."""

import json
import math

from .errors import OpenCodeError


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _reject_constant(value):
    raise ValueError


def parse_response(payload: bytes) -> str:
    """Never return partial text, tool output, reasoning, or error bodies."""
    try:
        if not payload or len(payload) > 2_000_000:
            raise ValueError
        state, identity = "initial", None
        part_ids, answer = set(), []
        for line in payload.decode("utf-8", errors="strict").splitlines():
            event = json.loads(line, object_pairs_hook=_object, parse_constant=_reject_constant)
            if not isinstance(event, dict) or set(event) != {"type", "timestamp", "sessionID", "part"}:
                raise ValueError
            if not _number(event["timestamp"]):
                raise ValueError
            part = event["part"]
            if not isinstance(part, dict):
                raise ValueError
            if "snapshot" in part and not isinstance(part["snapshot"], str):
                raise ValueError
            if "metadata" in part and not isinstance(part["metadata"], dict):
                raise ValueError
            for key in ("id", "sessionID", "messageID", "type"):
                if not isinstance(part.get(key), str) or not 0 < len(part[key]) <= 256:
                    raise ValueError
            current = (part["sessionID"], part["messageID"])
            if event["sessionID"] != current[0] or (identity is not None and identity != current):
                raise ValueError
            identity = current
            if part["id"] in part_ids:
                raise ValueError
            part_ids.add(part["id"])
            common = {"id", "sessionID", "messageID", "type"}
            kind = event["type"]
            if kind == "step_start" and state == "initial":
                if part["type"] != "step-start" or set(part) - common - {"snapshot"}:
                    raise ValueError
                state = "started"
            elif kind == "text" and state == "started":
                if part["type"] != "text" or set(part) - common - {"text", "time", "metadata", "synthetic", "ignored"}:
                    raise ValueError
                timing = part.get("time")
                if not isinstance(timing, dict) or set(timing) != {"start", "end"}:
                    raise ValueError
                if not all(_number(timing[k]) for k in timing) or timing["end"] < timing["start"]:
                    raise ValueError
                if not isinstance(part.get("text"), str) or part.get("synthetic", False) is not False or part.get("ignored", False) is not False:
                    raise ValueError
                answer.append(part["text"])
            elif kind == "step_finish" and state == "started":
                if part["type"] != "step-finish" or part.get("reason") != "stop" or set(part) - common - {"reason", "cost", "tokens", "snapshot"}:
                    raise ValueError
                if not _number(part.get("cost")):
                    raise ValueError
                tokens = part.get("tokens")
                if not isinstance(tokens, dict) or set(tokens) - {"input", "output", "reasoning", "cache", "total"}:
                    raise ValueError
                if not all(_number(tokens.get(k)) for k in ("input", "output", "reasoning")):
                    raise ValueError
                if "total" in tokens and not _number(tokens["total"]):
                    raise ValueError
                cache = tokens.get("cache")
                if not isinstance(cache, dict) or set(cache) != {"read", "write"} or not all(_number(v) for v in cache.values()):
                    raise ValueError
                state = "finished"
            else:
                raise ValueError
        if state != "finished" or not "".join(answer).strip():
            raise ValueError
        return "".join(answer)
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
        raise OpenCodeError() from None
