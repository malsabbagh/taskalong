"""Strict finite provider-wire JSON, separate from authority documents.

This parser admits transport escaping above the one-MiB authority ceiling.
Its values confer no authority and must pass canonical proposal validation.
"""
from __future__ import annotations

import json

from .errors import TaskAlongError

MAX_WIRE_BYTES = 16 * 1048576
MAX_RESPONSE_WIRE_BYTES = 4 * 1048576
MAX_WIRE_NODES = 65536


def _fail(code="invalid_json"):
    raise TaskAlongError(code, "The provider wire value exceeds its strict finite JSON contract.")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail("duplicate_key")
        result[key] = value
    return result


def _number(_):
    _fail("invalid_number")


def loads_wire(data: str | bytes, *, max_bytes: int = MAX_RESPONSE_WIRE_BYTES) -> dict:
    """Read one bounded object; floats, duplicate keys and bad Unicode fail.

    Native adapters needing decimal observations retain their native parser.
    Whole-protocol byte/record limits remain the process owner's responsibility.
    """
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_WIRE_BYTES:
        _fail("document_too_large")
    try:
        if type(data) not in (bytes, str):
            _fail()
        raw = data if type(data) is bytes else data.encode("utf-8", errors="strict")
        if len(raw) > max_bytes:
            _fail("document_too_large")
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                           parse_float=_number, parse_constant=_number)
        if type(value) is not dict:
            _fail()
        count = 0
        stack = [(value, 0)]
        while stack:
            item, depth = stack.pop()
            count += 1
            if depth > 64 or count > MAX_WIRE_NODES:
                _fail("document_too_deep" if depth > 64 else "document_too_large")
            if type(item) is str:
                if len(item.encode("utf-8", errors="strict")) > max_bytes:
                    _fail("document_too_large")
            elif type(item) is int:
                if abs(item) > 2**53 - 1:
                    _fail("invalid_number")
            elif item is None or type(item) is bool:
                continue
            elif type(item) in (dict, list):
                if len(item) > 4096:
                    _fail("document_too_large")
                if type(item) is dict:
                    stack.extend((key, depth + 1) for key in item)
                    stack.extend((child, depth + 1) for child in item.values())
                else:
                    stack.extend((child, depth + 1) for child in item)
            else:
                _fail()
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise TaskAlongError("invalid_json", "The provider wire value is not strict bounded UTF-8 JSON.") from exc
