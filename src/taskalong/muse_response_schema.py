"""Opt-in native JSON-schema transport; never repairs provider source text.

The array envelope fits the native closed-object schema subset. Normalization
only changes the container, retaining every path and content code point.
"""
from __future__ import annotations

import json
import math
from .errors import TaskAlongError
from .validation import canonical_bytes

FORMAT = 'local-muse-provider/7'
CONTRACT = 'json-schema-file-changes/1'


def _fail(code='provider_response_unrecognized'):
    raise TaskAlongError(code, 'The schema response is invalid or exceeds its independent byte limit; preserve the failed evidence.', exit_code=3, effect_outcome='uncertain')


def document(request, bundle_digest, maximum):
    paths = sorted(request['files'])
    value = {'type':'object', 'additionalProperties':False,
        'properties': {'bundle_digest': {'type':'string', 'enum':[bundle_digest]},
            'changes': {'type':'array', 'minItems':1, 'maxItems':32,
                'items': {'type':'object', 'additionalProperties':False,
                    'properties': {'path': {'type':'string', 'enum':paths},
                        'content': {'type':['string','null'], 'maxLength':maximum}},
                    'required':['path','content']}}}, 'required':['bundle_digest','changes']}
    if len(canonical_bytes(value)) > 65536:
        raise TaskAlongError('provider_schema_too_large', 'The finite native schema limit is exceeded.', exit_code=3, effect_outcome='not_sent')
    return value


def prompt(original):
    return original + (b'\n\nTransport amendment json-schema-file-changes/1: the output-schema file overrides '
        b'the earlier response shape only. Return changes as an array of closed objects, each with '
        b'path and content (string or null), rather than a map. Keep bundle_digest unchanged. '
        b'Use each selected path at most once; return only intended changes. All other task, scope, '
        b'safety and review requirements remain unchanged. Return valid JSON with escaped source text.\n')


def normalize(value, request, bundle_digest, maximum):
    def bounded(item):
        raw = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(raw) > maximum:
            _fail('provider_proposal_too_large')
        return raw
    bounded(value)
    if (type(value) is not dict or set(value) != {'bundle_digest','changes'} or value['bundle_digest'] != bundle_digest
            or type(value['changes']) is not list or not 1 <= len(value['changes']) <= 32):
        _fail()
    changes = {}
    for item in value['changes']:
        if (type(item) is not dict or set(item) != {'path','content'} or type(item['path']) is not str
                or item['path'] not in request['files'] or item['path'] in changes
                or item['content'] is not None and type(item['content']) is not str):
            _fail()
        changes[item['path']] = item['content']
    result = {'bundle_digest':bundle_digest, 'changes':changes}
    bounded(result)
    canonical_bytes(result)
    return result


from .muse_native_lifecycle import NativeModelTaskGuard


class SingleAttemptGuard(NativeModelTaskGuard):
    """Stop on an observed native retry; never claim a remote hard cap."""
    def _status_descriptor(self, row, payload, event):
        descriptor = super()._status_descriptor(row, payload, event)
        if descriptor is not None and descriptor["attempt"] != 1:
            self._stop("native_retry_observed")
        if descriptor is None and type(event) is dict and event.get("kind") == "status":
            details = event.get("details", {})
            pending = [details]
            while pending:
                part = pending.pop()
                if type(part) is dict:
                    if part.get("kind") == "external_attempt" or part.get("phase") == "retrying":
                        self._stop("native_retry_or_unknown_attempt_observed")
                    pending.extend(part.values())
                elif type(part) is list:
                    pending.extend(part)
        return descriptor


def escaping_failure(text):
    """Recognize otherwise complete JSON with only string escaping defects.

    This syntax-only recognizer produces no decoded value or repaired text. Its
    result can authorize an explicit new attempt, never proposal acceptance.
    """
    position = nodes = defects = 0
    def invalid_constant(value):
        raise ValueError("Non-JSON constant")
    decoder = json.JSONDecoder(parse_constant=invalid_constant)
    whitespace = ' \t\r\n'
    def space():
        nonlocal position
        while position < len(text) and text[position] in whitespace:
            position += 1
    def string():
        nonlocal position, defects
        if position >= len(text) or text[position] != '"': raise ValueError()
        position += 1
        while position < len(text):
            char = text[position]; position += 1
            if char == '"': return
            if ord(char) < 32:
                defects += 1
            elif char == '\\':
                if position == len(text): raise ValueError()
                escaped = text[position]; position += 1
                if escaped == 'u':
                    part = text[position:position+4]
                    if len(part) != 4 or any(c not in '0123456789abcdefABCDEF' for c in part): raise ValueError()
                    position += 4
                    code = int(part,16)
                    if 0xD800 <= code <= 0xDBFF:
                        pair = text[position:position+6]
                        if (len(pair) != 6 or not pair.startswith('\\u')
                                or any(c not in '0123456789abcdefABCDEF' for c in pair[2:])
                                or not 0xDC00 <= int(pair[2:],16) <= 0xDFFF): raise ValueError()
                        position += 6
                    elif 0xDC00 <= code <= 0xDFFF: raise ValueError()
                elif escaped not in '"\\/bfnrt':
                    defects += 1
        raise ValueError()
    def value(depth=0):
        nonlocal position, nodes
        space(); nodes += 1
        if depth > 64 or nodes > 100000 or position == len(text): raise ValueError()
        char = text[position]
        if char == '"': string(); return
        if char in '{[':
            position += 1; space(); close = '}' if char == '{' else ']'
            if position < len(text) and text[position] == close:
                position += 1; return
            while True:
                if char == '{':
                    space(); string(); space()
                    if position == len(text) or text[position] != ':': raise ValueError()
                    position += 1
                value(depth+1); space()
                if position == len(text): raise ValueError()
                token = text[position]; position += 1
                if token == close: return
                if token != ',': raise ValueError()
        else:
            if not (char in '-0123456789' or text.startswith(('true','false','null'),position)): raise ValueError()
            parsed, end = decoder.raw_decode(text,position)
            if type(parsed) not in (int,float,bool,type(None)) or type(parsed) is float and not math.isfinite(parsed): raise ValueError()
            position = end
    try:
        value(); space()
        return position == len(text) and defects > 0
    except (ValueError,RecursionError,OverflowError):
        return False
