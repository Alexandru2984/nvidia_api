"""Canonical, resource-bounded JSON decoding for trust boundaries."""
import json
import math


STRICT_JSON_MAX_NODES = 100_000
STRICT_JSON_MAX_DEPTH = 64


class StrictJSONError(ValueError):
    """A JSON document was malformed, ambiguous, or outside safe bounds."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError('JSON contained a duplicate key')
        result[key] = value
    return result


def _reject_constant(_value):
    raise StrictJSONError('JSON contained a non-finite number')


def _validate_values(value, max_nodes, max_depth):
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > max_nodes:
            raise StrictJSONError('JSON exceeded its node limit')
        if depth > max_depth:
            raise StrictJSONError('JSON exceeded its depth limit')
        if isinstance(current, str):
            try:
                current.encode('utf-8')
            except UnicodeEncodeError as exc:
                raise StrictJSONError('JSON contained invalid Unicode') from exc
        elif isinstance(current, float) and not math.isfinite(current):
            raise StrictJSONError('JSON contained a non-finite number')
        elif isinstance(current, dict):
            pending.extend((key, depth + 1) for key in current.keys())
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def strict_json_loads(
    data, *, max_nodes=STRICT_JSON_MAX_NODES, max_depth=STRICT_JSON_MAX_DEPTH,
):
    """Decode one UTF-8 JSON value with unique keys and finite scalars."""
    if not isinstance(max_nodes, int) or isinstance(max_nodes, bool) or max_nodes < 1:
        raise ValueError('max_nodes must be a positive integer')
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        raise ValueError('max_depth must be a positive integer')
    try:
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode('utf-8')
        if not isinstance(data, str):
            raise StrictJSONError('JSON input was not text')
        value = json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_values(value, max_nodes, max_depth)
        return value
    except StrictJSONError:
        raise
    except (TypeError, UnicodeError, RecursionError, ValueError) as exc:
        raise StrictJSONError('JSON was invalid') from exc
