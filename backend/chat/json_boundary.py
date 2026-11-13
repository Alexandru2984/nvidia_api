"""Canonical, resource-bounded JSON decoding for trust boundaries."""
import json
import math


STRICT_JSON_MAX_NODES = 100_000


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


def _validate_values(value, max_nodes):
    pending = [value]
    nodes = 0
    while pending:
        current = pending.pop()
        nodes += 1
        if nodes > max_nodes:
            raise StrictJSONError('JSON exceeded its node limit')
        if isinstance(current, str):
            try:
                current.encode('utf-8')
            except UnicodeEncodeError as exc:
                raise StrictJSONError('JSON contained invalid Unicode') from exc
        elif isinstance(current, float) and not math.isfinite(current):
            raise StrictJSONError('JSON contained a non-finite number')
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def strict_json_loads(data, *, max_nodes=STRICT_JSON_MAX_NODES):
    """Decode one UTF-8 JSON value with unique keys and finite scalars."""
    if not isinstance(max_nodes, int) or isinstance(max_nodes, bool) or max_nodes < 1:
        raise ValueError('max_nodes must be a positive integer')
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
        _validate_values(value, max_nodes)
        return value
    except StrictJSONError:
        raise
    except (TypeError, UnicodeError, RecursionError, ValueError) as exc:
        raise StrictJSONError('JSON was invalid') from exc
