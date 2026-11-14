"""Explicit JSON depth limits must not depend on interpreter recursion limits."""
import pytest

from chat.json_boundary import (
    STRICT_JSON_MAX_DEPTH,
    StrictJSONError,
    strict_json_loads,
)


@pytest.mark.parametrize('opening,closing', [('[', ']'), ('{"value":', '}')])
def test_json_accepts_exact_depth_limit(opening, closing):
    raw = opening * STRICT_JSON_MAX_DEPTH + '0' + closing * STRICT_JSON_MAX_DEPTH

    assert strict_json_loads(raw) is not None


@pytest.mark.parametrize('opening,closing', [('[', ']'), ('{"value":', '}')])
def test_json_rejects_first_excess_depth(opening, closing):
    depth = STRICT_JSON_MAX_DEPTH + 1
    raw = opening * depth + '0' + closing * depth

    with pytest.raises(StrictJSONError, match='depth limit'):
        strict_json_loads(raw)


@pytest.mark.parametrize('value', [True, 0, -1, 1.5])
def test_json_depth_configuration_requires_positive_integer(value):
    with pytest.raises(ValueError, match='max_depth must be a positive integer'):
        strict_json_loads('{}', max_depth=value)
