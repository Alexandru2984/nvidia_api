"""Shared request boundaries for the session-only API."""
import math

from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser

from .converters import PositiveBigIntConverter


class CSRFSafeSessionAuthentication(SessionAuthentication):
    """Login and account recovery need CSRF checks even before authentication."""

    def authenticate(self, request):
        self.enforce_csrf(request)
        return super().authenticate(request)


class ObjectJSONParser(JSONParser):
    """All JSON endpoints accept objects, with strings for shared text fields."""

    text_fields = frozenset({
        'username', 'email', 'password', 'current_password', 'new_password',
        'code', 'website', 'title', 'model_id', 'system_prompt', 'content', 'prompt',
        'invite_code',
    })
    integer_fields = frozenset({'max_tokens', 'width', 'height', 'steps', 'seed'})
    number_fields = frozenset({'temperature'})
    boolean_fields = frozenset({'archived', 'is_pinned'})
    integer_list_fields = frozenset({'attachment_ids'})

    def parse(self, stream, media_type=None, parser_context=None):
        data = super().parse(stream, media_type, parser_context)
        if not isinstance(data, dict):
            raise ParseError('Expected a JSON object.')
        for field in self.text_fields & data.keys():
            if not isinstance(data[field], str):
                raise ParseError(f'{field} must be a string.')
        for field in self.integer_fields & data.keys():
            if not isinstance(data[field], int) or isinstance(data[field], bool):
                raise ParseError(f'{field} must be an integer.')
        for field in self.number_fields & data.keys():
            value = data[field]
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
            ):
                raise ParseError(f'{field} must be a finite number.')
        for field in self.boolean_fields & data.keys():
            if not isinstance(data[field], bool):
                raise ParseError(f'{field} must be a boolean.')
        for field in self.integer_list_fields & data.keys():
            values = data[field]
            if not isinstance(values, list) or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= PositiveBigIntConverter.maximum
                for value in values
            ):
                raise ParseError(f'{field} must be a list of positive integer IDs.')
        return data
