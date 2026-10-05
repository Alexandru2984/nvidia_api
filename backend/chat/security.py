"""Shared request boundaries for the session-only API."""
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser


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
    })

    def parse(self, stream, media_type=None, parser_context=None):
        data = super().parse(stream, media_type, parser_context)
        if not isinstance(data, dict):
            raise ParseError('Expected a JSON object.')
        for field in self.text_fields & data.keys():
            if not isinstance(data[field], str):
                raise ParseError(f'{field} must be a string.')
        return data
