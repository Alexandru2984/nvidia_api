import pytest
from django.core.exceptions import ImproperlyConfigured

from chat.nvidia_client import ProviderStreamError, iter_sse_data
from nvidia_chat.settings import _nvidia_endpoint


def test_approved_nvidia_endpoint_is_accepted(monkeypatch):
    monkeypatch.setenv(
        'TEST_NVIDIA_ENDPOINT',
        'https://integrate.api.nvidia.com/v1/chat/completions',
    )
    assert _nvidia_endpoint(
        'TEST_NVIDIA_ENDPOINT',
        'unused',
        'integrate.api.nvidia.com',
        '/v1/chat/completions',
    ) == 'https://integrate.api.nvidia.com/v1/chat/completions'


@pytest.mark.parametrize('value', [
    'http://integrate.api.nvidia.com/v1/chat/completions',
    'https://attacker.invalid/v1/chat/completions',
    'https://integrate.api.nvidia.com.attacker.invalid/v1/chat/completions',
    'https://user:password@integrate.api.nvidia.com/v1/chat/completions',
    'https://integrate.api.nvidia.com:444/v1/chat/completions',
    'https://integrate.api.nvidia.com:notaport/v1/chat/completions',
    'https://integrate.api.nvidia.com/v1/other',
    'https://integrate.api.nvidia.com/v1/chat/completions?redirect=1',
    'https://integrate.api.nvidia.com/v1/chat/completions#fragment',
])
def test_unapproved_provider_endpoint_fails_closed(monkeypatch, value):
    monkeypatch.setenv('TEST_NVIDIA_ENDPOINT', value)
    with pytest.raises(ImproperlyConfigured, match='approved NVIDIA HTTPS endpoint'):
        _nvidia_endpoint(
            'TEST_NVIDIA_ENDPOINT',
            'unused',
            'integrate.api.nvidia.com',
            '/v1/chat/completions',
        )


def test_chunked_sse_stream_has_aggregate_bound(monkeypatch):
    response = type('Response', (), {
        'headers': {},
        'iter_content': lambda self, chunk_size: iter([b'data: {}\n', b'data: [DONE]\n']),
    })()
    monkeypatch.setattr('chat.nvidia_client.SSE_MAX_STREAM_BYTES', 12)

    with pytest.raises(ProviderStreamError, match='byte limit'):
        list(iter_sse_data(response))


def test_sse_stream_rejects_invalid_utf8():
    response = type('Response', (), {
        'headers': {},
        'iter_content': lambda self, chunk_size: iter([b'data: \xff\n']),
    })()

    with pytest.raises(ProviderStreamError, match='UTF-8'):
        list(iter_sse_data(response))
