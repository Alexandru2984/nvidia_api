"""Shared NVIDIA chat-completions request contract.

The scheduled availability probe and the user-facing stream must use the same
payload shape. Keeping it here prevents a model from passing a reduced probe
and then rejecting the first real conversation request.
"""


SSE_MAX_LINE_BYTES = 1024 * 1024
SSE_MAX_STREAM_BYTES = 4 * 1024 * 1024


class ProviderStreamError(RuntimeError):
    """The provider stream exceeded bounds or violated its byte contract."""


def _content_length_within(response, limit):
    raw = response.headers.get('Content-Length')
    if raw in (None, ''):
        return True
    try:
        length = int(raw)
    except (TypeError, ValueError):
        return False
    return 0 <= length <= limit


def iter_sse_data(response):
    """Yield bounded UTF-8 data payloads from a single-line SSE stream."""
    if not _content_length_within(response, SSE_MAX_STREAM_BYTES):
        raise ProviderStreamError('provider stream declared an invalid size')

    pending = bytearray()
    total = 0

    def parse_line(raw_line):
        line = raw_line.rstrip(b'\r')
        if not line or not line.startswith(b'data:'):
            return None
        try:
            return line[5:].strip().decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ProviderStreamError('provider stream was not UTF-8') from exc

    for chunk in response.iter_content(chunk_size=16 * 1024):
        if not chunk:
            continue
        if isinstance(chunk, str):
            chunk = chunk.encode('utf-8')
        if not isinstance(chunk, bytes):
            raise ProviderStreamError('provider stream returned invalid bytes')
        total += len(chunk)
        if total > SSE_MAX_STREAM_BYTES:
            raise ProviderStreamError('provider stream exceeded its byte limit')
        pending.extend(chunk)
        while True:
            newline = pending.find(b'\n')
            if newline < 0:
                break
            if newline > SSE_MAX_LINE_BYTES:
                raise ProviderStreamError('provider stream line exceeded its byte limit')
            line = bytes(pending[:newline])
            del pending[:newline + 1]
            data = parse_line(line)
            if data is not None:
                yield data
        if len(pending) > SSE_MAX_LINE_BYTES:
            raise ProviderStreamError('provider stream line exceeded its byte limit')
    if pending:
        data = parse_line(bytes(pending))
        if data is not None:
            yield data


def chat_completion_payload(
    model_id, messages, *, max_tokens=1024, temperature=0.7,
):
    return {
        'model': model_id,
        'messages': messages,
        'max_tokens': max_tokens,
        'temperature': temperature,
        'stream': True,
        'stream_options': {'include_usage': True},
    }


def chat_completion_headers(api_key):
    return {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
    }
