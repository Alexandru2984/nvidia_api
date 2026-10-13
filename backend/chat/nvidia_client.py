"""Shared NVIDIA chat-completions request contract.

The scheduled availability probe and the user-facing stream must use the same
payload shape. Keeping it here prevents a model from passing a reduced probe
and then rejecting the first real conversation request.
"""


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
