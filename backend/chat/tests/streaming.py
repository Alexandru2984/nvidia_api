"""Streaming disconnect simulation matching Django's test-client lifecycle."""
from django.core.signals import request_finished
from django.db import close_old_connections


def close_streaming_response(response):
    """Run real response closers without closing the test's outer transaction.

    Django's closing_iterator_wrapper temporarily disconnects this same receiver.
    Manual disconnect tests must do that too: the request finished, but the
    surrounding TestCase transaction still needs its PostgreSQL connection.
    Other request_finished receivers and every response resource closer run.
    """
    connected = request_finished.disconnect(close_old_connections)
    try:
        # Close Django's client wrapper first. Once iteration has started,
        # its finally block calls response.close() and reconnects the receiver.
        # Calling response.close() first would re-enter that wrapper and then
        # send a second request_finished with the receiver already reconnected.
        iterator_close = getattr(getattr(response, '_iterator', None), 'close', None)
        if iterator_close is not None:
            iterator_close()
        if not response.closed:
            response.close()
    finally:
        if connected:
            request_finished.connect(close_old_connections)
