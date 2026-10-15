import socket
from unittest import mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError

from chat import document_parser_service as service
from chat.attachments import (
    DOCX_MIME,
    PARSER_MAGIC,
    PARSER_REQUEST,
    PARSER_RESPONSE,
    DocumentParserError,
    extract_text,
)


class FakeSocket:
    def __init__(self, reply=b''):
        self.reply = bytearray(reply)
        self.sent = bytearray()
        self.timeout = None
        self.path = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        self.path = path

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, size):
        data = self.reply[:size]
        del self.reply[:size]
        return bytes(data)


def test_client_sends_bounded_content_without_filename_and_rewinds(settings):
    payload = b'%PDF-1.7 private bytes'
    reply_text = b'extracted content'
    fake = FakeSocket(PARSER_RESPONSE.pack(PARSER_MAGIC, 0, len(reply_text)) + reply_text)
    upload = SimpleUploadedFile('customer-secret-name.pdf', payload)
    settings.DOCUMENT_PARSER_REQUIRED = True
    settings.DOCUMENT_PARSER_SOCKET = '/run/test-parser.sock'
    settings.DOCUMENT_PARSER_TIMEOUT_SECONDS = 9

    with mock.patch('chat.attachments.socket.socket', return_value=fake):
        assert extract_text(upload, 'application/pdf') == 'extracted content'

    assert fake.path == '/run/test-parser.sock'
    assert fake.timeout == 9
    assert fake.sent == PARSER_REQUEST.pack(PARSER_MAGIC, 1, 50_000, len(payload)) + payload
    assert b'customer-secret-name.pdf' not in fake.sent
    assert upload.tell() == 0


@pytest.mark.parametrize('reply', [
    b'',
    PARSER_RESPONSE.pack(b'BAD!', 0, 0),
    PARSER_RESPONSE.pack(PARSER_MAGIC, 9, 0),
    PARSER_RESPONSE.pack(PARSER_MAGIC, 0, 1) + b'\xff',
    PARSER_RESPONSE.pack(PARSER_MAGIC, 0, 0) + b'trailing',
])
def test_client_fails_closed_on_ambiguous_response(settings, reply):
    settings.DOCUMENT_PARSER_REQUIRED = True
    upload = SimpleUploadedFile('x.pdf', b'%PDF-1.7')
    with mock.patch('chat.attachments.socket.socket', return_value=FakeSocket(reply)):
        with pytest.raises(DocumentParserError):
            extract_text(upload, 'application/pdf')
    assert upload.tell() == 0


def test_client_accepts_authoritative_unreadable_response(settings):
    settings.DOCUMENT_PARSER_REQUIRED = True
    reply = PARSER_RESPONSE.pack(PARSER_MAGIC, 1, 0)
    with mock.patch('chat.attachments.socket.socket', return_value=FakeSocket(reply)):
        assert extract_text(SimpleUploadedFile('x.pdf', b'%PDF-1.7'), 'application/pdf') == ''


def test_service_health_protocol_is_exact():
    client, server = socket.socketpair()
    try:
        client.sendall(service.REQUEST.pack(service.MAGIC, service.KIND_HEALTH, 0, 0))
        service._handle(server)
        assert client.recv(service.RESPONSE.size) == service.RESPONSE.pack(
            service.MAGIC,
            service.STATUS_OK,
            0,
        )
    finally:
        client.close()
        server.close()


def test_service_forwards_only_valid_bounded_request():
    data = b'PK\x03\x04document'
    client, server = socket.socketpair()
    try:
        client.sendall(service.REQUEST.pack(service.MAGIC, 2, 1234, len(data)) + data)
        with mock.patch.object(service, '_extract', return_value=b'hello') as extract:
            service._handle(server)
        assert client.recv(service.RESPONSE.size + 5) == (
            service.RESPONSE.pack(service.MAGIC, service.STATUS_OK, 5) + b'hello'
        )
        extract.assert_called_once_with('docx', 1234, data)
    finally:
        client.close()
        server.close()


@pytest.mark.parametrize('kind,cap,length', [
    (0, 1, 0),
    (3, 1, 1),
    (1, 0, 1),
    (1, service.MAX_OUTPUT_CHARS + 1, 1),
    (1, 1, 0),
    (1, 1, service.MAX_INPUT_BYTES + 1),
])
def test_service_rejects_invalid_bounds_before_reading_body(kind, cap, length):
    client, server = socket.socketpair()
    try:
        client.sendall(service.REQUEST.pack(service.MAGIC, kind, cap, length))
        with pytest.raises(ValueError):
            service._handle(server)
    finally:
        client.close()
        server.close()


def test_readiness_command_requires_marker():
    command = 'chat.management.commands.check_document_parser'
    with mock.patch(
        f'{command}.extract_text',
        return_value='AI Chat Hub isolated parser readiness marker',
    ):
        call_command('check_document_parser', verbosity=0)
    with (
        mock.patch(f'{command}.extract_text', return_value='wrong'),
        pytest.raises(CommandError, match='unexpected'),
    ):
        call_command('check_document_parser', verbosity=0)
    with (
        mock.patch(f'{command}.extract_text', side_effect=DocumentParserError('unavailable')),
        pytest.raises(CommandError, match='unavailable'),
    ):
        call_command('check_document_parser', verbosity=0)
