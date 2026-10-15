"""Credential-free, sequential Unix-socket service for untrusted documents."""

import logging
import os
import socket
import struct
import subprocess
import tempfile
from pathlib import Path


MAGIC = b'AIP1'
REQUEST = struct.Struct('!4sBII')
RESPONSE = struct.Struct('!4sBI')
KIND_HEALTH = 0
KINDS = {1: 'pdf', 2: 'docx'}
STATUS_OK = 0
STATUS_UNREADABLE = 1
MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_OUTPUT_CHARS = 50_000
MAX_OUTPUT_BYTES = MAX_OUTPUT_CHARS * 4
READ_TIMEOUT_SECONDS = 3
WORKER_TIMEOUT_SECONDS = 8
SOCKET_PATH = Path('/run/aichat-document-parser/parser.sock')
WORKER_PATH = Path('/usr/local/libexec/aichat-document-worker')
PYTHON_PATH = Path('/opt/aichat-python-current/bin/python')

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
log = logging.getLogger('aichat-document-parser')


def _read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ValueError('truncated request')
        data.extend(chunk)
    return bytes(data)


def _respond(connection, status, payload=b''):
    connection.sendall(RESPONSE.pack(MAGIC, status, len(payload)) + payload)


def _extract(kind, cap, data):
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
                [str(PYTHON_PATH), '-I', str(WORKER_PATH), kind, str(cap)],
                input=data,
                stdout=output,
                stderr=subprocess.DEVNULL,
                timeout=WORKER_TIMEOUT_SECONDS,
                check=False,
                env={
                    'PATH': os.defpath,
                    'LANG': 'C.UTF-8',
                    'PYTHONDONTWRITEBYTECODE': '1',
                },
            )
        except subprocess.TimeoutExpired:
            log.warning('event=document_parser_failure type=%s reason=timeout', kind)
            return None
        except OSError:
            log.error('event=document_parser_failure type=%s reason=worker_unavailable', kind)
            return None
        if result.returncode != 0:
            log.warning(
                'event=document_parser_failure type=%s reason=unreadable exit=%s',
                kind,
                result.returncode,
            )
            return None
        output.seek(0)
        payload = output.read(MAX_OUTPUT_BYTES + 1)
        if len(payload) > MAX_OUTPUT_BYTES:
            log.error('event=document_parser_failure type=%s reason=oversized_output', kind)
            return None
        try:
            payload.decode('utf-8')
        except UnicodeDecodeError:
            log.error('event=document_parser_failure type=%s reason=invalid_output', kind)
            return None
        return payload


def _handle(connection):
    connection.settimeout(READ_TIMEOUT_SECONDS)
    magic, kind_id, cap, length = REQUEST.unpack(_read_exact(connection, REQUEST.size))
    if magic != MAGIC:
        raise ValueError('invalid protocol version')
    if kind_id == KIND_HEALTH:
        if cap != 0 or length != 0:
            raise ValueError('invalid health request')
        _respond(connection, STATUS_OK)
        return
    if kind_id not in KINDS or not 1 <= cap <= MAX_OUTPUT_CHARS:
        raise ValueError('invalid parser bounds')
    if not 1 <= length <= MAX_INPUT_BYTES:
        raise ValueError('invalid document length')
    data = _read_exact(connection, length)
    payload = _extract(KINDS[kind_id], cap, data)
    if payload is None:
        _respond(connection, STATUS_UNREADABLE)
    else:
        _respond(connection, STATUS_OK, payload)


def main():
    if not PYTHON_PATH.is_file() or not WORKER_PATH.is_file():
        log.error('event=document_parser_startup_failed reason=runtime_missing')
        return 1
    SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    try:
        SOCKET_PATH.unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(SOCKET_PATH))
            SOCKET_PATH.chmod(0o660)
            server.listen(8)
            log.info('event=document_parser_ready')
            while True:
                connection, _ = server.accept()
                with connection:
                    try:
                        _handle(connection)
                    except (OSError, ValueError, struct.error):
                        log.warning('event=document_parser_failure reason=invalid_request')
    finally:
        SOCKET_PATH.unlink(missing_ok=True)


if __name__ == '__main__':
    raise SystemExit(main())
