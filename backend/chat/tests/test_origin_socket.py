import os
import socket
from pathlib import Path

import pytest

from chat.prepare_origin_socket import prepare_origin_socket


def _directory(tmp_path):
    root = tmp_path / 'origin'
    root.mkdir(mode=0o750)
    return root


def test_prepare_origin_socket_enforces_exact_mode(tmp_path):
    root = _directory(tmp_path)
    path = root / 'gunicorn.sock'
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        path.chmod(0o700)
        prepare_origin_socket(
            path,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            wait_seconds=0,
        )
        assert path.stat().st_mode & 0o777 == 0o660
    finally:
        server.close()


@pytest.mark.parametrize('kind', ['regular', 'symlink'])
def test_prepare_origin_socket_rejects_non_socket(tmp_path, kind):
    root = _directory(tmp_path)
    path = root / 'gunicorn.sock'
    target = root / 'target'
    target.write_text('not a socket')
    if kind == 'regular':
        target.rename(path)
    else:
        path.symlink_to(target)
    with pytest.raises(RuntimeError, match='unsafe type'):
        prepare_origin_socket(
            path,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            wait_seconds=0,
        )


def test_prepare_origin_socket_rejects_unsafe_directory_mode(tmp_path):
    root = _directory(tmp_path)
    root.chmod(0o755)
    with pytest.raises(RuntimeError, match='directory'):
        prepare_origin_socket(
            root / 'gunicorn.sock',
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
            wait_seconds=0,
        )
