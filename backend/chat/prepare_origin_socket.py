"""Validate and permission the gunicorn origin socket during systemd startup."""
from __future__ import annotations

import grp
import os
import stat
import time
from pathlib import Path

SOCKET_PATH = Path('/run/aichat-backend/gunicorn.sock')
ORIGIN_GROUP = 'aichat-origin'
WAIT_SECONDS = 10


def prepare_origin_socket(
    path=SOCKET_PATH,
    *,
    expected_uid=None,
    expected_gid=None,
    wait_seconds=WAIT_SECONDS,
):
    path = Path(path)
    expected_uid = os.geteuid() if expected_uid is None else expected_uid
    expected_gid = (
        grp.getgrnam(ORIGIN_GROUP).gr_gid if expected_gid is None else expected_gid
    )
    parent = path.parent
    parent_info = parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != expected_uid
        or parent_info.st_gid != expected_gid
        or stat.S_IMODE(parent_info.st_mode) != 0o750
    ):
        raise RuntimeError('origin socket directory has unsafe ownership or permissions')

    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            info = path.lstat()
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise RuntimeError('origin socket was not created before the startup deadline')
            time.sleep(0.05)
            continue
        if (
            not stat.S_ISSOCK(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
        ):
            raise RuntimeError('origin socket has unsafe type or ownership')
        path.chmod(0o660)
        final = path.lstat()
        if (
            not stat.S_ISSOCK(final.st_mode)
            or final.st_uid != expected_uid
            or final.st_gid != expected_gid
            or stat.S_IMODE(final.st_mode) != 0o660
        ):
            raise RuntimeError('origin socket permissions could not be enforced')
        return


def main():
    prepare_origin_socket()


if __name__ == '__main__':
    main()
