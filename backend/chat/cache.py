"""Single-host cache with atomic counters across gunicorn processes.

Use a dedicated Redis cache when moving to multiple application hosts. The
cache directory is private trusted storage: Django's file cache uses pickle.
"""
from contextlib import contextmanager
import fcntl
import os

from django.core.cache.backends.base import DEFAULT_TIMEOUT
from django.core.cache.backends.filebased import FileBasedCache


class AtomicFileCache(FileBasedCache):
    @contextmanager
    def _counter_lock(self):
        self._createdir()
        fd = os.open(os.path.join(self._dir, '.counter.lock'),
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def add(self, key, value, timeout=DEFAULT_TIMEOUT, version=None):
        with self._counter_lock():
            return super().add(key, value, timeout, version)

    def incr(self, key, delta=1, version=None):
        with self._counter_lock():
            return super().incr(key, delta, version)
