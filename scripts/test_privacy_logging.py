#!/usr/bin/env python3
"""Regression checks for privacy-minimized AI Chat Hub request logs."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / 'ops/systemd/aichat-backend.service'
VHOST = ROOT / 'ops/nginx/aichat.micutu.com.conf'


class PrivacyLoggingTests(unittest.TestCase):
    def test_gunicorn_access_format_excludes_client_and_query_metadata(self):
        unit = UNIT.read_text(encoding='utf-8')
        exec_start = next(
            line for line in unit.splitlines() if line.startswith('ExecStart=')
        )
        expected = (
            "--access-logformat '%%(t)s \"%%(m)s %%(U)s %%(H)s\" "
            "%%(s)s %%(b)s %%(L)s'"
        )
        self.assertIn(expected, exec_start)
        for forbidden in (
            '%%(h)s',
            '%%(a)s',
            '%%(f)s',
            '%%(q)s',
            '%%(r)s',
        ):
            self.assertNotIn(forbidden, exec_start)
        for forbidden in ('x-forwarded-for', 'cookie'):
            self.assertNotIn(forbidden, exec_start.lower())

    def test_nginx_servers_do_not_inherit_the_host_wide_access_log(self):
        vhost = VHOST.read_text(encoding='utf-8')
        # Both the HTTPS application and HTTP redirect server must opt out.
        self.assertEqual(vhost.count('\n    access_log off;\n'), 2)
        self.assertNotIn('access_log /', vhost)


if __name__ == '__main__':
    unittest.main()
