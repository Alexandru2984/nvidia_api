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

    def test_nginx_reserves_large_bodies_only_for_multipart_upload(self):
        vhost = VHOST.read_text(encoding='utf-8')
        upload = vhost.split('location = /api/attachments/upload/ {', 1)[1].split(
            '\n    }', 1,
        )[0]
        streaming = vhost.split(
            'location ~ ^/api/(conversations/[0-9]+/messages|messages/[0-9]+'
            '/regenerate)/?$ {',
            1,
        )[1].split('\n    }', 1)[0]
        general = vhost.split('location /api/ {', 1)[1].split('\n    }', 1)[0]

        self.assertIn('client_max_body_size 12m;', upload)
        self.assertIn('client_max_body_size 64k;', streaming)
        self.assertIn('client_max_body_size 64k;', general)


if __name__ == '__main__':
    unittest.main()
