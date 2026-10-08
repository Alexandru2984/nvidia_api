import asyncio
import ast
import json
import logging
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import cf_analytics_bot as bot


class FakeResponse:
    def __init__(self, status_code=200, chunks=()):
        self.status_code = status_code
        self.chunks = list(chunks)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def iter_content(self, chunk_size):
        del chunk_size
        yield from self.chunks


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.response

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.response


class SecurityTests(unittest.TestCase):
    def credentials(self, directory: str, **overrides) -> Path:
        payload = {
            "bot_token": "12345678:" + "A" * 35,
            "allowed_chat_id": 12345678,
            "cloudflare_api_token": "C" * 40,
            "cloudflare_zone_id": "d" * 32,
        }
        payload.update(overrides)
        path = Path(directory) / "credentials.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o640)
        return path

    def test_settings_require_exact_schema_and_private_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.credentials(directory)
            settings = bot.Settings.load(path, require_root_owner=False)
            self.assertEqual(settings.allowed_chat_id, 12345678)

            path.chmod(0o644)
            with self.assertRaises(bot.ConfigurationError):
                bot.Settings.load(path, require_root_owner=False)

            path = self.credentials(directory, unexpected="value")
            with self.assertRaises(bot.ConfigurationError):
                bot.Settings.load(path, require_root_owner=False)

    def test_settings_reject_invalid_values(self):
        invalid = (
            {"bot_token": "not-a-token"},
            {"allowed_chat_id": True},
            {"cloudflare_api_token": "short"},
            {"cloudflare_zone_id": "not-a-zone"},
        )
        for overrides in invalid:
            with self.subTest(overrides=tuple(overrides)):
                with tempfile.TemporaryDirectory() as directory:
                    path = self.credentials(directory, **overrides)
                    with self.assertRaises(bot.ConfigurationError):
                        bot.Settings.load(path, require_root_owner=False)

    def test_settings_reject_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.credentials(directory)
            link = Path(directory) / "linked-credentials.json"
            link.symlink_to(path)
            with self.assertRaises(bot.ConfigurationError):
                bot.Settings.load(link, require_root_owner=False)

    def test_bounded_json_rejects_status_size_and_invalid_json(self):
        with self.assertRaises(bot.UpstreamError) as raised:
            bot.bounded_json_response(FakeResponse(403, [b"sensitive upstream body"]))
        self.assertNotIn("sensitive", str(raised.exception))

        with self.assertRaises(bot.UpstreamError):
            bot.bounded_json_response(FakeResponse(200, [b"x" * (bot.MAX_RESPONSE_BYTES + 1)]))
        with self.assertRaises(bot.UpstreamError):
            bot.bounded_json_response(FakeResponse(200, [b"not-json"]))

    def test_ip_lookup_accepts_only_public_validated_addresses(self):
        payload = {
            "success": True,
            "country": "Romania",
            "city": "Bucharest",
            "latitude": 44.4,
            "longitude": 26.1,
            "connection": {"isp": "Example ISP", "org": "Example Org"},
        }
        session = FakeSession(FakeResponse(200, [json.dumps(payload).encode()]))
        client = bot.IPLookupClient(session)
        result = client.lookup("8.8.8.8")
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(session.calls[0][1], "https://ipwho.is/8.8.8.8")

        for value in ("127.0.0.1", "10.0.0.1", "::1", "8.8.8.8/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                client.lookup(value)
        self.assertEqual(len(session.calls), 1)

    def test_authorization_requires_private_matching_chat_and_user(self):
        calls = []

        @bot.authorized
        async def handler(update, context):
            del update, context
            calls.append(True)

        settings = SimpleNamespace(allowed_chat_id=42)
        context = SimpleNamespace(application=SimpleNamespace(bot_data={"settings": settings}))

        async def exercise():
            await handler(
                SimpleNamespace(
                    effective_chat=SimpleNamespace(id=42, type="private"),
                    effective_user=SimpleNamespace(id=42),
                ),
                context,
            )
            await handler(
                SimpleNamespace(
                    effective_chat=SimpleNamespace(id=42, type="group"),
                    effective_user=SimpleNamespace(id=42),
                ),
                context,
            )
            await handler(
                SimpleNamespace(
                    effective_chat=SimpleNamespace(id=42, type="private"),
                    effective_user=SimpleNamespace(id=7),
                ),
                context,
            )

        asyncio.run(exercise())
        self.assertEqual(calls, [True])

    def test_nginx_log_reader_is_bounded_and_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "error.log"
            lines = [f"line-{index}-" + "x" * 200 for index in range(1000)]
            lines[-1] += "\x00control"
            path.write_text("\n".join(lines), encoding="utf-8")
            result = bot.read_nginx_errors(path)
        self.assertEqual(len(result), bot.MAX_LOG_LINES)
        self.assertTrue(all(len(line) <= 180 for line in result))
        self.assertTrue(all("\x00" not in line for line in result))

    def test_source_contains_no_embedded_token_or_home_path(self):
        source_path = Path(bot.__file__)
        source = source_path.read_text(encoding="utf-8")
        self.assertNotRegex(source, re.compile(r"[0-9]{8,12}:[A-Za-z0-9_-]{30,}"))
        self.assertNotIn("/home/micu", source)

        tree = ast.parse(source)
        banned_names = {"eval", "exec", "compile"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, banned_names)

    def test_safe_label_removes_controls_and_applies_limit(self):
        self.assertEqual(bot.safe_label("a\n\tb", 3), "a b")
        self.assertEqual(bot.safe_label("abcdef", 4), "abcd")

    def test_log_formatter_redacts_tokens_in_messages_and_exceptions(self):
        telegram_token = "12345678:" + "T" * 35
        bearer_token = "B" * 40
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg=f"url=/bot{telegram_token}/getMe Authorization: Bearer {bearer_token}",
            args=(),
            exc_info=None,
        )
        rendered = bot.RedactingFormatter("%(message)s").format(record)
        self.assertNotIn(telegram_token, rendered)
        self.assertNotIn(bearer_token, rendered)
        self.assertIn("REDACTED", rendered)


if __name__ == "__main__":
    unittest.main()
