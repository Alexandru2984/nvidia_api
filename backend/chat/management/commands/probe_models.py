"""Probe every catalog model against the live NVIDIA API and record which ones
are currently unavailable, so /api/models/ can hide them.

NVIDIA's /v1/models listing is unreliable in both directions (it lists models
that 404 on invocation and omits ones that work), so the only trustworthy
check is a real streamed chat/completions call with max_tokens=1 per model.

Scheduled in production by `aichat-model-probe.timer`.
"""
import concurrent.futures
import json
import logging
import time

import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from chat.model_status import (
    MAX_INCONCLUSIVE_STREAK,
    TRANSIENT_OUTCOMES,
    get_status,
    write_status,
)
from chat.models_catalog import MODEL_IDS
from chat.nvidia_client import chat_completion_headers, chat_completion_payload


DEFINITIVE_UNAVAILABLE_OUTCOMES = frozenset({'retired', 'rejected'})
INCONCLUSIVE_HIDE_THRESHOLD = 3
security_log = logging.getLogger('security')


def annotate_inconclusive_streaks(results, previous_status):
    """Bound consecutive transient failures without trusting them forever."""
    previous_results = previous_status.get('results', {})
    annotated = {}
    for model_id, result in results.items():
        current = dict(result)
        if current['outcome'] in TRANSIENT_OUTCOMES:
            previous = previous_results.get(model_id, {})
            previous_streak = previous.get('inconclusive_streak', 0)
            if previous.get('outcome') in TRANSIENT_OUTCOMES:
                current['inconclusive_streak'] = min(
                    previous_streak + 1, MAX_INCONCLUSIVE_STREAK,
                )
            else:
                current['inconclusive_streak'] = 1
        else:
            current['inconclusive_streak'] = 0
        annotated[model_id] = current
    return annotated


def resolve_unavailable(results, previous_status):
    """Absorb brief provider failures without trusting a dead endpoint forever."""
    prior_unavailable = set(previous_status.get('unavailable', []))
    prior_trusted = previous_status.get('state') in {'verified', 'degraded'}
    unavailable = set()
    for model_id, result in results.items():
        outcome = result['outcome']
        if outcome == 'available':
            continue
        if outcome in DEFINITIVE_UNAVAILABLE_OUTCOMES:
            unavailable.add(model_id)
            continue
        if outcome in TRANSIENT_OUTCOMES:
            if (
                not prior_trusted
                or model_id in prior_unavailable
                or result.get('inconclusive_streak', 1) >= INCONCLUSIVE_HIDE_THRESHOLD
            ):
                unavailable.add(model_id)
    return sorted(unavailable)


class Command(BaseCommand):
    help = 'Probe catalog models against the NVIDIA API; write model_status.json with the unavailable set.'

    def add_arguments(self, parser):
        parser.add_argument('--timeout', type=int, default=45, help='Per-request timeout in seconds.')
        parser.add_argument('--workers', type=int, default=8, help='Concurrent probe requests.')
        parser.add_argument('--dry-run', action='store_true', help='Probe and report, but do not write the status file.')

    def _probe(self, model_id, timeout):
        headers = chat_completion_headers(settings.NVIDIA_API_KEY)
        payload = chat_completion_payload(
            model_id,
            [{'role': 'user', 'content': 'Reply OK.'}],
            max_tokens=1,
            temperature=0.7,
        )
        started = time.monotonic()
        response = None
        try:
            response = requests.post(
                settings.NVIDIA_API_URL,
                json=payload,
                headers=headers,
                timeout=timeout,
                stream=True,
            )
            latency_ms = min(round((time.monotonic() - started) * 1000), 120_000)
            if response.status_code == 200:
                outcome = self._stream_outcome(response)
                latency_ms = min(round((time.monotonic() - started) * 1000), 120_000)
            elif response.status_code in (404, 410):
                outcome = 'retired'
            elif response.status_code in (400, 422):
                outcome = 'rejected'
            elif response.status_code == 429:
                outcome = 'throttled'
            elif response.status_code in (401, 403):
                outcome = 'authorization_error'
            elif response.status_code == 402:
                outcome = 'entitlement_error'
            else:
                outcome = 'provider_error'
        except requests.Timeout:
            latency_ms = min(round((time.monotonic() - started) * 1000), 120_000)
            outcome = 'timeout'
        except requests.RequestException:
            latency_ms = min(round((time.monotonic() - started) * 1000), 120_000)
            outcome = 'network_error'
        finally:
            if response is not None:
                response.close()
        return model_id, {'outcome': outcome, 'latency_ms': latency_ms, 'attempts': 1}

    @staticmethod
    def _stream_outcome(response):
        """Require the same complete SSE contract consumed by real chats."""
        content_type = str(response.headers.get('Content-Type', '')).lower()
        if content_type.split(';', 1)[0].strip() != 'text/event-stream':
            return 'protocol_error'

        saw_event = False
        saw_usage = False
        saw_done = False
        for line in response.iter_lines(decode_unicode=True):
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='replace')
            if not line or not line.startswith('data:'):
                continue
            data = line[5:].strip()
            if data == '[DONE]':
                saw_done = True
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict) or 'error' in event:
                return 'protocol_error'
            if 'choices' in event:
                saw_event = True
            if isinstance(event.get('usage'), dict):
                saw_usage = True
        return 'available' if saw_event and saw_usage and saw_done else 'protocol_error'

    def handle(self, *args, **opts):
        timeout = max(1, min(opts['timeout'], 120))
        workers = max(1, min(opts['workers'], 16))
        dry = opts['dry_run']
        ids = sorted(MODEL_IDS)
        previous_status = get_status()
        results = {}
        with concurrent.futures.ThreadPoolExecutor(workers) as ex:
            for mid, outcome in ex.map(lambda m: self._probe(m, timeout), ids):
                results[mid] = outcome

        # Retry every incomplete/failed contract once — serverless NIMs can
        # cold-start slowly, and one flaky stream must not hide a working model.
        flaky = [m for m, result in results.items() if result['outcome'] != 'available']
        if flaky:
            with concurrent.futures.ThreadPoolExecutor(min(workers, len(flaky))) as ex:
                for mid, outcome in ex.map(lambda m: self._probe(m, timeout), flaky):
                    outcome['attempts'] = 2
                    results[mid] = outcome

        results = annotate_inconclusive_streaks(results, previous_status)
        unavailable = resolve_unavailable(results, previous_status)
        inconclusive = sorted(
            model_id for model_id, result in results.items()
            if result['outcome'] in TRANSIENT_OUTCOMES
        )
        ok = len(ids) - len(unavailable)
        for m in unavailable:
            self.stdout.write(f"  DOWN ({results[m]['outcome']}): {m}")
        summary = f'{ok}/{len(ids)} models available; {len(unavailable)} marked unavailable.'
        if inconclusive:
            summary += f' {len(inconclusive)} probe results were inconclusive.'
        persistently_inconclusive = sum(
            result['outcome'] in TRANSIENT_OUTCOMES
            and result['inconclusive_streak'] >= INCONCLUSIVE_HIDE_THRESHOLD
            for result in results.values()
        )
        if persistently_inconclusive:
            summary += f' {persistently_inconclusive} exceeded the failure threshold.'

        if dry:
            self.stdout.write(f'[dry-run] {summary}')
            return
        write_status(unavailable, timezone.now().isoformat(), results=results)
        if inconclusive:
            authorization_failures = sum(
                result['outcome'] in {'authorization_error', 'entitlement_error'}
                for result in results.values()
            )
            security_log.warning(
                'event=model_probe_degraded inconclusive=%s persistent=%s',
                len(inconclusive), persistently_inconclusive,
            )
            if authorization_failures:
                security_log.error(
                    'event=model_probe_authorization_failed count=%s',
                    authorization_failures,
                )
        self.stdout.write(self.style.SUCCESS(summary))
