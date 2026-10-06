"""Probe every catalog model against the live NVIDIA API and record which ones
are currently unavailable, so /api/models/ can hide them.

NVIDIA's /v1/models listing is unreliable in both directions (it lists models
that 404 on invocation and omits ones that work), so the only trustworthy
check is a real chat/completions call with max_tokens=1 per model.

Scheduled in production by `aichat-model-probe.timer`.
"""
import concurrent.futures
import time

import requests
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from chat.model_status import write_status
from chat.models_catalog import MODEL_IDS


class Command(BaseCommand):
    help = 'Probe catalog models against the NVIDIA API; write model_status.json with the unavailable set.'

    def add_arguments(self, parser):
        parser.add_argument('--timeout', type=int, default=45, help='Per-request timeout in seconds.')
        parser.add_argument('--workers', type=int, default=8, help='Concurrent probe requests.')
        parser.add_argument('--dry-run', action='store_true', help='Probe and report, but do not write the status file.')

    def _probe(self, model_id, timeout):
        headers = {
            'Authorization': f'Bearer {settings.NVIDIA_API_KEY}',
            'Content-Type': 'application/json',
        }
        payload = {'model': model_id, 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1}
        started = time.monotonic()
        try:
            r = requests.post(settings.NVIDIA_API_URL, json=payload, headers=headers, timeout=timeout)
            latency_ms = min(round((time.monotonic() - started) * 1000), 120_000)
            if r.status_code == 200:
                outcome = 'available'
            elif r.status_code in (404, 410):
                outcome = 'retired'
            elif r.status_code == 429:
                outcome = 'throttled'
            elif 400 <= r.status_code < 500:
                outcome = 'rejected'
            else:
                outcome = 'provider_error'
        except requests.Timeout:
            latency_ms = min(round((time.monotonic() - started) * 1000), 120_000)
            outcome = 'timeout'
        except requests.RequestException:
            latency_ms = min(round((time.monotonic() - started) * 1000), 120_000)
            outcome = 'network_error'
        return model_id, {'outcome': outcome, 'latency_ms': latency_ms, 'attempts': 1}

    def handle(self, *args, **opts):
        timeout = max(1, min(opts['timeout'], 120))
        workers = max(1, min(opts['workers'], 16))
        dry = opts['dry_run']
        ids = sorted(MODEL_IDS)
        results = {}
        with concurrent.futures.ThreadPoolExecutor(workers) as ex:
            for mid, outcome in ex.map(lambda m: self._probe(m, timeout), ids):
                results[mid] = outcome

        # Retry non-200s once — serverless NIMs can cold-start slowly, and a
        # single flaky timeout shouldn't hide a working model for a week.
        flaky = [m for m, result in results.items() if result['outcome'] != 'available']
        if flaky:
            with concurrent.futures.ThreadPoolExecutor(min(workers, len(flaky))) as ex:
                for mid, outcome in ex.map(lambda m: self._probe(m, timeout), flaky):
                    outcome['attempts'] = 2
                    results[mid] = outcome

        unavailable = sorted(
            model_id for model_id, result in results.items()
            if result['outcome'] != 'available'
        )
        ok = len(ids) - len(unavailable)
        for m in unavailable:
            self.stdout.write(f"  DOWN ({results[m]['outcome']}): {m}")
        summary = f'{ok}/{len(ids)} models available; {len(unavailable)} marked unavailable.'

        if dry:
            self.stdout.write(f'[dry-run] {summary}')
            return
        write_status(unavailable, timezone.now().isoformat(), results=results)
        self.stdout.write(self.style.SUCCESS(summary))
