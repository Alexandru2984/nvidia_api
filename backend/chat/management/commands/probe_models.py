"""Probe every catalog model against the live NVIDIA API and record which ones
are currently unavailable, so /api/models/ can hide them.

NVIDIA's /v1/models listing is unreliable in both directions (it lists models
that 404 on invocation and omits ones that work), so the only trustworthy
check is a real chat/completions call with max_tokens=1 per model.

Scheduled in production by `aichat-model-probe.timer`.
"""
import concurrent.futures

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
        try:
            r = requests.post(settings.NVIDIA_API_URL, json=payload, headers=headers, timeout=timeout)
            return model_id, r.status_code
        except requests.RequestException as e:
            return model_id, type(e).__name__

    def handle(self, *args, **opts):
        timeout, workers, dry = opts['timeout'], opts['workers'], opts['dry_run']
        ids = sorted(MODEL_IDS)
        results = {}
        with concurrent.futures.ThreadPoolExecutor(workers) as ex:
            for mid, outcome in ex.map(lambda m: self._probe(m, timeout), ids):
                results[mid] = outcome

        # Retry non-200s once — serverless NIMs can cold-start slowly, and a
        # single flaky timeout shouldn't hide a working model for a week.
        flaky = [m for m, s in results.items() if s != 200]
        if flaky:
            with concurrent.futures.ThreadPoolExecutor(min(workers, len(flaky))) as ex:
                for mid, outcome in ex.map(lambda m: self._probe(m, timeout), flaky):
                    results[mid] = outcome

        unavailable = sorted(m for m, s in results.items() if s != 200)
        ok = len(ids) - len(unavailable)
        for m in unavailable:
            self.stdout.write(f'  DOWN ({results[m]}): {m}')
        summary = f'{ok}/{len(ids)} models available; {len(unavailable)} marked unavailable.'

        if dry:
            self.stdout.write(f'[dry-run] {summary}')
            return
        write_status(unavailable, timezone.now().isoformat(), results={m: str(s) for m, s in results.items()})
        self.stdout.write(self.style.SUCCESS(summary))
