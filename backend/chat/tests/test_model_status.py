"""Tests for the probe_models command and the /models/ availability filter."""
import json
import os
import stat
from unittest import mock

import pytest
import requests
from django.core.management import call_command
from django.utils import timezone

from chat.management.commands.probe_models import Command
from chat.model_status import get_status, write_status
from chat.models_catalog import DEFAULT_MODEL_ID, MODEL_IDS


@pytest.fixture
def status_file(settings, tmp_path):
    settings.MODEL_STATUS_FILE = str(tmp_path / 'model_status.json')
    return settings.MODEL_STATUS_FILE


class TestModelsEndpoint:
    def test_all_models_when_no_status_file(self, auth_client, status_file):
        r = auth_client.get('/api/models/')
        assert r.status_code == 200
        assert len(r.json()['models']) == len(MODEL_IDS)
        assert r.json()['default'] == DEFAULT_MODEL_ID

    def test_unavailable_models_are_hidden(self, auth_client, status_file):
        some_id = sorted(MODEL_IDS - {DEFAULT_MODEL_ID})[0]
        write_status([some_id], timezone.now().isoformat())
        r = auth_client.get('/api/models/')
        ids = {m['id'] for m in r.json()['models']}
        assert some_id not in ids
        assert len(ids) == len(MODEL_IDS) - 1
        assert r.json()['availability_checked_at'] is not None

    def test_default_falls_back_when_down(self, auth_client, status_file):
        write_status([DEFAULT_MODEL_ID], timezone.now().isoformat())
        r = auth_client.get('/api/models/')
        assert r.json()['default'] != DEFAULT_MODEL_ID
        assert r.json()['default'] in {m['id'] for m in r.json()['models']}

    def test_corrupt_existing_status_file_fails_closed(self, auth_client, status_file):
        with open(status_file, 'w') as f:
            f.write('{not json')
        r = auth_client.get('/api/models/')
        assert r.json()['models'] == []
        assert r.json()['default'] is None

    def test_successful_probe_exposes_only_coarse_performance(self, auth_client, status_file):
        write_status([], timezone.now().isoformat(), results={
            DEFAULT_MODEL_ID: {
                'outcome': 'available', 'latency_ms': 1234, 'attempts': 1,
            },
        })

        response = auth_client.get('/api/models/')
        model = next(item for item in response.json()['models'] if item['id'] == DEFAULT_MODEL_ID)

        assert model['performance'] == {
            'probe_latency_ms': 1200,
            'latency_band': 'fast',
            'sample': 'synthetic_1_token',
        }
        assert model['best_for'] == 'General chat and document analysis'
        assert 'outcome' not in json.dumps(model)

    def test_failed_probe_details_are_not_exposed(self, auth_client, status_file):
        write_status([], timezone.now().isoformat(), results={
            DEFAULT_MODEL_ID: {
                'outcome': 'provider_error', 'latency_ms': 9876, 'attempts': 2,
            },
        })

        response = auth_client.get('/api/models/')
        model = next(item for item in response.json()['models'] if item['id'] == DEFAULT_MODEL_ID)
        assert model['performance'] is None

    def test_runtime_status_is_catalog_scoped_and_schema_validated(self, status_file):
        with open(status_file, 'w') as status:
            json.dump({
                'checked_at': 'not-a-date',
                'unavailable': [DEFAULT_MODEL_ID, 'attacker/model', 42],
                'results': {
                    DEFAULT_MODEL_ID: {
                        'outcome': 'available', 'latency_ms': 'fast', 'attempts': 1,
                    },
                    'attacker/model': {
                        'outcome': 'available', 'latency_ms': 1, 'attempts': 1,
                    },
                },
                'unexpected': 'discard me',
            }, status)

        assert get_status() == {'unavailable': [DEFAULT_MODEL_ID]}


class TestProbeCommand:
    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_writes_unavailable_set(self, m_post, status_file):
        dead_id = sorted(MODEL_IDS)[0]

        def fake_post(url, json=None, **kwargs):
            r = mock.Mock()
            r.status_code = 404 if json['model'] == dead_id else 200
            return r

        m_post.side_effect = fake_post
        call_command('probe_models')
        data = json.loads(open(status_file).read())
        assert data['unavailable'] == [dead_id]
        assert data['results'][dead_id]['outcome'] == 'retired'
        assert data['results'][dead_id]['attempts'] == 2
        assert all(
            result['outcome'] == 'available'
            for model_id, result in data['results'].items()
            if model_id != dead_id
        )
        assert stat.S_IMODE(os.stat(status_file).st_mode) == 0o600
        # dead model was retried once before being marked
        dead_calls = [c for c in m_post.call_args_list if c.kwargs['json']['model'] == dead_id]
        assert len(dead_calls) == 2

    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_dry_run_writes_nothing(self, m_post, status_file):
        r = mock.Mock()
        r.status_code = 200
        m_post.return_value = r
        call_command('probe_models', '--dry-run')
        assert not os.path.exists(status_file)

    @mock.patch('chat.management.commands.probe_models.time.monotonic', side_effect=[10, 11.5])
    @mock.patch('chat.management.commands.probe_models.requests.post', side_effect=requests.ReadTimeout)
    def test_probe_sanitizes_timeout_and_bounds_latency(self, _post, _monotonic):
        model_id, result = Command()._probe(DEFAULT_MODEL_ID, 45)
        assert model_id == DEFAULT_MODEL_ID
        assert result == {'outcome': 'timeout', 'latency_ms': 1500, 'attempts': 1}
