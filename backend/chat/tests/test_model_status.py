"""Tests for the probe_models command and the /models/ availability filter."""
import json
from unittest import mock

import pytest
from django.core.management import call_command
from django.utils import timezone

from chat.model_status import write_status
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

    def test_corrupt_status_file_is_ignored(self, auth_client, status_file):
        with open(status_file, 'w') as f:
            f.write('{not json')
        r = auth_client.get('/api/models/')
        assert len(r.json()['models']) == len(MODEL_IDS)


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
        # dead model was retried once before being marked
        dead_calls = [c for c in m_post.call_args_list if c.kwargs['json']['model'] == dead_id]
        assert len(dead_calls) == 2

    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_dry_run_writes_nothing(self, m_post, status_file):
        r = mock.Mock()
        r.status_code = 200
        m_post.return_value = r
        call_command('probe_models', '--dry-run')
        import os
        assert not os.path.exists(status_file)
