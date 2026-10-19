"""Tests for the probe_models command and the /models/ availability filter."""
import json
import os
import pwd
import grp
import stat
from datetime import timedelta
from unittest import mock

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.core.management import call_command
from django.utils import timezone

from chat.management.commands.probe_models import Command
from chat.model_status import get_status, write_status
from chat.models_catalog import DEFAULT_MODEL_ID, MODEL_IDS


@pytest.fixture
def status_file(settings, tmp_path):
    settings.MODEL_STATUS_FILE = str(tmp_path / 'model_status.json')
    return settings.MODEL_STATUS_FILE


@pytest.fixture
def signing_keys(settings, tmp_path):
    private = Ed25519PrivateKey.generate()
    private_path = tmp_path / 'model-status-private.pem'
    public_path = tmp_path / 'model-status-public.pem'
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    private_path.chmod(0o600)
    public_path.chmod(0o600)
    settings.MODEL_STATUS_PRIVATE_KEY_FILE = str(private_path)
    settings.MODEL_STATUS_PUBLIC_KEY_FILE = str(public_path)
    settings.MODEL_STATUS_SIGNATURE_REQUIRED = True
    settings.MODEL_STATUS_SECURE_PERMISSIONS_REQUIRED = False
    return private_path, public_path


def complete_results(unavailable=()):
    unavailable = set(unavailable)
    return {
        model_id: {
            'outcome': 'retired' if model_id in unavailable else 'available',
            'latency_ms': 100,
            'attempts': 1,
        }
        for model_id in MODEL_IDS
    }


def healthy_probe_response(status_code=200):
    response = mock.Mock()
    response.status_code = status_code
    response.headers = {'Content-Type': 'text/event-stream; charset=utf-8'}
    response.iter_content.return_value = [b'\n'.join([
        b'data: {"choices":[{"delta":{"content":"OK"}}]}',
        b'data: {"choices":[],"usage":{"total_tokens":2}}',
        b'data: [DONE]',
    ]) + b'\n']
    return response


class TestModelsEndpoint:
    def test_all_models_when_no_status_file(self, auth_client, status_file):
        r = auth_client.get('/api/models/')
        assert r.status_code == 200
        assert len(r.json()['models']) == len(MODEL_IDS)
        assert r.json()['default'] == DEFAULT_MODEL_ID
        assert r.json()['availability'] == {
            'state': 'unverified', 'checked_at': None, 'inconclusive_models': 0,
            'unverified_models': len(MODEL_IDS),
            'catalog_models': len(MODEL_IDS), 'available_models': len(MODEL_IDS),
            'unavailable_models': 0,
        }

    def test_required_missing_status_fails_closed(self, auth_client, status_file, settings):
        settings.MODEL_STATUS_REQUIRED = True
        response = auth_client.get('/api/models/')
        assert response.status_code == 200
        assert response.json()['models'] == []
        assert response.json()['default'] is None
        assert response.json()['availability']['state'] == 'missing'
        assert response.json()['availability']['catalog_models'] == len(MODEL_IDS)
        assert response.json()['availability']['available_models'] == 0
        assert response.json()['availability']['unavailable_models'] == len(MODEL_IDS)

    def test_unavailable_models_are_hidden(self, auth_client, status_file):
        some_id = sorted(MODEL_IDS - {DEFAULT_MODEL_ID})[0]
        write_status(
            [some_id], timezone.now().isoformat(), results=complete_results([some_id]),
        )
        r = auth_client.get('/api/models/')
        ids = {m['id'] for m in r.json()['models']}
        assert some_id not in ids
        assert len(ids) == len(MODEL_IDS) - 1
        assert r.json()['availability_checked_at'] is not None
        assert r.json()['availability']['state'] == 'verified'
        assert r.json()['availability']['available_models'] == len(MODEL_IDS) - 1
        assert r.json()['availability']['unavailable_models'] == 1

    def test_default_falls_back_when_down(self, auth_client, status_file):
        write_status(
            [DEFAULT_MODEL_ID], timezone.now().isoformat(),
            results=complete_results([DEFAULT_MODEL_ID]),
        )
        r = auth_client.get('/api/models/')
        assert r.json()['default'] != DEFAULT_MODEL_ID
        assert r.json()['default'] in {m['id'] for m in r.json()['models']}

    def test_corrupt_existing_status_file_fails_closed(self, auth_client, status_file):
        with open(status_file, 'w') as f:
            f.write('{not json')
        r = auth_client.get('/api/models/')
        assert r.json()['models'] == []
        assert r.json()['default'] is None
        assert r.json()['availability']['state'] == 'invalid'

    def test_stale_status_fails_closed(self, auth_client, status_file, settings):
        settings.MODEL_STATUS_MAX_AGE_SECONDS = 60 * 60
        checked_at = timezone.now() - timedelta(hours=2)
        write_status([], checked_at.isoformat(), results=complete_results())

        response = auth_client.get('/api/models/')

        assert response.json()['models'] == []
        assert response.json()['default'] is None
        assert response.json()['availability']['state'] == 'stale'
        assert response.json()['availability']['checked_at'] == checked_at.isoformat()

    def test_future_status_timestamp_fails_closed(self, auth_client, status_file):
        write_status(
            [], (timezone.now() + timedelta(minutes=10)).isoformat(),
            results=complete_results(),
        )

        response = auth_client.get('/api/models/')

        assert response.json()['models'] == []
        assert response.json()['availability']['state'] == 'invalid'

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
        results = complete_results()
        results[DEFAULT_MODEL_ID] = {
            'outcome': 'provider_error', 'latency_ms': 9876, 'attempts': 2,
        }
        write_status([], timezone.now().isoformat(), results=results)

        response = auth_client.get('/api/models/')
        model = next(item for item in response.json()['models'] if item['id'] == DEFAULT_MODEL_ID)
        assert model['performance'] is None

    def test_model_without_probe_result_stays_hidden(self, auth_client, status_file):
        results = complete_results()
        results.pop(DEFAULT_MODEL_ID)
        write_status([], timezone.now().isoformat(), results=results)

        response = auth_client.get('/api/models/')

        ids = {model['id'] for model in response.json()['models']}
        assert DEFAULT_MODEL_ID not in ids
        assert response.json()['availability']['state'] == 'degraded'
        assert response.json()['availability']['unverified_models'] == 1

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

        status = get_status()
        assert status['state'] == 'invalid'
        assert set(status['unavailable']) == MODEL_IDS

    def test_runtime_status_rejects_inconsistent_inconclusive_streak(
        self, status_file,
    ):
        with open(status_file, 'w') as status:
            json.dump({
                'checked_at': timezone.now().isoformat(),
                'unavailable': [],
                'results': {
                    DEFAULT_MODEL_ID: {
                        'outcome': 'timeout', 'latency_ms': 100,
                        'attempts': 2, 'inconclusive_streak': 0,
                    },
                },
            }, status)

        runtime = get_status()
        assert DEFAULT_MODEL_ID not in runtime.get('results', {})
        assert DEFAULT_MODEL_ID in runtime['unavailable']
        assert runtime['unverified_models'] == len(MODEL_IDS)

    def test_status_symlink_fails_closed(self, settings, tmp_path):
        target = tmp_path / 'target.json'
        target.write_text(json.dumps({
            'checked_at': timezone.now().isoformat(),
            'unavailable': [],
            'results': complete_results(),
        }), encoding='utf-8')
        status = tmp_path / 'model_status.json'
        status.symlink_to(target)
        settings.MODEL_STATUS_FILE = str(status)

        assert get_status()['state'] == 'invalid'

    def test_signed_status_is_verified_but_signature_is_not_exposed(
        self, auth_client, status_file, signing_keys,
    ):
        write_status([], timezone.now().isoformat(), results=complete_results())

        stored = json.loads(open(status_file, encoding='utf-8').read())
        assert isinstance(stored['signature'], str)
        assert len(stored['signature']) == 88
        response = auth_client.get('/api/models/')
        assert response.json()['availability']['state'] == 'verified'
        assert 'signature' not in json.dumps(response.json())

    def test_required_unsigned_status_fails_closed(
        self, status_file, signing_keys,
    ):
        with open(status_file, 'w', encoding='utf-8') as status:
            json.dump({
                'checked_at': timezone.now().isoformat(),
                'unavailable': [],
                'results': complete_results(),
            }, status)

        assert get_status()['state'] == 'invalid'

    @pytest.mark.parametrize('mutation', ['unavailable', 'result', 'extra'])
    def test_signed_status_tampering_fails_closed(
        self, status_file, signing_keys, mutation,
    ):
        write_status([], timezone.now().isoformat(), results=complete_results())
        with open(status_file, encoding='utf-8') as status:
            data = json.load(status)
        if mutation == 'unavailable':
            data['unavailable'] = [DEFAULT_MODEL_ID]
        elif mutation == 'result':
            data['results'][DEFAULT_MODEL_ID]['latency_ms'] += 1
        else:
            data['unsigned_extra'] = True
        with open(status_file, 'w', encoding='utf-8') as status:
            json.dump(data, status)

        assert get_status()['state'] == 'invalid'
        assert set(get_status()['unavailable']) == MODEL_IDS

    def test_public_key_rotation_invalidates_cached_status(
        self, status_file, signing_keys,
    ):
        _, public_path = signing_keys
        write_status([], timezone.now().isoformat(), results=complete_results())
        assert get_status()['state'] == 'verified'
        replacement = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_path.write_bytes(replacement)
        public_path.chmod(0o600)

        assert get_status()['state'] == 'invalid'

    def test_status_permission_drift_fails_closed(
        self, settings, status_file, signing_keys,
    ):
        settings.MODEL_STATUS_SECURE_PERMISSIONS_REQUIRED = True
        settings.MODEL_STATUS_EXPECTED_OWNER = pwd.getpwuid(os.getuid()).pw_name
        settings.MODEL_STATUS_EXPECTED_GROUP = grp.getgrgid(os.getgid()).gr_name
        settings.MODEL_STATUS_EXPECTED_MODE = 0o600
        write_status([], timezone.now().isoformat(), results=complete_results())
        assert get_status()['state'] == 'verified'

        os.chmod(status_file, 0o640)
        assert get_status()['state'] == 'invalid'

    def test_legacy_runtime_status_infers_bounded_streak(self, status_file):
        with open(status_file, 'w') as status:
            json.dump({
                'checked_at': timezone.now().isoformat(),
                'unavailable': [],
                'results': {
                    DEFAULT_MODEL_ID: {
                        'outcome': 'timeout', 'latency_ms': 100, 'attempts': 2,
                    },
                },
            }, status)

        result = get_status()['results'][DEFAULT_MODEL_ID]
        assert result['outcome'] == 'timeout'
        assert result['inconclusive_streak'] == 1


class TestProbeCommand:
    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_writes_unavailable_set(self, m_post, status_file):
        dead_id = sorted(MODEL_IDS)[0]

        def fake_post(url, json=None, **kwargs):
            return healthy_probe_response(404 if json['model'] == dead_id else 200)

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
    def test_transient_failure_preserves_last_verified_availability(
        self, m_post, status_file,
    ):
        write_status([], timezone.now().isoformat(), results={
            DEFAULT_MODEL_ID: {
                'outcome': 'available', 'latency_ms': 100, 'attempts': 1,
            },
        })

        def fake_post(url, json=None, **kwargs):
            if json['model'] == DEFAULT_MODEL_ID:
                raise requests.ReadTimeout
            return healthy_probe_response()

        m_post.side_effect = fake_post
        call_command('probe_models')

        data = json.loads(open(status_file).read())
        assert DEFAULT_MODEL_ID not in data['unavailable']
        assert data['results'][DEFAULT_MODEL_ID]['outcome'] == 'timeout'
        assert data['results'][DEFAULT_MODEL_ID]['inconclusive_streak'] == 1
        assert get_status()['state'] == 'degraded'
        assert get_status()['inconclusive_models'] == 1

    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_repeated_transient_failures_eventually_hide_then_recover_model(
        self, m_post, status_file,
    ):
        write_status([], timezone.now().isoformat(), results=complete_results())
        failing = True

        def fake_post(url, json=None, **kwargs):
            if failing and json['model'] == DEFAULT_MODEL_ID:
                raise requests.ReadTimeout
            return healthy_probe_response()

        m_post.side_effect = fake_post
        for expected_streak in (1, 2):
            call_command('probe_models')
            data = json.loads(open(status_file).read())
            assert DEFAULT_MODEL_ID not in data['unavailable']
            assert data['results'][DEFAULT_MODEL_ID]['inconclusive_streak'] == expected_streak

        call_command('probe_models')
        data = json.loads(open(status_file).read())
        assert DEFAULT_MODEL_ID in data['unavailable']
        assert data['results'][DEFAULT_MODEL_ID]['inconclusive_streak'] == 3

        failing = False
        call_command('probe_models')
        data = json.loads(open(status_file).read())
        assert DEFAULT_MODEL_ID not in data['unavailable']
        assert data['results'][DEFAULT_MODEL_ID]['outcome'] == 'available'
        assert data['results'][DEFAULT_MODEL_ID]['inconclusive_streak'] == 0

    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_transient_failure_for_unverified_model_fails_closed(
        self, m_post, status_file,
    ):
        def fake_post(url, json=None, **kwargs):
            if json['model'] == DEFAULT_MODEL_ID:
                raise requests.ConnectionError
            return healthy_probe_response()

        m_post.side_effect = fake_post
        call_command('probe_models')

        data = json.loads(open(status_file).read())
        assert DEFAULT_MODEL_ID in data['unavailable']
        assert data['results'][DEFAULT_MODEL_ID]['outcome'] == 'network_error'

    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_dry_run_writes_nothing(self, m_post, status_file):
        m_post.return_value = healthy_probe_response()
        call_command('probe_models', '--dry-run')
        assert not os.path.exists(status_file)

    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_probe_uses_the_production_streaming_contract(self, m_post):
        m_post.return_value = healthy_probe_response()

        _, result = Command()._probe(DEFAULT_MODEL_ID, 45)

        assert result['outcome'] == 'available'
        request = m_post.call_args
        assert request.kwargs['stream'] is True
        assert request.kwargs['allow_redirects'] is False
        assert request.kwargs['headers']['Accept'] == 'text/event-stream'
        assert request.kwargs['json'] == {
            'model': DEFAULT_MODEL_ID,
            'messages': [{'role': 'user', 'content': 'Reply OK.'}],
            'max_tokens': 1,
            'temperature': 0.7,
            'stream': True,
            'stream_options': {'include_usage': True},
        }
        m_post.return_value.close.assert_called_once_with()

    @pytest.mark.parametrize(('content_type', 'lines'), [
        ('application/json', [b'{"choices":[]}']),
        ('text/event-stream', [b'data: {"choices":[]}']),
        ('text/event-stream', [b'data: {"choices":[]}', b'data: [DONE]']),
        ('text/event-stream', [b'data: {"error":{"message":"unavailable"}}', b'data: [DONE]']),
        ('text/event-stream', [b'data: not-json', b'data: [DONE]']),
    ])
    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_http_200_requires_a_complete_valid_sse_stream(
        self, m_post, content_type, lines,
    ):
        response = healthy_probe_response()
        response.headers = {'Content-Type': content_type}
        response.iter_content.return_value = [b'\n'.join(lines) + b'\n']
        m_post.return_value = response

        _, result = Command()._probe(DEFAULT_MODEL_ID, 45)

        assert result['outcome'] == 'protocol_error'

    @mock.patch('chat.management.commands.probe_models.time.monotonic', side_effect=[10, 11.5])
    @mock.patch('chat.management.commands.probe_models.requests.post', side_effect=requests.ReadTimeout)
    def test_probe_sanitizes_timeout_and_bounds_latency(self, _post, _monotonic):
        model_id, result = Command()._probe(DEFAULT_MODEL_ID, 45)
        assert model_id == DEFAULT_MODEL_ID
        assert result == {'outcome': 'timeout', 'latency_ms': 1500, 'attempts': 1}

    @pytest.mark.parametrize(('status_code', 'expected'), [
        (200, 'available'),
        (400, 'rejected'),
        (401, 'authorization_error'),
        (402, 'entitlement_error'),
        (403, 'authorization_error'),
        (404, 'retired'),
        (408, 'provider_error'),
        (410, 'retired'),
        (422, 'rejected'),
        (425, 'provider_error'),
        (429, 'throttled'),
        (500, 'provider_error'),
    ])
    @mock.patch('chat.management.commands.probe_models.requests.post')
    def test_probe_classifies_only_model_contract_errors_as_definitive(
        self, m_post, status_code, expected,
    ):
        m_post.return_value = healthy_probe_response(status_code)

        _, result = Command()._probe(DEFAULT_MODEL_ID, 45)

        assert result['outcome'] == expected
