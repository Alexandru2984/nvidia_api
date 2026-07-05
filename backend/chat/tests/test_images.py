"""Tests for /api/images/generate/ — dimension validation and the NVCF flow."""
import base64
from unittest import mock

import pytest

from chat.models import Attachment

PNG_1PX = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk'
    'YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
)


def _resp(status_code=200, json_data=None, headers=None, text=''):
    r = mock.Mock()
    r.status_code = status_code
    r.headers = headers or {}
    r.text = text
    if json_data is not None:
        r.json.return_value = json_data
    else:
        r.json.side_effect = ValueError('no json')
    return r


@pytest.mark.django_db
class TestGenerateImage:
    URL = '/api/images/generate/'

    def test_requires_prompt(self, auth_client):
        r = auth_client.post(self.URL, {}, format='json')
        assert r.status_code == 400

    def test_rejects_dims_outside_flux_whitelist(self, auth_client):
        r = auth_client.post(self.URL, {'prompt': 'a cat', 'width': 512, 'height': 512}, format='json')
        assert r.status_code == 400
        assert 'allowed_dims' in r.json()

    def test_rejects_unknown_model(self, auth_client):
        r = auth_client.post(self.URL, {'prompt': 'a cat', 'model_id': 'nope/nope'}, format='json')
        assert r.status_code == 400

    @mock.patch('chat.views.requests.post')
    def test_success_saves_attachment(self, m_post, auth_client, user):
        b64 = base64.b64encode(PNG_1PX).decode()
        m_post.return_value = _resp(200, {'artifacts': [{'base64': b64}]})
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 201, r.content
        att = Attachment.objects.get(user=user)
        assert att.kind == Attachment.KIND_GENERATED
        assert att.size == len(PNG_1PX)
        # request carried the NVCF poll header
        _, kwargs = m_post.call_args
        assert 'NVCF-POLL-SECONDS' in kwargs['headers']

    @mock.patch('chat.views.requests.get')
    @mock.patch('chat.views.requests.post')
    def test_202_polls_status_until_done(self, m_post, m_get, auth_client, user):
        b64 = base64.b64encode(PNG_1PX).decode()
        m_post.return_value = _resp(202, headers={'NVCF-REQID': 'req-123'})
        m_get.side_effect = [
            _resp(202, headers={'NVCF-REQID': 'req-123'}),
            _resp(200, {'artifacts': [{'base64': b64}]}),
        ]
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 201, r.content
        assert m_get.call_count == 2
        assert 'req-123' in m_get.call_args[0][0]

    @mock.patch('chat.views.requests.post')
    def test_nvcf_errored_maps_to_clean_502(self, m_post, auth_client):
        m_post.return_value = _resp(504, headers={'Nvcf-Status': 'errored'}, text='gateway timeout')
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 502
        assert 'unavailable' in r.json()['error']

    @mock.patch('chat.views.requests.post')
    def test_upstream_400_maps_to_502_with_detail(self, m_post, auth_client):
        m_post.return_value = _resp(422, text='{"detail": "bad input"}')
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 502
        assert 'detail' in r.json()

    def test_anonymous_401(self, client, db):
        r = client.post(self.URL, {'prompt': 'a cat'}, format='json')
        assert r.status_code in (401, 403)
