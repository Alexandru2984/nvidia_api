"""Tests for /api/images/generate/ — dimension validation and the NVCF flow."""
import base64
import json
import struct
from unittest import mock

import pytest
from django.core.files.storage import default_storage

from chat.malware import INFECTED, MalwareScanError
from chat.models import Attachment

PNG_1PX = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk'
    'YPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='
)


def _resp(status_code=200, json_data=None, headers=None, text=''):
    r = mock.Mock()
    r.status_code = status_code
    content = json.dumps(json_data).encode() if json_data is not None else b''
    r.headers = dict(headers or {})
    r.headers.setdefault('Content-Type', 'application/json')
    if content:
        r.headers.setdefault('Content-Length', str(len(content)))
    r.text = text
    r.iter_content.return_value = [content] if content else []
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

    def test_rejects_out_of_range_seed(self, auth_client):
        r = auth_client.post(self.URL, {'prompt': 'a cat', 'seed': -1}, format='json')
        assert r.status_code == 400

    @pytest.mark.parametrize(('field', 'value'), [
        ('width', '1024'),
        ('height', 1024.0),
        ('steps', True),
        ('seed', 1.5),
    ])
    @mock.patch('chat.views.requests.post')
    def test_numeric_parameters_require_exact_json_integers(
        self, m_post, auth_client, field, value,
    ):
        response = auth_client.post(
            self.URL, {'prompt': 'a cat', field: value}, format='json',
        )

        assert response.status_code == 400
        m_post.assert_not_called()

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
        assert kwargs['stream'] is True
        assert kwargs['allow_redirects'] is False
        m_post.return_value.close.assert_called_once_with()

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
        assert m_get.call_args.kwargs['allow_redirects'] is False
        assert m_post.return_value.close.called

    @mock.patch('chat.views.requests.post')
    def test_database_rollback_discards_generated_storage_file(
        self, m_post, auth_client,
    ):
        encoded = base64.b64encode(PNG_1PX).decode()
        m_post.return_value = _resp(200, {'image': encoded})
        saved_names = []
        original_save = Attachment.save

        def save_then_fail(instance, *args, **kwargs):
            original_save(instance, *args, **kwargs)
            saved_names.append(instance.file.name)
            raise RuntimeError('forced database rollback')

        with mock.patch.object(Attachment, 'save', save_then_fail):
            response = auth_client.post(
                self.URL, {'prompt': 'a red dot'}, format='json',
            )

        assert response.status_code == 500
        assert saved_names
        assert not Attachment.objects.exists()
        assert all(not default_storage.exists(name) for name in saved_names)

    @mock.patch('chat.views.IMAGE_PROVIDER_MAX_POLLS', 3)
    @mock.patch('chat.views.requests.get')
    @mock.patch('chat.views.requests.post')
    def test_202_polling_is_bounded(
        self, m_post, m_get, auth_client, caplog,
    ):
        caplog.set_level('WARNING', logger='security')
        m_post.return_value = _resp(202, headers={'NVCF-REQID': 'req-123'})
        poll_responses = [
            _resp(202, headers={'NVCF-REQID': 'req-123'}) for _ in range(3)
        ]
        m_get.side_effect = poll_responses

        response = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert response.status_code == 502
        assert 'unavailable' in response.json()['error']
        assert m_get.call_count == 3
        assert all(item.close.called for item in poll_responses)
        assert (
            'event=provider_protocol_rejected kind=image reason=poll_limit'
            in caplog.text
        )

    @mock.patch('chat.views.requests.post')
    def test_nvcf_errored_maps_to_clean_502(self, m_post, auth_client):
        m_post.return_value = _resp(504, headers={'Nvcf-Status': 'errored'}, text='gateway timeout')
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 502
        assert 'unavailable' in r.json()['error']

    @mock.patch('chat.views.requests.post')
    def test_invalid_generated_bytes_are_not_stored(self, m_post, auth_client):
        m_post.return_value = _resp(200, {'image': base64.b64encode(b'<script>x</script>').decode()})
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 502
        assert not Attachment.objects.exists()

    @mock.patch('chat.views.requests.post')
    def test_generated_image_pixel_bomb_is_not_stored(
        self, m_post, auth_client, caplog,
    ):
        caplog.set_level('WARNING', logger='security')
        bomb = bytearray(PNG_1PX)
        bomb[16:24] = struct.pack('>II', 100_000, 100_000)
        m_post.return_value = _resp(200, {
            'image': base64.b64encode(bomb).decode(),
        })

        response = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert response.status_code == 502
        assert response.json()['error'] == 'Generated image failed validation'
        assert not Attachment.objects.exists()
        assert (
            'event=provider_protocol_rejected kind=image reason=image_dimensions'
            in caplog.text
        )

    @pytest.mark.parametrize('body', [
        lambda encoded: f'{{"image":"{encoded}","image":"{encoded}"}}'.encode(),
        lambda encoded: f'{{"image":"{encoded}","score":NaN}}'.encode(),
        lambda encoded: f'{{"image":"{encoded}","score":1e9999}}'.encode(),
        lambda encoded: f'{{"image":"{encoded}","label":"\\ud800"}}'.encode(),
    ])
    @mock.patch('chat.views.requests.post')
    def test_noncanonical_provider_json_is_rejected(
        self, m_post, auth_client, caplog, body,
    ):
        caplog.set_level('WARNING', logger='security')
        content = body(base64.b64encode(PNG_1PX).decode())
        response = _resp(200)
        response.headers['Content-Length'] = str(len(content))
        response.iter_content.return_value = [content]
        m_post.return_value = response

        result = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert result.status_code == 502
        assert not Attachment.objects.exists()
        assert (
            'event=provider_protocol_rejected kind=image reason=bounds_or_shape'
            in caplog.text
        )

    @mock.patch('chat.views.requests.post')
    def test_provider_json_requires_exact_content_type(
        self, m_post, auth_client, caplog,
    ):
        caplog.set_level('WARNING', logger='security')
        encoded = base64.b64encode(PNG_1PX).decode()
        response = _resp(200, {'image': encoded}, headers={'Content-Type': 'text/plain'})
        m_post.return_value = response

        result = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert result.status_code == 502
        assert not Attachment.objects.exists()
        response.iter_content.assert_not_called()
        assert (
            'event=provider_protocol_rejected kind=image reason=content_type'
            in caplog.text
        )

    @mock.patch('chat.views._reserve_provider_call')
    @mock.patch('chat.views.ping_scanner', side_effect=MalwareScanError)
    def test_scanner_outage_blocks_before_provider_budget(
        self, ping, reserve, auth_client, settings,
    ):
        settings.ATTACHMENT_MALWARE_SCAN_REQUIRED = True
        response = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert response.status_code == 503
        assert response.json()['code'] == 'attachment_scanner_unavailable'
        assert response['Retry-After'] == '60'
        reserve.assert_not_called()

    @mock.patch('chat.views.scan_attachment', return_value=INFECTED)
    @mock.patch('chat.views.ping_scanner')
    @mock.patch('chat.views.requests.post')
    def test_generated_malware_is_not_stored(
        self, m_post, ping, scan, auth_client, settings,
    ):
        settings.ATTACHMENT_MALWARE_SCAN_REQUIRED = True
        b64 = base64.b64encode(PNG_1PX).decode()
        m_post.return_value = _resp(200, {'artifacts': [{'base64': b64}]})

        response = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert response.status_code == 502
        assert response.json()['code'] == 'attachment_malware_detected'
        scan.assert_called_once()
        assert not Attachment.objects.exists()

    @mock.patch('chat.views.requests.post')
    def test_invalid_poll_identifier_is_rejected(
        self, m_post, auth_client, caplog,
    ):
        caplog.set_level('WARNING', logger='security')
        m_post.return_value = _resp(202, headers={'NVCF-REQID': '../admin'})
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 502
        assert 'event=provider_protocol_rejected kind=image reason=poll_identifier' in caplog.text

    @mock.patch('chat.views.requests.post')
    def test_oversized_provider_json_is_rejected_without_reading_body(
        self, m_post, auth_client,
    ):
        response = _resp(200)
        response.headers = {'Content-Length': str(16 * 1024 * 1024 + 1)}
        m_post.return_value = response

        result = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert result.status_code == 502
        response.iter_content.assert_not_called()
        response.close.assert_called_once_with()

    @mock.patch('chat.views.IMAGE_PROVIDER_MAX_RESPONSE_BYTES', 8)
    @mock.patch('chat.views.requests.post')
    def test_chunked_provider_json_is_bounded_while_streaming(
        self, m_post, auth_client,
    ):
        response = _resp(200)
        response.iter_content.return_value = [b'{"image"', b':"too large"}']
        m_post.return_value = response

        result = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')

        assert result.status_code == 502
        response.close.assert_called_once_with()

    @mock.patch('chat.views.requests.post')
    def test_upstream_400_maps_to_clean_502(self, m_post, auth_client):
        secret_upstream_detail = 'upstream-internal-secret'
        m_post.return_value = _resp(422, text=secret_upstream_detail)
        r = auth_client.post(self.URL, {'prompt': 'a red dot'}, format='json')
        assert r.status_code == 502
        assert secret_upstream_detail not in str(r.json())
        assert 'detail' not in r.json()

    def test_anonymous_401(self, client, db):
        r = client.post(self.URL, {'prompt': 'a cat'}, format='json')
        assert r.status_code in (401, 403)
