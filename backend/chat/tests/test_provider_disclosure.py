"""Versioned disclosure gate before user content crosses to NVIDIA."""

from unittest import mock

import pytest
from rest_framework.test import APIClient

from chat.models import Message, ProviderDisclosureAcceptance
from chat.provider_disclosure import CURRENT_PROVIDER_DISCLOSURE_VERSION

pytestmark = pytest.mark.django_db


def _unaccepted_client(user):
    client = APIClient()
    client.force_login(user)
    return client


def test_acceptance_requires_authentication_and_csrf(user):
    anonymous = APIClient()
    assert anonymous.post(
        '/api/provider-disclosure/',
        {'version': CURRENT_PROVIDER_DISCLOSURE_VERSION},
        format='json',
    ).status_code == 403

    authenticated = APIClient(enforce_csrf_checks=True)
    authenticated.force_login(user)
    assert authenticated.post(
        '/api/provider-disclosure/',
        {'version': CURRENT_PROVIDER_DISCLOSURE_VERSION},
        format='json',
    ).status_code == 403
    assert not ProviderDisclosureAcceptance.objects.exists()


def test_auth_me_exposes_minimal_versioned_disclosure_state(client, user):
    anonymous = client.get('/api/auth/me/').json()
    assert 'provider_disclosure' not in anonymous

    client.force_login(user)
    state = client.get('/api/auth/me/').json()['provider_disclosure']
    assert state == {
        'required_version': CURRENT_PROVIDER_DISCLOSURE_VERSION,
        'accepted': False,
        'accepted_at': None,
    }


def test_acceptance_is_version_checked_idempotent_and_minimal(user):
    client = _unaccepted_client(user)
    wrong = client.post('/api/provider-disclosure/', {'version': True}, format='json')
    assert wrong.status_code == 409
    assert wrong.json()['code'] == 'provider_disclosure_version_mismatch'
    assert not ProviderDisclosureAcceptance.objects.exists()

    accepted = client.post('/api/provider-disclosure/', {
        'version': CURRENT_PROVIDER_DISCLOSURE_VERSION,
    }, format='json')
    assert accepted.status_code == 200
    first_timestamp = accepted.json()['provider_disclosure']['accepted_at']
    assert accepted.json()['provider_disclosure']['accepted'] is True

    replay = client.post('/api/provider-disclosure/', {
        'version': CURRENT_PROVIDER_DISCLOSURE_VERSION,
    }, format='json')
    assert replay.status_code == 200
    assert replay.json()['provider_disclosure']['accepted_at'] == first_timestamp
    row = ProviderDisclosureAcceptance.objects.get()
    assert row.user_id == user.pk
    assert row.version == CURRENT_PROVIDER_DISCLOSURE_VERSION


@mock.patch('chat.views._stream_nvidia')
def test_chat_fails_before_provider_or_message_write(mock_stream, user, convo):
    client = _unaccepted_client(user)
    response = client.post(
        f'/api/conversations/{convo.pk}/messages/',
        {'content': 'private prompt'},
        format='json',
    )

    assert response.status_code == 428
    assert response.json()['code'] == 'provider_disclosure_required'
    assert not Message.objects.filter(conversation=convo).exists()
    mock_stream.assert_not_called()


@mock.patch('chat.views._stream_nvidia')
def test_regenerate_preserves_branch_before_disclosure(mock_stream, user, convo):
    prompt = Message.objects.create(conversation=convo, role='user', content='private')
    reply = Message.objects.create(conversation=convo, role='assistant', content='keep me')
    client = _unaccepted_client(user)

    response = client.post(f'/api/messages/{reply.pk}/regenerate/')

    assert response.status_code == 428
    assert list(convo.messages.values_list('pk', flat=True)) == [prompt.pk, reply.pk]
    mock_stream.assert_not_called()


@mock.patch('chat.views._reserve_provider_call')
@mock.patch('chat.views._nvcf_generate')
def test_image_generation_fails_before_budget_or_provider(
    mock_generate, mock_reserve, user,
):
    client = _unaccepted_client(user)
    response = client.post(
        '/api/images/generate/',
        {'prompt': 'private image prompt'},
        format='json',
    )

    assert response.status_code == 428
    assert response.json()['code'] == 'provider_disclosure_required'
    mock_reserve.assert_not_called()
    mock_generate.assert_not_called()
