"""Owner-scoped persisted chat defaults and safe availability fallback."""
from unittest.mock import patch

import pytest
from django.core.cache import cache
from django.db import IntegrityError, transaction

from chat.models import ChatPreference
from chat.models_catalog import DEFAULT_MODEL_ID, MODEL_IDS


def _alternative_model():
    return sorted(MODEL_IDS - {DEFAULT_MODEL_ID})[0]


@pytest.mark.django_db
class TestChatPreferences:
    def test_endpoint_requires_authentication(self, client):
        assert client.get('/api/account/preferences/').status_code in (401, 403)
        assert client.patch(
            '/api/account/preferences/',
            {'default_model_id': DEFAULT_MODEL_ID},
            format='json',
        ).status_code in (401, 403)

    def test_absent_preference_uses_service_recommendation_without_writing(self, auth_client):
        response = auth_client.get('/api/account/preferences/')

        assert response.status_code == 200
        assert response.json() == {
            'default_model_id': None,
            'effective_default_model_id': DEFAULT_MODEL_ID,
            'service_default_model_id': DEFAULT_MODEL_ID,
            'configured_default_available': None,
            'default_temperature': None,
            'default_max_tokens': None,
            'effective_temperature': 0.7,
            'effective_max_tokens': 1024,
        }
        assert not ChatPreference.objects.exists()

    def test_preference_is_owner_scoped_and_drives_models_and_new_chats(
        self,
        auth_client,
        other_client,
        user,
        other_user,
    ):
        model_id = _alternative_model()

        updated = auth_client.patch(
            '/api/account/preferences/',
            {'default_model_id': model_id},
            format='json',
        )
        owner_models = auth_client.get('/api/models/')
        other_models = other_client.get('/api/models/')
        conversation = auth_client.post(
            '/api/conversations/',
            {'title': 'Uses my default'},
            format='json',
        )

        assert updated.status_code == 200
        assert updated.json()['default_model_id'] == model_id
        assert updated.json()['effective_default_model_id'] == model_id
        assert owner_models.json()['default'] == model_id
        assert other_models.json()['default'] == DEFAULT_MODEL_ID
        assert conversation.status_code == 201
        assert conversation.json()['model_id'] == model_id
        assert ChatPreference.objects.get(user=user).default_model_id == model_id
        assert not ChatPreference.objects.filter(user=other_user).exists()

    def test_generation_defaults_drive_new_conversations_only(
        self,
        auth_client,
        user,
    ):
        updated = auth_client.patch(
            '/api/account/preferences/',
            {'default_temperature': 0.2, 'default_max_tokens': 2048},
            format='json',
        )
        conversation = auth_client.post(
            '/api/conversations/', {'title': 'Custom generation'}, format='json',
        )

        assert updated.status_code == 200
        assert updated.json()['default_temperature'] == 0.2
        assert updated.json()['default_max_tokens'] == 2048
        assert updated.json()['effective_temperature'] == 0.2
        assert updated.json()['effective_max_tokens'] == 2048
        assert conversation.status_code == 201
        assert conversation.json()['temperature'] == 0.2
        assert conversation.json()['max_tokens'] == 2048
        preference = ChatPreference.objects.get(user=user)
        assert preference.default_model_id is None

    @pytest.mark.parametrize(('patch_value', 'code'), [
        ({'default_temperature': True}, 'invalid_default_temperature'),
        ({'default_temperature': 'nan'}, 'invalid_default_temperature'),
        ({'default_temperature': 1.1}, 'invalid_default_temperature'),
        ({'default_max_tokens': True}, 'invalid_default_max_tokens'),
        ({'default_max_tokens': 63}, 'invalid_default_max_tokens'),
        ({'default_max_tokens': 64.5}, 'invalid_default_max_tokens'),
        ({'default_max_tokens': 8193}, 'invalid_default_max_tokens'),
    ])
    def test_invalid_generation_defaults_are_rejected(
        self,
        auth_client,
        patch_value,
        code,
    ):
        response = auth_client.patch(
            '/api/account/preferences/', patch_value, format='json',
        )

        assert response.status_code == 400
        assert response.json()['code'] == code
        assert not ChatPreference.objects.exists()

    def test_model_specific_limit_is_enforced_and_existing_value_is_clamped(
        self,
        auth_client,
        user,
    ):
        riva = 'nvidia/riva-translate-4b-instruct-v2'
        ChatPreference.objects.create(user=user, default_max_tokens=8192)

        selected = auth_client.patch(
            '/api/account/preferences/', {'default_model_id': riva}, format='json',
        )
        rejected = auth_client.patch(
            '/api/account/preferences/', {'default_max_tokens': 4097}, format='json',
        )
        conversation = auth_client.post(
            '/api/conversations/', {'title': 'Riva bounded'}, format='json',
        )

        assert selected.status_code == 200, selected.content
        assert selected.json()['default_max_tokens'] == 8192
        assert selected.json()['effective_max_tokens'] == 4096
        assert rejected.status_code == 400
        assert rejected.json()['code'] == 'invalid_default_max_tokens'
        assert conversation.json()['max_tokens'] == 4096

    def test_reset_generation_defaults_keeps_selected_model(self, auth_client, user):
        ChatPreference.objects.create(
            user=user,
            default_model_id=_alternative_model(),
            default_temperature=0.2,
            default_max_tokens=2048,
        )

        response = auth_client.patch(
            '/api/account/preferences/',
            {'default_temperature': None, 'default_max_tokens': None},
            format='json',
        )

        assert response.status_code == 200
        preference = ChatPreference.objects.get(user=user)
        assert preference.default_model_id == _alternative_model()
        assert preference.default_temperature is None
        assert preference.default_max_tokens is None

    def test_null_or_empty_value_minimizes_data_by_deleting_preference(
        self,
        auth_client,
        user,
    ):
        ChatPreference.objects.create(user=user, default_model_id=_alternative_model())

        reset = auth_client.patch(
            '/api/account/preferences/',
            {'default_model_id': None},
            format='json',
        )

        assert reset.status_code == 200
        assert reset.json()['default_model_id'] is None
        assert reset.json()['effective_default_model_id'] == DEFAULT_MODEL_ID
        assert not ChatPreference.objects.filter(user=user).exists()

    @pytest.mark.parametrize('payload', [
        [],
        {},
        {'default_model_id': 7},
        {'default_model_id': True},
        {'default_model_id': 'attacker/unknown'},
        {'default_model_id': DEFAULT_MODEL_ID, 'unexpected': 'field'},
    ])
    def test_invalid_or_overposted_payload_is_rejected(self, auth_client, payload):
        response = auth_client.patch(
            '/api/account/preferences/', payload, format='json',
        )

        assert response.status_code == 400
        if isinstance(payload, dict):
            assert response.json()['code'] in {
                'invalid_preferences_payload', 'invalid_default_model',
            }
        assert not ChatPreference.objects.exists()

    def test_unavailable_model_cannot_be_selected(self, auth_client):
        model_id = _alternative_model()

        with patch('chat.views.unavailable_model_ids', return_value={model_id}):
            response = auth_client.patch(
                '/api/account/preferences/',
                {'default_model_id': model_id},
                format='json',
            )

        assert response.status_code == 409
        assert response.json()['code'] == 'model_unavailable'
        assert not ChatPreference.objects.exists()

    def test_saved_unavailable_model_falls_back_without_losing_owner_choice(
        self,
        auth_client,
        user,
    ):
        model_id = _alternative_model()
        ChatPreference.objects.create(user=user, default_model_id=model_id)

        with patch('chat.views.unavailable_model_ids', return_value={model_id}):
            preference = auth_client.get('/api/account/preferences/')
            models = auth_client.get('/api/models/')
            conversation = auth_client.post(
                '/api/conversations/', {'title': 'Fallback'}, format='json',
            )

        assert preference.json()['default_model_id'] == model_id
        assert preference.json()['configured_default_available'] is False
        assert preference.json()['effective_default_model_id'] != model_id
        assert models.json()['default'] != model_id
        assert conversation.status_code == 201
        assert conversation.json()['model_id'] != model_id
        assert ChatPreference.objects.get(user=user).default_model_id == model_id

    def test_patch_is_rate_limited(self, auth_client, settings):
        settings.RATELIMIT_ENABLE = True
        cache.clear()

        for _ in range(20):
            response = auth_client.patch(
                '/api/account/preferences/',
                {'default_model_id': None},
                format='json',
            )
            assert response.status_code == 200

        limited = auth_client.patch(
            '/api/account/preferences/',
            {'default_model_id': None},
            format='json',
        )
        assert limited.status_code == 429
        cache.clear()

    def test_account_deletion_cascades_preference(self, user):
        ChatPreference.objects.create(user=user, default_model_id=DEFAULT_MODEL_ID)

        user.delete()

        assert not ChatPreference.objects.exists()

    def test_database_rejects_generation_defaults_outside_global_bounds(self, user):
        with pytest.raises(IntegrityError), transaction.atomic():
            ChatPreference.objects.create(user=user, default_temperature=2.0)
