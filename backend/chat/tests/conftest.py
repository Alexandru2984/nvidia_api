"""Shared fixtures for chat tests."""
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from chat.models import Conversation, ProviderDisclosureAcceptance
from chat.models_catalog import DEFAULT_MODEL_ID
from chat.provider_disclosure import CURRENT_PROVIDER_DISCLOSURE_VERSION


@pytest.fixture
def user(db):
    User = get_user_model()
    return User.objects.create_user(
        username='alice', email='alice@example.com', password='Hunter2pass', is_active=True,
    )


@pytest.fixture
def other_user(db):
    User = get_user_model()
    return User.objects.create_user(
        username='bob', email='bob@example.com', password='Hunter2pass', is_active=True,
    )


@pytest.fixture
def client():
    return APIClient()


@pytest.fixture
def auth_client(client, user):
    ProviderDisclosureAcceptance.objects.create(
        user=user,
        version=CURRENT_PROVIDER_DISCLOSURE_VERSION,
    )
    client.force_login(user)
    return client


@pytest.fixture
def other_client(client, other_user):
    c = APIClient()
    ProviderDisclosureAcceptance.objects.create(
        user=other_user,
        version=CURRENT_PROVIDER_DISCLOSURE_VERSION,
    )
    c.force_login(other_user)
    return c


@pytest.fixture
def convo(user):
    return Conversation.objects.create(
        user=user, title='Test convo', model_id=DEFAULT_MODEL_ID,
    )
