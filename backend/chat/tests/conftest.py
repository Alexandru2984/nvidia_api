"""Shared fixtures for chat tests."""
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from chat.models import Conversation


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
    client.force_login(user)
    return client


@pytest.fixture
def other_client(client, other_user):
    c = APIClient()
    c.force_login(other_user)
    return c


@pytest.fixture
def convo(user):
    return Conversation.objects.create(
        user=user, title='Test convo', model_id='meta/llama-3.1-8b-instruct',
    )
