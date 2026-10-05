"""Transactional daily budgets for calls that can incur provider cost."""
from datetime import datetime, time, timedelta
from datetime import timezone as datetime_timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from .models import DailyAIUsage, GlobalAIUsage


def _limits(kind):
    if kind == 'chat':
        return (
            'chat_requests',
            settings.AI_USER_DAILY_CHAT_LIMIT,
            settings.AI_GLOBAL_DAILY_CHAT_LIMIT,
        )
    if kind == 'image':
        return (
            'image_requests',
            settings.AI_USER_DAILY_IMAGE_LIMIT,
            settings.AI_GLOBAL_DAILY_IMAGE_LIMIT,
        )
    raise ValueError('unknown AI usage kind')


def reserve_ai_request(user, kind, prompt_characters=0):
    """Atomically reserve one provider call.

    Returns ``None`` when allowed, otherwise a stable reason string. Provider
    counters are locked before user counters so concurrent workers cannot
    overspend the global limit or deadlock through inconsistent lock order.
    """
    if not settings.AI_GENERATION_ENABLED:
        return 'disabled'

    field, user_limit, global_limit = _limits(kind)
    day = timezone.localdate()
    prompt_characters = max(0, int(prompt_characters))
    User = get_user_model()

    with transaction.atomic():
        global_usage, _ = GlobalAIUsage.objects.select_for_update().get_or_create(day=day)
        User.objects.select_for_update().only('pk').get(pk=user.pk)
        user_usage, _ = DailyAIUsage.objects.select_for_update().get_or_create(user=user, day=day)

        if getattr(global_usage, field) >= global_limit:
            return 'global_daily_limit'
        if getattr(user_usage, field) >= user_limit:
            return 'user_daily_limit'

        setattr(global_usage, field, getattr(global_usage, field) + 1)
        global_usage.prompt_characters += prompt_characters
        global_usage.save(update_fields=[field, 'prompt_characters'])

        setattr(user_usage, field, getattr(user_usage, field) + 1)
        user_usage.prompt_characters += prompt_characters
        user_usage.save(update_fields=[field, 'prompt_characters'])

    return None


def next_reset():
    now = timezone.now()
    tomorrow = now.date() + timedelta(days=1)
    reset = datetime.combine(tomorrow, time.min, tzinfo=datetime_timezone.utc)
    return reset, max(1, int((reset - now).total_seconds()))


def user_usage_snapshot(user):
    day = timezone.localdate()
    usage = DailyAIUsage.objects.filter(user=user, day=day).first()
    reset, _ = next_reset()
    return {
        'date': day.isoformat(),
        'chat_requests': usage.chat_requests if usage else 0,
        'chat_limit': settings.AI_USER_DAILY_CHAT_LIMIT,
        'image_requests': usage.image_requests if usage else 0,
        'image_limit': settings.AI_USER_DAILY_IMAGE_LIMIT,
        'prompt_characters': usage.prompt_characters if usage else 0,
        'resets_at': reset.isoformat().replace('+00:00', 'Z'),
        'enabled': settings.AI_GENERATION_ENABLED,
    }
