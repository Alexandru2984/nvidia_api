"""Transactional daily budgets for calls that can incur provider cost."""
from datetime import datetime, time, timedelta
from datetime import timezone as datetime_timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from .models import DailyAIUsage, GlobalAIUsage

MAX_REPORTED_TOKENS = 10_000_000


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


def reserve_ai_request(user, kind, prompt_characters=0, token_reservation=0, day=None):
    """Atomically reserve one provider call.

    Returns ``None`` when allowed, otherwise a stable reason string. Provider
    counters are locked before user counters so concurrent workers cannot
    overspend the global limit or deadlock through inconsistent lock order.
    """
    if not settings.AI_GENERATION_ENABLED:
        return 'disabled'

    field, user_limit, global_limit = _limits(kind)
    day = day or timezone.localdate()
    prompt_characters = max(0, int(prompt_characters))
    token_reservation = max(0, int(token_reservation)) if kind == 'chat' else 0
    User = get_user_model()

    with transaction.atomic():
        global_usage, _ = GlobalAIUsage.objects.select_for_update().get_or_create(day=day)
        User.objects.select_for_update().only('pk').get(pk=user.pk)
        user_usage, _ = DailyAIUsage.objects.select_for_update().get_or_create(user=user, day=day)

        if getattr(global_usage, field) >= global_limit:
            return 'global_daily_limit'
        if getattr(user_usage, field) >= user_limit:
            return 'user_daily_limit'
        if token_reservation:
            global_tokens = (
                global_usage.prompt_tokens
                + global_usage.completion_tokens
                + global_usage.reserved_tokens
            )
            user_tokens = (
                user_usage.prompt_tokens
                + user_usage.completion_tokens
                + user_usage.reserved_tokens
            )
            if global_tokens + token_reservation > settings.AI_GLOBAL_DAILY_TOKEN_LIMIT:
                return 'global_daily_token_limit'
            if user_tokens + token_reservation > settings.AI_USER_DAILY_TOKEN_LIMIT:
                return 'user_daily_token_limit'

        setattr(global_usage, field, getattr(global_usage, field) + 1)
        global_usage.prompt_characters += prompt_characters
        global_usage.reserved_tokens += token_reservation
        global_usage.save(update_fields=[field, 'prompt_characters', 'reserved_tokens'])

        setattr(user_usage, field, getattr(user_usage, field) + 1)
        user_usage.prompt_characters += prompt_characters
        user_usage.reserved_tokens += token_reservation
        user_usage.save(update_fields=[field, 'prompt_characters', 'reserved_tokens'])

    return None


def _validated_token_usage(usage):
    if not isinstance(usage, dict):
        return None

    def token_value(name, default=None):
        value = usage.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        if value < 0 or value > MAX_REPORTED_TOKENS:
            return None
        return value

    total = token_value('total_tokens')
    if total is None:
        return None
    prompt = token_value('prompt_tokens', 0)
    completion = token_value('completion_tokens', max(0, total - (prompt or 0)))
    if prompt is None or completion is None:
        return None
    # Never undercount an inconsistent upstream total.
    if prompt + completion > MAX_REPORTED_TOKENS:
        return None
    billed_total = max(total, prompt + completion)
    completion += billed_total - (prompt + completion)
    return prompt, completion, billed_total


def finalize_chat_usage(user_id, day, token_reservation, usage):
    """Replace a pre-call reservation with validated provider token usage.

    Missing or malformed usage fails closed: the reservation remains charged
    until the UTC reset and an unmetered counter is incremented for detection.
    Returns ``recorded``, ``overrun``, or ``unmetered``.
    """
    token_reservation = max(0, int(token_reservation))
    parsed = _validated_token_usage(usage)

    with transaction.atomic():
        global_usage = GlobalAIUsage.objects.select_for_update().get(day=day)
        try:
            user_usage = DailyAIUsage.objects.select_for_update().get(user_id=user_id, day=day)
        except DailyAIUsage.DoesNotExist:
            # Account deletion cascades the user row while a stream may still
            # be winding down. Keep the global reservation fail-closed.
            return 'unmetered'

        if parsed is None:
            global_usage.unmetered_chat_requests += 1
            user_usage.unmetered_chat_requests += 1
            global_usage.save(update_fields=['unmetered_chat_requests'])
            user_usage.save(update_fields=['unmetered_chat_requests'])
            return 'unmetered'

        prompt, completion, total = parsed
        released_global = min(token_reservation, global_usage.reserved_tokens)
        released_user = min(token_reservation, user_usage.reserved_tokens)
        global_usage.reserved_tokens -= released_global
        user_usage.reserved_tokens -= released_user
        global_usage.prompt_tokens += prompt
        global_usage.completion_tokens += completion
        user_usage.prompt_tokens += prompt
        user_usage.completion_tokens += completion
        fields = ['reserved_tokens', 'prompt_tokens', 'completion_tokens']
        global_usage.save(update_fields=fields)
        user_usage.save(update_fields=fields)
        return 'overrun' if total > token_reservation else 'recorded'


def next_reset():
    now = timezone.now()
    tomorrow = now.date() + timedelta(days=1)
    reset = datetime.combine(tomorrow, time.min, tzinfo=datetime_timezone.utc)
    return reset, max(1, int((reset - now).total_seconds()))


def user_usage_snapshot(user):
    day = timezone.localdate()
    usage = DailyAIUsage.objects.filter(user=user, day=day).first()
    reset, _ = next_reset()
    prompt_tokens = usage.prompt_tokens if usage else 0
    completion_tokens = usage.completion_tokens if usage else 0
    reserved_tokens = usage.reserved_tokens if usage else 0
    return {
        'date': day.isoformat(),
        'chat_requests': usage.chat_requests if usage else 0,
        'chat_limit': settings.AI_USER_DAILY_CHAT_LIMIT,
        'image_requests': usage.image_requests if usage else 0,
        'image_limit': settings.AI_USER_DAILY_IMAGE_LIMIT,
        'prompt_characters': usage.prompt_characters if usage else 0,
        'prompt_tokens': prompt_tokens,
        'completion_tokens': completion_tokens,
        'reserved_tokens': reserved_tokens,
        'token_budget_used': prompt_tokens + completion_tokens + reserved_tokens,
        'token_limit': settings.AI_USER_DAILY_TOKEN_LIMIT,
        'unmetered_chat_requests': usage.unmetered_chat_requests if usage else 0,
        'resets_at': reset.isoformat().replace('+00:00', 'Z'),
        'enabled': settings.AI_GENERATION_ENABLED,
    }
