from django.contrib import admin
from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import GroupAdmin, UserAdmin
from django.contrib.auth.models import Group

from .admin_audit import PrivacyAuditAdminMixin
from .models import (
    AdminAuditEvent,
    Conversation,
    DailyAIUsage,
    GlobalAIUsage,
    Message,
    RegistrationInvite,
)

User = get_user_model()
admin.site.unregister(User)
admin.site.unregister(Group)


@admin.register(User)
class AuditedUserAdmin(PrivacyAuditAdminMixin, UserAdmin):
    pass


@admin.register(Group)
class AuditedGroupAdmin(PrivacyAuditAdminMixin, GroupAdmin):
    pass


@admin.register(Conversation)
class ConversationAdmin(PrivacyAuditAdminMixin, admin.ModelAdmin):
    list_display = ('id', 'title', 'model_id', 'updated_at')
    search_fields = ('title', 'model_id')


@admin.register(Message)
class MessageAdmin(PrivacyAuditAdminMixin, admin.ModelAdmin):
    list_display = ('id', 'conversation', 'role', 'short_content', 'created_at')
    list_filter = ('role',)
    search_fields = ('content',)

    def short_content(self, obj):
        return (obj.content[:60] + '…') if len(obj.content) > 60 else obj.content


class ReadOnlyUsageAdmin(PrivacyAuditAdminMixin, admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def get_readonly_fields(self, request, obj=None):
        return [field.name for field in self.model._meta.fields]


@admin.register(DailyAIUsage)
class DailyAIUsageAdmin(ReadOnlyUsageAdmin):
    list_display = ('day', 'user', 'chat_requests', 'image_requests', 'prompt_characters')
    list_filter = ('day',)
    search_fields = ('user__username', 'user__email')


@admin.register(GlobalAIUsage)
class GlobalAIUsageAdmin(ReadOnlyUsageAdmin):
    list_display = ('day', 'chat_requests', 'image_requests', 'prompt_characters')
    list_filter = ('day',)


@admin.register(RegistrationInvite)
class RegistrationInviteAdmin(PrivacyAuditAdminMixin, admin.ModelAdmin):
    list_display = ('id', 'created_at', 'expires_at', 'used_at', 'used_by')
    list_filter = ('used_at', 'expires_at')
    exclude = ('code_hash',)
    readonly_fields = ('created_at', 'expires_at', 'used_at', 'used_by')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class ReadOnlyAuditAdmin(PrivacyAuditAdminMixin, admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LogEntry)
class LogEntryAdmin(ReadOnlyAuditAdmin):
    list_display = ('action_time', 'user', 'content_type', 'object_repr', 'action_flag')
    list_filter = ('action_flag', 'content_type')
    date_hierarchy = 'action_time'
    readonly_fields = tuple(field.name for field in LogEntry._meta.fields)


@admin.register(AdminAuditEvent)
class AdminAuditEventAdmin(ReadOnlyAuditAdmin):
    list_display = (
        'occurred_at', 'actor_user_id', 'action', 'model_label', 'object_ref', 'changed_fields',
    )
    list_filter = ('action', 'model_label')
    search_fields = ('=actor_user_id', 'model_label', 'object_ref')
    date_hierarchy = 'occurred_at'
    exclude = ('integrity_tag',)
    readonly_fields = (
        'occurred_at', 'admin_log_id', 'actor_user_id', 'action', 'model_label',
        'object_ref', 'changed_fields',
    )
