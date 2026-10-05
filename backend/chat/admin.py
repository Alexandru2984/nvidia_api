from django.contrib import admin

from .models import Conversation, DailyAIUsage, GlobalAIUsage, Message


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'model_id', 'updated_at')
    search_fields = ('title', 'model_id')


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'conversation', 'role', 'short_content', 'created_at')
    list_filter = ('role',)
    search_fields = ('content',)

    def short_content(self, obj):
        return (obj.content[:60] + '…') if len(obj.content) > 60 else obj.content


class ReadOnlyUsageAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
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
