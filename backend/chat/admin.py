from django.contrib import admin

from .models import Conversation, Message


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
