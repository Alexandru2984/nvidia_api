from rest_framework import serializers

from .models import Attachment, Conversation, Message


class AttachmentSerializer(serializers.ModelSerializer):
    url = serializers.CharField(read_only=True)
    has_text = serializers.SerializerMethodField()
    deletable = serializers.SerializerMethodField()

    class Meta:
        model = Attachment
        fields = ['id', 'kind', 'original_name', 'mime_type', 'size', 'url', 'has_text', 'created_at', 'deletable']

    def get_has_text(self, obj):
        return bool(obj.extracted_text)

    def get_deletable(self, obj):
        return obj.message_id is None


class MessageSerializer(serializers.ModelSerializer):
    attachments = AttachmentSerializer(many=True, read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'role', 'content', 'created_at', 'attachments']


class ConversationListSerializer(serializers.ModelSerializer):
    message_count = serializers.SerializerMethodField()

    class Meta:
        model = Conversation
        fields = ['id', 'title', 'model_id', 'is_pinned', 'archived_at',
                  'created_at', 'updated_at', 'message_count']

    def get_message_count(self, obj):
        annotated = getattr(obj, 'message_count', None)
        return annotated if annotated is not None else obj.messages.count()


class ConversationDetailSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = ['id', 'title', 'model_id', 'system_prompt', 'temperature', 'max_tokens',
                  'is_pinned', 'archived_at', 'created_at', 'updated_at', 'messages']
