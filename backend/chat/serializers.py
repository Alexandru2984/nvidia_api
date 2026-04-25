from rest_framework import serializers

from .models import Attachment, Conversation, Message


class AttachmentSerializer(serializers.ModelSerializer):
    url = serializers.CharField(read_only=True)
    has_text = serializers.SerializerMethodField()

    class Meta:
        model = Attachment
        fields = ['id', 'kind', 'original_name', 'mime_type', 'size', 'url', 'has_text', 'created_at']

    def get_has_text(self, obj):
        return bool(obj.extracted_text)


class MessageSerializer(serializers.ModelSerializer):
    attachments = AttachmentSerializer(many=True, read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'role', 'content', 'created_at', 'attachments']


class ConversationListSerializer(serializers.ModelSerializer):
    message_count = serializers.IntegerField(source='messages.count', read_only=True)

    class Meta:
        model = Conversation
        fields = ['id', 'title', 'model_id', 'created_at', 'updated_at', 'message_count']


class ConversationDetailSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = ['id', 'title', 'model_id', 'created_at', 'updated_at', 'messages']
