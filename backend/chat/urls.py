from django.urls import path, register_converter

from . import sessions as sessions_views, twofactor, views
from .converters import PositiveBigIntConverter, SessionHandleConverter

register_converter(PositiveBigIntConverter, 'positive_bigint')
register_converter(SessionHandleConverter, 'session_handle')

urlpatterns = [
    path('health/', views.health),
    path('auth/me/', views.auth_me),
    path('account/usage/', views.account_usage),
    path('account/chat-retention/', views.account_chat_retention),
    path('provider-disclosure/', views.accept_provider_disclosure),
    path('auth/login/', views.auth_login),
    path('auth/logout/', views.auth_logout),
    path('auth/reauthenticate/', views.auth_reauthenticate),
    path('auth/register/', views.auth_register),
    path('auth/verify/', views.auth_verify),
    path('auth/resend/', views.auth_resend),
    path('auth/forgot/', views.auth_forgot),
    path('auth/reset/', views.auth_reset),
    path('auth/password/', views.auth_change_password),
    path('auth/delete-account/', views.auth_delete_account),
    path('auth/2fa/status/', twofactor.status),
    path('auth/2fa/enroll/', twofactor.enroll),
    path('auth/2fa/verify-enroll/', twofactor.verify_enroll),
    path('auth/2fa/disable/', twofactor.disable),
    path('auth/2fa/recovery-codes/', twofactor.regenerate_recovery_codes),
    path('auth/sessions/', sessions_views.list_sessions),
    path('auth/sessions/revoke-others/', sessions_views.revoke_other_sessions),
    path('auth/sessions/<session_handle:key>/', sessions_views.revoke_session),
    path('models/', views.list_models),
    path('conversations/', views.conversations),
    path('conversations/<positive_bigint:pk>/', views.conversation_detail),
    path('conversations/<positive_bigint:pk>/export/', views.export_conversation),
    path('conversations/<positive_bigint:pk>/messages/', views.send_message),
    path('messages/<positive_bigint:pk>/', views.message_detail),
    path('messages/<positive_bigint:pk>/regenerate/', views.regenerate_message),
    path('attachments/', views.list_attachments),
    path('attachments/upload/', views.upload_attachment),
    path(
        'attachments/upload/<uuid:attempt_id>/',
        views.cancel_attachment_upload,
    ),
    path('attachments/<positive_bigint:pk>/', views.delete_attachment),
    path('attachments/<positive_bigint:pk>/preview/', views.attachment_preview),
    path('attachments/<positive_bigint:pk>/download/', views.download_attachment, name='attachment-download'),
    path('images/generate/', views.generate_image),
    path('images/models/', views.list_image_models),
]
