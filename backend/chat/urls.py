from django.urls import path

from . import views

urlpatterns = [
    path('health/', views.health),
    path('auth/me/', views.auth_me),
    path('auth/login/', views.auth_login),
    path('auth/logout/', views.auth_logout),
    path('auth/register/', views.auth_register),
    path('auth/verify/', views.auth_verify),
    path('auth/resend/', views.auth_resend),
    path('models/', views.list_models),
    path('conversations/', views.conversations),
    path('conversations/<int:pk>/', views.conversation_detail),
    path('conversations/<int:pk>/messages/', views.send_message),
    path('attachments/', views.list_attachments),
    path('attachments/upload/', views.upload_attachment),
    path('attachments/<int:pk>/', views.delete_attachment),
    path('images/generate/', views.generate_image),
    path('images/models/', views.list_image_models),
]
