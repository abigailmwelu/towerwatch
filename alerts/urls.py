from django.urls import path
from . import views

urlpatterns = [
    path('alerts/create/', views.create_alert, name='create-alert'),
    path('alerts/recent/', views.recent_alerts, name='recent-alerts'),
    # Add other URL patterns as needed
]