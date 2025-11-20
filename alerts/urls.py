from django.urls import path
from . import views

urlpatterns = [
    path('api/alerts/', views.get_alerts, name='get_alerts'),
    path("alerts/", views.create_alert, name="create_alert"),
    path("recent-alerts/", views.recent_alerts, name="recent_alerts"),
]