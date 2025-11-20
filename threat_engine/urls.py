from django.urls import path
from . import views

urlpatterns = [
    path('analyze/', views.analyze_event, name='analyze_event'),
]
