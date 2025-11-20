from django.http import JsonResponse
from django.shortcuts import render
from .models import ThreatAlert

def dashboard_home(request):
    # Get recent alerts to display on the dashboard
    alerts = ThreatAlert.objects.order_by("-timestamp")[:10]
    context = {
        'alerts': alerts,
    }
    return render(request, 'dashboard/home.html', context)

def recent_alerts(request):
    alerts = ThreatAlert.objects.order_by("-timestamp")[:20]
    data = [{
        "timestamp": str(a.timestamp),
        "verdict": a.verdict,
        "score": a.score,
        "threat_level": a.threat_level
    } for a in alerts]
    return JsonResponse(data, safe=False)