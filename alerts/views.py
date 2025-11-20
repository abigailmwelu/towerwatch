from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
from .models import Alert
import json

@csrf_exempt
def create_alert(request):
    if request.method == "POST":
        data = json.loads(request.body)
        alert = Alert.objects.create(
            alert_name=data.get("alert"),
            threat_score=float(data.get("threat_score")),
            description=data.get("description", "")
        )
        return JsonResponse({"status": "ok", "alert": alert.as_dict()})
    return JsonResponse({"error": "POST required"}, status=400)

def recent_alerts(request):
    alerts = Alert.objects.order_by('-timestamp')[:10]
    return JsonResponse([a.as_dict() for a in alerts], safe=False)

@require_GET
def get_alerts(request):
    alerts = Alert.objects.all().order_by('-timestamp')[:50]
    alerts_data = [alert.as_dict() for alert in alerts]
    return JsonResponse(alerts_data, safe=False)