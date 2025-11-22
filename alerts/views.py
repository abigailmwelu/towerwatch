from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .models import Alert
from .rate_limiter import rate_limit
import json

@csrf_exempt
@require_http_methods(["POST"])
@rate_limit(scope='api', requests=10, window=60)  # 10 requests per minute
def create_alert(request):
    try:
        data = json.loads(request.body)
        alert = Alert.objects.create(
            alert_name=data.get("alert"),
            threat_score=float(data.get("threat_score", 0)),
            description=data.get("description", ""),
            source_ip=request.META.get('REMOTE_ADDR'),
            metadata={'user_agent': request.META.get('HTTP_USER_AGENT', '')}
        )
        return JsonResponse({"status": "ok", "alert": alert.as_dict()})
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@require_http_methods(["GET"])
@rate_limit(scope='api', requests=60, window=60)  # 60 requests per minute
def recent_alerts(request):
    alerts = Alert.objects.order_by('-created_at')[:10]  # Get 10 most recent alerts
    return JsonResponse({
        'alerts': [alert.as_dict() for alert in alerts]
    })