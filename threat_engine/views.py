import json
import logging
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

@csrf_exempt
@require_http_methods(["POST"])
def analyze_event(request):
    """
    API endpoint for threat detection analysis.
    
    Expected JSON payload:
    {
        "failed_logins": int,
        "successful_logins": int,
        "bytes_sent": int,
        "bytes_recv": int,
        "destination_port": int,
        "hour_of_day": int,
        "source_ip": str
    }
    
    Returns:
        JSON response with detection results
    """
    try:
        # Parse JSON data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse(
                {'error': 'Invalid JSON'}, 
                status=400
            )
        
        # Initialize the engine
        from .engine import TowerWatchEngine
        engine = TowerWatchEngine()
        
        # Call the detect method
        result = engine.detect(data)
        
        # Log the detection result to ThreatAlert
        from dashboard.models import ThreatAlert
        
        ThreatAlert.objects.create(
            tenant_id="global",
            verdict=result.get("threat_type") or "none",
            score=result.get("confidence", 0.0),
            ml_score=result.get("details", {}).get("ml", {}).get("ml_score", 0.0),
            matched_rules=result.get("details", {}).get("rules", {})
        )
        
        # Return the result as JSON
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Error in analyze_event: {str(e)}", exc_info=True)
        return JsonResponse(
            {'error': 'Internal server error', 'details': str(e)}, 
            status=500
        )
