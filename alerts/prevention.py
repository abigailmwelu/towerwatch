# safe app-level prevention helpers
from .models import BlockedIP, PreventionLog
import redis
from django.conf import settings

# configure REDIS_URL in settings or default
REDIS_HOST = getattr(settings, "REDIS_HOST", "localhost")
REDIS_PORT = getattr(settings, "REDIS_PORT", 6379)
try:
    _redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    _redis.ping()
except Exception:
    _redis = None

BLOCKED_SET = "towerwatch_blocked_ips"

def block_ip_app_level(ip, reason=None, source="auto_detector", performed_by="system"):
    if not ip:
        return False
    ip = str(ip)
    obj, created = BlockedIP.objects.get_or_create(ip=ip, defaults={"reason": reason or "", "source": source})
    if not created and obj.removed:
        obj.removed = False
        obj.reason = reason or obj.reason
        obj.save()
    # add to Redis for fast checking
    if _redis:
        _redis.sadd(BLOCKED_SET, ip)
    # log the prevention
    PreventionLog.objects.create(ip=ip, action="block", reason=reason or "", performed_by=performed_by)
    return True

def unblock_ip(ip, performed_by="system"):
    if not ip:
        return False
    try:
        obj = BlockedIP.objects.get(ip=ip)
        obj.removed = True
        obj.save()
    except BlockedIP.DoesNotExist:
        pass
    if _redis:
        _redis.srem(BLOCKED_SET, ip)
    PreventionLog.objects.create(ip=ip, action="unblock", reason="manual/unblock", performed_by=performed_by)
    return True

def is_ip_blocked(ip):
    if not ip:
        return False
    if _redis:
        try:
            return _redis.sismember(BLOCKED_SET, str(ip))
        except Exception:
            pass
    # fallback to DB check
    return BlockedIP.objects.filter(ip=ip, removed=False).exists()
