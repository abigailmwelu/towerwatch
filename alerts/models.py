from django.db import models
from django.utils import timezone

class Alert(models.Model):
    alert_name = models.CharField(max_length=150)
    threat_score = models.FloatField(default=0.0)
    description = models.TextField(blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    prevention = models.CharField(max_length=100, blank=True)  # e.g. "blocked", "rate_limited"
    created_at = models.DateTimeField(default=timezone.now)

    def color(self):
        if self.threat_score <= 0.3:
            return "green"
        if self.threat_score <= 0.7:
            return "yellow"
        return "red"

    def as_dict(self):
        return {
            "alert": self.alert_name,
            "threat_score": self.threat_score,
            "description": self.description,
            "source_ip": self.source_ip,
            "color": self.color(),
            "prevention": self.prevention,
            "timestamp": self.created_at.isoformat()
        }

class BlockedIP(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=200, blank=True)
    source = models.CharField(max_length=100, blank=True)  # e.g. 'auto_detector'
    created_at = models.DateTimeField(default=timezone.now)
    removed = models.BooleanField(default=False)

class PreventionLog(models.Model):
    ip = models.GenericIPAddressField(null=True, blank=True)
    action = models.CharField(max_length=100)  # e.g. 'block', 'notify'
    reason = models.CharField(max_length=250, blank=True)
    alert = models.ForeignKey(Alert, null=True, blank=True, on_delete=models.SET_NULL)
    performed_by = models.CharField(max_length=100, default='system')  # system or username
    timestamp = models.DateTimeField(default=timezone.now)
