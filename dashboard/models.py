from django.db import models

class ThreatAlert(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    tenant_id = models.CharField(max_length=50)
    verdict = models.CharField(max_length=20)
    score = models.FloatField()
    ml_score = models.FloatField()
    matched_rules = models.JSONField()

    def __str__(self):
        return f"[{self.timestamp}] {self.tenant_id} - {self.verdict}"
