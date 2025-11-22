from django.contrib import admin
from .models import Alert

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('alert_name', 'threat_score', 'color', 'created_at')
    list_filter = ('threat_score', 'created_at')
    search_fields = ('alert_name', 'description')
    readonly_fields = ('created_at',)

    def color(self, obj):
        return obj.color()
    color.admin_order_field = 'threat_score'