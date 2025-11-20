from django.contrib import admin
from .models import Alert

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('alert_name', 'threat_score', 'color', 'timestamp')
    list_filter = ('threat_score', 'timestamp')
    search_fields = ('alert_name', 'description')
    readonly_fields = ('timestamp',)

    def color(self, obj):
        return obj.color()
    color.admin_order_field = 'threat_score'