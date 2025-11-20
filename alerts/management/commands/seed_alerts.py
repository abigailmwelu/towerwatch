
from django.core.management.base import BaseCommand
from alerts.models import Alert
import random
from datetime import datetime, timedelta

class Command(BaseCommand):
    help = 'Seed the database with sample alert data'

    def handle(self, *args, **options):
        # List of possible alert types
        alert_types = [
            "Unauthorized Access Attempt",
            "Suspicious Login",
            "Data Exfiltration",
            "Malware Detected",
            "Brute Force Attack",
            "Phishing Attempt",
            "DDoS Attack",
            "SQL Injection",
            "Cross-Site Scripting",
            "Port Scan"
        ]

        # Clear existing data
        Alert.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Cleared existing alert data'))

        # Create sample alerts
        for i in range(50):  # Create 50 sample alerts
            alert_name = random.choice(alert_types)
            threat_score = round(random.uniform(0, 1), 2)  # Random score between 0 and 1
            
            # Create the alert
            Alert.objects.create(
                alert_name=alert_name,
                threat_score=threat_score,
                description=f"Sample {alert_name} with score {threat_score}",
                timestamp=datetime.now() - timedelta(minutes=random.randint(0, 10080))  # Up to 1 week old
            )

        self.stdout.write(self.style.SUCCESS('Successfully seeded alert data'))