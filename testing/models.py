from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User


class Scan(models.Model):
    SCAN_TYPE = (
        ("Full Scan", "Full Scan"),
        ("Subdomain", "Subdomain"),
        ("Dirsearch", "Dirsearch"),
        ("Wayback URL", "Wayback URL"),
        ("JS File Discovery", "JS File Discovery"),
        ("Secret/API key", "Secret/API key"),
        ("Endpoint from JS", "Endpoint from JS"),
    )
    target_name = models.CharField(max_length=100)
    scan_type = models.CharField(max_length=50, choices=SCAN_TYPE)
    domain_url = models.CharField(max_length=100)
    scan_date = models.DateTimeField(default=timezone.now)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.target_name


class ResultFileName(models.Model):
    file_name = models.CharField(max_length=100)
    scan_item = models.ForeignKey(Scan, on_delete=models.CASCADE)

    def __str__(self):
        return self.file_name
