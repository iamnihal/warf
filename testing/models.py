from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

class Scan(models.Model):
    target_name = models.CharField(max_length=100)
    scan_type = models.CharField(max_length=50)
    scan_date = models.DateTimeField(default=timezone.now)
    author = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.target_name