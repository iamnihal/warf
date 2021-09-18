from django.db import models
from django.contrib.auth.models import User

# To make email field unique
User._meta.get_field('email')._unique = True

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.user.username} Profile'
