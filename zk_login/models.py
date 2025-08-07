from django.contrib.auth.models import User
from django.db import models

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    raw_password = models.CharField(max_length=256, blank=True)
    zk_pubkey = models.TextField(max_length=256, blank=True)

    def __str__(self):
        return f"{self.user.username}"
