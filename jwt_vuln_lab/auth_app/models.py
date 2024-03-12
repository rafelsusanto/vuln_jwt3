from django.db import models

class BlacklistedToken(models.Model):
    token = models.CharField(max_length=1000)
    expires_at = models.DateTimeField()

    def __str__(self):
        return self.token
