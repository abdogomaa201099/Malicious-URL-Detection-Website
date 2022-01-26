from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class Report (models.Model):
    url = models.CharField(max_length=250, unique=False)
    uid = models.IntegerField()
    prop_good=models.FloatField(default=None)
    prop_bad=models.FloatField(default=None)