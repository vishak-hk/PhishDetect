from django.db import models
from picklefield.fields import PickledObjectField

# Create your models here.
class new_model(models.Model):
    args = PickledObjectField()