from django.db import models
from django.contrib.auth.models import User, Group

NAME_MAX_CHAR = 32


# 展厅
class Scene(models.Model):
    def __str__(self):
        return str(self.name)
    name = models.CharField(max_length=NAME_MAX_CHAR)
    file = models.FileField(blank=True, null=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE, blank=True, null=True)


# 展品
class Item(models.Model):
    def __str__(self):
        return str(self.name)
    name = models.CharField(max_length=NAME_MAX_CHAR)
    author = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    scene = models.ForeignKey(Scene, on_delete=models.CASCADE, blank=True, null=True)

