from django.db import models
from django.contrib.auth.models import User, Group

NAME_MAX_CHAR = 128


# 展厅
class Scene(models.Model):
    def __str__(self):
        return str(self.name)
    name = models.CharField(max_length=NAME_MAX_CHAR)
    author = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    file = models.FileField(blank=True, null=True)


# 策展
class Exhibition(models.Model):
    class Meta:
        permissions = (
                ('item_exhibition', 'Can change item in exhibition'),
                ('tool_exhibition', 'Can change tool in exhibition'),
                ('scene_exhibition', 'Can change scene in exhibition'),
                ('admin_exhibition', 'Can change scene in exhibition'),
        )
    def __str__(self):
        return str(self.name)
    name = models.CharField(max_length=NAME_MAX_CHAR)
    scene = models.ForeignKey(Scene, on_delete=models.CASCADE, blank=True, null=True)
    users = models.ForeignKey(Group, related_name='users', on_delete=models.CASCADE, blank=True, null=True)
    artists = models.ForeignKey(Group, related_name='artists', on_delete=models.CASCADE, blank=True, null=True)
    stuffs = models.ForeignKey(Group, related_name='stuffs', on_delete=models.CASCADE, blank=True, null=True)
    managers = models.ForeignKey(Group, related_name='managers', on_delete=models.CASCADE, blank=True, null=True)
    # admin 也是策展管理员，但相对manager，admin可以添加其他用户为admin或manager
    admins = models.ForeignKey(Group, related_name='admins', on_delete=models.CASCADE, blank=True, null=True)


# 展品
class Item(models.Model):
    def __str__(self):
        return str(self.name)
    name = models.CharField(max_length=NAME_MAX_CHAR)
    author = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    scene = models.ForeignKey(Scene, on_delete=models.CASCADE, blank=True, null=True)
    file = models.FileField(blank=True, null=True)
    # itemtype: 展品类型
    itemtype = models.CharField(max_length=20, default='model')
    pos_x = models.FloatField(default=0.0)
    pos_y = models.FloatField(default=0.0)
    pos_z = models.FloatField(default=0.0)
    rot_x = models.FloatField(default=0.0)
    rot_y = models.FloatField(default=0.0)
    rot_z = models.FloatField(default=0.0)
    rot_w = models.FloatField(default=0.0)
    scl_x = models.FloatField(default=1.0)
    scl_y = models.FloatField(default=1.0)
    scl_z = models.FloatField(default=1.0)
    description = models.CharField(max_length=256, default='')


# tool
class Tool(models.Model):
    def __str__(self):
        return str(self.name)
    name = models.CharField(max_length=NAME_MAX_CHAR)
    scene = models.ForeignKey(Scene, on_delete=models.CASCADE, blank=True, null=True)


# 用户注册请求登记表
# 每个记录可以理解为该user向exhibition申请user_type的权限
class SignupRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    exhibition = models.ForeignKey(Exhibition, on_delete=models.CASCADE, blank=True, null=True)
    user_type = models.CharField(max_length=12, blank=True, null=True)
