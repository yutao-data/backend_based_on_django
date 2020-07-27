from django.contrib import admin
from guardian.admin import GuardedModelAdmin
from . import models
# Old way:
# class AuthorAdmin(admin.ModelAdmin):
#    pass


# With object permissions support
class AuthorAdmin(GuardedModelAdmin):
    pass


admin.site.register(models.Item, AuthorAdmin)
admin.site.register(models.Scene, AuthorAdmin)
