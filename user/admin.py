from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import ugettext_lazy as _
from .models import *
# Register your models here.

admin.site.register(User)
admin.site.register(Role)
admin.site.register(UserSelectedGym)
admin.site.register(Subscription)
admin.site.register(UserHistory)
admin.site.register(UserClass)
admin.site.register(UserCourse)
admin.site.register(GymManager)
admin.site.register(AdminPermissions)
admin.site.register(RoleWisePermissions)