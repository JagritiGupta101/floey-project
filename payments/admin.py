from django.contrib import admin
from . models import * 
# Register your models here.

admin.site.register(PromoCode)
admin.site.register(Ruleset)
admin.site.register(MaxUsageRule)
admin.site.register(GymRule)
admin.site.register(CouponUser)