from django.db import models
from base.models import BaseModel
from gymprofile.models import GymProfile
from user.models import User
# Create your models here.


class GymRule(BaseModel):
    all_gyms = models.BooleanField(default=False)
    gyms = models.ManyToManyField(GymProfile,blank=True)


class MaxUsageRule(BaseModel):
    all_users = models.BooleanField(default=False)
    allowed_user = models.ManyToManyField(User,blank=True)
    max_usage_per_user = models.IntegerField(default=1)


class Ruleset(BaseModel):
    gyms_ruleset = models.ForeignKey(GymRule,on_delete=models.CASCADE,null=True)
    max_uses_rule = models.ForeignKey(MaxUsageRule,on_delete=models.CASCADE,null=True)

from decimal import Decimal

class PromoCode(BaseModel):

    Statuses = [("Active","Active"),("Inactive","Inactive")]
    code = models.CharField(max_length=10)
    discount = models.DecimalField(max_digits=12,default=0,decimal_places=2)
    is_perc = models.BooleanField(default=False)
    start_date = models.DateField()
    active_status = models.BooleanField(default=False)
    end_date = models.DateField()
    max_usage = models.IntegerField(default=100)
    ruleset_id = models.ForeignKey(Ruleset,on_delete=models.CASCADE,null=True)

    def get_discounted_value(self,initial_value):
        if self.is_perc:
            return (self.discount * Decimal(float(initial_value)))/100
        else:
            return self.discount

    def use_coupon(self,user):
        if CouponUser.objects.filter(coupon_user=user,coupon=self).exists():
            c= CouponUser.objects.get(coupon_user=user,coupon=self)
        else:
            c = CouponUser()
            c.coupon_user = user
            c.coupon = self
        c.usage_count+=1
        c.save()


class CouponUser(BaseModel):
    coupon_user = models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    coupon = models.ForeignKey(PromoCode,on_delete=models.CASCADE,null=True)
    usage_count = models.IntegerField(default=1)