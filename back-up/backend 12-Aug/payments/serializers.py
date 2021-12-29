from .models import * 
from rest_framework import serializers


class PromocodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PromoCode
        fields = '__all__'

class GymRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = GymRule
        fields = '__all__'

class MaxUsesSerializer(serializers.ModelSerializer):
    class Meta:
        model = MaxUsageRule
        fields = '__all__'

class CouponUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CouponUser
        fields = '__all__'


class RulesetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ruleset
        fields = '__all__'

