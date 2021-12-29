from .models import *
from rest_framework import serializers
from django.contrib.auth.hashers import make_password

class GymManagerSerializer(serializers.ModelSerializer):
    class Meta:
        model = GymManager
        fields = '__all__'

class UserGymSer(serializers.ModelSerializer):
    class Meta:
        model = UserSelectedGym
        fields = '__all__'

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'
        
class UserSerializer(serializers.ModelSerializer):
    class Meta:
    
        model = User
        fields = '__all__'
    
    def validate_password(self, password) -> str:
        return make_password(password)

class UserHistorySerializer(serializers.ModelSerializer):
    class Meta:
    
        model = UserHistory
        fields = '__all__'

class UserclassSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserClass
        fields = '__all__'

# ********course********

class UsercourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCourse
        fields = '__all__'

class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields='__all__'
        
class SubAdminSerializer(serializers.ModelSerializer):
 
    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "password", "is_active","is_staff")

    def validate_password(self, password) -> str:
        """ A function to save the password for storing the values """
        return make_password(password)

class GymMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("user_role","first_name", "last_name", "email", "password", "profile_picture","dob","gender","is_active","is_staff")
    def validate_password(self, password) -> str:
        """ A function to save the password for storing the values """
        return make_password(password)    


class RolesNPermsSer(serializers.ModelSerializer):
    class Meta:
        model = RoleWisePermissions
        fields = '__all__'