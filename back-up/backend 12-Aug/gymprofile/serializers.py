from rest_framework import serializers
from .models import *
from user.models import * 

class GymProfileSerializer(serializers.ModelSerializer):
     class Meta:
        model = GymProfile
        fields = ('__all__')

class GymTimeSerializer(serializers.ModelSerializer):
     class Meta:
        model = GymTime
        fields = ('__all__')


class PackagesSerializer(serializers.ModelSerializer):
     class Meta:
        model = Packages
        fields = ('__all__')

class MembershipSerializer(serializers.ModelSerializer):
     class Meta:
        model = Membership
        fields = ('__all__')

class LocationSerializer(serializers.ModelSerializer):
     class Meta:
        model = Location
        fields = ('__all__')
        
class WeekdaysSerializer(serializers.ModelSerializer):
     class Meta:
        model = Weekdays
        fields = ('__all__')


class InstructorSerializer(serializers.ModelSerializer):
     class Meta:
        model = Instructor
        fields = ('__all__')

class CourseSerializer(serializers.ModelSerializer):
     class Meta:
        model = Course
        fields = ('__all__')

class ClassSerializer(serializers.ModelSerializer):
      class Meta:
        model = Classes
        fields = ('__all__')

class AgeSerializer(serializers.ModelSerializer):
     class Meta:
        model = Age_Group
        fields = ('__all__')

class HolidaySerializer(serializers.ModelSerializer):
        class Meta:
                model = Holiday
                fields = ('__all__')

class CancellationPolicySerializer(serializers.ModelSerializer):
        class Meta:
                model = CancellationPolicy
                fields = ('__all__')

class AmmenitiesSerializer(serializers.ModelSerializer):
        class Meta:
                model = Ammenities
                fields = ("__all__")


class GymProfileList(serializers.ModelSerializer):
        class Meta:
                model = GymProfile
                fields = ['uuid','gym_name']


class ClassListSer(serializers.ModelSerializer):
        class Meta:
                model = Classes
                fields = ['uuid','gym','level','class_scheduled_on','class_topic','class_description','class_image','start_time','end_time','duration','classes_age_group','select_location']


class TransactionSerilaizer(serializers.ModelSerializer):
        class Meta:
                model = Transaction
                fields =('__all__')

class OnlineSerializer(serializers.ModelSerializer):
        class Meta:
                model = Online
                fields = '__all__'

class instructorclassSer(serializers.ModelSerializer):
        class Meta:
                model = UserClass
                fields = ['select_classes']