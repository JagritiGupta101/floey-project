from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import ugettext_lazy as _
from .managers import UserManager
from base.models import *
from gymprofile.models import *
from django.contrib.auth.models import PermissionsMixin
from django.utils import timezone
from django.db.models.signals import post_save, pre_save
# Create your models here.

USER_ROLES = (
    ('Customer', 'Customer'),
    ('Admin', 'Admin'),
    ('SubAdmin', 'SubAdmin'),
    ('Gym Owner', 'Gym Owner'),
    ('Instructor', 'Instructor'),
)

GENDER_CHOICE = (
    ('Male', 'Male'),
    ('Female', 'Female'),
)


FEE_STATUS = (
    ('paid', 'Paid'),
    ('pending', 'Pending'),
)

class Role(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True)
    user_roles = models.CharField(max_length=100,null=True)

    def __str__(self):
        return self.user_roles

class User(BaseModel,AbstractBaseUser,PermissionsMixin):
    user_role = models.ForeignKey(Role,on_delete=models.CASCADE,null=True)
    username = models.CharField(max_length=50,null=True,blank=True)
    email = models.EmailField(unique = True)         
    password = models.CharField(max_length=255,null=True,blank=True)               
    first_name = models.CharField(max_length = 255)
    last_name = models.CharField(max_length = 255,null=True,blank=True)
    phone_number = models.CharField(max_length = 15,null=True,blank=True)
    dob = models.DateField(null=True)
    gender = models.CharField(choices = GENDER_CHOICE, max_length = 20,null=True,blank=True)
    address = models.TextField(null=True,blank=True)
    profile_picture = models.FileField(upload_to ='profile',null = True,blank = True)
    civil_id = models.CharField(max_length=12,null=True,blank=True)
    social_id = models.TextField(null=True,blank=True)
    unique_id = models.CharField(max_length=255,default='',null=True,blank = True)
    # registration_date = models.DateTimeField(default=timezone.now,null=True)

    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)


     # str function to return name instead of object
    def __str__(self):
        """Return full name in representation instead of objects"""
        return self.email
    
    class Meta:
        """A meta object for defining name of the user table"""
        db_table = "user" 
        ordering =   ["-created_at"]
        

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name','last_name']

    objects = UserManager()

class UserSelectedGym(BaseModel):
    gym_user = models.ForeignKey(User,on_delete=models.CASCADE)
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE)

    def __str__(self):
        return self.gym_user.first_name

class RoleWisePermissions(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True)
    for_role = models.ForeignKey(Role,on_delete=models.SET_NULL,null=True)
    permissions_list = models.TextField( null=True, blank=True)

    def __str__(self):
        return self.for_role.user_roles


class AdminPermissions(BaseModel):
    userinfo = models.ForeignKey(User, on_delete=models.CASCADE, related_name="admin_user")
    perm_role = models.ForeignKey(RoleWisePermissions,on_delete=models.CASCADE,null=True)
    # admin_permissions = models.TextField( null=True, blank=True)

    def __str__(self):
        return self.userinfo.first_name



class Subscription(BaseModel):

    subscription_user = models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True)
    gym = models.ForeignKey(GymProfile,on_delete = models.DO_NOTHING,null = True,blank=True)
    membership_purchased = models.ForeignKey(Membership,on_delete=models.SET_NULL,null=True,blank=True)
    membership_validity = models.DateField(blank=True, null=True)
    package  = models.ForeignKey(Packages,on_delete = models.SET_NULL,null=True,blank=True)
    passes =models.IntegerField(default=0)
    subscription_validity = models.DateField(blank=True, null=True)
    subscription_status = models.BooleanField(default=False)
    fee_status = models.CharField(
                                ('Fee Status'),
                                max_length=255,
                                # choices=FEE_STATUS,
                                default='Paid'
                            )
    def __str__(self):
        return self.subscription_user.first_name

class UserHistory(BaseModel):
    user_detail = models.ForeignKey(User,on_delete=models.DO_NOTHING)
    action = models.TextField(null=True)
    type = models.CharField(max_length=255,default='History')
    for_date = models.DateField(blank=True, null=True)
    package_class_passes = models.CharField(max_length=10,default='')
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)
    history_image = models.FileField(upload_to='userhisytory',null=True,blank=True)
    history_price = models.FloatField(default='0')

    def __str__(self):
        return self.user_detail.first_name
    class Meta:
        ordering =   ["-created_at"]

class UserClass(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)
    select_user = models.ForeignKey(User,on_delete = models.CASCADE)
    select_classes = models.ForeignKey(Classes,on_delete=models.CASCADE,null=True,blank=True)
    booked_date = models.DateField(null=True)
    # class_instructor = models.ForeignKey(Instructor,on_delete=models.CASCADE,null=True,blank=True)
    class_passes = models.CharField(max_length=12,null=True,blank=True)
    seat_available = models.CharField(max_length=12,null=True,blank=True)

    def __str__(self):
        return self.select_user.first_name
    class Meta:
        ordering =   ["-created_at"]

# ***********Courseclass************

class UserCourse(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)
    select_user = models.ForeignKey(User,on_delete = models.CASCADE)
    select_courses = models.ForeignKey(Course,on_delete=models.CASCADE,null=True,blank=True)
    booked_date = models.DateField(null=True)
    # class_instructor = models.ForeignKey(Instructor,on_delete=models.CASCADE,null=True,blank=True)
    class_passes = models.CharField(max_length=12,null=True,blank=True)
    seat_available = models.CharField(max_length=12,null=True,blank=True)

    def __str__(self):
        return self.select_user.first_name
    class Meta:
        ordering =   ["-created_at"]


# ***********************************
class GymManager(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)
    owner = models.ForeignKey('user.User',related_name='Gym_owner',null=True,on_delete=models.CASCADE)
    employee = models.ManyToManyField(User,blank=True)

    def __str__(self):
        return self.owner.first_name

class Notifications(BaseModel):
    to = models.ForeignKey(User,on_delete=models.CASCADE)
    notification_text = models.TextField()
    notification_title = models.TextField()
