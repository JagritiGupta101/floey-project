from django.db import models
from user.models import *
from base.models import *

# Create your models here.

GENDER_CHOICE = (
    ('Male', 'Male'),
    ('Female', 'Female'),
    ('Unisex', 'Unisex'),
)

THEME_CHOICE = (

    ('red', 'red'),
    ('green', 'green'),
    ('brown', 'brown'),
    ('orange', 'orange'),
    ('pink', 'pink'),
    ('blue', 'blue'),
    ('lightgreen', 'lightgreen'),
    ('yelolow' , 'yellow'),
    ('purple', 'purple')

)

LEVEL_CHOICE =(
    ('All Levels','All Levels'),
    ('Intermediate','Intermediate'),
    ('Advance','Advance')
)



class Age_Group(BaseModel):
    age = models.CharField(max_length=100)

    # def __str__(self):
    #     return self.age

class Location(BaseModel):
    gym_location = models.CharField(max_length = 500,null=True,blank=True)

    def __str__(self):
        return self.gym_location

class Weekdays(BaseModel):
    day = models.CharField(max_length = 50)
    int_day = models.CharField(max_length=10, default='')

    def __str__(self):
        return self.int_day

    class Meta:
        ordering = ["created_at"]
        verbose_name_plural = "Weekdays"

class Classes(BaseModel):
    gym = models.ForeignKey('GymProfile',on_delete=models.CASCADE,null=True)
    class_topic = models.CharField(max_length=200)
    class_description = models.TextField(null=True,blank=True)
    class_image = models.FileField(upload_to='course',null=True,blank=True)
    class_scheduled_on = models.ManyToManyField(Weekdays)
    start_time = models.TimeField()
    end_time = models.TimeField()
    class_gender = models.CharField(choices = GENDER_CHOICE,max_length=50,default='')
    class_price = models.IntegerField(default=5)

    duration = models.CharField(max_length=200,default=0)
    instructor_info = models.ForeignKey('Instructor',null= True,blank=True,on_delete=models.SET_NULL)
    classes_age_group = models.ForeignKey(Age_Group,on_delete = models.DO_NOTHING,null=True,blank=True)
    no_of_participants = models.CharField(max_length = 20)
    select_location = models.ForeignKey(Location,on_delete=models.DO_NOTHING,null=True,blank=True)
    level = models.CharField(choices=LEVEL_CHOICE,max_length = 100,default="Select Level")
    class_expiry_date = models.DateField(null=True,blank=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.class_topic
    
    class Meta:
        verbose_name_plural = "Classes"

    @property
    def age_data(self):
        return Age_Group.objects.filter(uuid=self.classes_age_group.uuid).values('age')[0]['age']
        
class Packages(BaseModel):
    gym = models.ForeignKey('GymProfile',on_delete=models.DO_NOTHING)
    package_name = models.CharField(max_length=250)
    package_description = models.TextField(null=True,blank=True,default='')
    package_price = models.CharField(max_length=10)
    class_passes = models.CharField(max_length=10,default='')
    package_duration = models.CharField(max_length=10, null=True,blank=True)
    
    def __str__(self):
        return self.package_name
    class Meta:
        verbose_name_plural = "Packages"

class GymTime(BaseModel):
    time_text = models.CharField(max_length=200,default='')
    open_at = models.TimeField()
    close_at = models.TimeField()

    def __str__(self):
        return self.time_text

class GymProfile(BaseModel):
    gym_name = models.CharField(max_length=250,null=True,blank=True)
    gym_theme = models.CharField(choices = THEME_CHOICE,max_length=255,default='red')
    email = models.EmailField()
    address = models.CharField(max_length=250)
    city = models.ManyToManyField(Location,blank=True)
    contact_number = models.CharField(max_length=12)
    gym_image = models.FileField(upload_to='Gymimage',null=True,blank=True)
    opening_days = models.ManyToManyField(Weekdays)
    gym_timings = models.ForeignKey(GymTime,on_delete=models.CASCADE)
    about = models.TextField()
    gender_criteria = models.CharField(choices = GENDER_CHOICE,max_length=50)
    age_criteria = models.ForeignKey(Age_Group,on_delete = models.DO_NOTHING)

    def __str__(self):
        return self.gym_name

class Instructor(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)
    instructor_info = models.ForeignKey('user.User',on_delete=models.CASCADE,null=True,blank=True)
    instructor_specializaton = models.CharField(max_length=300, default='',null=True,blank=True)
    
    def __str__(self):
        return self.instructor_info.first_name

class Course(BaseModel):
    gym = models.ForeignKey('GymProfile',on_delete=models.CASCADE,null=True)
    course_name = models.CharField(max_length=200)
    # course_description = models.TextField()
    course_image = models.FileField(upload_to='course',null=True,blank=True)
    start_time = models.TimeField(default="10:00:00")
    end_time = models.TimeField(default="11:00:00")
    course_gender = models.CharField(choices = GENDER_CHOICE,max_length=50,default='')
    # course_address = models.CharField(max_length=250,default='')

    course_start_date = models.DateField()
    course_end_date = models.DateField()
    no_of_participants = models.CharField(max_length=20,default='')
    no_of_classes = models.IntegerField(default=10)
    course_scheduled_on = models.ManyToManyField(Weekdays)
    course_price = models.FloatField(default='0')
    course_age_group = models.ForeignKey(Age_Group,on_delete=models.DO_NOTHING,blank=True,null=True)
    instructor_info = models.ForeignKey(Instructor,on_delete=models.SET_NULL,null=True,blank=True)
    select_location = models.ForeignKey(Location,on_delete=models.DO_NOTHING,null=True,blank=True)
    level = models.CharField(choices=LEVEL_CHOICE,max_length=100,default="Select Level")

    def __str__(self):
        return self.course_name

class Membership(BaseModel):
    gym = models.ForeignKey('GymProfile',on_delete=models.CASCADE,null=True)
    membership_title = models.CharField(max_length=250)
    membership_description = models.TextField()
    membership_duration = models.CharField(max_length=10)
    select_location = models.ForeignKey(Location,on_delete=models.DO_NOTHING,null=True,blank=True)
    membership_age_group = models.ForeignKey(Age_Group,on_delete = models.DO_NOTHING)
    membership_amount = models.CharField(max_length=100)

    def __str__(self):
        return self.membership_title

class Online(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE)
    topic = models.CharField(max_length=100)
    description = models.TextField(null=True)
    img = models.FileField(upload_to = 'online',null=True)
    date = models.DateField()
    Type = models.CharField(max_length=100)
    duration = models.CharField(max_length=10,null=True)
    max_strength = models.CharField(max_length=50,null=True)
    online_instructor = models.ForeignKey(Instructor,on_delete=models.SET_NULL,null=True,blank=True)
    
    def __str__(self):
        return self.topic


class Holiday(BaseModel):
    occasion = models.CharField(max_length=255,null=True)
    start_date = models.DateField(null=True)
    end_date = models.DateField(null=True)
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)

    def __str__(self):
        return self.occasion

class Ammenities(BaseModel):
    gym = models.ForeignKey('GymProfile',on_delete=models.CASCADE,null=True,blank=True)
    ammenities_name = models.CharField(max_length=250,null=True,blank=True)
    ammenities_detail = models.TextField()

    def __str__(self):
        return self.gym.gym_name+' -->'+ self.ammenities_name
    
class CancellationPolicy(BaseModel):
    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)
    policy_title = models.TextField(default='')
    policy_text = models.TextField(default='')

class HelpText(BaseModel):
    help_text = models.TextField()

class Transaction(BaseModel):
    
    STATUS_CHOICE = (
    ('Pending', 'Pending'),
    ('Paid', 'Paid'),
    )

    FREQUENCY_CHOICES = (
    ('Monthly', 'Monthly'),
    ('Quaterly', 'Quaterly'),
    ('Yearly', 'Yearly'),
    ('One Time', 'One Time'),
    
    )

    gym = models.ForeignKey(GymProfile,on_delete=models.CASCADE,null=True,blank=True)
    # transact_by = models.ForeignKey('user.User',on_delete=models.CASCADE)
    transaction_reason = models.CharField(max_length=200,null=True,blank=True)
    date_paid = models.DateField(null=True,blank=True)
    transaction_amount = models.CharField(max_length=12,null=True,blank=True)
    frequency = models.CharField(choices=FREQUENCY_CHOICES,max_length=50,null=True)
    status = models.CharField(choices=STATUS_CHOICE,max_length=50,null=True)

    def __str__(self):
        return self.transaction_reason

