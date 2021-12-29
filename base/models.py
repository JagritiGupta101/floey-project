from django.db import models

# Create your models here.
from django.db import models
import uuid

# Create your models here.

class BaseModel(models.Model):
    uuid = models.UUIDField( 
         primary_key = True, 
         default = uuid.uuid4, 
         editable = False) 
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_seconds_since_creation(self):
        """
        Find how much time has been elapsed since creation, in seconds.
        This function is timezone agnostic, meaning this will work even if
        you have specified a timezone.
        """
        return (datetime.strftime('%Y-%m-%d - %H:%M:%S'))
    # def created_at(self):
    #     return (datetime.strftime('%Y-%m-%d - %H:%M:%S'))
        # return (datetime.datetime.utcnow() -
                # self.created_at.replace(tzinfo=None)).seconds