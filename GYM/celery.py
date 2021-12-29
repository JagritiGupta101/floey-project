from __future__ import absolute_import,unicode_literals
from datetime import timezone
from django.conf import settings
from celery.schedules import crontab
import os
from celery import Celery



os.environ.setdefault('DJANGO_SETTINGS_MODULE','send_mail_celery.settings')
app=Celery('send_mail_celery')
app.conf.update(timezone='Asia/Kolkata')
app.config_from_object('django.conf:settings')

# app.conf.beat_schedule={
#     'mail-send':{
#         'task':'celeryapp.task.shared_with_celery',
#         'schedule':crontab(minute=20),
#     }
# }

app.conf.beat_scheduler='django_celery_beat.schedulers.DatabaseScheduler'
app.autodiscover_tasks(settings.INSTALLED_APPS)



@app.task(bind=True)
def debug_task(self):
    print(f'request:{self.request!r}')

