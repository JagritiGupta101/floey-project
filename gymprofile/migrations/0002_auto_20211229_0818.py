# Generated by Django 3.2 on 2021-12-29 13:18

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('gymprofile', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='classes',
            name='instructor_info',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='gymprofile.instructor'),
        ),
        migrations.AddField(
            model_name='course',
            name='instructor_info',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='gymprofile.instructor'),
        ),
        migrations.AddField(
            model_name='instructor',
            name='instructor_info',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='transaction',
            name='transact_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
