# Generated by Django 3.2 on 2021-07-22 13:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0005_remove_subscription_membership_purchased'),
        ('gymprofile', '0007_auto_20210714_0124'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Membership',
        ),
    ]
