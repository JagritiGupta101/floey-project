# Generated by Django 3.2 on 2021-12-29 13:16

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('gymprofile', '0001_initial'),
        ('base', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='GymRule',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('all_gyms', models.BooleanField(default=False)),
                ('gyms', models.ManyToManyField(blank=True, to='gymprofile.GymProfile')),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='MaxUsageRule',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('all_users', models.BooleanField(default=False)),
                ('max_usage_per_user', models.IntegerField(default=1)),
                ('allowed_user', models.ManyToManyField(blank=True, to=settings.AUTH_USER_MODEL)),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='Ruleset',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('gyms_ruleset', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='payments.gymrule')),
                ('max_uses_rule', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='payments.maxusagerule')),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='PromoCode',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('code', models.CharField(max_length=10)),
                ('discount', models.DecimalField(decimal_places=2, default=0, max_digits=12)),
                ('is_perc', models.BooleanField(default=False)),
                ('start_date', models.DateField()),
                ('active_status', models.BooleanField(default=False)),
                ('end_date', models.DateField()),
                ('max_usage', models.IntegerField(default=100)),
                ('ruleset_id', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='payments.ruleset')),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='CouponUser',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('usage_count', models.IntegerField(default=1)),
                ('coupon', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='payments.promocode')),
                ('coupon_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            bases=('base.basemodel',),
        ),
    ]
