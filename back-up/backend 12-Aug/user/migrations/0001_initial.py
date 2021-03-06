# Generated by Django 3.1.7 on 2021-04-06 10:38

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('gymprofile', '0001_initial'),
        ('base', '0001_initial'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('username', models.CharField(max_length=50)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('password', models.CharField(max_length=255)),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
                ('phone_number', models.CharField(max_length=15)),
                ('dob', models.DateField(null=True)),
                ('gender', models.CharField(choices=[('Male', 'Male'), ('Female', 'Female')], max_length=20)),
                ('address', models.TextField(blank=True, null=True)),
                ('profile_picture', models.FileField(blank=True, null=True, upload_to='profile')),
                ('civil_id', models.CharField(blank=True, max_length=12, null=True)),
                ('unique_id', models.CharField(blank=True, default='', max_length=255, null=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'db_table': 'user',
                'ordering': ['-created_at'],
            },
            bases=('base.basemodel', models.Model),
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('user_roles', models.CharField(max_length=100, null=True)),
                ('gym', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='gymprofile.gymprofile')),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='UserSelectedGym',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('gym', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='gymprofile.gymprofile')),
                ('gym_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='UserHistory',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('action', models.TextField(null=True)),
                ('package_class_passes', models.CharField(default='', max_length=10)),
                ('gym', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='gymprofile.gymprofile')),
                ('user_detail', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='UserClass',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('booked_date', models.DateField(null=True)),
                ('class_passes', models.CharField(blank=True, max_length=12, null=True)),
                ('seat_available', models.CharField(blank=True, max_length=12, null=True)),
                ('gym', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='gymprofile.gymprofile')),
                ('select_classes', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='gymprofile.classes')),
                ('select_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='Subscription',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('membership_validity', models.DateField(blank=True, null=True)),
                ('subscription_validity', models.DateField(blank=True, null=True)),
                ('subscription_status', models.BooleanField(default=False)),
                ('fee_status', models.CharField(default='Paid', max_length=255, verbose_name='Fee Status')),
                ('gym', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.DO_NOTHING, to='gymprofile.gymprofile')),
                ('membership_purchased', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='gymprofile.membership')),
                ('package', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='gymprofile.packages')),
                ('subscription_user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='RoleWisePermissions',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('permissions_list', models.TextField(blank=True, null=True)),
                ('for_role', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='user.role')),
                ('gym', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='gymprofile.gymprofile')),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='Notifications',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('notification_text', models.TextField()),
                ('notification_title', models.TextField()),
                ('to', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='GymManager',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('employee', models.ManyToManyField(blank=True, to=settings.AUTH_USER_MODEL)),
                ('gym', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='gymprofile.gymprofile')),
                ('owner', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='Gym_owner', to=settings.AUTH_USER_MODEL)),
            ],
            bases=('base.basemodel',),
        ),
        migrations.CreateModel(
            name='AdminPermissions',
            fields=[
                ('basemodel_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to='base.basemodel')),
                ('perm_role', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='user.rolewisepermissions')),
                ('userinfo', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='admin_user', to=settings.AUTH_USER_MODEL)),
            ],
            bases=('base.basemodel',),
        ),
        migrations.AddField(
            model_name='user',
            name='user_role',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='user.role'),
        ),
    ]
