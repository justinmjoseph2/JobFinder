# Generated by Django 4.2.11 on 2024-09-16 19:21

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('jobPlatform', '0027_admin'),
    ]

    operations = [
        migrations.RenameField(
            model_name='admin',
            old_name='admin_email',
            new_name='email',
        ),
        migrations.RenameField(
            model_name='admin',
            old_name='admin_name',
            new_name='name',
        ),
        migrations.RenameField(
            model_name='admin',
            old_name='admin_password',
            new_name='password',
        ),
        migrations.RenameField(
            model_name='admin',
            old_name='admin_phone',
            new_name='phone',
        ),
    ]
