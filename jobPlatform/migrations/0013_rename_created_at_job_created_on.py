# Generated by Django 4.2.11 on 2024-09-13 09:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('jobPlatform', '0012_alter_job_till_date'),
    ]

    operations = [
        migrations.RenameField(
            model_name='job',
            old_name='created_at',
            new_name='created_on',
        ),
    ]
