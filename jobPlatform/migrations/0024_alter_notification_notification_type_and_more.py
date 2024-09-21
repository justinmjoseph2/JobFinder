# Generated by Django 4.2.11 on 2024-09-16 18:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jobPlatform', '0023_notification_delete_contact_provider'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notification',
            name='notification_type',
            field=models.CharField(choices=[('job_expiry_soon', 'Job Expiry Soon'), ('job_expired', 'Job Expired'), ('new_application', 'New Application')], max_length=50),
        ),
        migrations.AlterUniqueTogether(
            name='notification',
            unique_together={('provider', 'notification_type', 'message')},
        ),
    ]
