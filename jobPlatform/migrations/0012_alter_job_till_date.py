# Generated by Django 4.2.11 on 2024-09-13 04:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jobPlatform', '0011_job_till_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='job',
            name='till_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
