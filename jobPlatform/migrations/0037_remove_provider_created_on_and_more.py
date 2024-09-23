# Generated by Django 4.2.11 on 2024-09-23 14:08

import cloudinary.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('jobPlatform', '0036_alter_provider_company_logo'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='provider',
            name='created_on',
        ),
        migrations.AlterField(
            model_name='provider',
            name='company_logo',
            field=cloudinary.models.CloudinaryField(max_length=255, verbose_name='image'),
        ),
    ]