# Generated by Django 4.2.11 on 2024-09-15 15:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('jobPlatform', '0017_alter_contact_customer'),
    ]

    operations = [
        migrations.AddField(
            model_name='jobapplication',
            name='reviewed',
            field=models.BooleanField(default=False),
        ),
    ]
