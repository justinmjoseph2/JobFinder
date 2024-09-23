from django.db import models
from django.contrib.auth.models import User


from django.contrib import admin
from django.db import models

class JobCategory(models.Model):
    name = models.CharField(max_length=255)
    created_on = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return self.name

from cloudinary.models import CloudinaryField

class Provider(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    provider_name = models.CharField(max_length=255)
    company_name = models.CharField(max_length=255)
    email = models.EmailField()
    company_logo = models.ImageField(upload_to='Company/')
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.provider_name


# Create your models here.
class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    customer_name = models.CharField(max_length=100)
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.customer_name
    

from django.db import models
from.models import Provider  # Import the Provider model

class Job(models.Model):
    provider = models.ForeignKey('Provider', on_delete=models.CASCADE)
    title = models.CharField(max_length=255, default="Null")
    category = models.ForeignKey('JobCategory', on_delete=models.CASCADE)
    job_type = models.CharField(max_length=255, default="Full-time")
    description = models.TextField()
    salary = models.DecimalField(max_digits=6, decimal_places=2)
    vacancies = models.PositiveIntegerField(default=0)  # Ensure this matches
    link = models.CharField(max_length=255, blank=True)
    location = models.CharField(max_length=255)
    skills = models.CharField(max_length=255)
    experience = models.CharField(max_length=255)
    till_date = models.DateField(null=True)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title  # Ensure this matches
   

from django.db import models
from django.utils import timezone

class Contact(models.Model):
    customer = models.ForeignKey('Customer', on_delete=models.CASCADE)
    name = models.CharField(max_length=100, null=True)
    email = models.CharField(max_length=100, null=True)
    message = models.TextField(max_length=2000)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.name}, {self.email}, {self.message}"


from django.db import models
from django.contrib.auth.models import User

class ResumeUpload(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_file = models.FileField(upload_to='resumes/')
    fileName = models.CharField(max_length=255)  # Ensure this field is defined
    uploaded_at = models.DateTimeField(auto_now_add=True)




class JobApplication(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resume = models.ForeignKey(ResumeUpload, on_delete=models.CASCADE)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    provider = models.ForeignKey('Provider', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')  # New status field

    def __str__(self):
        return f"Application for {self.job.title} by {self.user.username}"


class Admin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    username = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    def __str__(self):
        return self.admin_name
    

from django.db import models
from django.contrib.auth.models import User

class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('job_expiry_soon', 'Job Expiry Soon'),
        ('job_expired', 'Job Expired'),
        ('new_application', 'New Application'),
    ]

    provider = models.ForeignKey('Provider', on_delete=models.CASCADE)
    notification_type = models.CharField(max_length=50, choices=NOTIFICATION_TYPES)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        unique_together = ('provider', 'notification_type', 'message')

    def __str__(self):
        return f"{self.notification_type} - {self.message}"


from django.db import models
from django.utils import timezone
from django.conf import settings
import uuid

class PasswordResetToken(models.Model):
    admin = models.ForeignKey(Admin, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    is_used = models.BooleanField(default=False)

    def is_valid(self):
        # Token is valid for 1 hour
        return not self.is_used and (timezone.now() - self.created_at).total_seconds() < 3600

    def __str__(self):
        return str(self.token)
