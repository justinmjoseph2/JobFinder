# utils.py
import requests
from django.conf import settings

def extract_text_from_resume(resume_path):
    api_key = settings.GEMINI_API_KEY
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/pdf'  # or 'application/octet-stream' if binary
    }

    with open(resume_path, 'rb') as file:
        response = requests.post('https://api.gemini.com/extract', headers=headers, files={'file': file})
    
    if response.status_code == 200:
        data = response.json()
        return data.get('text', '')
    else:
        # Handle error
        return ''



from .models import Notification, Job, JobApplication
from django.utils import timezone
from datetime import timedelta

def create_notification(provider):
    now = timezone.now()
    
    # Job expiry soon
    jobs_expiring_soon = Job.objects.filter(
        provider=provider,
        till_date__lte=now + timedelta(days=2),
        till_date__gte=now
    )
    
    for job in jobs_expiring_soon:
        Notification.objects.get_or_create(
            provider=provider,
            notification_type='job_expiry_soon',
            message=f"Job '{job.title}' expires in 2 days.",
            defaults={'created_at': now}
        )
    
    # Job expired
    expired_jobs = Job.objects.filter(
        provider=provider,
        till_date__lt=now
    )
    
    for job in expired_jobs:
        Notification.objects.get_or_create(
            provider=provider,
            notification_type='job_expired',
            message=f"Job '{job.title}' has expired.",
            defaults={'created_at': now}
        )
    
    # New applications
    new_applications = JobApplication.objects.filter(
        provider=provider,
        created_at__gte=now - timedelta(days=1)
    )
    
    for application in new_applications:
        Notification.objects.get_or_create(
            provider=provider,
            notification_type='new_application',
            message=f"New application by {application.user.username} for job '{application.job.title}'.",
            defaults={'created_at': now}
        )
