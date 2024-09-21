# job_matching.py
from .models import Job
from django.utils.dateformat import format

def find_suitable_jobs(extracted_text):
    # Mock function to find jobs. Replace with your actual matching logic.
    # Example: Simple keyword matching
    keywords = extracted_text.split()
    suitable_jobs = Job.objects.filter(description__icontains=' '.join(keywords))[:10]

    job_list = []
    for job in suitable_jobs:
        job_info = {
            'id': job.id,
            'title': job.title,
            'company': job.company,
            'location': job.location,
            'salary_range': job.salary_range,
            'job_type': job.job_type,
            'posted_time': format(job.posted_date, 'd M, Y'),  # Format the date as needed
        }
        job_list.append(job_info)

    return job_list
