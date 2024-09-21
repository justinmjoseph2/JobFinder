import requests
from django.conf import settings

def extract_text_from_resume(file_path):
    api_url = 'https://api.example.com/extract-text'
    headers = {
        'Authorization': f'Bearer {settings.GEMINI_API_KEY}',
        'Content-Type': 'multipart/form-data'
    }
    files = {'file': open(file_path, 'rb')}
    
    response = requests.post(api_url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json().get('text', '')
    else:
        response.raise_for_status()

def find_suitable_jobs(extracted_text):
    api_url = 'https://api.example.com/find-jobs'
    headers = {
        'Authorization': f'Bearer {settings.GEMINI_API_KEY}',
        'Content-Type': 'application/json'
    }
    data = {'resume_text': extracted_text}
    
    response = requests.post(api_url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json().get('jobs', [])
    else:
        response.raise_for_status()
