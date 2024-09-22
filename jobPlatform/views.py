from urllib import request
from django import forms
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.urls import reverse, reverse_lazy
import job
from .models import Customer
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib import messages
from .models import *
from django.template.loader import get_template
from xhtml2pdf import pisa
from django.http import HttpResponse
from django.template.loader import get_template
from django.template import Context
import pydotplus
from graphviz import Digraph
import pathlib
import textwrap
from .forms import ContactForm, CustomPasswordChangeForm


import google.generativeai as genai

from IPython.display import display
from IPython.display import Markdown

# Create your views here.
def index(request):
    
    return render(request, 'index.html')

def cv(request):
    
    return render(request, 'cv.html')

def customer_dashboard(request):
    return render(request, 'customer/customer_dashboard.html')

from django.shortcuts import render
from .models import Provider

def provider_index(request):
    if request.user.is_authenticated:
        try:
            provider = Provider.objects.get(user=request.user)
        except Provider.DoesNotExist:
            provider = None
    else:
        provider = None

    return render(request, 'provider/index.html', {'provider': provider})


from .models import Provider

from .models import Customer
def register_customer(request):
    if request.method == 'POST':
        full_name = request.POST.get('full-name')
        email = request.POST.get('your-email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')
        phone_number = request.POST.get('phone-number')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, 'Passwords Do Not Match!')
            return render(request, 'customer/register_customer.html')

        # Check password strength using Django's built-in validators
        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, ', '.join(e.messages))
            return render(request, 'customer/register_customer.html')

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists!')
            return render(request, 'customer/register_customer.html')

        # Check if phone number already exists
        if Customer.objects.filter(contact_number=phone_number).exists():
            messages.error(request, 'Phone number already exists!')
            return render(request, 'customer/register_customer.html')

        # Check if phone number has exactly 10 digits
        if len(phone_number) != 10:
            messages.error(request, 'Phone number must have exactly 10 digits!')
            return render(request, 'customer/register_customer.html')

        # Create user
        try:
            user = User.objects.create_user(username=email, email=email, password=password)
        except:
            messages.error(request, 'Failed to create user.')
            return render(request, 'customer/register_customer.html')

        # Create customer
        customer = Customer.objects.create(user=user, customer_name=full_name, email=email, contact_number=phone_number)

        # Authenticate and login user
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Your Account Has Been Registered Successfully!')
            return redirect('index')
        else:
            messages.error(request, 'Failed to login user.')
            return render(request, 'customer/register_customer.html')

    return render(request, 'customer/register_customer.html')


def login_customer(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            user = User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                customer = Customer.objects.get(user=user)
                if customer:  # Check if customer exists
                    login(request, user)
                    messages.success(request, 'You have successfully logged in!')
                    return redirect('index')
                else:
                    messages.error(request, 'You are not a customer.')
            else:
                # Incorrect password
                error_message = "Incorrect email or password."
        except User.DoesNotExist:
            # User not found
            error_message = "User with this email does not exist."
        except Exception as e:
            # Other error occurred
            error_message = f"An error occurred: {str(e)}"
            
        messages.error(request, error_message)
        
    return render(request, 'customer/login_customer.html')

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import Provider

User = get_user_model()

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import Provider

User = get_user_model()

def register_provider(request):
    if request.method == 'POST':
        provider_name = request.POST.get('provider_name')
        company_name = request.POST.get('company_name')
        email = request.POST.get('your-email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')
        company_logo = request.FILES.get('image_upload')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, 'Passwords Do Not Match!')
            return render(request, 'customer/register_provider.html')

        # Check password strength using Django's built-in validators
        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, ', '.join(e.messages))
            return render(request, 'customer/register_provider.html')

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists!')
            return render(request, 'customer/register_provider.html')

        # Create user
        try:
            user = User.objects.create_user(username=email, email=email, password=password)
        except:
            messages.error(request, 'Failed to create user.')
            return render(request, 'customer/register_provider.html')

        # Create provider
        provider = Provider.objects.create(user=user, provider_name=provider_name, company_name=company_name, email=email, company_logo=company_logo)

        # Authenticate and login user
        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Your Account Has Been Registered Successfully!')
            return redirect('provider_index')
        else:
            messages.error(request, 'Failed to login user.')
            return render(request, 'customer/register_provider.html')

    return render(request, 'customer/register_provider.html')




def login_provider(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            user = User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                provider = Provider.objects.get(user=user)
                if provider:  # Check if provider exists
                    login(request, user)
                    messages.success(request, 'You have successfully logged in!')
                    return redirect('provider_index')
                else:
                    messages.error(request, 'You are not a provider.')
            else:
                # Incorrect password
                error_message = "Incorrect email or password."
        except User.DoesNotExist:
            # User not found
            error_message = "User with this email does not exist."
        except Exception as e:
            # Other error occurred
            error_message = f"An error occurred: {str(e)}"
            
        messages.error(request, error_message)
        
    return render(request, 'customer/login_provider.html')



def user_logout(request):
    logout(request)
    return redirect('index') 





def reg1(request):
    
    return render(request, 'customer/reg1.html')

def log1(request):
    
    return render(request, 'customer/log1.html')

def user_logout(request):
    logout(request)
    return redirect('index') 


@login_required
def change_password(request):
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        user = request.user  # Assuming the user is already logged in

        if user.check_password(old_password):
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                messages.success(request, "Password changed successfully.")
                return redirect('login')
            else:
                messages.error(request, "New passwords do not match.")
        else:
            messages.error(request, "Old password is incorrect.")

    return render(request, 'customer/change_password.html')


class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + user.password + str(timestamp)
        )



def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = CustomTokenGenerator().make_token(user)
            reset_password_url = request.build_absolute_uri('/reset_password/{}/{}/'.format(uid, token))
            email_subject = 'Reset Your Password'

            # Render both HTML and plain text versions of the email
            email_body_html = render_to_string('customer/reset_password_email.html', {
                'reset_password_url': reset_password_url,
                'user': user,
            })
            email_body_text = "Click the following link to reset your password: {}".format(reset_password_url)

            # Create an EmailMultiAlternatives object to send both HTML and plain text versions
            email = EmailMultiAlternatives(
                email_subject,
                email_body_text,
                settings.EMAIL_HOST_USER,
                [email],
            )
            email.attach_alternative(email_body_html, 'text/html')  # Attach HTML version
            email.send(fail_silently=False)

            messages.success(request, 'An email has been sent to your email address with instructions on how to reset your password.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, "User with this email does not exist.")
    return render(request, 'customer/forgot_password.html')


def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and CustomTokenGenerator().check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                messages.success(request, "Password reset successfully. You can now login with your new password.")
                return redirect('login')
            else:
                messages.error(request, "Passwords do not match.")
        return render(request, 'customer/reset_password.html')
    else:
        messages.error(request, "Invalid reset link. Please try again or request a new reset link.")
        return redirect('login')


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Customer

@login_required
def edit_customer(request):
    # Retrieve the current logged-in user
    current_user = request.user
    # Check if the current user has a corresponding Customer instance
    try:
        customer = Customer.objects.get(user=current_user)
    except Customer.DoesNotExist:
        # Handle the case where the logged-in user does not have a corresponding Customer instance
        return HttpResponse("You are not associated with any customer profile.")

    if request.method == 'POST':
        # Update customer details with the data from the form
        customer.customer_name = request.POST['full-name']
        customer.email = request.POST['your-email']
        customer.contact_number = request.POST['phone-number']
        customer.save()

        # Update associated user's email
        current_user.email = request.POST['your-email']
        current_user.username = request.POST['your-email']
        current_user.save()

        # Redirect to the customer detail page after editing
        return redirect('index')

    # If it's a GET request, display the edit form with existing customer details
    return render(request, 'customer/edit_customer.html', {'customer': customer})

@login_required
def contact_view(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your message has been sent successfully!')
            return redirect('contact')  # Redirect back to the contact page
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'Error in {field}: {error}', extra_tags='alert-dismissible')
    else:
        form = ContactForm()
    return render(request, 'contact_form.html', {'form': form})



import speech_recognition as sr
from django.shortcuts import render
from.models import Job

def voice_search(request):
    if request.method == 'GET':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            audio = r.listen(source)
            try:
                query = r.recognize_google(audio, language='en-US')
                jobs = job.objects.filter(name__icontains=query)
                return render(request, 'search_results.html', {'jobs': jobs})
            except sr.UnknownValueError:
                return render(request, 'search_results.html', {'error': 'Sorry, I didn\'t catch that.'})
            except sr.RequestError:
                return render(request, 'search_results.html', {'error': 'Sorry, there was an error processing your request.'})
    return render(request, 'search_results.html')


def search_results(request):
    return render(request, 'search_results.html')



def category_jobs(request):    
    return render(request, 'category_jobs.html')

def job_details(request):
    return render(request, 'job_details.html')

def about(request):
    return render(request, 'about.html')

def single_blog(request):
    return render(request, 'single_blog.html')

def blog(request):
    return render(request, 'blog.html')

def elements(request):
    return render(request, 'elements.html')

def contact(request):
    return render(request, 'contact.html')


from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Provider



from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Provider
from .forms import ProviderForm

@login_required
def edit_provider(request):
    current_user = request.user
    try:
        provider = Provider.objects.get(user=current_user)
    except Provider.DoesNotExist:
        return HttpResponse("You are not associated with any provider profile.")

    if request.method == 'POST':
        form = ProviderForm(request.POST, request.FILES, instance=provider)
        if form.is_valid():
            form.save()
            current_user.email = form.cleaned_data['email']
            current_user.username = form.cleaned_data['email']
            current_user.save()
            return redirect('provider/index')
    else:
        form = ProviderForm(instance=provider)

    return render(request, 'provider/details.html', {'form': form})


from django.shortcuts import render, redirect
from .forms import JobForm

from django.shortcuts import render, redirect, get_object_or_404
from .models import Provider  # Import the Provider model
from django.contrib import messages

def add_job(request):
    if request.method == 'POST':
        form = JobForm(request.POST)
        if form.is_valid():
            job = form.save(commit=False)
            # Get the Provider instance associated with the current user
            provider = get_object_or_404(Provider, user=request.user)
            job.provider = provider  # Assign the correct Provider instance
            job.save()
            # Set success flag in context
            return render(request, 'provider/add_job.html', {'form': JobForm(), 'success': True})
    else:
        form = JobForm()

    return render(request, 'provider/add_job.html', {'form': form})

# views.py
from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from .utils import create_notification, extract_text_from_resume
from .job_matching import find_suitable_jobs
import os

from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from .api_utils import extract_text_from_resume, find_suitable_jobs





# views.py
def job_details(request, id):
    job = Job.objects.get(id=id)
    return render(request, 'job_details.html', {'job': job})

# from django.shortcuts import render
# from django.conf import settings
# import google.generativeai as genai
# import os

# # Configure Google AI with the API key
# genai.configure(api_key="AIzaSyDHlaH_BLjVfTy-zDD6FAeJGEasRvAh9iU")

# def upload_resume(request):
#     if request.method == 'POST' and request.FILES['resume']:
#         resume_file = request.FILES['resume']

#         # Read the file content
#         resume_content = resume_file.read().decode('utf-8')

#         # Prepare the input for the generative model
#         chat_session = genai.GenerativeModel(
#             model_name="gemini-1.5-flash",
#             generation_config={
#                 "temperature": 1,
#                 "top_p": 0.95,
#                 "top_k": 64,
#                 "max_output_tokens": 8192,
#                 "response_mime_type": "text/plain",
#             }
#         ).start_chat(history=[
#             {
#                 "role": "user",
#                 "parts": [
#                     f"user uploads the resume: {resume_content}. Find the jobs based on the resume and suggest improvements."
#                 ],
#             }
#         ])

#         response = chat_session.send_message("Find suitable jobs")

#         # Assuming the response contains job matches
#         suitable_jobs = parse_jobs(response.text)

#         return render(request, 'cv_page.html', {'suitable_jobs': suitable_jobs})
    
#     return render(request, 'cv_page.html')


def parse_jobs(response_text):
    # Here, parse the response text to extract job details
    # This function needs to be customized based on the output format of Google Generative AI SDK
    job_list = []
    # Example parsing logic (this will depend on the actual output from your AI model)
    # You may need to refine this function based on your specific needs
    for line in response_text.splitlines():
        # Parse job title, company, location, etc.
        job_details = {}
        # Assume some logic to extract job details
        job_list.append(job_details)
    return job_list

from django.core.files.storage import FileSystemStorage
import os
import time
import google.generativeai as genai

# Configure the Google Gemini API key
genai.configure(api_key="AIzaSyDHlaH_BLjVfTy-zDD6FAeJGEasRvAh9iU")


def upload_to_gemini(path, mime_type=None):
    """Uploads the given file to Gemini."""
    file = genai.upload_file(path, mime_type=mime_type)
    return file

def wait_for_files_active(files):
    """Waits for the given files to be active."""
    for name in (file.name for file in files):
        file = genai.get_file(name)
        while file.state.name == "PROCESSING":
            time.sleep(10)
            file = genai.get_file(name)
        if file.state.name != "ACTIVE":
            raise Exception(f"File {file.name} failed to process")


# decorators.py

from django.shortcuts import redirect
from functools import wraps

def login_required_custom(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login_customer')  # Replace 'login_customer' with the name of your URL pattern
        return view_func(request, *args, **kwargs)
    return _wrapped_view






# views.py
# views.py
from django.shortcuts import render
from .models import Job

def jobcv(request, job_title):
    # Remove "- " from the job_title
    clean_job_title = job_title.replace("- ", "")

    # Fetch all jobs that match the cleaned title
    jobs = Job.objects.filter(title=clean_job_title)

    # If no jobs are found, render a template with a custom message
    if not jobs:
        return render(request, 'jobcv.html', {'error': 'No jobs found with the title "{}".'.format(job_title)})

    # Render the template with job details
    return render(request, 'jobcv.html', {'jobs': jobs})




from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Job
from .forms import JobForm  # Assuming you have a form for the Job model

@login_required
def manage_jobs(request):
    # Get the logged-in employer
    employer = request.user.provider  # Assuming the user model is linked to a Provider model

    # Fetch jobs posted by the logged-in employer
    jobs = Job.objects.filter(provider=employer)

    context = {
        'jobs': jobs
    }
    return render(request, './provider/manage_jobs.html', context)



from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Job
from .forms import JobFormEdit

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Job
from .forms import JobFormEdit

@login_required
def edit_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, provider=request.user.provider)

    if request.method == 'POST':
        form = JobFormEdit(request.POST, instance=job)
        if form.is_valid():
            form.save()
            return redirect('manage_jobs')
    else:
        form = JobFormEdit(instance=job)

    return render(request, 'provider/edit_job.html', {'form': form})


@login_required
def delete_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, provider=request.user.provider)

    if request.method == 'POST':
        job.delete()
        return redirect('manage_jobs')  # Redirect to the manage jobs page

    return render(request, 'jobPlatform/delete_job.html', {'job': job})



from django.shortcuts import render, redirect, get_object_or_404
from .models import JobApplication, Job, ResumeUpload
@login_required
def handle_no_link(request, user_id, job_id):
    # Assuming the user is authenticated and a resume exists
    resume = ResumeUpload.objects.filter(user_id=user_id).first()  # Fetch the user's resume

    if not resume:
        # Handle the case where no resume is found
        return render(request, 'error_page.html', {'message': 'No resume found for this user.'})

    # Fetch provider_id from Job model
    provider_id = Job.objects.get(id=job_id).provider.id

    # Check if an application already exists for the same user, job, and provider
    existing_application = JobApplication.objects.filter(
        user_id=user_id,
        job_id=job_id,
        provider_id=provider_id
    ).first()

    if existing_application:
        # Show already applied pop-up or message
        return render(request, 'error_page.html', {'message': 'You have already applied for this job.'})

    # If no existing application, create a new one
    JobApplication.objects.create(
        user_id=user_id,
        resume=resume,
        job_id=job_id,
        provider_id=provider_id
    )

    return render(request, 'thank_you.html')  # Redirect to thank you page



from django.shortcuts import render
@login_required
def thank_you_page(request):
    return render(request, 'thank_you.html')



from django.shortcuts import render, get_object_or_404, redirect
from .models import JobApplication
@login_required_custom
def applied_jobs(request):
    # Get the current user
    user = request.user

    # Fetch all job applications for the logged-in user
    job_applications = JobApplication.objects.filter(user=user)

    context = {
        'job_applications': job_applications,
    }
    return render(request, 'applied_jobs.html', context)
@login_required
def cancel_application(request, application_id):
    # Fetch the job application by ID
    job_application = get_object_or_404(JobApplication, id=application_id, user=request.user)

    # Delete the job application
    job_application.delete()

    # Redirect back to the applied jobs page
    return redirect('applied_jobs')

from django.shortcuts import render
from .models import Job, JobCategory, Provider
from django.utils.timezone import now  # Import current date handling

def job_list_user(request):
    # Fetch all jobs initially, filter out jobs where till_date is less than the current date
    jobs = Job.objects.filter(till_date__gt=now())

    # Fetch filter options
    categories = JobCategory.objects.all()
    providers = Provider.objects.all()
    locations = Job.objects.values_list('location', flat=True).distinct()

    # Get filter parameters from the GET request
    category_id = request.GET.get('category', '')
    job_type = request.GET.get('job_type', '')
    location = request.GET.get('location', '')
    provider_id = request.GET.get('provider', '')
    experience = request.GET.get('experience', '')

    # Apply filters if present
    if category_id:
        jobs = jobs.filter(category_id=category_id)
    if job_type:
        jobs = jobs.filter(job_type=job_type)
    if location:
        jobs = jobs.filter(location=location)
    if provider_id:
        jobs = jobs.filter(provider_id=provider_id)
    if experience:
        if experience == "fresher":
            jobs = jobs.filter(experience="fresher")
        elif experience == "Above10":
            jobs = jobs.filter(experience__in=[str(i) for i in range(1, 11)] + ["Above10"])
        else:
            try:
                experience = int(experience)
                if 1 <= experience <= 10:
                    jobs = jobs.filter(experience=str(experience))
            except ValueError:
                # Handle invalid experience values if needed
                pass

    # Generate experience year range (1 year to 10 years)
    experience_years = list(range(1, 11))

    context = {
        'jobs': jobs,
        'categories': categories,
        'providers': providers,
        'locations': locations,
        'experience_years': experience_years,
        'experience_choices': Job.experience  # Add this for use in the template
    }

    return render(request, 'job_list.html', context)




from django.shortcuts import render, get_object_or_404
from .models import Job

@login_required_custom
def job_detail(request, id):
    job = get_object_or_404(Job, id=id)  # Fetch the job by ID
    return render(request, 'job_detail.html', {'job': job})

from django.http import JsonResponse
from django.shortcuts import render
from .models import Contact, Customer

@login_required_custom
def contact_process(request):
    if request.method == 'POST':
        # Get the currently logged-in user
        user = request.user

        # Retrieve the Customer object associated with the user
        try:
            customer = Customer.objects.get(user=user)
            name = customer.customer_name
            email = customer.email
        except Customer.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Customer record not found'}, status=404)

        message = request.POST.get('message')
        subject = request.POST.get('subject')
        customer_id = request.POST.get('customer_id')

        # Get the customer object if customer_id is provided
        contact_customer = None
        if customer_id:
            contact_customer = Customer.objects.filter(id=customer_id).first()

        # Create and save the Contact instance
        contact = Contact(name=name, email=email, message=message, customer=contact_customer)
        contact.save()

        # Respond with JSON for AJAX
        return JsonResponse({'success': True})

    # Handle GET requests or other methods
    return render(request, 'contact.html')



@login_required
def contact_success(request):    
    return render(request, 'contact_success.html')


from django.shortcuts import render
from .models import Job
from django.db.models import Q
@login_required_custom
def search_jobs(request):
    query = request.GET.get('q', '')
    jobs = Job.objects.all()
    
    if query:
        # Update to use only fields that support 'icontains'
        jobs = jobs.filter(
            Q(title__icontains=query) |
            Q(provider__company_name__icontains=query) | 
            Q(category__name__icontains=query) | 
            Q(skills__icontains=query) 
        ).distinct()

    return render(request, 'job_list.html', {'jobs': jobs})


from django.shortcuts import render
from .models import JobApplication
from django.contrib.auth.decorators import login_required

@login_required
def provider_applications(request):
    provider = request.user.provider  # Fetch the provider instance based on logged-in user
    applications = JobApplication.objects.filter(provider=provider)  # Get all applications for jobs posted by the provider
    
    context = {
        'applications': applications
    }
    return render(request, 'provider/applications.html', context)

from django.shortcuts import render, redirect
from .models import JobApplication
from django.contrib.auth.decorators import login_required

from django.shortcuts import render, redirect
from .models import JobApplication
from django.contrib.auth.decorators import login_required

@login_required
def mark_reviewed(request):
    if request.method == "POST":
        reviewed_applications = request.POST.getlist('reviewed_applications')
        applications = JobApplication.objects.filter(provider=request.user.provider)

        for application in applications:
            # Update application status
            status = request.POST.get(f'status_{application.id}')
            if status:
                application.status = status

            application.save()

        return redirect('provider_applications')


from django.shortcuts import render, get_object_or_404
from .models import Job, JobApplication
@login_required
def applications_page(request):
    # Fetch all jobs posted by the current user
    user_jobs = Job.objects.filter(provider=request.user.provider)
    
    # Get filter parameters
    job_id = request.GET.get('job_id')
    status = request.GET.get('status')

    # Initialize the query
    applications_query = JobApplication.objects.filter(job__in=user_jobs)

    # Apply additional filters if provided
    if job_id:
        applications_query = applications_query.filter(job_id=job_id)
    if status:
        applications_query = applications_query.filter(status=status)
    
    # Organize applications by status
    applications = {
        'new': applications_query.filter(status='pending'),
        'shortlisted': applications_query.filter(status='short-list'),
        'hired': applications_query.filter(status='hire'),
        'rejected': applications_query.filter(status='reject'),
    }

    context = {
        'applications': applications,
        'jobs': user_jobs,  # Pass the user's jobs to the template if needed for dropdown/filtering
    }
    
    return render(request, 'provider/applications_page.html', context)


from django.shortcuts import render
from django.shortcuts import render
from .models import JobApplication
@login_required
def new_applications(request):
    # Query for applications with status 'pending' for the current user
    applications = JobApplication.objects.filter(status='pending', job__provider=request.user.provider)
    
    # Pass the applications to the template
    return render(request, 'provider/new_applications.html', {'applications': applications})

@login_required
def shortlisted_applications(request):
    # Logic for shortlisted applications
    applications = JobApplication.objects.filter(status='short-list', job__provider=request.user.provider)
    
    # Pass the applications to the template
    return render(request, 'provider/shortlisted_applications.html', {'applications': applications})
@login_required
def hired_applications(request):
    # Logic for hired applications
    applications = JobApplication.objects.filter(status='hire', job__provider=request.user.provider)
    
    # Pass the applications to the template
    return render(request, 'provider/hired_applications.html', {'applications': applications})
@login_required
def rejected_applications(request):
    # Logic for hired applications
    applications = JobApplication.objects.filter(status='reject', job__provider=request.user.provider)
    
    # Pass the applications to the template
    return render(request, 'provider/rejected_applications.html', {'applications': applications})

from django.shortcuts import render, get_object_or_404
from .models import JobApplication
@login_required
def application_detail(request, application_id):
    # Retrieve the specific application using the provided ID
    application = get_object_or_404(JobApplication, id=application_id)
    
    # Pass the application to the template
    return render(request, 'provider/application_detail.html', {'application': application})


from django.shortcuts import redirect, get_object_or_404
from .models import JobApplication
@login_required
def update_application_status(request, application_id):
    if request.method == 'POST':
        application = get_object_or_404(JobApplication, id=application_id)
        new_status = request.POST.get('status')
        application.status = new_status
        application.save()
    return redirect(request.META.get('HTTP_REFERER', 'applications_page'))


from django.shortcuts import render, get_object_or_404
from .models import Job, JobApplication
@login_required
def profile_opt(request):
    # Fetch all jobs posted by the current user
    return render(request, 'provider/profile_opt.html')


from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import EditPasswordForm

@login_required
def edit_pass(request):
    if request.method == 'POST':
        form = EditPasswordForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()  # Save the new password if valid
            messages.success(request, 'Your password has been successfully updated! Please log in again.')
            logout(request)  # Log the user out after successful password change
            return redirect('index')  # Redirect to the index page after logging out
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = EditPasswordForm(user=request.user)

    return render(request, 'provider/edit_pass.html', {'form': form})



# views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from .forms import ForgotPasswordForm, ResetPasswordForm
from .models import Provider

# Forgot password view
def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                provider = Provider.objects.get(email=email)
                user = provider.user
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_url = request.build_absolute_uri(reverse('reset_password', args=[uid, token]))

                # Send reset email
                send_mail(
                    'Password Reset Request',
                    f'Click the link to reset your password: {reset_url}',
                    'admin@example.com',
                    [email],
                    fail_silently=False,
                )

                return render(request, 'provider/password_reset_sent.html')
            except Provider.DoesNotExist:
                form.add_error('email', 'Email not found.')
    else:
        form = ForgotPasswordForm()

    return render(request, 'provider/forgot_password.html', {'form': form})

# Reset password view
def reset_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = ResetPasswordForm(request.POST)
            if form.is_valid():
                new_password = form.cleaned_data['new_password']
                user.set_password(new_password)
                user.save()
                return redirect('index')  # Redirect to login after successful reset
        else:
            form = ResetPasswordForm()
        return render(request, 'provider/reset_password.html', {'form': form})
    else:
        return render(request, 'provider/password_reset_invalid.html')



from django.shortcuts import render, redirect
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.http import HttpResponse
from .models import Customer
from .forms import CustomerPasswordResetForm, SetCustomerPasswordForm

User = get_user_model()

def forgot_password_customer(request):
    if request.method == 'POST':
        form = CustomerPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                customer = Customer.objects.get(email=email)
                token = default_token_generator.make_token(customer.user)
                uid = urlsafe_base64_encode(force_bytes(customer.user.pk))
                domain = get_current_site(request).domain
                reset_link = f"http://{domain}/customer/reset-password/{uid}/{token}/"
                message = render_to_string('customer/password_reset_email.html', {
                    'reset_link': reset_link,
                    'user': customer.user,
                })
                send_mail('Password Reset Request', message, 'no-reply@example.com', [email])
                return render(request, 'customer/password_reset_sent.html')
            except Customer.DoesNotExist:
                form.add_error('email', 'Email address not found.')
    else:
        form = CustomerPasswordResetForm()
    
    return render(request, 'customer/forgot_password.html', {'form': form})

def reset_password_customer(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        if not default_token_generator.check_token(user, token):
            return render(request, 'customer/invalid_reset_link.html')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return render(request, 'customer/invalid_reset_link.html')

    if request.method == 'POST':
        form = SetCustomerPasswordForm(user, request.POST)
        if form.is_valid():
            form.save()
            return redirect('index')
    else:
        form = SetCustomerPasswordForm(user)
    
    return render(request, 'customer/reset_password.html', {'form': form})


from django.shortcuts import render, redirect
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import CustomPasswordChangeForm

@login_required
def password_change_form(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important to keep the user logged in
            messages.success(request, 'Your password has been successfully updated.')
            return redirect('index')  # Redirect to the index page after success
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomPasswordChangeForm(user=request.user)
    
    return render(request, 'customer/password_change_form.html', {'form': form})


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Notification, Job
from .utils import create_notification, extract_text_from_resume


@login_required
def notifications(request):
    provider = request.user.provider
    # Create notifications if they do not exist already
    create_notification(provider)
    
    notifications = Notification.objects.filter(provider=provider).order_by('-created_at')

    context = {
        'notifications': notifications,
    }
    return render(request, 'provider/notifications.html', context)


from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from .models import Notification  # Ensure you have a Notification model

@login_required
@require_POST
def mark_as_read(request, notification_id):
    try:
        notification = Notification.objects.get(id=notification_id, provider=request.user.provider)
        notification.is_read = True
        notification.save()
        return JsonResponse({'success': True})
    except Notification.DoesNotExist:
        return JsonResponse({'success': False}, status=404)


from django.shortcuts import render, redirect
from .models import Job, JobApplication, Notification
from django.utils import timezone
from datetime import timedelta
@login_required
def check_notifications(request):
    provider = request.user.provider
    now = timezone.now()
    
    # Check for job expiry notifications
    jobs_expiring_soon = Job.objects.filter(
        provider=provider,
        till_date__lte=now + timedelta(days=2),
        till_date__gte=now
    )
    
    for job in jobs_expiring_soon:
        create_notification(
            notification_type='job_expiry_soon',
            provider=provider,
            message=f"Job '{job.title}' expires in 2 days."
        )
    
    # Check for expired jobs
    expired_jobs = Job.objects.filter(
        provider=provider,
        till_date__lt=now
    )
    
    for job in expired_jobs:
        create_notification(
            notification_type='job_expired',
            provider=provider,
            message=f"Job '{job.title}' has expired."
        )
    
    # Check for new applications
    new_applications = JobApplication.objects.filter(
        provider=provider,
        created_at__gte=now - timedelta(days=1)  # Check for applications in the last day
    )
    
    for application in new_applications:
        create_notification(
            notification_type='new_application',
            provider=provider,
            message=f"New application by {application.user.customer.customer_name} for job '{application.job.title}'."
        )

    return redirect('notifications_page')  # Redirect to the page where notifications are displayed


from .utils import create_notification

@login_required
def notifications_view(request):
    provider = request.user.provider
    create_notification(provider)
    
    notifications = Notification.objects.filter(provider=provider).order_by('-created_at')
    
    return render(request, 'notifications.html', {'notifications': notifications})


from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from .models import Notification

@login_required
@require_POST
def delete_notification(request, notification_id):
    try:
        notification = Notification.objects.get(id=notification_id, provider=request.user.provider)
        notification.delete()
        return JsonResponse({'status': 'success'})
    except Notification.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Notification not found'}, status=404)


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login
from .models import Admin
from django.contrib.auth.hashers import check_password

def custom_admin_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        try:
            # Check if the username exists in the Admin model
            admin = Admin.objects.get(username=username)
            
            # Check if the provided password matches the stored hashed password
            if check_password(password, admin.password):
                # Create a user session manually
                login(request, admin.user)  # log in using the related `User` object
                return redirect('admin_dashboard')  # redirect to the admin dashboard
            else:
                messages.error(request, 'Invalid password.')
        except Admin.DoesNotExist:
            messages.error(request, 'Admin with the provided username does not exist.')
    
    return render(request, 'admin/admin_login.html')


@login_required
def form(request):
    return render(request, 'admin/form.html')


from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Admin
from django.db import IntegrityError
@login_required
def edit_admin_details(request):
    # Assuming the admin is already logged in and we can access them from request.user
    try:
        admin = Admin.objects.get(user=request.user)
    except Admin.DoesNotExist:
        messages.error(request, "Admin profile not found.")
        return redirect('dashboard')  # Redirect to some other page if admin does not exist
    
    if request.method == 'POST':
        username = request.POST.get('username')
        name = request.POST.get('name')
        phone = request.POST.get('phone')
        email = request.POST.get('email')

        # Validate and update admin details
        admin.username = username
        admin.name = name
        admin.phone = phone
        admin.email = email
        try:
            admin.save()
            messages.success(request, 'Admin details updated successfully!')
            return redirect('edit_admin_details')  # Redirect to the same page after saving
        except IntegrityError as e:
            if 'unique constraint' in str(e):
                messages.error(request, 'Email address must be unique.')
            else:
                messages.error(request, 'An error occurred while updating details.')
    
    context = {
        'admin': admin
    }
    return render(request, 'admin/edit_admin_details.html', context)



@login_required
def table(request):
    return render(request, 'admin/table.html')

from django.shortcuts import render
from .models import Contact
@login_required
def messages_dropdown(request):
    # Fetch the last 3 messages
    return render(request, 'all_messages.html')


from django.shortcuts import render
from .models import Contact
@login_required
def all_messages(request):
    messages = Contact.objects.all().order_by('-id')
    return render(request, 'admin/all_messages.html', {'messages': messages})


from django.shortcuts import get_object_or_404, redirect
from .models import Contact

@login_required
def delete_message(request, message_id):
    # Fetch the message object or return a 404 if not found
    message = get_object_or_404(Contact, id=message_id)
    
    # Delete the message
    message.delete()
    
    # Redirect to the 'all-messages' page after deletion
    return redirect('messages_list')
 
from django.shortcuts import render, get_object_or_404
from .models import Contact

@login_required
def view_message(request, message_id):
    message = get_object_or_404(Contact, id=message_id)
    return render(request, 'admin/view_message.html', {'message': message})


from django.shortcuts import render
from .models import Customer, Provider
from django.contrib.auth.decorators import login_required

@login_required
def all_customers(request):
    # Get all customers and their count
    customers = Customer.objects.all().order_by('-id')
    customer_count = customers.count()

    # Pass customers and count to the template
    return render(request, 'admin/all_customers.html', {
        'customers': customers,
        'customer_count': customer_count
    })

@login_required
def all_providers(request):
    # Get all providers and their count
    providers = Provider.objects.all().order_by('-id')
    provider_count = providers.count()

    # Pass providers and count to the template
    return render(request, 'admin/all_providers.html', {
        'providers': providers,
        'provider_count': provider_count
    })

@login_required
def view_provider(request, provider_id):
    provider = get_object_or_404(Provider, id=provider_id)
    return render(request, 'admin/view_provider.html', {'provider': provider})

from django.shortcuts import render, get_object_or_404

@login_required
def view_customer(request, customer_id):
    customer = get_object_or_404(Customer, id=customer_id)
    return render(request, 'admin/view_customer.html', {'customer': customer})



@login_required
def button(request):
    return render(request, 'admin/button.html')


from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import JobApplication

@login_required
def new_applications_admin(request):
    # Query for pending applications
    applications = JobApplication.objects.filter(status='pending')

    # Get the count of pending applications
    application_count = applications.count()

    # Pass applications and count to the template
    return render(request, 'admin/new_applications.html', {
        'applications': applications,
        'application_count': application_count
    })


@login_required
def shortlisted_applications_admin(request):
    # Query for shortlisted applications
    applications = JobApplication.objects.filter(status='short-list')

    # Get the count of shortlisted applications
    application_count = applications.count()

    # Pass applications and count to the template
    return render(request, 'admin/shortlisted_applications.html', {
        'applications': applications,
        'application_count': application_count
    })


@login_required
def hired_applications_admin(request):
    # Query for hired applications
    applications = JobApplication.objects.filter(status='hire')

    # Get the count of hired applications
    application_count = applications.count()

    # Pass applications and count to the template
    return render(request, 'admin/hired_applications.html', {
        'applications': applications,
        'application_count': application_count
    })


@login_required
def rejected_applications_admin(request):
    # Fetch the rejected applications
    applications = JobApplication.objects.filter(status='reject')

    # Get the count of rejected applications
    application_count = applications.count()

    # Pass both the applications and the count to the template
    return render(request, 'admin/rejected_applications.html', {
        'applications': applications,
        'application_count': application_count
    })


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import JobCategory
from .forms import JobCategoryForm

@login_required
def category_list(request):
    categories = JobCategory.objects.all().order_by('-created_on')
    if request.method == 'POST':
        if 'delete' in request.POST:
            category_id = request.POST.get('delete')
            category = get_object_or_404(JobCategory, id=category_id)
            category.delete()
            return redirect('category_list')
    return render(request, 'admin/category_list.html', {'categories': categories})

@login_required
def add_category(request):
    if request.method == 'POST':
        form = JobCategoryForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('category_list')
    else:
        form = JobCategoryForm()
    return render(request, 'admin/add_category.html', {'form': form})

@login_required
def edit_category(request, category_id):
    category = get_object_or_404(JobCategory, id=category_id)
    if request.method == 'POST':
        form = JobCategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            return redirect('category_list')
    else:
        form = JobCategoryForm(instance=category)
    return render(request, 'admin/edit_category.html', {'form': form, 'category': category})

from django.shortcuts import render
from .models import Job
from django.contrib.auth.decorators import login_required

@login_required
def job_list(request):
    # Fetch all jobs and order them by the date they were created
    jobs = Job.objects.all().order_by('-created_on')
    job_count = jobs.count()  # Get the count of jobs
    return render(request, 'admin/job_list.html', {'jobs': jobs, 'job_count': job_count})

from django.shortcuts import render
from .models import Job
from django.contrib.auth.decorators import login_required
from django.utils import timezone

@login_required
def expired_jobs(request):
    # Get the current date
    today = timezone.now().date()
    
    # Filter jobs where the till_date is less than today
    expired_jobs = Job.objects.filter(till_date__lt=today).order_by('-till_date')
    expired_job_count = expired_jobs.count()  # Get the count of expired jobs
    
    return render(request, 'admin/expired_jobs.html', {'expired_jobs': expired_jobs, 'expired_job_count': expired_job_count})


from django.shortcuts import render
from .models import Provider
from django.utils import timezone
import calendar

@login_required
def provider_registration_chart(request):
    # Get the current year
    current_year = timezone.now().year

    # Create a dictionary to hold the count of registrations per month
    registrations_per_month = {month: 0 for month in calendar.month_name[1:]}

    # Fetch provider registrations for the current year
    providers = Provider.objects.filter(created_on__year=current_year)

    # Count registrations per month
    for provider in providers:
        month_name = calendar.month_name[provider.created_on.month]
        registrations_per_month[month_name] += 1

    # Pass the data to the template
    return render(request, 'admin/provider_registration_chart.html', {
        'registrations_per_month': registrations_per_month,
        'current_year': current_year
    })


from django.shortcuts import render
from .models import Customer
from django.utils import timezone
import calendar

@login_required
def customer_registration_chart(request):
    # Get the current year
    current_year = timezone.now().year

    # Create a dictionary to hold the count of registrations per month
    registrations_per_month = {month: 0 for month in calendar.month_name[1:]}

    # Fetch customer registrations for the current year
    customers = Customer.objects.filter(created_on__year=current_year)

    # Count registrations per month
    for customer in customers:
        month_name = calendar.month_name[customer.created_on.month]
        registrations_per_month[month_name] += 1

    # Pass the data to the template
    return render(request, 'admin/customer_registration_chart.html', {
        'registrations_per_month': registrations_per_month,
        'current_year': current_year
    })


from django.shortcuts import render
from .models import Job
from django.utils import timezone
import calendar

@login_required
def job_posting_chart(request):
    # Get the current year
    current_year = timezone.now().year

    # Create a dictionary to hold the count of jobs posted per month
    jobs_per_month = {month: 0 for month in calendar.month_name[1:]}

    # Fetch jobs posted in the current year
    jobs = Job.objects.filter(created_on__year=current_year)

    # Count jobs posted per month
    for job in jobs:
        month_name = calendar.month_name[job.created_on.month]
        jobs_per_month[month_name] += 1

    # Pass the data to the template
    return render(request, 'admin/job_posting_chart.html', {
        'jobs_per_month': jobs_per_month,
        'current_year': current_year
    })


from django.shortcuts import render
from .models import Job, JobCategory
from django.db.models import Count

@login_required
def job_category_distribution(request):
    # Aggregate job counts by category
    categories = Job.objects.values('category__name').annotate(count=Count('category')).order_by('-count')

    # Prepare data for the pie chart
    category_names = [category['category__name'] for category in categories]
    job_counts = [category['count'] for category in categories]

    # Pass the data to the template
    return render(request, 'admin/job_category_distribution.html', {
        'category_names': category_names,
        'job_counts': job_counts
    })


from django.shortcuts import render
from .models import JobApplication
from django.db.models import Count
from datetime import datetime
from django.db.models.functions import TruncMonth

@login_required
def application_status_distribution(request):
    # Aggregate application counts by status
    status_distribution = JobApplication.objects.values('status').annotate(count=Count('status')).order_by('-count')

    # Prepare data for the pie chart
    status_names = [status['status'] for status in status_distribution]
    status_counts = [status['count'] for status in status_distribution]

    # Pass the data to the template
    return render(request, 'admin/application_status_distribution.html', {
        'status_names': status_names,
        'status_counts': status_counts
    })

@login_required
def job_postings_and_application_ratio(request):
    # Aggregate job postings and applications by month
    postings = Job.objects.annotate(month=TruncMonth('created_on')).values('month').annotate(total_postings=Count('id')).order_by('month')
    applications = JobApplication.objects.annotate(month=TruncMonth('created_at')).values('month').annotate(total_applications=Count('id')).order_by('month')

    # Prepare data for the charts
    months = [posting['month'].strftime('%Y-%m') for posting in postings]
    job_counts = [posting['total_postings'] for posting in postings]
    application_counts = [application['total_applications'] for application in applications]

    # Fill missing months with 0 counts
    all_months = set(months)
    month_to_postings = dict(zip(months, job_counts))
    month_to_applications = dict(zip(months, application_counts))

    for month in all_months:
        if month not in month_to_postings:
            month_to_postings[month] = 0
        if month not in month_to_applications:
            month_to_applications[month] = 0

    sorted_months = sorted(all_months)
    sorted_postings = [month_to_postings[month] for month in sorted_months]
    sorted_applications = [month_to_applications[month] for month in sorted_months]

    # Pass the data to the template
    return render(request, 'admin/job_postings_and_application_ratio.html', {
        'months': sorted_months,
        'job_counts': sorted_postings,
        'application_counts': sorted_applications
    })


from django.shortcuts import render
from .models import Provider
from django.utils.dateparse import parse_date

@login_required
def filter_providers_by_date(request):
    providers = []
    start_date = None
    end_date = None
    
    if 'start_date' in request.GET and 'end_date' in request.GET:
        start_date = request.GET['start_date']
        end_date = request.GET['end_date']
        
        # Convert date strings to date objects
        start_date = parse_date(start_date)
        end_date = parse_date(end_date)
        
        if start_date and end_date:
            providers = Provider.objects.filter(created_on__range=[start_date, end_date])
    
    return render(request, 'admin/filter_providers_by_date.html', {
        'providers': providers,
        'start_date': start_date,
        'end_date': end_date
    })


from django.shortcuts import render
from .models import Customer
from django.contrib.auth.decorators import login_required

@login_required
def filter_customers_by_date(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Filter customers based on the date range
    if start_date and end_date:
        customers = Customer.objects.filter(created_on__date__range=[start_date, end_date])
    else:
        customers = []

    # Pass data to the template
    return render(request, 'admin/filter_customers_by_date.html', {
        'customers': customers,
        'start_date': start_date,
        'end_date': end_date,
    })


from django.shortcuts import render
from .models import Job

@login_required
def filter_jobs_by_date(request):
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    jobs = Job.objects.all()

    if start_date and end_date:
        jobs = jobs.filter(created_on__range=[start_date, end_date])

    return render(request, 'admin/filter_jobs.html', {'jobs': jobs, 'start_date': start_date, 'end_date': end_date})


from django.shortcuts import render
from django.db.models import Q
from .models import Provider, Customer, Job, JobCategory
@login_required
def search_results_admin(request):
    query = request.GET.get('search', '')
    providers = Provider.objects.filter(
        Q(provider_name__icontains=query) | Q(company_name__icontains=query)
    )
    customers = Customer.objects.filter(
        Q(customer_name__icontains=query) | Q(email__icontains=query)
    )
    jobs = Job.objects.filter(
        Q(title__icontains=query) | Q(description__icontains=query) | Q(location__icontains=query) | Q(skills__icontains=query)
    )
    categories = JobCategory.objects.filter(name__icontains=query)
    
    context = {
        'query': query,
        'providers': providers,
        'customers': customers,
        'jobs': jobs,
        'categories': categories,
        'provider_count': providers.count(),
        'customer_count': customers.count(),
        'job_count': jobs.count(),
        'category_count': categories.count(),
    }

    return render(request, 'admin/search_results.html', context)


@login_required
def admin_dashboard(request):
    # Get total counts for each model
    provider_count = Provider.objects.count()
    customer_count = Customer.objects.count()
    job_count = Job.objects.count()
    category_count = JobCategory.objects.count()

    # Get last 5 providers
    last_5_providers = Provider.objects.order_by('-created_on')[:4]

    # Get last 5 jobs
    last_5_jobs = Job.objects.order_by('-created_on')[:5]

    # Get last 5 customers
    last_5_customers = Customer.objects.order_by('-created_on')[:5]

    # Get all categories
    categories = JobCategory.objects.order_by('-created_on')[:6]

    # Get monthly counts for each model
    monthly_providers = Provider.objects.annotate(month=TruncMonth('created_on')).values('month').annotate(count=Count('id')).order_by('month')
    monthly_customers = Customer.objects.annotate(month=TruncMonth('created_on')).values('month').annotate(count=Count('id')).order_by('month')
    monthly_jobs = Job.objects.annotate(month=TruncMonth('created_on')).values('month').annotate(count=Count('id')).order_by('month')
    monthly_categories = JobCategory.objects.annotate(month=TruncMonth('created_on')).values('month').annotate(count=Count('id')).order_by('month')

    # Merge all months into one unique sorted list
    all_months = sorted(set(entry['month'] for entry in monthly_providers) |
                        set(entry['month'] for entry in monthly_customers) |
                        set(entry['month'] for entry in monthly_jobs) |
                        set(entry['month'] for entry in monthly_categories))

    # Convert datetime months to string format
    months = [month.strftime('%Y-%m') for month in all_months]

    # Prepare counts for the chart
    provider_counts = [next((entry['count'] for entry in monthly_providers if entry['month'] == month), 0) for month in all_months]
    customer_counts = [next((entry['count'] for entry in monthly_customers if entry['month'] == month), 0) for month in all_months]
    job_counts = [next((entry['count'] for entry in monthly_jobs if entry['month'] == month), 0) for month in all_months]
    category_counts = [next((entry['count'] for entry in monthly_categories if entry['month'] == month), 0) for month in all_months]

    # Pass all data to the template
    context = {
        'provider_count': provider_count,
        'customer_count': customer_count,
        'job_count': job_count,
        'category_count': category_count,
        'months': months,
        'provider_counts': provider_counts,
        'customer_counts': customer_counts,
        'job_counts': job_counts,
        'category_counts': category_counts,
        'last_5_providers': last_5_providers,
        'last_5_jobs': last_5_jobs,
        'categories': categories,
        'last_5_customers': last_5_customers,  # Add this line
    }

    return render(request, 'admin/admin_dashboard.html', context)




from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from .models import Admin, PasswordResetToken
from .forms import ForgotPasswordFormAdmin, ResetPasswordFormAdmin
import uuid

def forgot_password_admin(request):
    if request.method == 'POST':
        form = ForgotPasswordFormAdmin(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            try:
                admin = Admin.objects.get(username=username, email=email)
                # Create a password reset token
                token = PasswordResetToken.objects.create(admin=admin)
                reset_link = request.build_absolute_uri(f'reset-password-admin/{token.token}/')
                send_mail(
                    'Password Reset Request',
                    f'Please use the following link to reset your password: {reset_link}',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                )
                messages.success(request, 'A password reset link has been sent to your email.')
                return redirect('forgot_password_admin')
            except Admin.DoesNotExist:
                messages.error(request, 'Invalid username or email address.')
    else:
        form = ForgotPasswordFormAdmin()
    return render(request, 'admin/forgot_password.html', {'form': form})

def reset_password_admin(request, token):
    reset_token = get_object_or_404(PasswordResetToken, token=token)
    if not reset_token.is_valid():
        messages.error(request, 'This link has expired or is invalid.')
        return redirect('forgot_password_admin')
    
    if request.method == 'POST':
        form = ResetPasswordFormAdmin(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password']
            confirm_password = form.cleaned_data['confirm_password']
            if new_password == confirm_password:
                admin = reset_token.admin
                admin.password = make_password(new_password)  # Hash the password
                admin.save()
                reset_token.is_used = True
                reset_token.save()
                messages.success(request, 'Your password has been successfully reset.')
                return redirect('admin_login')
            else:
                messages.error(request, 'Passwords do not match.')
    else:
        form = ResetPasswordFormAdmin()
    return render(request, 'admin/reset_password.html', {'form': form})


from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Provider

@login_required
def edit_provider(request):
    current_user = request.user
    try:
        provider = Provider.objects.get(user=current_user)
    except Provider.DoesNotExist:
        return render(request, 'error.html', {'message': 'You are not associated with any provider profile.'})

    if request.method == 'POST':
        form = ProviderForm(request.POST, request.FILES, instance=provider)
        if form.is_valid():
            # Save the form, Cloudinary will handle the file upload
            form.save()
            messages.success(request, 'Provider profile updated successfully!')
            return redirect('provider_index')
        else:
            messages.error(request, 'Please correct the errors below.')

    else:
        form = ProviderForm(instance=provider)

    return render(request, 'provider/details.html', {'form': form})

from django.shortcuts import render
from .models import Provider
from django.utils import timezone
import calendar

@login_required
def provider_registration_chart(request):
    # Get the current year
    current_year = timezone.now().year

    # Create a dictionary to hold the count of registrations per month
    registrations_per_month = {month: 0 for month in calendar.month_name[1:]}

    # Fetch provider registrations for the current year
    providers = Provider.objects.filter(created_on__year=current_year)

    # Count registrations per month
    for provider in providers:
        month_name = calendar.month_name[provider.created_on.month]
        registrations_per_month[month_name] += 1

    # Pass the data to the template
    return render(request, 'admin/provider_registration_chart.html', {
        'registrations_per_month': registrations_per_month,
        'current_year': current_year
    })




from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import ResumeUpload
import cloudinary

@login_required
def analyze_resume(request):
    if request.method == 'POST' and request.FILES.get('resume'):
        resume = request.FILES['resume']

        existing_resume = ResumeUpload.objects.filter(user=request.user).first()
        if existing_resume:
            existing_resume.delete()  # Just delete the record from the database

        # Save the new uploaded resume in the database
        new_resume = ResumeUpload.objects.create(
            user=request.user,
            uploaded_file=resume,
            fileName=resume.name  
        )

        # Get the URL of the uploaded file for processing
        uploaded_file_url = new_resume.uploaded_file.url

        # Your upload_to_gemini and analysis logic here...
        gemini_file = upload_to_gemini(uploaded_file_url, mime_type='application/pdf')

        # Wait for the file to be ready
        wait_for_files_active([gemini_file])

        # Set up model generation configuration
        generation_config = {
            "temperature": 1,
            "top_p": 0.95,
            "top_k": 64,
            "max_output_tokens": 8192,
            "response_mime_type": "text/plain",
        }

        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config=generation_config
        )

        # Start chat session with the model
        chat_session = model.start_chat(
            history=[{"role": "user", "parts": [gemini_file, ""]}]
        )

        # Send messages to get responses
        response1 = chat_session.send_message("Analyze the resume for suitable job matches. when listing, provide details such as job title, average salary a person could get in INR and why it is suitable. dont provide any other data. show job title at the beginning. avoid heading like suitable jobs too. use you/your for pointing to the person and display the best job that suits the user. also include ':' after the heading.")
        response3 = chat_session.send_message("Analyze the resume and suggest points to improve the quality of the resume and ATS score. dont provide any other data. avoid heading like resume improvements too. use you/your for pointing to the person")

        suitable_jobs = response1.text.replace('#', '').replace('*', '')
        improve_resume = response2.text.replace('#', '').replace('*', '')

        # Preprocess the data for template rendering
        def process_data(data):
            result = []
            for line in data.splitlines():
                if ':' in line:
                    parts = line.split(':', 1)
                    result.append({'title': parts[0].strip(), 'description': parts[1].strip()})
                else:
                    result.append({'title': '', 'description': line.strip()})
            return result

        context = {
            'suitable_jobs': process_data(suitable_jobs),
            'improve_resume': process_data(improve_resume)
        }

        return render(request, 'analyze_resume.html', context)

    return render(request, 'upload_resume.html')
