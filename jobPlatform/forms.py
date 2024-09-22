from django import forms
from django.core.exceptions import ValidationError
from .models import Contact, Provider

class ContactForm(forms.ModelForm):
    class Meta:
        model = Contact
        fields = ['name', 'email', 'message']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'message': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        }


from django import forms
from .models import Provider

class ProviderForm(forms.ModelForm):
    class Meta:
        model = Provider
        fields = ['provider_name', 'company_name', 'company_logo']  # Email is excluded
        widgets = {
            'provider_name': forms.TextInput(attrs={'class': 'form-control'}),
            'company_name': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        # Add email field manually
        self.fields['email'] = forms.EmailField(initial=self.user.email, disabled=True)

    def clean_email(self):
        # Skip validation for email since it's not editable
        return self.user.email

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.email = self.user.email  # Ensure the email stays the same
        if commit:
            instance.save()
        return instance



from django import forms
from .models import Job, JobCategory

# Experience choices as a tuple of options
EXPERIENCE_CHOICES = [
    ('fresher', 'Fresher'),
    (1, '1 Year'),
    (2, '2 Years'),
    (3, '3 Years'),
    (4, '4 Years'),
    (5, '5 Years'),
    (6, '6 Years'),
    (7, '7 Years'),
    (8, '8 Years'),
    (9, '9 Years'),
    (10, '10 Years'),
    ('Above10', 'Above 10 Years'),
]

JOB_TYPE_CHOICES = [
    ('full-time', 'Full-time'),
    ('part-time', 'Part-time'),
    ('intern', 'Intern'),
]

class JobForm(forms.ModelForm):
    experience = forms.ChoiceField(
        choices=EXPERIENCE_CHOICES,
        label='Experience',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    category = forms.ModelChoiceField(
        queryset=JobCategory.objects.all(),
        label='Job Category',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    job_type = forms.ChoiceField(
        choices=JOB_TYPE_CHOICES,
        label='Job Type',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Job
        fields = ['title', 'category', 'job_type', 'description', 'salary', 'vacancies', 'link', 'location', 'skills', 'till_date', 'experience']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Job Title'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 5, 'placeholder': 'Job Description'}),
            'salary': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Salary'}),
            'vacancies': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Number of Vacancies'}),
            'link': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'Application Link'}),
            'location': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Job Location'}),
            'skills': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Required Skills'}),
            'till_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control', 'placeholder': 'DD/MM/YYYY'}),
        }
        labels = {
            'title': 'Job Title',
            'category': 'Job Category',
            'job_type': 'Job Type',
            'description': 'Job Description',
            'salary': 'Salary',
            'vacancies': 'Vacancies',
            'link': 'Application Link',
            'location': 'Job Location',
            'skills': 'Required Skills',
            'till_date': 'Job Posting Till Date',
            'experience': 'Experience',
        }
        

class JobFormEdit(forms.ModelForm):
    experience = forms.ChoiceField(
        choices=EXPERIENCE_CHOICES,
        label='Experience',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    category = forms.ModelChoiceField(
        queryset=JobCategory.objects.all(),
        label='Job Category',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    job_type = forms.ChoiceField(
        choices=JOB_TYPE_CHOICES,
        label='Job Type',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Job
        fields = ['title', 'category', 'job_type', 'description', 'salary', 'vacancies', 'link', 'location', 'skills', 'till_date', 'experience']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Job Title'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 5, 'placeholder': 'Job Description'}),
            'salary': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Salary'}),
            'vacancies': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Number of Vacancies'}),
            'link': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'Application Link'}),
            'location': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Job Location'}),
            'skills': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Required Skills'}),
            'till_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control', 'placeholder': 'YYYY-MM-DD'}),
        }
        labels = {
            'title': 'Job Title',
            'category': 'Job Category',
            'job_type': 'Job Type',
            'description': 'Job Description',
            'salary': 'Salary',
            'vacancies': 'Vacancies',
            'link': 'Application Link',
            'location': 'Job Location',
            'skills': 'Required Skills',
            'till_date': 'Job Posting Till Date',
            'experience': 'Experience',
        }




from django import forms
from .models import JobCategory

class JobCategoryForm(forms.ModelForm):
    class Meta:
        model = JobCategory
        fields = ['name']  # List the fields you want in the form


from django import forms
from django.contrib.auth.forms import PasswordChangeForm

class EditPasswordForm(PasswordChangeForm):
    old_password = forms.CharField(
        label="Current Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )
    new_password1 = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )
    new_password2 = forms.CharField(
        label="Confirm New Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )

    class Meta:
        fields = ['old_password', 'new_password1', 'new_password2']


# forms.py
from django import forms

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Enter your registered email'}))


# forms.py
class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New password'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm password'}))

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password != confirm_password:
            raise forms.ValidationError("Passwords do not match")
        return cleaned_data


from django import forms
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from .models import Customer

class CustomerPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address',
            'style': 'border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'
        }),
        label='Email Address',
        max_length=254,
        error_messages={
            'required': 'Please enter your email address.',
            'invalid': 'Enter a valid email address.'
        }
    )

    def save(self, domain_override=None, subject_template_name='customer/password_reset_subject.txt',
             email_template_name='customer/password_reset_email.html', use_https=False,
             token_generator=default_token_generator, from_email=None, request=None, extra_email_context=None):
        email = self.cleaned_data["email"]
        customers = Customer.objects.filter(email=email)
        for customer in customers:
            user = customer.user
            opts = {
                'domain': domain_override or get_current_site(request).domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token_generator.make_token(user),
            }
            context = dict(extra_email_context or {}, **opts)
            send_mail(
                subject_template_name,
                render_to_string(email_template_name, context),
                from_email,
                [email],
                fail_silently=False,
            )
class SetCustomerPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter new password',
            'style': 'border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'
        }),
        label='New Password',
        max_length=128,
        error_messages={
            'required': 'Please enter a new password.',
        }
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm new password',
            'style': 'border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'
        }),
        label='Confirm Password',
        max_length=128,
        error_messages={
            'required': 'Please confirm your new password.',
            'password_mismatch': 'The two password fields must match.',
        }
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(user, *args, **kwargs)

from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import authenticate

class CustomPasswordChangeForm(PasswordChangeForm):
    current_password = forms.CharField(
        label='Current Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Current Password'})
    )
    new_password1 = forms.CharField(
        label='New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New Password'})
    )
    new_password2 = forms.CharField(
        label='Confirm New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm New Password'})
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(user=user, *args, **kwargs)

    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password')
        if not self.user.check_password(current_password):
            raise forms.ValidationError("Current password is incorrect.")
        return current_password

    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get("new_password1")
        new_password2 = cleaned_data.get("new_password2")

        if new_password1 and new_password2 and new_password1 != new_password2:
            raise forms.ValidationError("New passwords do not match.")

        return cleaned_data


# forms.py
from django import forms
from .models import JobCategory

class JobCategoryForm(forms.ModelForm):
    class Meta:
        model = JobCategory
        fields = ['name']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
        }
        labels = {
            'name': 'Category Name',
        }


from django import forms
from django.core.exceptions import ValidationError
from .models import Admin

class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(label='Email', max_length=254)

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not Admin.objects.filter(email=email).exists():
            raise ValidationError("No admin with this email address exists.")
        return email


from django.contrib.auth.forms import SetPasswordForm

class SetAdminPasswordForm(SetPasswordForm):
    def __init__(self, user=None, *args, **kwargs):
        super().__init__(user, *args, **kwargs)


class AdminPasswordResetForm(PasswordResetForm):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address',
            'style': 'border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'
        }),
        label='Email Address',
        max_length=254,
        error_messages={
            'required': 'Please enter your email address.',
            'invalid': 'Enter a valid email address.'
        }
    )

    def save(self, domain_override=None, subject_template_name='customer/password_reset_subject.txt',
             email_template_name='customer/password_reset_email.html', use_https=False,
             token_generator=default_token_generator, from_email=None, request=None, extra_email_context=None):
        email = self.cleaned_data["email"]
        customers = Customer.objects.filter(email=email)
        for customer in customers:
            user = customer.user
            opts = {
                'domain': domain_override or get_current_site(request).domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token_generator.make_token(user),
            }
            context = dict(extra_email_context or {}, **opts)
            send_mail(
                subject_template_name,
                render_to_string(email_template_name, context),
                from_email,
                [email],
                fail_silently=False,
            )

class AdminPasswordChangeForm(PasswordChangeForm):
    current_password = forms.CharField(
        label='Current Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Current Password'})
    )
    new_password1 = forms.CharField(
        label='New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New Password'})
    )
    new_password2 = forms.CharField(
        label='Confirm New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm New Password'})
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(user=user, *args, **kwargs)

    def clean_current_password(self):
        current_password = self.cleaned_data.get('current_password')
        if not self.user.check_password(current_password):
            raise forms.ValidationError("Current password is incorrect.")
        return current_password

    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get("new_password1")
        new_password2 = cleaned_data.get("new_password2")

        if new_password1 and new_password2 and new_password1 != new_password2:
            raise forms.ValidationError("New passwords do not match.")

        return cleaned_data


from django import forms

class ForgotPasswordFormAdmin(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address',
            'style': 'border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'
        }),
        max_length=254,
        error_messages={
            'required': 'Please enter your email address.',
            'invalid': 'Enter a valid email address.'
        }
    )

class ResetPasswordFormAdmin(forms.Form):
    new_password = forms.CharField(
        label="New Password", 
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'New Password',
            'style': 'border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'
        })
    )
    confirm_password = forms.CharField(
        label="Confirm Password", 
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm Password',
            'style': 'border: 1px solid #ddd; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);'
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password:
            if new_password != confirm_password:
                raise forms.ValidationError("Passwords do not match.")
        return cleaned_data


from django import forms

class ForgotPasswordFormAdmin(forms.Form):
    username = forms.CharField(
        label='Username',
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'})
    )
    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'})
    )


class ResetPasswordFormAdmin(forms.Form):
    new_password = forms.CharField(
        label='New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New Password'})
    )
    confirm_password = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm Password'})
    )


# jobPlatform/forms.py
from django import forms

class UploadFileForm(forms.Form):
    # Define a file field for uploading files
    file = forms.FileField(label='Select a file')
