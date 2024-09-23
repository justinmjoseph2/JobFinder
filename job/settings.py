"""
Django settings for job project.

Generated by 'django-admin startproject' using Django 4.2.11.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-7sc8q^+h5095(ov1h3y$8iqe0gs(bm2c!rj4crrmdhrw6zgpoa'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'justinmjoseph222@gmail.com'
EMAIL_HOST_PASSWORD = 'zihm lcfy fnxc fymp'

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'jobPlatform',
    'django_filters',
    'cloudinary',
    'cloudinary_storage',

    

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
]

ROOT_URLCONF = 'job.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],  # Ensure this is included
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'job.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'jobfinder',
        'USER': 'jobfinder_user',
        'PASSWORD': '7fePyLGuTe0PYdMypjDZzN3zSgZtShm3',
        'HOST': 'dpg-crohsgij1k6c739hrscg-a.oregon-postgres.render.com',
        'PORT': '5432',  # Default PostgreSQL port
    }
}



GEMINI_API_KEY="AIzaSyDHlaH_BLjVfTy-zDD6FAeJGEasRvAh9iU"

from decouple import config

from decouple import config

# Gemini API credentials
GEMINI_API_KEY = config('GEMINI_API_KEY', default='AIzaSyDHlaH_BLjVfTy-zDD6FAeJGEasRvAh9iU')



# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

# Directory where static files are collected during collectstatic
# settings.py

# Directory where Django will collect all static files when running `collectstatic`
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')  # Ensure this is not a directory you manually work with

# Directories where Django will search for static files during development
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),  # This should point to the folder containing your static assets
]

# URL to access static files
STATIC_URL = '/static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

MEDIA_ROOT = os.path.join(BASE_DIR, 'resumes/')

# The URL that serves media files
MEDIA_URL = '/resumes/'


# Add this at the top of your settings.py file
import cloudinary
import cloudinary_storage

# Cloudinary configuration
cloudinary.config(
    cloud_name='dxm5scbpw',  # Replace with your cloud name
    api_key='798278373751285',  # Replace with your API key
    api_secret='-FS_NRNlGTylyBoGr8yZaI7lN9M',  # Replace with your API secret
)

# Optional: Configure cloud storage (if needed)
CLOUDINARY_STORAGE = {
    'cloud_name': 'dxm5scbpw',
    'api_key': '798278373751285',
    'api_secret': '-FS_NRNlGTylyBoGr8yZaI7lN9M',
}

# Set Cloudinary as the default file storage backend
DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'


GEMINI_API_KEY='AIzaSyDHlaH_BLjVfTy-zDD6FAeJGEasRvAh9iU'
