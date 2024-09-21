from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import Customer, Provider, Job, Contact, JobCategory
from django.utils.html import format_html
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings


from django.contrib import admin
from .models import JobCategory

class JobCategoryAdmin(admin.ModelAdmin):
    list_display = ['name']
    search_fields = ['name']

admin.site.register(JobCategory, JobCategoryAdmin)



from django.contrib import admin
from django.contrib.auth.models import User
from .models import Customer, Provider

from django.contrib import admin
from django.contrib.auth.models import User
from .models import Customer, Provider, Job

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ['id', 'customer_name', 'email', 'contact_number']
    search_fields = ['customer_name', 'email', 'contact_number']


    def get_form(self, request, obj=None, **kwargs):
        if obj:
            self.exclude = ['password']
        else:
            self.exclude = []
        return super().get_form(request, obj=obj, **kwargs)

    

    def delete_model(self, request, obj):
        # Retrieve the Provider associated with the customer
        Provider = obj.Provider_set.first()
        if Provider:
            # Retrieve the Jobs associated with the Provider and set Provider to NULL
            Jobs = Job.objects.filter(Provider=Provider)
            Jobs.update(Provider=None)
            # Delete the Provider
            Provider.delete()
        # Call the superclass delete_model to delete the customer
        super().delete_model(request, obj)



from django.contrib import admin
from .models import Provider

@admin.register(Provider)
class ProviderAdmin(admin.ModelAdmin):
    list_display = ['id', 'provider_name', 'email']
    search_fields = ['name', 'email']

    def delete_model(self, request, obj):
        # Retrieve the Provider associated with the customer
        Provider = obj.Provider_set.first()
        if Provider:
            # Retrieve the Jobs associated with the Provider and set Provider to NULL
            Jobs = Job.objects.filter(Provider=Provider)
            Jobs.update(Provider=None)
            # Delete the Provider
            Provider.delete()
        # Call the superclass delete_model to delete the customer
        super().delete_model(request, obj)


from django.contrib import admin
from .models import Job

@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ['id', 'get_title', 'provider']
    def get_title(self, obj):
        return obj.title

from django.contrib import admin
from .models import Contact
from .forms import ContactForm

class ContactAdmin(admin.ModelAdmin):
    list_display = ['name', 'email', 'message']
    search_fields = ['name']

admin.site.register(Contact, ContactAdmin)



from django.contrib import admin
from .models import Job, JobCategory, Provider, Contact, Customer, ResumeUpload, JobApplication
