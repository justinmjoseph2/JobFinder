import django_filters
from .models import Job, JobCategory, Provider

class JobFilter(django_filters.FilterSet):
    category = django_filters.ModelChoiceFilter(queryset=JobCategory.objects.all(), label="Category")
    provider = django_filters.ModelChoiceFilter(queryset=Provider.objects.all(), label="Provider")
    job_type = django_filters.ChoiceFilter(choices=[('Full-time', 'Full-time'), ('Part-time', 'Part-time')], label="Job Type")
    salary = django_filters.RangeFilter(label="Salary Range")  # Salary range filter
    experience = django_filters.ChoiceFilter(choices=[('fresher', 'Fresher'), 
                                                      ('1', '1 Year'), 
                                                      ('2', '2 Years'), 
                                                      ('3', '3 Years'),
                                                      ('4', '4 Years'), 
                                                      ('5', '5 Years'), 
                                                      ('Above10', 'Above 10 Years')], label="Experience")

    class Meta:
        model = Job
        fields = ['category', 'provider', 'job_type', 'salary', 'experience']
