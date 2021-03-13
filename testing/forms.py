from django import forms
from .models import Subdomain

class SubdomainForm(forms.Form):
    subdomain_name = forms.CharField(max_length=100)

class DirectoryBruteForce(forms.Form):
    directory_url = forms.CharField(max_length=100)