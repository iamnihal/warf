from django import forms
from .models import Scan

class SubdomainForm(forms.Form):
    subdomain_name = forms.CharField(max_length=100)

class DirectoryBruteForce(forms.Form):
    directory_url = forms.CharField(max_length=100)

class Waybackurls(forms.Form):
    target_domain = forms.CharField(max_length=100)

class JsFiles(forms.Form):
    target_domain =  forms.CharField(max_length=100)

class JsLinks(forms.Form):
    target_domain = forms.CharField(max_length=100)

class JsSecrets(forms.Form):
    target_domain = forms.CharField(max_length=100)

class GithubSubdomainForm(forms.Form):
    target_domain = forms.CharField(max_length=100)
    token = forms.CharField(max_length=30)

class AddTargetForm(forms.ModelForm):
    class Meta:
        model = Scan
        fields = ['target_name', 'scan_type', 'domain_url']
