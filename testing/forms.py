from django import forms

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