"""wapf URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from testing.views import subdomain_finder, index, directory_brute_force, waybackurls, js_files, js_secrets, js_links

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index, name="index-page"),
    path('scan/subdomain', subdomain_finder, name="subdomain-page" ),
    path('scan/directory', directory_brute_force, name="directory-page"),
    path('scan/wayback', waybackurls, name="wayback-page"),
    path('scan/jsfile', js_files, name="jsfile-page" ),
    path('scan/secret', js_secrets, name="secret-page"),
    path('scan/endpoint', js_links, name="endpoint-page"),
]
