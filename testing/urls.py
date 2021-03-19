from django.urls import path
from . import views

urlpatterns = [
    path('', views.subdomain_finder, name='testing-home'),
    path('subs/', views.subdomain_finder, name='subdomain_finder'),
    path('directory/', views.directory_brute_force, name='directory_brute'),
    path('wayback/', views.waybackurls, name='wayback_url'),
    path('jsfiles/', views.js_files, name='jsfile'),
    path('jslinks/', views.js_links, name='jslink'),
    path('jsecret/', views.js_secrets, name='js-secrets'),
]