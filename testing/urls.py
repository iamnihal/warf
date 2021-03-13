from django.urls import path
from . import views

urlpatterns = [
    path('', views.testing, name='testing-home'),
    path('directory/', views.directory_brute_force, name='directory_brute')
]