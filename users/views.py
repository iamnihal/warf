from django.shortcuts import render, redirect
from .forms import UserRegisterForm, UserEmailUpdateForm, UserUsernameUpdateForm
from django.contrib import messages
from django.views.generic import DetailView
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from testing.forms import AddTargetForm
from testing.models import Scan
from testing.views import *


def register(request):
    if request.method == "POST":
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}! Now you can log in.')
            return redirect('login')
    else:
        form = UserRegisterForm()
    return render(request, 'users/register.html', {'form':form})

@login_required
def profile(request):
    if request.method == 'POST':
        u_form = UserUsernameUpdateForm(request.POST, instance=request.user)
        e_form = UserEmailUpdateForm(request.POST, instance=request.user)
        if u_form and u_form.is_valid():
            u_form.save()
            print("Username Changed")
            messages.success(request, 'Username successfully changed!!')
            return redirect('profile')
        elif e_form and e_form.is_valid():
            emailId = e_form.cleaned_data['email']
            if User.objects.filter(email__iexact=emailId).count() > 0:
                messages.error(request, 'Email already exist!!')
                return redirect('profile')
            else:
                e_form.save()
                print("Email changed")
                messages.success(request, 'Email successfully changed!!')
                return redirect('profile')
    else:
        u_form = UserUsernameUpdateForm(instance=request.user)
        e_form = UserEmailUpdateForm(instance=request.user)

    context = {
        'u_form': u_form,
        'e_form': e_form
    }

    return render(request, 'users/profile.html', context)

@login_required
def dashboard(request):
    return render(request, 'users/dashboard.html')

@login_required
def add_target(request):
    if request.method == 'POST':
        target_form = AddTargetForm(request.POST)
        scan_type = request.POST.get('scan_type')
        domain_url = request.POST.get('domain_url')
        if target_form.is_valid():
            new_target = target_form.save(commit=False)
            new_target.author = request.user
            new_target.save()
            # if scan_type == "Subdomain":
            #     subdomain_finder(request, domain_url)
            # elif scan_type == "Dirsearch":
            #     directory_brute_force(request, domain_url)
            # else:
            #     subdomain_finder(request, domain_url)
            return redirect('targets')
    else:
        target_form = AddTargetForm()
    return render(request, 'users/add-target.html', {'target_form':target_form})

@login_required
def target(request):
    target_list = Scan.objects.all().order_by('-scan_date')
    return render(request, 'users/targets.html', {'targets':target_list})


# class PostDetailView(DetailView):
#     model = Scan
#     template_name = 'users/scan_detail.html'


def target_view(request, pk):
    scan_item = Scan.objects.get(id=pk)
    scan_type = Scan.objects.get(id=pk).scan_type
    scan_domain_url = Scan.objects.get(id=pk).domain_url
    scan_date_posted = Scan.objects.get(id=pk).scan_date
    scan_target_name = Scan.objects.get(id=pk).target_name
    print("Hurray")
    print(scan_type)
    print(scan_domain_url)
    if scan_type == "Subdomain":
        subdomain_finder(request, scan_domain_url)
    elif scan_type == "Dirsearch":
        directory_brute_force(request, scan_domain_url)
    elif scan_type == "Wayback URL":
        waybackurls(request, scan_domain_url)
    elif scan_type == "JS File Discovery":
        js_urls(request, scan_domain_url)
    elif scan_type == "Secret/API key":
        js_secrets(request, scan_domain_url)
    elif scan_type == "Endpoint from JS":
        js_links(request, scan_domain_url)
 
    return render(request, 'users/scan_detail.html', {'scan_type':scan_type, 'scan_domain_url':scan_domain_url, 'scan_date_posted':scan_date_posted, 'scan_target_name':scan_target_name, 'scan_item':scan_item})



# def start_scan(request, pk):
#     scan_item = Scan.objects.get(id=pk)
#     scan_type = Scan.objects.get(id=pk).scan_type
#     scan_domain_url = Scan.objects.get(id=pk).domain_url
#     print(scan_type)
#     print(scan_domain_url)
#     if scan_type == "Subdomain":
#         print("Enter")
#         subdomain_finder(request, scan_domain_url)
#         return redirect('targets')
#     elif scan_type == "Dirsearch":
#         directory_brute_force(request, scan_domain_url)
#     elif scan_type == "Wayback URL":
#         waybackurls(request, scan_domain_url)
#     elif scan_type == "JS File Discovery":
#         js_urls(request, scan_domain_url)
#     elif scan_type == "Secret/API key":
#         js_secrets(request, scan_domain_url)
#     elif scan_type == "Endpoint from JS":
#         js_links(request, scan_domain_url)
#     return render(request, 'users/targets.html')
