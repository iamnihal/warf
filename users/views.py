from django.shortcuts import render, redirect
from .forms import UserRegisterForm, UserEmailUpdateForm, UserUsernameUpdateForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from testing.forms import AddTargetForm
from testing.models import Scan, ResultFileName
from testing.views import *
import string as st
import random


def register(request):
    password_suggestion = "".join(
        random.choices(
            st.digits + st.ascii_lowercase + st.ascii_letters + st.punctuation, k=15
        )
    )
    if request.method == "POST":
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            new_user = form.save()
            messages.success(request, "You are now logged in.")
            new_user = authenticate(
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password1"],
            )
            login(request, new_user)
            return redirect("dashboard")
    else:
        form = UserRegisterForm()
    return render(
        request, "users/register.html", {"form": form, "password": password_suggestion}
    )


@login_required
def profile(request):
    if request.method == "POST":
        u_form = UserUsernameUpdateForm(request.POST, instance=request.user)
        e_form = UserEmailUpdateForm(request.POST, instance=request.user)
        if u_form and u_form.is_valid():
            u_form.save()
            messages.success(request, "Username successfully changed!!")
            return redirect("profile")
        elif e_form and e_form.is_valid():
            emailId = e_form.cleaned_data["email"]
            if User.objects.filter(email__iexact=emailId).count() > 0:
                messages.error(request, "Email already exist!!")
                return redirect("profile")
            else:
                e_form.save()
                messages.success(request, "Email successfully changed!!")
                return redirect("profile")
    else:
        u_form = UserUsernameUpdateForm(instance=request.user)
        e_form = UserEmailUpdateForm(instance=request.user)

    context = {"u_form": u_form, "e_form": e_form}

    return render(request, "users/profile.html", context)


@login_required
def dashboard(request):
    if request.method == "GET":
        username = request.user
        scan_info = Scan.objects.filter(author=username)
        subdomain = scan_info.filter(scan_type="Subdomain")
        directory = scan_info.filter(scan_type="Dirsearch")
        wayback = scan_info.filter(scan_type="Wayback URL")
        jsfile = scan_info.filter(scan_type="JS File Discovery")
        secrets = scan_info.filter(scan_type="Secret/API key")
        endpoint = scan_info.filter(scan_type="Endpoint from JS")
        targets = Scan.objects.filter(
            author=User.objects.filter(username=username).first()
        )
        scans = ResultFileName.objects.filter(scan_item__in=targets)

    scanContext = {
        "scan_info": scan_info,
        "scans": scans,
        "subdomain": subdomain,
        "directory": directory,
        "wayback": wayback,
        "jsfile": jsfile,
        "secrets": secrets,
        "endpoint": endpoint,
    }
    return render(request, "users/dashboard.html", {"context": scanContext})


@login_required
def add_target(request):
    if request.method == "POST":
        target_form = AddTargetForm(request.POST)
        scan_type = request.POST.get("scan_type")
        domain_url = request.POST.get("domain_url")
        if target_form.is_valid():
            new_target = target_form.save(commit=False)
            new_target.author = request.user
            new_target.save()
            return redirect("targets")
    else:
        target_form = AddTargetForm()
    return render(request, "users/add-target.html", {"target_form": target_form})


@login_required
def target(request):
    if request.method == "GET":
        if request.user.is_authenticated:
            username = request.user
            q = request.GET.get("q", None)
            if q:
                targets = Scan.objects.filter(target_name__icontains=q)
                if targets:
                    return render(request, "users/targets.html", {"targets": targets})
                else:
                    messages.warning(request, "<center>Search not found!!</center>")
                    return render(request, "users/targets.html")
            else:
                target_list = Scan.objects.filter(author=username).order_by(
                    "-scan_date"
                )
                total_targets = target_list.count()
                paginator = Paginator(target_list, 8)
                page_number = request.GET.get("page")
                page_obj = paginator.get_page(page_number)

                return render(
                    request,
                    "users/targets.html",
                    {"targets": page_obj, "total_targets": total_targets},
                )


def target_bookmark(request, pk):
    target = Scan.objects.get(id=pk)
    if target.is_bookmark == 1:
        target.is_bookmark = 0
        target.save(update_fields=['is_bookmark'])
        messages.success(request, 'Target removed from Bookmark')
    else:
        target.is_bookmark = 1
        target.save(update_fields=['is_bookmark'])
        messages.success(request, 'Target added to Bookmark')

    return redirect(f"http://localhost:8000/targets/{pk}")

def bookmark_view(request):
    q = request.GET.get("q", None)
    if q:
        targets = Scan.objects.filter(target_name__icontains=q, is_bookmark=1).order_by('-scan_date')
        if targets:
            return render(request, "users/bookmark.html", {"targets":targets})
        else:
            messages.success(request, "Searchn not found")
            return render(request, "users/bookmark.html")
    else:
        targets = Scan.objects.filter(is_bookmark=1).order_by('-scan_date')
        return render(request, "users/bookmark.html", {"targets":targets})