from django.shortcuts import render, redirect
from .forms import UserRegisterForm, UserEmailUpdateForm, UserUsernameUpdateForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

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