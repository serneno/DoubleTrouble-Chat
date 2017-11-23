# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm

from django.shortcuts import render, redirect
from rest_framework.authtoken.models import Token


def home(request):
    return render(request, 'home.html')

def logout_user(request):
    return render(request, 'accounts/logout.html', {})

def login_form(request):
    return render(request, 'accounts/login.html', {})

def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})

#def get_auth_token(request):
#    username = request.POST.get('username')
#    password = request.POST.get('password')
#    user = authenticate(username=username, password=password)
#    if user is not None:
        # the password verified for the user
#        if user.is_active:
#            token, created = Token.objects.get_or_create(user=user)
#            request.session['auth'] = token.key
#            return redirect('/polls/', request)
#    return redirect(settings.LOGIN_URL, request)

