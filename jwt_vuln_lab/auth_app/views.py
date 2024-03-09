# auth_app/views.py
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .decorators import jwt_required
from django.utils import timezone
from .models import BlacklistedToken


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

def my_login_view(request):
    # Attempt to authenticate the user using the JWT token if already logged in
    access_token = request.COOKIES.get('access')
    if access_token:
        try:
            # Decode the token to check its validity
            AccessToken(access_token)
            # If the token is valid, redirect to the home page
            return redirect(reverse('home_page'))
        except (InvalidToken, TokenError):
            # If the token is invalid, remove it and proceed to login page
            response = render(request, 'login.html')
            response.delete_cookie('access')
            return response

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            tokens = get_tokens_for_user(user)
            response = redirect(reverse('home_page'))  # Redirect to a home page.
            response.set_cookie(key='access', value=tokens['access'], httponly=True)  # Securely set the access token in HttpOnly cookie
            return response
        else:
            return render(request, 'login.html')
    else:
        return render(request, 'login.html') 

@jwt_required
def home_page(request):
    # Accessible only when logged in
    return render(request, 'home.html')

@jwt_required
def admin_page(request):
    # print(request.user)
    # Check if the user is an admin
    if request.user.is_staff:
        return render(request, 'admin.html')
    else:
        return render(request, '403.html')

def logout(request):
    token = request.COOKIES.get('access', None)
    if token:
        try:
            # Attempt to decode the token
            decoded_token = AccessToken(token)
            expires_at = timezone.datetime.fromtimestamp(decoded_token['exp'], timezone.utc)
            
            # Add the token to the blacklist
            BlacklistedToken.objects.create(token=token, expires_at=expires_at)
        except (InvalidToken, TokenError):
            # If the token is invalid, just redirect to login
            return redirect('/login/')

    response = redirect('/login/')  # Redirect to the login page
    response.delete_cookie('access')  # Remove the 'access' cookie
    return response
