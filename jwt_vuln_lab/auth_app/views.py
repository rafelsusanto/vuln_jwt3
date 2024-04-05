# auth_app/views.py
# Standard library imports
from datetime import datetime, timedelta
import os

# Django imports
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.http import HttpResponseRedirect

# Third-party libraries imports
import jwt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

# Local application imports
# from .decorators import jwt_required
from .models import BlacklistedToken

from django.shortcuts import redirect
from django.conf import settings
from django.contrib.auth import get_user_model
import jwt
import requests
from functools import wraps


# Get the directory of the current script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the path to the private key file
PRIVATE_KEY_PATH = os.path.join(current_dir, 'private.pem')
def custom_verify_jwt(token):
    """Verify a JWT against the JWKS fetched from the JKU URL in the token's header."""
    # Decode the token without verification to extract the JKU URL from the headers
    print("debug1")
    unverified_header = jwt.get_unverified_header(token)
    print("debug1")
    jku_url = unverified_header.get('jku')
    print("debug1")
    if not jku_url:
        raise InvalidTokenError("JKU URL not found in token header")

    # Fetch the JWKS and get the first key
    print("debug1")
    jwks = fetch_jwks(jku_url)
    print("debug2")
    jwk = get_first_jwk(jwks)
    print("debug3")
    # print(f'jwk jwks {jwk} {jwks}')
    # Construct a public key instance from the JWK
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    print(f"token {token} public key {public_key}")
    # Now verify the JWT using the public key
    decoded = jwt.decode(token, public_key, algorithms=['RS256'])
    print(decoded)
    return decoded

def fetch_jwks(jku_url):
    """Fetch the JWKS from the specified URL."""
    response = requests.get(jku_url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch JWKS: HTTP {response.status_code}")

def get_first_jwk(jwks):
    """Get the first key from the JWKS."""
    keys = jwks.get('keys', [])
    if not keys:
        raise Exception("No keys found in JWKS.")
    return keys[0]  # Use the first key

def get_tokens_for_user(user):
    # print("here1")
    # Load your private key
    with open(PRIVATE_KEY_PATH, 'r') as f:
        private_key = f.read()
    # print("here2")
    # Payload of the JWT
    payload = {
        'user_id': user.id,  # User identification
        'exp': datetime.utcnow() + timedelta(minutes=60),  # Token expiration time
        'iat': datetime.utcnow(),  # Issued at time
    }
    # print("here3")
    # Headers with the 'jku' URL
    headers = {
        'jku': 'http://127.0.0.1:8003/jwks.json',
    }
    # print(headers)
    # print(f'private key {private_key}\n payload {payload}')
    # Sign the payload with the RS256 algorithm, including the 'jku' header
    try:
        token = jwt.encode(payload, private_key, algorithm='RS256', headers=headers)
    except:
        print("fail to encode")
        pass
    # print("here1")
    print(token)
    return {'access': token}

def jwt_required(f):
    @wraps(f)
    def wrap(request, *args, **kwargs):
        User = get_user_model()
        token = request.COOKIES.get('access', None)
        if token:
            try:
                print("try decode token12")
                # Ensure verify_jwt uses the 'RS256' algorithm explicitly
                decoded_token = custom_verify_jwt(token)  
                print(decoded_token)
                user_id = decoded_token['user_id']
                print(user_id)
                user = User.objects.get(id=user_id)
                request.user = user
                return f(request, *args, **kwargs)
            except:
                print("token error")
                # Clear the invalid "access" cookie
                response = redirect(settings.LOGIN_URL)
                response.delete_cookie('access')
                return response
        # No valid token in cookie; redirect to LOGIN_URL
        return redirect(settings.LOGIN_URL)
    return wrap

def my_login_view(request):
    access_token = request.COOKIES.get('access')
    # response = render(request, 'login.html')
    if access_token:
        try:
            decoded_token = custom_verify_jwt(access_token)
            # If verification is successful, proceed
            return redirect(reverse('home_page'))
        except jwt.ExpiredSignatureError:
            # Handle expired token
            pass
        except jwt.PyJWTError as e:
            # Handle invalid token
            pass
        
        # Token is invalid or expired, delete it and show login
        response.delete_cookie('access')
        return response
    # print("log2")
    # Handle login attempt
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            tokens = get_tokens_for_user(user)
            response = redirect(reverse('home_page'))  # Redirect to a home page.
            response.set_cookie(key='access', value=tokens['access'], httponly=True) 
            return response
        else:
            print("logxx")
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    else:
        return render(request, 'login.html')

@jwt_required
def home_page(request):
    # Accessible only when logged in
    return render(request, 'home.html')

@jwt_required
def admin_page(request):
    token = request.COOKIES.get('access', None)
    print("here")
    if not token:
        # If there's no token, return 403 directly
        return render(request, '403.html')

    try:
        # Decode the token to get the user_id
        print("1")
        decoded_token = custom_verify_jwt(token)
        user_id = decoded_token['user_id']
        print(f"decoded token {decoded_token}\nuserid {user_id}")
        # Fetch the user based on user_id
        User = get_user_model()
        user = User.objects.get(id=user_id)
        print("3")
        # Check if the user is an admin
        if user.is_staff:
            print("1")
            return render(request, 'admin.html')
        else:
            return render(request, '403.html')
    except Exception as e:  # Catch specific exceptions as needed
        # Log the error or handle it as appropriate
        return render(request, '403.html')

def logout(request):
    token = request.COOKIES.get('access', None)
    if token:
        try:
            # Attempt to decode the token
            decoded_token = custom_verify_jwt(token)
            expires_at = timezone.datetime.fromtimestamp(decoded_token['exp'], timezone.utc)
            
            # Add the token to the blacklist
            BlacklistedToken.objects.create(token=token, expires_at=expires_at)
        except (InvalidToken, TokenError):
            # If the token is invalid, just redirect to login
            return redirect('/login/')

    response = redirect('/login/')  # Redirect to the login page
    response.delete_cookie('access')  # Remove the 'access' cookie
    return response

def jwks_show(request):
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "jwt_challenge",
                "alg": "RS256",
                "n": "vSWeoBYefD1pgjK0ydQpOpSw0RGB2OoqVkc5Xr2AT4fukm03SJ_f9KsdUqadybIZFaivV2EUilaenu4DSNwcqhgOuSnhTcrak_1dTIcHZ3ANH34pI-wk6wA-ecBHrmnFlciyPmkP6uADnG1VC5n0TAtZfHn6J6qqyFGLFTQ1_OTvsR2oDNz-fMZBcoMot55_WCWZd7eC_MGHtj43aanbsRxXg6rdbuliDengJrJ3yiBJbsmiIBbSYk6SKV_q5yKVQ9_31eXNtckPSmVBJ9utXjVW6Y7-GQiiIMNm5bSV03rov5BBDGDRgRRmKueiTLuR8GF4LmQ1gs-4NWEshp5q2Q",
                "e": "AQAB"
            }
        ]
    }
    return JsonResponse(jwks)