from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from .models import BlacklistedToken
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.shortcuts import render, redirect

class BlockBlacklistedTokensMiddleware(MiddlewareMixin):
    def process_request(self, request):
        token = request.COOKIES.get('access', None)
        if token:
            try:
                # Ensure the token is valid and decode it
                decoded_token = AccessToken(token)
                # Check if this token is in the blacklist
                if BlacklistedToken.objects.filter(token=token).exists():
                    # If the token is blacklisted, do not proceed and return an error
                    return render(request, 'login.html') 
            except (InvalidToken, TokenError):
                # If the token is invalid, you can also choose to redirect to login here
                pass  # Or return JsonResponse({"detail": "Invalid token."}, status=401)
        
        # If the token is not provided, valid and not blacklisted, or an error occurs, just continue normally
        return None