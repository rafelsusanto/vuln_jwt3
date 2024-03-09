from django.shortcuts import redirect
from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth import get_user_model

def jwt_required(f):
    def wrap(request, *args, **kwargs):
        User = get_user_model()  # Move this line to the top of wrap function
        token = request.COOKIES.get('access', None)
        if token:
            try:
                valid_token = AccessToken(token)
                user_id = valid_token['user_id']
                user = User.objects.get(id=user_id)
                request.user = user
                return f(request, *args, **kwargs)
            except (InvalidToken, TokenError, User.DoesNotExist):
                pass  # Consider handling this case more explicitly, perhaps logging or redirecting
        return redirect(settings.LOGIN_URL)
    return wrap
