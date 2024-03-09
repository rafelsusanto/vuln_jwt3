from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import UntypedToken
from django.contrib.auth.models import User
from rest_framework import exceptions

class JWTAuthenticationFromCookie(BaseAuthentication):
    def authenticate(self, request):
        jwt_token = request.COOKIES.get('access')  # Get the token from the cookie
        if not jwt_token:
            return None

        try:
            # This will verify the token and raise an exception if it is not valid
            UntypedToken(jwt_token)
        except (InvalidToken, TokenError) as e:
            raise exceptions.AuthenticationFailed('Invalid token')

        try:
            # Assuming the token has a user_id claim, you can get the user object
            user_id = UntypedToken(jwt_token)['user_id']
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found')

        return (user, None)  # Authentication successful