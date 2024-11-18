import requests
from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.db.models.base import Model


class CognitoBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None):
        response = requests.post(
            settings.COGNITO_EP,
            json={
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": settings.COGNITO_CLIENT_ID,
                "AuthParameters": {"USERNAME": username, "PASSWORD": password},
            },
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
            },
        )
        if response.status_code != 200:
            return None
        request.session["cognito"] = response.json()
        user, _ = User.objects.get_or_create(
            username=username, is_staff=True, is_superuser=True
        )
        return user

    def get_user(self, user_id: int):
        return User.objects.filter(pk=user_id).first()
