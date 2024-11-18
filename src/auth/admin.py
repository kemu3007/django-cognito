from django.contrib import admin
from django.contrib.auth.forms import AuthenticationForm


# Register your models here.
class CognitoLoginForm(AuthenticationForm):
    def clean(self):
        return self.cleaned_data


class CustomAdminSite(admin.AdminSite):
    authentication_form = CognitoLoginForm
