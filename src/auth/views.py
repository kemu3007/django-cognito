import jwt
import requests
from django.conf import settings
from django.contrib.auth import authenticate, logout
from ninja import NinjaAPI, Schema

auth_api = NinjaAPI()


class LoginSchema(Schema):
    username: str
    password: str


class LoginResponseSchema(Schema):
    pk: int
    username: str


@auth_api.post("/login", response=LoginResponseSchema)
def login(request, input: LoginSchema):
    return authenticate(request, username=input.username, password=input.password)


class SignUpSchema(Schema):
    username: str
    password: str
    email: str


@auth_api.post("/signUp")
def signUp(request, input: SignUpSchema):
    response = requests.post(
        settings.COGNITO_EP,
        json={
            "ClientId": settings.COGNITO_CLIENT_ID,
            "Username": input.username,
            "Password": input.password,
            "UserAttributes": [{"Name": "email", "Value": input.email}],
        },
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
        },
    )
    return response.json()


class ConfirmSignUpSchema(Schema):
    username: str
    code: str


@auth_api.post("/confirmSignUp")
def confirmSignUp(request, input: ConfirmSignUpSchema):
    response = requests.post(
        settings.COGNITO_EP,
        json={
            "ClientId": settings.COGNITO_CLIENT_ID,
            "Username": input.username,
            "ConfirmationCode": input.code,
        },
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.ConfirmSignUp",
        },
    )
    return response.json()


@auth_api.get("/getUser")
def getUser(request):
    try:
        jwks_client = jwt.PyJWKClient(settings.COGNITO_JWK_EP)
        token = request.session["cognito"]["AuthenticationResult"]["IdToken"]
        payload = jwt.decode(
            token,
            jwks_client.get_signing_key_from_jwt(token),
            audience=settings.COGNITO_CLIENT_ID,
            algorithms=["RS256"],
        )
        return payload
    except (jwt.exceptions.PyJWTError, KeyError) as e:
        return None
