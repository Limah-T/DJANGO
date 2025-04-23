from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.http import HttpResponse
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.auth.hashers import make_password
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from datetime import datetime as dt, timezone, timedelta
from dotenv import load_dotenv
from .models import CustomUser, TempUser
from . import forms
import jwt
import os

load_dotenv()

# Expiration time for JWT token
# JWT token
# sub claim stands for subject — it's a standard claim that identifies who the token is about.
# iat issued at
# exp expires at
def token_expiration_time(request, username):
    now = dt.now(timezone.utc) 
    expiration_time = now + timedelta(minutes=int(os.getenv("JWT_EXPIRATION_TIME")))
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int(expiration_time.timestamp())
    }
    jwt_token = jwt.encode(payload=payload, key=os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("ALGORITHM"))
    return jwt_token

def send_email(request, username, email):
    token = token_expiration_time(request, username=username)
    verify = f"http://127.0.0.1:8000/user_account/verify_token/{token}/"
    # Secondly, render the HTML content.
    html_content = render_to_string(
        "user_account/email.html",
        context={"username": username, "email": email, "token": verify},
    )

    # Then, create a multipart email instance.
    msg = EmailMultiAlternatives(
        subject="Welcome to UMD!",
        from_email=os.getenv("EMAIL_HOST_USER"),
        to=[email],
    )

    # Lastly, attach the HTML content to the email instance and send.
    msg.attach_alternative(html_content, "text/html")
    msg.send(fail_silently=False)
    print("message sent successfully")
    return render(request, "user_account/verify_email.html", {"username": username, "email": email})

def verification(request, token):
    try:
        payload = jwt.decode(jwt=token, 
                   key=os.getenv("JWT_SECRET_KEY"), 
                   algorithms=[os.getenv("ALGORITHM")], 
                   options={"require": ["exp", "iat", "sub"]}
                   )
        username = payload['sub']
        return redirect(reverse_lazy("user_account:add_user", kwargs={'username': username}))
    except jwt.ExpiredSignatureError as e:
        return HttpResponse("Token has expired, request for a new one!")
    except jwt.ImmatureSignatureError:
        return HttpResponse("Token is not yet valid. Please wait and try again.")
    except jwt.InvalidTokenError:
        return HttpResponse("Invalid token. Please try again.")
    
# home page
@login_required
def home(request):
    return render(request, "user_account/home.html")

# Register page
class RegisterView(FormView):
    template_name = "user_account/register.html"
    form_class = forms.RegisterForm
    success_url = reverse_lazy("user_account:home")

    def post(self, request, *args, **kwargs):
        global storage
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():          
            firstname = form.cleaned_data.get('first_name')
            lastname = form.cleaned_data.get('last_name')   
            email = form.cleaned_data.get('email')
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password2')
            TempUser.objects.create(first_name=firstname, last_name=lastname, username=username, email=email, password=password)
            return redirect(reverse_lazy("user_account:send_token_to_email", kwargs={"username": username, "email": email}))
        return super().post(request, *args, **kwargs)

def add_user_to_database(request, username):
    print(username)
    user = TempUser.objects.get(username=username)
    if user:
        valid_user = CustomUser.objects.create(first_name=user.first_name,
                                last_name = user.last_name,
                                username = user.username,
                                email=user.email,
                                password = make_password(user.password)
                                )
        login(request, user=valid_user)
        valid_user.is_active = True
        user.delete()
        return redirect(reverse_lazy("user_account:home"))
    return HttpResponse("User registration expired!")

class LoginView(FormView):
    template_name = "user_account/login.html"
    form_class = forms.LoginForm
    success_url = reverse_lazy("user_account:home")

    def post(self, request, *args, **kwargs):
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():
            email = form.cleaned_data.get("email")
            password = form.cleaned_data.get("password")
            print(email, password)
            email_exist = get_object_or_404(CustomUser, email=email)
            if email_exist:
                user = authenticate(request, email=email_exist, password=password)
                if user:
                    login(request, user=user)
                    messages.success(request, message="Logged in!")
                    return redirect(self.success_url)
                else:
                    messages.error(request, message="Email or Password is incorrect!")
            else:
                messages.error(request, message="Email does not exist in database!")
        return super().post(request, *args, **kwargs)
