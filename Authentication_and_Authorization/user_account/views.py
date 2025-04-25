from django.shortcuts import render, redirect, get_object_or_404
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.http import HttpResponse
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.auth.hashers import make_password
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.views import PasswordChangeView, PasswordChangeDoneView, PasswordResetView, PasswordResetConfirmView, PasswordResetCompleteView
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import generic
from django.conf import settings
from datetime import datetime as dt, timezone, timedelta
from dotenv import load_dotenv
from .models import CustomUser, TempUser
from . import forms
import jwt, os, socket, smtplib, base64

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

    html_content = render_to_string(
        "user_account/email.html",
        context={"username": username, "email": email, "token": verify},
    )

    msg = EmailMultiAlternatives(
        subject="Welcome to UMD!",
        from_email=os.getenv("EMAIL_HOST_USER"),
        to=[email],
        headers={"X-Mail-Queue-Priority": "now"}  # highest Priority set here, do not queue
    )
    msg.attach_alternative(html_content, "text/html")
    
    try:
        msg.send()
        messages.success(request, f"Verification email sent to {email} successfully, please inform the user to check their email!")
        return render(request, "user_account/verify_email.html", {"username": username, "email": email})
    except (smtplib.SMTPException, socket.gaierror, socket.timeout) as e:
        messages.error(request, "Network error! Please check your connection and try again.")
        return redirect(reverse_lazy("user_account:register"))
    except Exception as e:
        messages.error(request, "An unexpected error occurred while sending the email.")
        print(e)
        return redirect(reverse_lazy("user_account:register"))
    
def verification(request, token):
    active_user = request.user
    try:
        payload = jwt.decode(jwt=token, 
                   key=os.getenv("JWT_SECRET_KEY"), 
                   algorithms=[os.getenv("ALGORITHM")], 
                   options={"require": ["exp", "iat", "sub"]}
                   )
        username = payload['sub']
        return redirect(reverse_lazy("user_account:add_user", kwargs={'username': username}))
    except jwt.ExpiredSignatureError as e:
        # Checks if user is logged in already or not
        if not active_user.is_authenticated:
            messages.info(request, message="Invalid request with expired token!")
            return render(request, "user_account/token_expired.html")
        messages.info(request, message="Cannot complete request with expired token, and you are already logged In!")
        return redirect(reverse_lazy("user_account:home"))
    except jwt.ImmatureSignatureError:
        error_message = "Token is not yet valid. Please wait and try again."
        return render(request, "user_account/error_message.html", {'error_message': error_message})       
    except jwt.InvalidTokenError:
        error_message = "Invalid token. Please try again."
        return render(request, "user_account/error_message.html", {'error_message': error_message})
    
# home page
def home(request):
    return render(request, "user_account/home.html")

# Register page
class RegisterView(FormView):
    template_name = "user_account/register.html"
    form_class = forms.RegisterForm
    success_url = reverse_lazy("user_account:home")

    def post(self, request, *args, **kwargs):
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():          
            firstname = form.cleaned_data.get('first_name')
            lastname = form.cleaned_data.get('last_name')   
            email = form.cleaned_data.get('email')
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password2')
            # Incase of future server problem where user has been added to temporary database to prevent breakdown of code
            username_exist = TempUser.objects.filter(username=username).exists()
            email_exist = TempUser.objects.filter(email=email).exists()
            print(username_exist, email_exist)
            if not username_exist and not email_exist:
                TempUser.objects.create(first_name=firstname, last_name=lastname, username=username, email=email, password=make_password(password=password))
                return redirect(reverse_lazy("user_account:send_token_to_email", kwargs={"username": username, "email": email}))
            u = TempUser.objects.get(username=username)
            print(u)
            u.delete()
            messages.error(request, message="Registration timeout, Retry!")
            return redirect(reverse_lazy("user_account:register"))
        return super().post(request, *args, **kwargs)

def add_user_to_database(request, username):
    print("Testing")
    # Checks if user already exist
    user_exist = TempUser.objects.filter(username=username).exists()
    if user_exist:
        try:
            user = TempUser.objects.get(username=username)
            valid_user = CustomUser.objects.create(first_name=user.first_name,
            last_name = user.last_name,
            username = user.username,
            email=user.email,
            password = make_password(user.password)
                                    )
            login(request, user=valid_user)
            valid_user.is_active = True
            messages.success(request, message="Logged in!")
            user.delete()
            return redirect(reverse_lazy("user_account:home"))
        except user.DoesNotExist:
            print()
    messages.error(request, message="User registration timeout, Retry!")
    return redirect(reverse_lazy("user_account:register"))
    
class LoginView(FormView):
    template_name = "user_account/login.html"
    form_class = forms.LoginForm
    success_url = reverse_lazy("user_account:home")

    def post(self, request, *args, **kwargs):
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():
            email = form.cleaned_data.get("email")
            password = form.cleaned_data.get("password")
            user_exist = CustomUser.objects.filter(email=email).first()
            if user_exist:
                user = authenticate(request, email=user_exist.email, password=password)
                if user:
                    login(request, user=user)
                    messages.success(request, message="Logged in!")
                    return redirect(self.success_url)
            messages.error(request, message="Email or Password is incorrect!")
            return redirect(reverse_lazy("user_account:login"))
        
class PasswordChngView(PasswordChangeView, LoginRequiredMixin):
    template_name = "user_account/password_change.html"
    login_url = settings.LOGIN_URL
    redirect_field_name = "next"
    form_class = PasswordChangeForm
    success_url = reverse_lazy("user_account:password_change_done")

    def post(self, request, *args, **kwargs):
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():
            print(form.cleaned_data)
        return super().post(request, *args, **kwargs)

class PasswordChngDoneView(PasswordChangeDoneView):
    template_name = "user_account/password_change_done.html"

def send_reset_link(user, uid, token):
    EMAIL_CONTEXT ={ 
            "user": user,
            "domain": os.getenv("DOMAIN"),
            "protocol": os.getenv("PASSWORD_RESET_PROTOCOL"),
            "uid": uid,
            "token": token,
    }
    html_content = render_to_string(
        template_name="user_account/reset_password_link.html",
        context = {"reset_link": f"{EMAIL_CONTEXT['protocol']}://{EMAIL_CONTEXT['domain']}/user_account/password_reset_confirm/{uid}/{token}/"}
    )
    msg = EmailMultiAlternatives(
        subject ="Reset Password on UMD",
        from_email= settings.EMAIL_HOST_USER,
        to = [user.email]
    )

    try:
        msg.attach_alternative(content=html_content, mimetype="text/html")
        msg.send()
        print("Email sent successfully to reset password")
        print(token, uid)
    except (smtplib.SMTPException, socket.gaierror, socket.timeout) as e:
        return HttpResponse("Your network is bad at the moment!")
    except Exception as e:
        print("Error :", e)
        return HttpResponse("An error occured while sending the message to email!")
    
def encode_primary_key_to_base64(pk):
    pk_bytes = str(pk).encode("utf-8") # convert the string to bytes
    print(pk_bytes)
    encoded_pk = urlsafe_base64_encode(s=pk_bytes) # convert bytes to base64 url
    print(encoded_pk)
    return encoded_pk

def email_message_view(request, user):
    return render(request, "user_account/check_email_message.html", {"email": user})

class PasswordresetView(PasswordResetView):
    template_name = "user_account/forget_password.html"
    form_class = PasswordResetForm
    success_url = "user_account:password_reset_done"
    html_email_template_name = "user_account/reset_password_link.html"

    def post(self, request, *args, **kwargs):
        form = self.get_form(form_class=self.form_class)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            email_exist = CustomUser.objects.filter(email=email).first()
            if email_exist:
                if CustomUser.objects.get(email=email).is_active:
                    user = CustomUser.objects.get(email=email)
                    base64_url = encode_primary_key_to_base64(pk=user.id)
                    token=default_token_generator.make_token(user)
                    send_reset_link(user=user, uid=base64_url, token=token) 
                    return redirect(reverse_lazy("user_account:check_email_message", kwargs={'user': user.email}))
            messages.error(request, message="Email does not exist!")
            return redirect(reverse_lazy("user_account:password_reset"))
        return super().post(request, *args, **kwargs)

class PasswordresetConfirm(PasswordResetConfirmView):
    template_name = "user_account/set_new_password.html"
    form_class = SetPasswordForm
    success_url = "user_account:password_reset_complete"

    def post(self, request, *args, **kwargs):
        form = self.get_form(form_class=self.form_class)
        print(self.kwargs.get("token"), self.kwargs.get("uidb64"))
        if form.is_valid():
            password1 = form.cleaned_data.get("new_password1")
            password2 = form.cleaned_data.get("new_password2")
            print(password1, password2)
            valid_link = self.validlink
            if password1 == password2 and valid_link:
                form.save()
                return redirect(reverse_lazy(self.success_url))
            return HttpResponse("Form submitted")       
        return super().post(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        uidb64 = self.kwargs.get("uidb64")
        token = self.kwargs.get("token")
        context = super().get_context_data(**kwargs)
        context['uid'] = uidb64
        context['token'] = token
        return context

class PasswordresetComplete(PasswordResetCompleteView):
    template_name = "user_account/login.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)  
        context['form'] = forms.LoginForm()
        messages.success(self.request, message="Password changed successfully, please login to enter your new password")
        return context
    
class AllUsers(generic.ListView):
    template_name = "user_account/all_users.html"
    model = CustomUser
    ordering = ["first_name"]
    context_object_name = "users"

