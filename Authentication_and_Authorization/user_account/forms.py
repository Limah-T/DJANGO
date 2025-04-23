from django.contrib.auth.forms import UserCreationForm
from django import forms
from .models import CustomUser

class RegisterForm(UserCreationForm):
    first_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(max_length=50, widget=forms.TextInput(attrs={'class': 'form-control'}))
    username = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'class': 'form-control'})) 
     # ✅ Explicitly define password fields with styling
    password1 = forms.CharField(
    label="Password",
    widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    help_text="At least 8 characters, use letters & numbers."
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )    

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'username']

class LoginForm(forms.Form):
    email = forms.EmailField(max_length=50, widget=forms.TextInput(attrs={'class': 'form-control'})) 
    password = forms.CharField(
    label="Password",
    widget=forms.PasswordInput(attrs={'class': 'form-control'}))


