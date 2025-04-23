from django.urls import path
from django.contrib.auth.views import LogoutView
from . import views

app_name = "user_account"

urlpatterns = [
    path("home/", views.home, name="home"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("code/<str:token>", views.token_expiration_time, name="code"),
    path("send_token_to_email/<str:username>/<str:email>/", views.send_email, name="send_token_to_email"),
    path("verify_token/<str:token>/", views.verification, name="verify_token"),
    path("add_user/<str:username>/", views.add_user_to_database, name="add_user"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("password_change", views.PasswordChngView.as_view(), name="password_change"),
    path("password_change_done", views.PasswordChngDoneView.as_view(), name="password_change_done"),
    path("all_users/", views.AllUsers.as_view(), name="all_users"),
    path('logout/', LogoutView.as_view(next_page='user_account:login'), name='logout'),

]