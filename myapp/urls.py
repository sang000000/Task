from django.urls import path
from . import views
from drf_yasg.views import get_schema_view
from drf_yasg import openapi



app_name = "accounts"
urlpatterns = [
    path("signup/", views.SignupView.as_view(), name="signup"), # 회원가입
    path("login/", views.LoginView.as_view(), name="Login"), # 로그인
    path("auth/", views.AuthView.as_view(), name="auth"), # Auth
]