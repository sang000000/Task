from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser): # 커스텀 사용자 모델
    nickname = models.CharField("nickname", max_length=10, unique=True)

