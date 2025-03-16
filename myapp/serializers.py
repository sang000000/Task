from rest_framework import serializers
from .models import User

class SignupSerializers(serializers.ModelSerializer): #회원가입 serializer
    class Meta:
        model = User
        fields = ["username","password","nickname"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = User(
            username=validated_data["username"],
            nickname=validated_data["nickname"]
        )
        user.set_password(validated_data["password"])  # 비밀번호 암호화
        user.save()
        return user
    
