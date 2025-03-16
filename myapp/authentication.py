import jwt
from django.conf import settings
from myapp.models import User
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

class CustomAuthentication(BaseAuthentication):
    def authenticate(self, request):
        if request.path in ['/accounts/signup/', '/accounts/login/','/swagger/']:
            return None  # 인증을 건너뛰고, 인증이 필요하지 않은 경우는 None 반환

        auth_header = request.headers.get("Authorization")
        
        if not auth_header:  # 토큰이 없는 경우 에러
            raise AuthenticationFailed("토큰이 없습니다.")

        try:
            token = auth_header.split(" ")[1]  # "Bearer <token>" 형식일 경우 공백 기준으로 분리
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload["user_id"])  # 예: payload에서 user_id를 사용한다고 가정
            request.user = user  # request.user에 User 객체를 할당
            return (user, token)  # 인증 성공 시 payload와 token을 반환
            
        except jwt.ExpiredSignatureError:  # 토큰이 만료되었을 경우 에러
            raise AuthenticationFailed("토큰이 만료되었습니다.")

        except jwt.InvalidTokenError:  # 토큰이 유효하지 않았을 경우 에러
            raise AuthenticationFailed("토큰이 유효하지 않습니다.")
