from rest_framework.views import APIView
from .serializers import SignupSerializers
from rest_framework.response import Response
from .models import User
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import login, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import jwt
from django.conf import settings




#--------------------------------------------------------------------------------------------------------------------------------------------------------
# 1. 회원가입
class SignupView(APIView):  
    permission_classes = [AllowAny]

    @swagger_auto_schema(
    operation_description=(
        "회원가입을 위한 API\n"
        "이 API는 사용자가 새로운 계정을 생성하는 데 사용됩니다.\n"
        "\n"
        "**요청 파라미터**:\n"
        "- **username** (string): 사용자의 고유한 아이디(사용자 이름). 이미 존재하는 경우, "
        "400 오류 코드와 함께 '이미 가입된 사용자입니다.' 메시지가 반환됩니다.\n"
        "- **nickname** (string): 사용자의 닉네임(최대 10자). 이미 사용 중인 경우, "
        "400 오류 코드와 함께 '이미 사용 중인 닉네임입니다.' 메시지가 반환됩니다.\n"
        "- **password** (string): 사용자의 비밀번호.\n"
        "\n"
        "**요청 예시**:\n"
        "```json\n"
        "{\n"
        "    \"username\": \"JIN HO\",\n"
        "    \"nickname\": \"Mentos\",\n"
        "    \"password\": \"12341234\"\n"
        "}\n"
        "```\n"
        "**응답**:\n"
        "- **201 Created**: 회원가입 성공\n"
        "  - 응답 예시:\n"
        "```json\n"
        "{\n"
        "    \"username\": \"JIN HO\",\n"
        "    \"nickname\": \"Mentos\"\n"
        "}\n"
        "```\n"
        "- **400 Bad Request**: 요청이 잘못된 경우\n"
        "  - 사용자 이름 중복:\n"
        "    ```json\n"
        "    {\n"
        "        \"error\": {\n"
        "            \"code\": \"USER_ALREADY_EXISTS\",\n"
        "            \"message\": \"이미 가입된 사용자입니다.\"\n"
        "        }\n"
        "    }\n"
        "    ```\n"
        "  - 닉네임 중복:\n"
        "    ```json\n"
        "    {\n"
        "        \"error\": {\n"
        "            \"code\": \"NICKNAME_ALREADY_EXISTS\",\n"
        "            \"message\": \"이미 사용 중인 닉네임입니다.\"\n"
        "        }\n"
        "    }\n"
        "    ```\n"
    ),
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'username': openapi.Schema(
                type=openapi.TYPE_STRING,
                description="사용자의 고유한 아이디(사용자 이름)"
            ),
            'nickname': openapi.Schema(
                type=openapi.TYPE_STRING,
                description="사용자의 닉네임(최대 10자)"
            ),
            'password': openapi.Schema(
                type=openapi.TYPE_STRING,
                description="사용자의 비밀번호"
            ),
        },
        required=['username', 'password', 'nickname']  # 필수 입력 항목 정의
    ),
    responses={
        201: openapi.Response(
            description="회원가입 성공",
            examples={
                'application/json': {
                    "username": "JIN HO",
                    "nickname": "Mentos",
                }
            }
        ),
        400: openapi.Response(
            description="회원 가입 실패(상단 참조)",
        ),
    }
)
    def post(self, request):
        serializer = SignupSerializers(data=request.data)

        # username 중복 확인
        if User.objects.filter(username=request.data.get("username")).exists():
            return Response({
                "error": {
                    "code": "USER_ALREADY_EXISTS",
                    "message": "이미 가입된 사용자입니다."
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        # nickname 중복 확인
        if User.objects.filter(nickname=request.data.get("nickname")).exists():
            return Response({
                "error": {
                    "code": "NICKNAME_ALREADY_EXISTS",
                    "message": "이미 사용 중인 닉네임입니다."
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        # 유효성 검사
        if serializer.is_valid():  # 유효성 검사 성공
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:  # 유효성 검사 실패
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



#--------------------------------------------------------------------------------------------------------------------------------------------------------
# 2. 로그인
class LoginView(APIView):  
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description=(
        "사용자의 아이디와 비밀번호로 로그인을 진행하는 API\n"
        "이 API는 사용자가 등록된 아이디와 비밀번호를 통해 인증을 시도합니다.\n"
        "\n"
        "**요청 파라미터**:\n"
        "- **username** (string): 사용자의 아이디. 등록된 사용자만 로그인할 수 있습니다.\n"
        "- **password** (string): 사용자의 비밀번호. 아이디와 함께 사용되어 인증을 진행합니다.\n"
        "\n"
        "**요청 예시**:\n"
        "```json\n"
        "{\n"
        "    \"username\": \"testuser\",\n"
        "    \"password\": \"password123\"\n"
        "}\n"
        "```\n"
        "**응답**:\n"
        "- **200 OK**: 로그인 성공\n"
        "  - 응답 예시:\n"
        "```json\n"
        "{\n"
        "    \"token\": \"eKDIkdfjoakIdkfjpekdkcjdkoIOdjOKJDFOlLDKFJKL\"\n"
        "}\n"
        "```\n"
        "- **400 Bad Request**: 아이디 또는 비밀번호 오류\n"
        "  - 응답 예시:\n"
        "```json\n"
        "{\n"
        "    \"error\": {\n"
        "        \"code\": \"INVALID_CREDENTIALS\",\n"
        "        \"message\": \"아이디 또는 비밀번호가 올바르지 않습니다.\"\n"
        "    }\n"
        "}\n"
        "```\n"
    ),
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="사용자의 아이디"
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="사용자의 비밀번호"
                ),
            },
            required=['username', 'password'],  # 필수 파라미터 명시
            example={
                "username": "testuser",
                "password": "password123"
            }
        ),
        responses={
            200: openapi.Response(
                description="로그인 성공, 인증 토큰 반환",
                examples={
                    'application/json': {
                        "token": "eKDIkdfjoakIdkfjpekdkcjdkoIOdjOKJDFOlLDKFJKL"
                    }
                }
            ),
            400: openapi.Response(
                description="아이디 또는 비밀번호 오류",
                examples={
                    'application/json': {
                        "error": {
                            "code": "INVALID_CREDENTIALS",
                            "message": "아이디 또는 비밀번호가 올바르지 않습니다."
                        }
                    }
                }
            ),
        }
    )
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            # JWT 토큰 생성
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # 로그인 상태 유지
            login(request, user)
            return Response({"token": access_token}, status=status.HTTP_200_OK)  # 로그인 성공
        else:
            return Response({
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "아이디 또는 비밀번호가 올바르지 않습니다."
                }
            }, status=status.HTTP_400_BAD_REQUEST)  # 로그인 실패


#--------------------------------------------------------------------------------------------------------------------------------------------------------
# 3. Auth
# CustomAuthentication 클래스는 Auth 과제 응답 예시를 위해 생성한 클래스로, authentication.py 파일에 작성되어 있습니다.
class AuthView(APIView):
    permission_classes = [AllowAny]  # 모든 사용자에게 접근 허용

    @swagger_auto_schema(
        operation_description=(
            "인증 상태 확인 API\n"
            "이 API는 사용자가 인증 상태를 확인하는 데 사용됩니다.\n"
            "로그인 후 발급된 토큰으로 테스트를 진행하면 됩니다.\n"
            "토큰은 오른쪽 상단에 'Bearer 토큰값' 형태로 입력한 후 Authorize를 누르면 됩니다.\n"
            "로그인 후 생성된 토큰은 테스트를 위해 30초 후면 만료됩니다.\n"
            "\n"
            "응답:\n"
            "- 200 OK: 인증 성공\n"
            "  - 응답 예시:\n"
            "```json\n"
            "{\n"
            "    \"message\": \"Hello, 사용자 이름!\",\n"
            "    \"status\": \"인증 성공\"\n"
            "}\n"
            "```\n"
            "- 401 Unauthorized: 토큰이 만료된 경우\n"
            "  - 응답 예시:\n"
            "```json\n"
            "{\n"
            "    \"error\": {\n"
            "        \"code\": \"TOKEN_EXPIRED\",\n"
            "        \"message\": \"토큰이 만료되었습니다.\"\n"
            "    }\n"
            "}\n"
            "```\n"
            "- 401 Unauthorized: 토큰이 없는 경우\n"
            "  - 응답 예시:\n"
            "```json\n"
            "{\n"
            "    \"error\": {\n"
            "        \"code\": \"TOKEN_NOT_FOUND\",\n"
            "        \"message\": \"토큰이 없습니다.\"\n"
            "    }\n"
            "}\n"
            "```\n"
            "- 401 Unauthorized: 유효하지 않은 토큰인 경우\n"
            "  - 응답 예시:\n"
            "```json\n"
            "{\n"
            "    \"error\": {\n"
            "        \"code\": \"INVALID_TOKEN\",\n"
            "        \"message\": \"토큰이 유효하지 않습니다.\"\n"
            "    }\n"
            "}\n"
            "```\n"
        ),
        responses={
            200: openapi.Response(
                description='인증 성공',
                schema=openapi.Schema(type=openapi.TYPE_OBJECT, properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Hello 사용자 이름'),
                    'status': openapi.Schema(type=openapi.TYPE_STRING, description='인증 성공')
                })
            ),
            401: openapi.Response(
                description='인증 실패(상단 참조)',
            )
        }
    )

    def get(self, request):

        if request.user.is_authenticated:  # 사용자가 인증된 경우
            return Response({
                "message": f"Hello, {request.user.username}!",  # 사용자 이름
                "status": "인증 성공"  # 인증 성공 메시지 추가
            })
