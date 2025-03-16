import pytest
from rest_framework import status
from rest_framework.test import APIClient
from myapp.models import User
from django.urls import reverse
import time


@pytest.fixture
def client():
    return APIClient()

@pytest.fixture
def user_data():
    return {
        "username": "ttuser",
        "password": "testpassword123",
        "nickname": "test"
    }
@pytest.mark.django_db
# 회원가입 성공 사례
def test_signup_success(client, user_data):
    response = client.post('/accounts/signup/', user_data, format='json')
    assert response.status_code == status.HTTP_201_CREATED
    assert response.data['username'] == user_data['username']
    assert response.data['nickname'] == user_data['nickname']

@pytest.mark.django_db
# 이미 존재하는 username으로 회원가입 시도
def test_signup_username_exists(client, user_data):
    User.objects.create_user(username=user_data['username'], password=user_data['password'], nickname=user_data['nickname'])
    response = client.post('/accounts/signup/', user_data, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['error']['code'] == 'USER_ALREADY_EXISTS'

@pytest.mark.django_db
# 이미 존재하는 nickname으로 회원가입 시도
def test_signup_nickname_exists(client, user_data):
    User.objects.create_user(username='otheruser', password=user_data['password'], nickname=user_data['nickname'])
    response = client.post('/accounts/signup/', user_data, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['error']['code'] == 'NICKNAME_ALREADY_EXISTS'

@pytest.mark.django_db
# 토큰이 없는 경우
def test_no_token(client):
    response = client.get('/accounts/auth/', HTTP_AUTHORIZATION="")  # 빈 Authorization 헤더
    
    # 토큰이 없은 경우에 대한 응답 확인
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data['error']['code'] == 'TOKEN_NOT_FOUND'


@pytest.mark.django_db
# 잘못된 토큰인 경우
def test_invalid_token(client):
    invalid_token = "invalidtoken" # 잘못된 토큰
    response = client.get('/accounts/auth/', HTTP_AUTHORIZATION=f"Bearer {invalid_token}")
    
    # 잘못 된 토큰에 대한 응답 확인
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data['error']['code'] == 'INVALID_TOKEN'

@pytest.mark.django_db
# 토큰이 만료된 경우
def test_expired_token(client, user_data):

    client.post('/accounts/signup/', user_data, format='json')
    # 기존 로그인 테스트에서 이미 발급된 토큰을 사용한다고 가정
    login_data = {
        "username": "ttuser",
        "password": "testpassword123"
    }
    response = client.post('/accounts/login/', login_data, format='json')
    token = response.data['token']  # 로그인 후 발급받은 토큰
    if not token:
        print("❌ 로그인 실패! 응답 데이터:", response.data)

    # 30초 기다려서 토큰 만료
    time.sleep(31)  # 30초 이상 대기 (토큰 만료)

    response = client.get('/accounts/auth/', HTTP_AUTHORIZATION=f"Bearer {token}")
    
    # 만료된 토큰에 대한 응답 확인
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data['error']['code'] == 'TOKEN_EXPIRED'

@pytest.mark.django_db
# 로그인 성공 사례
def test_login_success(client, user_data):

    client.post('/accounts/signup/', user_data, format='json')

    login_data = {
        "username": "ttuser",
        "password": "testpassword123"
    }
    response = client.post('/accounts/login/', login_data, format='json')
    assert response.status_code == status.HTTP_200_OK
    assert 'token' in response.data  # JWT 토큰이 응답에 포함되어야 합니다.

@pytest.mark.django_db
# 잘못된 비밀번호로 로그인 시도
def test_login_invalid_password(client, user_data):

    client.post('/accounts/signup/', user_data, format='json')

    login_data = {
        "username": "ttuser",
        "password": "wrongpassword"
    }
    response = client.post('/accounts/login/', login_data, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['error']['code'] == 'INVALID_CREDENTIALS'

@pytest.mark.django_db
# 잘못된 username으로 로그인 시도
def test_login_invalid_username(client, user_data):

    client.post('/accounts/signup/', user_data, format='json')

    login_data = {
        "username": "wronguser",
        "password": "testpassword123"
    }
    response = client.post('/accounts/login/', login_data, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['error']['code'] == 'INVALID_CREDENTIALS'



@pytest.mark.django_db
# 인증된 사용자만 접근 가능한 API 테스트
def test_authenticated_api_access(client, user_data):
    # 회원가입 및 로그인 후 JWT 토큰 발급
    client.post('/accounts/signup/', user_data, format='json')
    login_data = {
        "username": "ttuser",
        "password": "testpassword123"
    }
    response = client.post('/accounts/login/', login_data, format='json')
    token = response.data['token']  # 로그인 후 발급받은 토큰

    # 인증 헤더에 JWT 토큰을 포함하여 접근
    headers = {
        "Authorization": f"Bearer {token}"
    }
    # 인증이 필요한 API 요청
    response = client.get('/accounts/auth/', HTTP_AUTHORIZATION=f"Bearer {token}")
    
    # 정상 응답 확인
    assert response.status_code == status.HTTP_200_OK
    assert response.data["status"] == "인증 성공"