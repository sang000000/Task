from rest_framework.views import exception_handler
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework import status

def custom_exception_handler(exc, context):
    # 기본 예외 처리
    response = exception_handler(exc, context)

    if response is None:
        return response

    # AuthenticationFailed 예외에 대한 처리
    if isinstance(exc, AuthenticationFailed):
        error_message = str(exc)  # 에러 메시지를 추출
        error_code = "AUTH_FAILED"  # 기본 오류 코드 설정

        if "토큰이 없습니다." in error_message:
            error_code = "TOKEN_NOT_FOUND"
        elif "만료되었습니다" in error_message:
            error_code = "TOKEN_EXPIRED"
        elif "유효하지 않습니다" in error_message:
            error_code = "INVALID_TOKEN"

        return Response({
            "error": {
                "code": error_code,
                "message": error_message  # 오류 메시지만 포함
            }
        }, status=status.HTTP_401_UNAUTHORIZED)

    return response