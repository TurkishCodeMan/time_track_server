from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions
from rest_framework.authtoken.models import Token
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

def create_auth_token(user):
    """Kullanıcı için token oluştur veya var olanı getir"""
    token, _ = Token.objects.get_or_create(user=user)
    return token

class TokenAuthentication(authentication.BaseAuthentication):
    keyword = 'Bearer'

    def authenticate(self, request):
        auth = request.headers.get('Authorization', '').split()

        if not auth or auth[0].lower() != self.keyword.lower():
            return None

        if len(auth) == 1:
            msg = 'Token eksik.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Token geçersiz.'
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = Token.objects.select_related('user').get(key=auth[1])
        except Token.DoesNotExist:
            raise exceptions.AuthenticationFailed('Geçersiz token.')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed('Kullanıcı aktif değil.')

        # Debug için log ekle
        logger.debug(f'Token doğrulama başarılı: {token.user.email}')
        return (token.user, token)

    def authenticate_header(self, request):
        return self.keyword