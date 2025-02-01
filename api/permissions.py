from rest_framework import permissions
from functools import wraps
from rest_framework.response import Response
from rest_framework import status

class HasRole(permissions.BasePermission):
    message = 'Bu işlem için yetkiniz yok.'
    
    def __init__(self, allowed_roles):
        self.allowed_roles = allowed_roles
        super().__init__()

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.role in self.allowed_roles

def require_roles(allowed_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(view_instance, request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {'error': 'Giriş yapmanız gerekiyor'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            if request.user.role not in allowed_roles:
                return Response(
                    {'error': 'Bu işlem için yetkiniz yok'},
                    status=status.HTTP_403_FORBIDDEN
                )
            return func(view_instance, request, *args, **kwargs)
        return wrapper
    return decorator 