from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    UserViewSet, MachineViewSet, WorkerMachineViewSet,
    UserLogViewSet, MachineLocationViewSet,
    register, login, logout, get_user, location_history, shifts, end_shift, fuel_consumption,
    ShiftViewSet
)

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'machines', MachineViewSet, basename='machine')
router.register(r'worker-machines', WorkerMachineViewSet)
router.register(r'logs', UserLogViewSet)
router.register(r'locations', MachineLocationViewSet)
router.register(r'shifts', ShiftViewSet, basename='shift')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/register/', register, name='register'),
    path('auth/login/', login, name='login'),
    path('auth/logout/', logout, name='logout'),
    path('auth/user/', get_user, name='get_user'),
    path('machines/<int:machine_id>/locations/history/', location_history, name='location_history'),
    path('machines/<int:machine_id>/locations/history/<int:location_id>/', location_history, name='location_history_detail'),
    path('machines/<int:machine_id>/shifts/', shifts, name='shifts'),
    path('machines/<int:machine_id>/shifts/<int:shift_id>/end/', end_shift, name='end_shift'),
    path('machines/<int:machine_id>/fuel/', fuel_consumption, name='fuel_consumption'),
] 