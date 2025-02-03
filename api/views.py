from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from .models import User, Machine, WorkerMachine, UserLog, MachineLocation, LocationHistory, Shift, FuelConsumption
from .serializers import (
    UserSerializer, MachineSerializer, WorkerMachineSerializer,
    UserLogSerializer, MachineLocationSerializer, LocationHistorySerializer,
    ShiftSerializer, FuelConsumptionSerializer
)
from .permissions import HasRole, require_roles
from .auth import create_auth_token
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied
from django.db import models

# Auth Views
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register(request):
    data = {
        'email': request.data.get('email'),
        'password': request.data.get('password'),
        'name': request.data.get('name'),
        'surname': request.data.get('surname'),
        'role': request.data.get('role', 'WORKER'),
        'username': request.data.get('email')  # Email'i username olarak kullan
    }
    
    print("Request data:", data)  # Debug için
    serializer = UserSerializer(data=data)
    if not serializer.is_valid():
        print("Validation errors:", serializer.errors)  # Debug için
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    try:
        user = serializer.save()
        token = create_auth_token(user)
        
        UserLog.objects.create(
            user=user,
            action=UserLog.ActionTypes.ROLE_CHANGE,
            description=f"User registered with role {user.role}"
        )
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    except Exception as e:
        print("Save error:", str(e))  # Debug için
        return Response({
            'error': 'Kayıt işlemi başarısız'
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response({
            'error': 'Email ve şifre gerekli'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        if user.check_password(password):
            token = create_auth_token(user)
            
            UserLog.objects.create(
                user=user,
                action=UserLog.ActionTypes.LOGIN,
                description="User logged in"
            )
            
            return Response({
                'token': token.key,
                'user': UserSerializer(user).data
            })
        else:
            return Response({
                'error': 'Geçersiz şifre'
            }, status=status.HTTP_401_UNAUTHORIZED)
            
    except User.DoesNotExist:
        return Response({
            'error': 'Kullanıcı bulunamadı'
        }, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
def logout(request):
    """Kullanıcı çıkış ve token silme"""
    if request.user.is_authenticated:
        request.auth.delete()
        
        UserLog.objects.create(
            user=request.user,
            action=UserLog.ActionTypes.LOGOUT,
            description="User logged out"
        )
    return Response(status=status.HTTP_200_OK)

@api_view(['GET'])
def get_user(request):
    """Authenticated user bilgilerini döndür"""
    if request.user.is_authenticated:
        return Response(UserSerializer(request.user).data)
    return Response({
        'error': 'Giriş yapılmamış'
    }, status=status.HTTP_401_UNAUTHORIZED)

class UserViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            permission_classes = [HasRole(['ADMIN'])]
        elif self.action == 'list':
            permission_classes = [HasRole(['ADMIN', 'ENGINEER'])]
        else:
            permission_classes = [permissions.IsAuthenticated]
        return permission_classes

    def get_queryset(self):
        queryset = User.objects.all()
        role = self.request.query_params.get('role', None)
        if role:
            queryset = queryset.filter(role=role)
        return queryset

    @action(detail=False, methods=['get'])
    def me(self, request):
        """Giriş yapmış kullanıcının bilgilerini döndür"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def change_role(self, request, pk=None):
        """Kullanıcının rolünü değiştir"""
        if not request.user.is_authenticated or request.user.role != 'ADMIN':
            return Response(
                {'error': 'Bu işlem için yetkiniz yok'},
                status=status.HTTP_403_FORBIDDEN
            )

        user = self.get_object()
        new_role = request.data.get('role')
        
        if new_role not in User.RoleTypes.values:
            return Response(
                {'error': 'Geçersiz rol'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        old_role = user.role
        user.role = new_role
        user.save()
        
        UserLog.objects.create(
            user=user,
            action=UserLog.ActionTypes.ROLE_CHANGE,
            action_by=request.user,
            description=f"Role changed from {old_role} to {new_role}"
        )
        
        return Response({'status': 'success'})

class MachineViewSet(viewsets.ModelViewSet):
    serializer_class = MachineSerializer
    queryset = Machine.objects.all()
    
    def get_permissions(self):
        if self.action in ['assign_worker', 'unassign_worker', 'update_status']:
            permission_classes = [IsAuthenticated, HasRole(['ADMIN', 'ENGINEER'])]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() if isinstance(permission, type) else permission for permission in permission_classes]
    
    @action(detail=True, methods=['post'])
    def assign_worker(self, request, pk=None):
        machine = self.get_object()
        worker_id = request.data.get('worker_id')
        
        if not worker_id:
            return Response(
                {'error': 'worker_id gerekli'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            worker = User.objects.get(id=worker_id)
            if worker.role not in ['WORKER', 'ENGINEER']:
                return Response(
                    {'error': 'Sadece çalışan veya mühendis atanabilir'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            return Response(
                {'error': 'Belirtilen kullanıcı bulunamadı'},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Kullanıcının aktif ataması var mı kontrol et
        active_assignment = WorkerMachine.objects.filter(
            worker=worker,
            is_active=True
        ).first()
        
        if active_assignment:
            # Aktif atamayı sonlandır
            active_assignment.is_active = False
            active_assignment.ended_at = timezone.now()
            active_assignment.save()
            
            # Log kaydı oluştur
            UserLog.objects.create(
                user=worker,
                action=UserLog.ActionTypes.MACHINE_UNASSIGNMENT,
                action_by=request.user,
                description=f"{worker.full_name} unassigned from {active_assignment.machine.name}"
            )
            
        # Yeni atama oluştur
        assignment = WorkerMachine.objects.create(
            worker=worker,
            machine=machine,
            assigned_by=request.user,
            is_active=True
        )
        
        # Log kaydı oluştur
        UserLog.objects.create(
            user=worker,
            action=UserLog.ActionTypes.MACHINE_ASSIGNMENT,
            action_by=request.user,
            description=f"{worker.full_name} assigned to machine {machine.name}"
        )
        
        return Response(
            WorkerMachineSerializer(assignment).data,
            status=status.HTTP_201_CREATED
        )

    def get_queryset(self):
        if self.request.user.role == User.RoleTypes.WORKER:
            return Machine.objects.filter(
                worker_assignments__worker=self.request.user,
                worker_assignments__is_active=True
            )
        return Machine.objects.all()

    @action(detail=True, methods=['post'])
    def unassign_worker(self, request, pk=None):
        """Worker'ı makineden çıkar"""
        machine = self.get_object()
        worker_id = request.data.get('worker_id')
        
        if not worker_id:
            return Response(
                {'error': 'worker_id gerekli'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            assignment = WorkerMachine.objects.get(
                machine=machine,
                worker_id=worker_id,
                is_active=True
            )
        except WorkerMachine.DoesNotExist:
            return Response(
                {'error': 'Bu çalışanın aktif ataması bulunamadı'},
                status=status.HTTP_404_NOT_FOUND
            )

        assignment.is_active = False
        assignment.ended_at = timezone.now()
        assignment.save()

        UserLog.objects.create(
            user=assignment.worker,
            action=UserLog.ActionTypes.MACHINE_UNASSIGNMENT,
            action_by=request.user,
            description=f"Unassigned from machine {machine.name}"
        )

        return Response({'status': 'success'})

    @action(detail=True, methods=['post'])
    @require_roles(['ADMIN', 'ENGINEER'])
    def update_location(self, request, pk=None):
        """
        Makine konumunu günceller
        """
        machine = self.get_object()
        
        try:
            data = request.data
            latitude = float(data.get('latitude'))
            longitude = float(data.get('longitude'))
            heading = float(data.get('heading', 0))
            accuracy = float(data.get('accuracy', 0))
            timestamp = data.get('timestamp')

            if not all([latitude, longitude]):
                return Response(
                    {'error': 'Enlem ve boylam bilgileri gerekli'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Yeni konum kaydı oluştur
            location = MachineLocation.objects.create(
                machine=machine,
                latitude=latitude,
                longitude=longitude,
                heading=heading,
                accuracy=accuracy,
                timestamp=timestamp or timezone.now()
            )

            return Response(
                MachineLocationSerializer(location).data,
                status=status.HTTP_201_CREATED
            )

        except (TypeError, ValueError) as e:
            return Response(
                {'error': f'Geçersiz konum bilgisi: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': f'Beklenmeyen bir hata oluştu: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Makinenin durumunu güncelle"""
        machine = self.get_object()
        new_status = request.data.get('status')
        
        if not new_status:
            return Response(
                {'error': 'status gerekli'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if new_status not in Machine.StatusTypes.values:
            return Response(
                {'error': 'Geçersiz durum'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        old_status = machine.status
        machine.status = new_status
        machine.save()
        
        return Response(MachineSerializer(machine).data)

class WorkerMachineViewSet(viewsets.ModelViewSet):
    queryset = WorkerMachine.objects.all()
    serializer_class = WorkerMachineSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy', 'end_assignment']:
            permission_classes = [HasRole(['ADMIN', 'ENGINEER'])]
        else:
            permission_classes = [permissions.IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        user = self.request.user
        if user.role == User.RoleTypes.WORKER:
            return WorkerMachine.objects.filter(worker=user)
        return WorkerMachine.objects.all()

    def perform_create(self, serializer):
        if not self.request.user.is_authenticated or \
           self.request.user.role not in ['ADMIN', 'ENGINEER']:
            raise PermissionDenied("Bu işlem için yetkiniz yok")
            
        assignment = serializer.save(assigned_by=self.request.user)
        UserLog.objects.create(
            user=assignment.worker,
            action=UserLog.ActionTypes.MACHINE_ASSIGNMENT,
            action_by=self.request.user,
            description=f"Assigned to machine {assignment.machine.name}"
        )

    @action(detail=True, methods=['post'])
    def end_assignment(self, request, pk=None):
        """Makine atama işlemini sonlandır"""
        if not request.user.is_authenticated or \
           request.user.role not in ['ADMIN', 'ENGINEER']:
            return Response(
                {'error': 'Bu işlem için yetkiniz yok'},
                status=status.HTTP_403_FORBIDDEN
            )

        assignment = self.get_object()
        if assignment.is_active:
            assignment.is_active = False
            assignment.ended_at = timezone.now()
            assignment.save()
            
            UserLog.objects.create(
                user=assignment.worker,
                action=UserLog.ActionTypes.MACHINE_UNASSIGNMENT,
                action_by=request.user,
                description=f"Unassigned from machine {assignment.machine.name}"
            )
            
            return Response({'status': 'assignment ended'})
        return Response(
            {'error': 'Assignment already ended'},
            status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=True, methods=['post'])
    def assign_worker(self, request, pk=None):
        """Worker'ı makineye ata"""
        machine = self.get_object()
        worker_id = request.data.get('worker_id')
        
        if not worker_id:
            return Response(
                {'error': 'worker_id gerekli'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            worker = User.objects.get(id=worker_id)
            if worker.role not in ['WORKER', 'ENGINEER']:
                return Response(
                    {'error': 'Sadece çalışan veya mühendis atanabilir'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            return Response(
                {'error': 'Belirtilen kullanıcı bulunamadı'},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Kullanıcının aktif ataması var mı kontrol et
        active_assignment = WorkerMachine.objects.filter(
            worker=worker,
            is_active=True
        ).first()
        
        if active_assignment:
            # Aktif atamayı sonlandır
            active_assignment.is_active = False
            active_assignment.ended_at = timezone.now()
            active_assignment.save()
            
            # Log kaydı oluştur
            UserLog.objects.create(
                user=worker,
                action=UserLog.ActionTypes.MACHINE_UNASSIGNMENT,
                action_by=request.user,
                description=f"{worker.full_name} unassigned from {active_assignment.machine.name}"
            )
            
        # Yeni atama oluştur
        assignment = WorkerMachine.objects.create(
            worker=worker,
            machine=machine,
            assigned_by=request.user,
            is_active=True
        )
        
        # Log kaydı oluştur
        UserLog.objects.create(
            user=worker,
            action=UserLog.ActionTypes.MACHINE_ASSIGNMENT,
            action_by=request.user,
            description=f"{worker.full_name} assigned to machine {machine.name}"
        )
        
        return Response(
            WorkerMachineSerializer(assignment).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def unassign_worker(self, request, pk=None):
        """Worker'ı makineden çıkar"""
        if not request.user.is_authenticated or \
           request.user.role not in ['ADMIN', 'ENGINEER']:
            return Response(
                {'error': 'Bu işlem için yetkiniz yok'},
                status=status.HTTP_403_FORBIDDEN
            )

        machine = get_object_or_404(Machine, pk=pk)
        assignment = get_object_or_404(
            WorkerMachine,
            machine=machine,
            is_active=True
        )

        assignment.is_active = False
        assignment.ended_at = timezone.now()
        assignment.save()

        UserLog.objects.create(
            user=assignment.worker,
            action=UserLog.ActionTypes.MACHINE_UNASSIGNMENT,
            action_by=request.user,
            description=f"Unassigned from machine {machine.name}"
        )

        return Response({'status': 'success'})

    def get_queryset(self):
        """Sadece aktif atamaları getir"""
        return WorkerMachine.objects.filter(is_active=True)

class UserLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = UserLog.objects.all()  # Varsayılan queryset

    def get_queryset(self):
        user = self.request.user
        if user.role == User.RoleTypes.WORKER:
            return UserLog.objects.filter(user=user)
        elif user.role == User.RoleTypes.ENGINEER:
            return UserLog.objects.filter(
                user__role=User.RoleTypes.WORKER
            )
        return UserLog.objects.all()  # ADMIN tüm logları görebilir

class MachineLocationViewSet(viewsets.ModelViewSet):
    """
    Makine konum bilgilerini yönetmek için viewset
    """
    serializer_class = MachineLocationSerializer
    permission_classes = [IsAuthenticated]
    queryset = MachineLocation.objects.all()

    def get_queryset(self):
        return MachineLocation.objects.all()

    @action(detail=False, methods=['get'])
    def latest(self, request):
        """Her makine için en son konum bilgisini getir"""
        # Her makine için en son konumu SubQuery ile al
        from django.db.models import OuterRef, Subquery
        latest_locations = MachineLocation.objects.filter(
            machine=OuterRef('machine')
        ).order_by('-timestamp')

        # Her makine için en son konumu filtrele
        locations = MachineLocation.objects.filter(
            id=Subquery(
                latest_locations.values('id')[:1]
            )
        ).select_related('machine')

        serializer = self.get_serializer(locations, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Yeni konum kaydı oluştur"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        """Tüm konum kayıtlarını listele"""
        machine_id = request.query_params.get('machine_id')
        if machine_id:
            queryset = self.get_queryset().filter(machine_id=machine_id)
        else:
            queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

class WorkerAssignmentViewSet(viewsets.ModelViewSet):
    queryset = WorkerMachine.objects.all()
    serializer_class = WorkerMachineSerializer

    @action(detail=True, methods=['post'])
    def assign_worker(self, request, pk=None):
        """Worker'ı makineye ata"""
        worker_id = request.data.get('worker_id')
        try:
            # Worker ve makineyi kontrol et
            worker = User.objects.get(id=worker_id, role=User.RoleTypes.WORKER)
            machine = Machine.objects.get(id=pk)
            
            # Aktif atama var mı kontrol et
            if WorkerMachine.objects.filter(machine=machine, is_active=True).exists():
                return Response(
                    {"error": "Bu makineye zaten bir worker atanmış durumda"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Yeni atama oluştur
            assignment = WorkerMachine.objects.create(
                worker=worker,
                machine=machine,
                assigned_by=request.user,
                is_active=True
            )
            
            # Log kaydı oluştur
            UserLog.objects.create(
                user=worker,
                action=UserLog.ActionTypes.MACHINE_ASSIGNMENT,
                action_by=request.user,
                description=f"{worker.full_name} assigned to {machine.name}",
                metadata={
                    'machine_id': machine.id,
                    'worker_id': worker.id,
                    'assigned_by_id': request.user.id
                }
            )
            
            return Response(
                WorkerMachineSerializer(assignment).data,
                status=status.HTTP_201_CREATED
            )
            
        except User.DoesNotExist:
            return Response(
                {"error": "Worker bulunamadı"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Machine.DoesNotExist:
            return Response(
                {"error": "Makine bulunamadı"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def unassign_worker(self, request, pk=None):
        """Worker'ı makineden çıkar"""
        try:
            # Aktif atamayı bul
            assignment = WorkerMachine.objects.get(
                machine_id=pk,
                is_active=True
            )
            
            # Atamayı pasif yap
            assignment.is_active = False
            assignment.ended_at = timezone.now()
            assignment.save()
            
            # Log kaydı oluştur
            UserLog.objects.create(
                user=assignment.worker,
                action=UserLog.ActionTypes.MACHINE_UNASSIGNMENT,
                action_by=request.user,
                description=f"{assignment.worker.full_name} unassigned from {assignment.machine.name}",
                metadata={
                    'machine_id': assignment.machine.id,
                    'worker_id': assignment.worker.id,
                    'unassigned_by_id': request.user.id
                }
            )
            
            return Response(status=status.HTTP_200_OK)
            
        except WorkerMachine.DoesNotExist:
            return Response(
                {"error": "Aktif atama bulunamadı"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )

    def get_queryset(self):
        """Sadece aktif atamaları getir"""
        return WorkerMachine.objects.filter(is_active=True)

class ShiftViewSet(viewsets.ModelViewSet):
    serializer_class = ShiftSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Shift.objects.all()

    @action(detail=True, methods=['delete'])
    @require_roles(['ADMIN', 'ENGINEER'])
    def delete_shift(self, request, pk=None):
        """Vardiyayı sil"""
        shift = self.get_object()
        
        if not shift.end_time:
            return Response(
                {'error': 'Aktif vardiya silinemez. Önce vardiyayı sonlandırın.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # İlgili yakıt tüketimi kayıtlarını sil
            FuelConsumption.objects.filter(shift=shift).delete()
            
            # Geçici çalışanları sil
            for worker in shift.workers.all():
                if worker.email.startswith('temp_'):
                    shift.workers.remove(worker)
                    worker.delete()
            
            # Vardiyayı sil
            shift.delete()

            return Response(status=status.HTTP_204_NO_CONTENT)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post', 'delete'])
    def workers(self, request, pk=None):
        """Vardiyaya çalışan ekle veya çıkar"""
        shift = self.get_object()
        
        # DELETE metodu için
        if request.method == 'DELETE':
            worker_id = request.data.get('worker_id')
            if not worker_id:
                return Response(
                    {'error': 'worker_id gerekli'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                worker = User.objects.get(id=worker_id)
                shift.workers.remove(worker)
                # Geçici çalışanı sil
                if worker.email.startswith('temp_'):
                    worker.delete()
                return Response(status=status.HTTP_204_NO_CONTENT)
            except User.DoesNotExist:
                return Response(
                    {'error': 'Çalışan bulunamadı'},
                    status=status.HTTP_404_NOT_FOUND
                )

        # POST metodu için
        data = request.data
        try:
            # Yeni çalışan oluştur
            worker = User.objects.create(
                name=data.get('name'),
                surname=data.get('surname', ''),
                email=f"temp_{pk}_{timezone.now().timestamp()}@temp.com",
                role='WORKER',
                username=f"temp_{pk}_{timezone.now().timestamp()}",
                is_active=True
            )
            
            # Çalışanı vardiyaya ekle
            shift.workers.add(worker)
            shift.save()

            return Response({
                'id': worker.id,
                'name': worker.name,
                'role': worker.role
            })

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def end(self, request, pk=None):
        """Vardiyayı sonlandır"""
        shift = self.get_object()
        
        if shift.end_time:
            return Response(
                {'error': 'Bu vardiya zaten sonlandırılmış'},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = request.data
        drilling_depth = data.get('drilling_depth', 0)
        fuel_consumption = data.get('fuel_consumption', 0)

        try:
            # Vardiyayı sonlandır
            shift.end_time = timezone.now()
            shift.drilling_depth = drilling_depth
            shift.fuel_consumption = fuel_consumption
            shift.save()

            # Yakıt tüketimini kaydet
            FuelConsumption.objects.create(
                machine=shift.machine,
                shift=shift,
                amount=fuel_consumption,
                timestamp=shift.end_time
            )

            # Geçici çalışanları sil
            for worker in shift.workers.all():
                if worker.email.startswith('temp_'):
                    shift.workers.remove(worker)
                    worker.delete()

            return Response(ShiftSerializer(shift).data)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated])
def location_history(request, machine_id, location_id=None):
    """
    Makinenin lokasyon geçmişini getir, yeni lokasyon ekle veya lokasyon sil
    """
    if request.method == 'GET':
        try:
            # Lokasyonları al
            locations = LocationHistory.objects.filter(machine_id=machine_id)
            
            # Her lokasyon için toplam değerleri hesapla
            location_data = []
            for location in locations:
                # Bu lokasyonda yapılan tüm vardiyaların toplamını hesapla
                shifts = Shift.objects.filter(
                    models.Q(start_location=location) | models.Q(end_location=location),
                    end_time__isnull=False
                )
                
                total_drilling = 0
                total_fuel = 0
                
                # Her vardiya için o lokasyonda yapılan işi hesapla
                for shift in shifts:
                    # Delgi miktarı için lokasyon bazlı hesaplama
                    if shift.start_location == location and shift.end_location == location:
                        total_drilling += float(shift.drilling_depth or 0)
                    elif shift.start_location == location:
                        total_drilling += float(shift.drilling_depth or 0) / 2
                    elif shift.end_location == location:
                        total_drilling += float(shift.drilling_depth or 0) / 2
                    
                    # Yakıt tüketimi için vardiya bazlı toplam hesaplama
                    total_fuel += float(shift.fuel_consumption or 0)
                
                # Lokasyon verisini güncelle
                location.drilling_depth = total_drilling
                location.fuel_consumption = total_fuel
                location_data.append(location)
            
            serializer = LocationHistorySerializer(location_data, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=400)
    
    elif request.method == 'POST':
        try:
            data = request.data.copy()
            data['machine'] = machine_id
            data['timestamp'] = timezone.now()
            # Varsayılan değerleri ekle
            data['accuracy'] = data.get('accuracy', 0)
            data['heading'] = data.get('heading', 0)
            data['drilling_depth'] = 0  # Başlangıçta 0 olarak ayarla
            data['fuel_consumption'] = 0  # Başlangıçta 0 olarak ayarla
            
            serializer = LocationHistorySerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        except Exception as e:
            return Response({'error': str(e)}, status=400)
            
    elif request.method == 'DELETE':
        try:
            if not location_id:
                return Response({'error': 'Location ID is required'}, status=400)
            
            location = LocationHistory.objects.get(id=location_id, machine_id=machine_id)
            location.delete()
            return Response(status=204)
        except LocationHistory.DoesNotExist:
            return Response({'error': 'Location not found'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=400)

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def shifts(request, machine_id):
    """
    Makinenin vardiyalarını getir veya yeni vardiya oluştur
    """
    if request.method == 'GET':
        shifts = Shift.objects.filter(machine_id=machine_id)
        serializer = ShiftSerializer(shifts, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = ShiftSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(machine_id=machine_id)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def end_shift(request, shift_id):
    """
    Vardiyayı sonlandır
    """
    try:
        shift = Shift.objects.get(id=shift_id)
        serializer = ShiftSerializer(shift, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)
    except Shift.DoesNotExist:
        return Response({'error': 'Vardiya bulunamadı'}, status=404)

@api_view(['GET', 'POST', 'DELETE'])
@permission_classes([IsAuthenticated])
def fuel_consumption(request, machine_id, consumption_id=None):
    machine = get_object_or_404(Machine, id=machine_id)
    
    if request.method == 'DELETE':
        if not consumption_id:
            return Response(
                {'error': 'Yakıt tüketimi ID\'si gerekli'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        consumption = get_object_or_404(FuelConsumption, id=consumption_id, machine=machine)
        consumption.delete()
        
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    elif request.method == 'GET':
        # Mevcut GET işlemi
        consumptions = FuelConsumption.objects.filter(machine=machine)
        total_consumption = consumptions.aggregate(total=models.Sum('amount'))['total'] or 0
        
        serializer = FuelConsumptionSerializer(consumptions, many=True)
        return Response({
            'total_consumption': total_consumption,
            'history': serializer.data
        })
        
    elif request.method == 'POST':
        # Mevcut POST işlemi
        data = {
            'machine': machine.id,
            'amount': request.data.get('amount'),
            'shift': request.data.get('shift'),
            'location': request.data.get('location'),
            'notes': request.data.get('notes', ''),
            'timestamp': request.data.get('timestamp', timezone.now())
        }
        
        serializer = FuelConsumptionSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LocationHistoryViewSet(viewsets.ModelViewSet):
    serializer_class = LocationHistorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        machine_id = self.kwargs.get('machine_id')
        return LocationHistory.objects.filter(machine_id=machine_id)

    def perform_create(self, serializer):
        machine_id = self.kwargs.get('machine_id')
        serializer.save(
            machine_id=machine_id,
            timestamp=timezone.now()
        )