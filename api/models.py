from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from django.core.validators import MinLengthValidator, EmailValidator
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email field must be set')
        email = self.normalize_email(email)
        username = email  # Email'i username olarak kullan
        extra_fields.setdefault('username', username)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'ADMIN')
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    """
    Custom user model extending Django's AbstractUser to include additional fields
    and role-based authorization.
    """
    class RoleTypes(models.TextChoices):
        ADMIN = 'ADMIN', _('Admin')
        ENGINEER = 'ENGINEER', _('Engineer')
        WORKER = 'WORKER', _('Worker')

    role = models.CharField(
        max_length=20,
        choices=RoleTypes.choices,
        default=RoleTypes.WORKER
    )
    
    # Additional user information
    name = models.CharField(max_length=100, validators=[MinLengthValidator(2)])
    surname = models.CharField(max_length=100, validators=[MinLengthValidator(2)])
    email = models.EmailField(unique=True, validators=[EmailValidator()])
    username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    
    # Email'i username olarak kullan
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'surname']
    
    objects = CustomUserManager()
    
    class Meta:
        db_table = 'users'
        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self):
        return f"{self.name} {self.surname}"

    @property
    def full_name(self):
        return f"{self.name} {self.surname}"

    def is_admin(self):
        return self.role == self.RoleTypes.ADMIN

    def is_engineer(self):
        return self.role == self.RoleTypes.ENGINEER

    def is_worker(self):
        return self.role == self.RoleTypes.WORKER

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email
        super().save(*args, **kwargs)

class Machine(models.Model):
    """
    Machine model representing equipment that workers can be assigned to.
    """
    class StatusTypes(models.TextChoices):
        DRILLING = 'DRILLING', _('Sondaj')
        MOVING = 'MOVING', _('Nakliye')
        MAINTENANCE = 'MAINTENANCE', _('Bakım')
        IDLE = 'IDLE', _('Boşta')
        SETUP = 'SETUP', _('Kurulum')

    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=StatusTypes.choices,
        default=StatusTypes.IDLE,
        help_text=_('Makinenin mevcut durumu')
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'machines'
        verbose_name = _('Machine')
        verbose_name_plural = _('Machines')

    def __str__(self):
        return self.name

class WorkerMachine(models.Model):
    """
    Association model tracking worker assignments to machines.
    A worker can only be assigned to one machine at a time.
    A machine can have multiple workers.
    """
    worker = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='machine_assignments',
        limit_choices_to={'role': User.RoleTypes.WORKER}
    )
    machine = models.ForeignKey(
        Machine,
        on_delete=models.CASCADE,
        related_name='worker_assignments'
    )
    assigned_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='machine_assignments_made',
        limit_choices_to={'role__in': [User.RoleTypes.ADMIN, User.RoleTypes.ENGINEER]}
    )
    assigned_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'worker_machines'
        verbose_name = _('Worker Machine Assignment')
        verbose_name_plural = _('Worker Machine Assignments')
        constraints = [
            models.UniqueConstraint(
                fields=['worker'],
                condition=models.Q(is_active=True),
                name='unique_active_worker'
            )
        ]

    def __str__(self):
        return f"{self.worker.full_name} - {self.machine.name}"

    def save(self, *args, **kwargs):
        # Eğer bu bir aktif atama ise, işçinin diğer aktif atamalarını pasif yap
        if self.is_active:
            WorkerMachine.objects.filter(
                worker=self.worker,
                is_active=True
            ).exclude(id=self.id).update(
                is_active=False,
                ended_at=timezone.now()
            )
        super().save(*args, **kwargs)

class UserLog(models.Model):
    """
    Audit log for tracking important user-related actions.
    """
    class ActionTypes(models.TextChoices):
        LOGIN = 'LOGIN', _('Login')
        LOGOUT = 'LOGOUT', _('Logout')
        ROLE_CHANGE = 'ROLE_CHANGE', _('Role Change')
        MACHINE_ASSIGNMENT = 'MACHINE_ASSIGNMENT', _('Machine Assignment')
        MACHINE_UNASSIGNMENT = 'MACHINE_UNASSIGNMENT', _('Machine Unassignment')
        WORKER_REMOVAL = 'WORKER_REMOVAL', _('Worker Removal')

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='logs'
    )
    action = models.CharField(
        max_length=50,
        choices=ActionTypes.choices
    )
    action_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='actions_performed'
    )
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = 'user_logs'
        verbose_name = _('User Log')
        verbose_name_plural = _('User Logs')

class MachineLocation(models.Model):
    """
    Makinelerin konum bilgilerini takip eden model
    """
    machine = models.ForeignKey(
        Machine,
        on_delete=models.CASCADE,
        related_name='locations'
    )
    latitude = models.DecimalField(
        max_digits=10,
        decimal_places=8,
        help_text="Enlem bilgisi"
    )
    longitude = models.DecimalField(
        max_digits=11,
        decimal_places=8,
        help_text="Boylam bilgisi"
    )
    heading = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Yön bilgisi (derece)"
    )
    accuracy = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Konum doğruluk değeri (metre)"
    )
    timestamp = models.DateTimeField(
        help_text="Konum bilgisinin alındığı zaman"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Kaydın oluşturulma zamanı"
    )

    class Meta:
        db_table = 'machine_locations'
        verbose_name = _('Machine Location')
        verbose_name_plural = _('Machine Locations')
        indexes = [
            models.Index(fields=['machine', '-timestamp']),
            models.Index(fields=['timestamp']),
        ]
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.machine.name} - {self.timestamp}"

class LocationHistory(models.Model):
    machine = models.ForeignKey('Machine', on_delete=models.CASCADE, related_name='location_history')
    latitude = models.DecimalField(max_digits=9, decimal_places=6)
    longitude = models.DecimalField(max_digits=9, decimal_places=6)
    heading = models.DecimalField(max_digits=5, decimal_places=2, null=True)
    accuracy = models.DecimalField(max_digits=5, decimal_places=2)
    drilling_depth = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    fuel_consumption = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    timestamp = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

class Shift(models.Model):
    machine = models.ForeignKey('Machine', on_delete=models.CASCADE, related_name='shifts')
    workers = models.ManyToManyField('User', related_name='shifts')
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    drilling_depth = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    fuel_consumption = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    start_location = models.ForeignKey('LocationHistory', on_delete=models.SET_NULL, null=True, related_name='shift_starts')
    end_location = models.ForeignKey('LocationHistory', on_delete=models.SET_NULL, null=True, related_name='shift_ends')
    report_image = models.ImageField(upload_to='shift_reports/', null=True, blank=False, help_text=_('Vardiya rapor defteri fotoğrafı'))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-start_time']

class FuelConsumption(models.Model):
    machine = models.ForeignKey('Machine', on_delete=models.CASCADE, related_name='fuel_consumptions')
    shift = models.ForeignKey(Shift, on_delete=models.SET_NULL, null=True, related_name='fuel_records')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    location = models.ForeignKey(LocationHistory, on_delete=models.SET_NULL, null=True)
    timestamp = models.DateTimeField()
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
