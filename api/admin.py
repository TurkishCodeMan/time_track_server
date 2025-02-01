from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Machine, WorkerMachine, UserLog, MachineLocation, Shift, LocationHistory, FuelConsumption

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'name', 'surname', 'role', 'is_active')
    list_filter = ('role', 'is_active')
    search_fields = ('username', 'email', 'name', 'surname')
    ordering = ('username',)

@admin.register(Machine)
class MachineAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active',)
    search_fields = ('name',)
    ordering = ('-created_at',)

@admin.register(WorkerMachine)
class WorkerMachineAdmin(admin.ModelAdmin):
    list_display = ('worker', 'machine', 'assigned_by', 'assigned_at', 'ended_at', 'is_active')
    list_filter = ('is_active', 'assigned_at')
    search_fields = ('worker__username', 'machine__name')
    ordering = ('-assigned_at',)

@admin.register(UserLog)
class UserLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'action_by', 'created_at')
    list_filter = ('action', 'created_at')
    search_fields = ('user__username', 'description')
    ordering = ('-created_at',)

@admin.register(MachineLocation)
class MachineLocationAdmin(admin.ModelAdmin):
    list_display = ('machine', 'latitude', 'longitude', 'heading', 'accuracy', 'timestamp', 'created_at')
    list_filter = ('machine', 'timestamp', 'created_at')
    search_fields = ('machine__name',)
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'

@admin.register(LocationHistory)
class LocationHistoryAdmin(admin.ModelAdmin):
    list_display = ('machine', 'latitude', 'longitude', 'drilling_depth', 'fuel_consumption', 'timestamp', 'created_at')
    list_filter = ('machine', 'timestamp', 'created_at')
    search_fields = ('machine__name',)
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'

@admin.register(Shift)
class ShiftAdmin(admin.ModelAdmin):
    list_display = ('machine', 'start_time', 'end_time', 'drilling_depth', 'fuel_consumption', 'created_at')
    list_filter = ('machine', 'start_time', 'end_time')
    search_fields = ('machine__name',)
    ordering = ('-start_time',)
    date_hierarchy = 'start_time'
    filter_horizontal = ('workers',)

@admin.register(FuelConsumption)
class FuelConsumptionAdmin(admin.ModelAdmin):
    list_display = ('machine', 'shift', 'amount', 'timestamp', 'created_at')
    list_filter = ('machine', 'shift', 'timestamp')
    search_fields = ('machine__name', 'notes')
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'
