from rest_framework import serializers
from .models import User, Machine, WorkerMachine, UserLog, MachineLocation, LocationHistory, Shift, FuelConsumption

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    username = serializers.CharField(required=False, allow_blank=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'name', 'surname', 'email', 'role', 'full_name', 'password')
        read_only_fields = ('full_name',)
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'required': False, 'allow_blank': True},
        }

    def create(self, validated_data):
        # Email'i username olarak kullan
        validated_data['username'] = validated_data.get('email')
        
        # Şifreyi ayır ve hash'le
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        
        return user

class MachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Machine
        fields = '__all__'

class WorkerMachineSerializer(serializers.ModelSerializer):
    worker_name = serializers.CharField(source='worker.full_name', read_only=True)
    machine_name = serializers.CharField(source='machine.name', read_only=True)
    assigned_by_name = serializers.CharField(source='assigned_by.full_name', read_only=True)

    class Meta:
        model = WorkerMachine
        fields = [
            'id', 'worker', 'worker_name', 
            'machine', 'machine_name',
            'assigned_by', 'assigned_by_name',
            'assigned_at', 'ended_at', 'is_active'
        ]
        read_only_fields = ['assigned_at', 'ended_at', 'is_active']

class UserLogSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.full_name', read_only=True)
    action_by_name = serializers.CharField(source='action_by.full_name', read_only=True)

    class Meta:
        model = UserLog
        fields = '__all__'
        read_only_fields = ('created_at', 'user_name', 'action_by_name')

class MachineLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = MachineLocation
        fields = (
            'id', 'machine', 'latitude', 'longitude',
            'heading', 'accuracy', 'timestamp', 'created_at'
        )
        read_only_fields = ('id', 'created_at')

    def validate(self, data):
        """
        Konum verilerinin doğruluğunu kontrol et
        """
        if data.get('latitude') and (data['latitude'] < -90 or data['latitude'] > 90):
            raise serializers.ValidationError(
                {'latitude': 'Enlem değeri -90 ile 90 arasında olmalıdır.'}
            )
        
        if data.get('longitude') and (data['longitude'] < -180 or data['longitude'] > 180):
            raise serializers.ValidationError(
                {'longitude': 'Boylam değeri -180 ile 180 arasında olmalıdır.'}
            )
        
        if data.get('heading') and (data['heading'] < 0 or data['heading'] > 360):
            raise serializers.ValidationError(
                {'heading': 'Yön değeri 0 ile 360 arasında olmalıdır.'}
            )
        
        if data.get('accuracy') and data['accuracy'] < 0:
            raise serializers.ValidationError(
                {'accuracy': 'Doğruluk değeri 0\'dan büyük olmalıdır.'}
            )
        
        return data 

class LocationHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = LocationHistory
        fields = ['id', 'machine', 'latitude', 'longitude', 'heading', 'accuracy', 
                 'drilling_depth', 'fuel_consumption', 'timestamp', 'created_at']

class ShiftSerializer(serializers.ModelSerializer):
    report_image_url = serializers.SerializerMethodField()

    def get_report_image_url(self, obj):
        if obj.report_image:
            return obj.report_image.url
        return None

    class Meta:
        model = Shift
        fields = ['id', 'machine', 'workers', 'start_time', 'end_time', 
                 'drilling_depth', 'fuel_consumption', 'created_at', 'updated_at',
                 'report_image', 'report_image_url']
        read_only_fields = ['report_image_url']

class FuelConsumptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = FuelConsumption
        fields = ['id', 'machine', 'shift', 'amount', 'location', 
                 'timestamp', 'notes', 'created_at'] 