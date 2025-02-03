from rest_framework import serializers
from .models import InventoryItem, InventoryTransaction

class InventoryItemSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = InventoryItem
        fields = [
            'id', 'name', 'description', 'quantity', 'unit',
            'image', 'image_url', 'min_quantity', 'created_at', 'updated_at'
        ]
        read_only_fields = ['quantity', 'created_at', 'updated_at']

    def get_image_url(self, obj):
        if obj.image:
            return obj.image.url
        return None

class InventoryTransactionSerializer(serializers.ModelSerializer):
    item_name = serializers.CharField(source='item.name', read_only=True)
    transaction_type_display = serializers.CharField(source='get_transaction_type_display', read_only=True)

    class Meta:
        model = InventoryTransaction
        fields = [
            'id', 'item', 'item_name', 'quantity', 'transaction_type',
            'transaction_type_display', 'notes', 'created_at'
        ] 