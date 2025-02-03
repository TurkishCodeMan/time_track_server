from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.decorators import action, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from .models import InventoryItem, InventoryTransaction
from .serializers import InventoryItemSerializer, InventoryTransactionSerializer

# Create your views here.

class InventoryItemViewSet(viewsets.ModelViewSet):
    queryset = InventoryItem.objects.all()
    serializer_class = InventoryItemSerializer
    parser_classes = (MultiPartParser, FormParser)

    @action(detail=True, methods=['post'])
    def add_stock(self, request, pk=None):
        item = self.get_object()
        quantity = request.data.get('quantity', 0)
        notes = request.data.get('notes', '')

        if quantity <= 0:
            return Response(
                {'error': 'Miktar 0\'dan büyük olmalıdır'},
                status=status.HTTP_400_BAD_REQUEST
            )

        transaction = InventoryTransaction.objects.create(
            item=item,
            quantity=quantity,
            transaction_type='IN',
            notes=notes
        )

        return Response(
            InventoryTransactionSerializer(transaction).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['post'])
    def remove_stock(self, request, pk=None):
        item = self.get_object()
        quantity = request.data.get('quantity', 0)
        notes = request.data.get('notes', '')

        if quantity <= 0:
            return Response(
                {'error': 'Miktar 0\'dan büyük olmalıdır'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if item.quantity < quantity:
            return Response(
                {'error': 'Stokta yeterli miktar bulunmamaktadır'},
                status=status.HTTP_400_BAD_REQUEST
            )

        transaction = InventoryTransaction.objects.create(
            item=item,
            quantity=quantity,
            transaction_type='OUT',
            notes=notes
        )

        return Response(
            InventoryTransactionSerializer(transaction).data,
            status=status.HTTP_201_CREATED
        )

class InventoryTransactionViewSet(viewsets.ModelViewSet):
    queryset = InventoryTransaction.objects.all()
    serializer_class = InventoryTransactionSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        item_id = self.request.query_params.get('item', None)
        if item_id:
            queryset = queryset.filter(item_id=item_id)
        return queryset
