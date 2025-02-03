from django.db import models
from django.core.validators import MinValueValidator

class InventoryItem(models.Model):
    name = models.CharField(max_length=255, verbose_name="Malzeme Adı")
    description = models.TextField(verbose_name="Açıklama", blank=True)
    quantity = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        verbose_name="Miktar"
    )
    unit = models.CharField(
        max_length=50,
        verbose_name="Birim",
        choices=[
            ('ADET', 'Adet'),
            ('KG', 'Kilogram'),
            ('LT', 'Litre'),
            ('MT', 'Metre'),
        ],
        default='ADET'
    )
    image = models.ImageField(
        upload_to='inventory/',
        verbose_name="Fotoğraf",
        null=True,
        blank=True
    )
    min_quantity = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)],
        verbose_name="Minimum Miktar"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Stok Kalemi"
        verbose_name_plural = "Stok Kalemleri"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.quantity} {self.unit})"

class InventoryTransaction(models.Model):
    TRANSACTION_TYPES = [
        ('IN', 'Giriş'),
        ('OUT', 'Çıkış'),
    ]

    item = models.ForeignKey(
        InventoryItem,
        on_delete=models.CASCADE,
        related_name='transactions',
        verbose_name="Malzeme"
    )
    quantity = models.IntegerField(verbose_name="Miktar")
    transaction_type = models.CharField(
        max_length=3,
        choices=TRANSACTION_TYPES,
        verbose_name="İşlem Tipi"
    )
    notes = models.TextField(verbose_name="Notlar", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Stok Hareketi"
        verbose_name_plural = "Stok Hareketleri"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_transaction_type_display()} - {self.item.name} ({self.quantity})"

    def save(self, *args, **kwargs):
        if self.transaction_type == 'IN':
            self.item.quantity += self.quantity
        else:
            self.item.quantity -= self.quantity
        self.item.save()
        super().save(*args, **kwargs)
