# Generated by Django 5.1 on 2025-02-01 16:57

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_locationhistory_shift_fuelconsumption'),
    ]

    operations = [
        migrations.AddField(
            model_name='shift',
            name='end_location',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='shift_ends', to='api.locationhistory'),
        ),
        migrations.AddField(
            model_name='shift',
            name='start_location',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='shift_starts', to='api.locationhistory'),
        ),
    ]
