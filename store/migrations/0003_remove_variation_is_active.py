# Generated by Django 3.1 on 2021-07-26 09:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('store', '0002_variation'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='variation',
            name='is_active',
        ),
    ]