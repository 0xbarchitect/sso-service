# Generated by Django 4.0.4 on 2024-09-30 08:35

from django.db import migrations
from sso.models import Client

import uuid

def seed_client(apps, schema_editor):
    client_id = str(uuid.uuid4())
    client_secret = str(uuid.uuid4())
    
    clients = [
        {
            'id': 1,
            'name': 'Client0',
            'description': 'Oauth2 Client0',
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_url': 'http://localhost:9000', # need to modify for env
            'scope': 'all',
        },
    ]

    for item in clients:
        cli = Client(
            id=item['id'],
            name=item['name'],
            description=item['description'],
            client_id=item['client_id'],
            client_secret=item['client_secret'],
            redirect_url=item['redirect_url'],
            scope=item['scope'],
        )
        cli.save()

def reverse_client(apps, schema_editor):
    schema_editor.execute("DELETE FROM clients")

class Migration(migrations.Migration):

    dependencies = [
        ('sso', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_client, reverse_client),
    ]
