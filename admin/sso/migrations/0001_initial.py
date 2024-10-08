# Generated by Django 4.0.4 on 2024-09-30 07:54

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Account',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('uid', models.BigIntegerField(unique=True)),
                ('wallet_address', models.CharField(blank=True, max_length=64, null=True, unique=True)),
                ('name', models.CharField(blank=True, max_length=512, null=True)),
                ('email', models.CharField(blank=True, max_length=512, null=True, unique=True)),
                ('phone', models.CharField(blank=True, max_length=32, null=True)),
                ('password_hash', models.CharField(blank=True, max_length=256, null=True)),
                ('username', models.CharField(blank=True, max_length=128, null=True, unique=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('avatar_url', models.TextField(blank=True, null=True)),
                ('email_verified', models.IntegerField(default=0, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('is_deleted', models.IntegerField(default=0, null=True)),
            ],
            options={
                'db_table': 'accounts',
            },
        ),
        migrations.CreateModel(
            name='ChainConfig',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=256)),
                ('chain_id', models.CharField(max_length=16, unique=True)),
                ('rpc', models.CharField(max_length=512)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('is_deleted', models.IntegerField(default=0, null=True)),
            ],
            options={
                'db_table': 'chain_config',
            },
        ),
        migrations.CreateModel(
            name='Challenge',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('wallet', models.CharField(max_length=42)),
                ('chain_id', models.CharField(max_length=16, null=True)),
                ('nonce', models.CharField(max_length=64, unique=True)),
                ('hash', models.CharField(max_length=128)),
                ('expired_at', models.DateTimeField(null=True)),
                ('is_verified', models.IntegerField(default=0, null=True)),
                ('verified_at', models.DateTimeField(null=True)),
                ('signature', models.CharField(max_length=132, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('is_deleted', models.IntegerField(default=0, null=True)),
            ],
            options={
                'db_table': 'challenges',
            },
        ),
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=512)),
                ('description', models.TextField(blank=True, null=True)),
                ('client_id', models.CharField(blank=True, max_length=128, null=True, unique=True)),
                ('client_secret', models.CharField(blank=True, max_length=128, null=True)),
                ('redirect_url', models.TextField(blank=True, null=True)),
                ('scope', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('is_deleted', models.IntegerField(default=0, null=True)),
            ],
            options={
                'db_table': 'clients',
            },
        ),
        migrations.CreateModel(
            name='AccountSecret',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('api_key', models.CharField(max_length=64, unique=True)),
                ('expired_at', models.DateTimeField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('is_deleted', models.IntegerField(default=0, null=True)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='sso.account')),
            ],
            options={
                'db_table': 'account_secrets',
            },
        ),
        migrations.CreateModel(
            name='AccountGoogle',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('uid', models.BigIntegerField(unique=True)),
                ('sub', models.CharField(blank=True, max_length=64, null=True)),
                ('name', models.CharField(blank=True, max_length=1024, null=True)),
                ('given_name', models.CharField(blank=True, max_length=512, null=True)),
                ('family_name', models.CharField(blank=True, max_length=512, null=True)),
                ('profile', models.TextField(blank=True, null=True)),
                ('picture', models.TextField(blank=True, null=True)),
                ('email', models.CharField(max_length=512)),
                ('email_verified', models.IntegerField(default=0, null=True)),
                ('gender', models.CharField(blank=True, max_length=32, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True)),
                ('updated_at', models.DateTimeField(auto_now=True, null=True)),
                ('is_deleted', models.IntegerField(default=0, null=True)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.DO_NOTHING, to='sso.account')),
            ],
            options={
                'db_table': 'account_googles',
            },
        ),
    ]
