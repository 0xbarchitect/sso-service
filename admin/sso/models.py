from django.db import models

# Create your models here.
class Client(models.Model):
    class Meta():
        db_table = "clients"    

    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=512)
    description = models.TextField(null=True,blank=True)
    client_id = models.CharField(max_length=128, null=True,blank=True, unique=True)
    client_secret = models.CharField(max_length=128, null=True,blank=True)
    redirect_url = models.TextField(null=True,blank=True)
    scope = models.TextField(null=True,blank=True)

    created_at = models.DateTimeField(null=True,auto_now_add=True)
    updated_at = models.DateTimeField(null=True,auto_now=True)
    is_deleted = models.IntegerField(null=True,default=0)

    def __str__(self) -> str:
        return str(self.name)

class Account(models.Model):
    class Meta():
        db_table = "accounts"

    id = models.BigAutoField(primary_key=True)
    uid = models.BigIntegerField(unique=True)
    wallet_address = models.CharField(max_length=64, null=True, blank=True, unique=True)
    name = models.CharField(max_length=512, null=True, blank=True)
    email = models.CharField(max_length=512, null=True, blank=True, unique=True)
    phone = models.CharField(max_length=32, null=True, blank=True)
    password_hash = models.CharField(max_length=256, null=True, blank=True)
    username = models.CharField(max_length=128, null=True, blank=True, unique=True)
    description = models.TextField(null=True, blank=True)
    avatar_url = models.TextField(null=True, blank=True)
    email_verified = models.IntegerField(null=True, default=0)

    created_at = models.DateTimeField(null=True,auto_now_add=True)
    updated_at = models.DateTimeField(null=True,auto_now=True)
    is_deleted = models.IntegerField(null=True,default=0)

    def __str__(self) -> str:
        return str(self.uid)

class AccountGoogle(models.Model):
    class Meta():
        db_table = "account_googles"

    id = models.BigAutoField(primary_key=True)
    account = models.ForeignKey(Account, on_delete=models.DO_NOTHING)
    uid = models.BigIntegerField(unique=True)

    sub = models.CharField(max_length=64, null=True, blank=True)
    name = models.CharField(max_length=1024, null=True, blank=True)
    given_name = models.CharField(max_length=512, null=True, blank=True)
    family_name = models.CharField(max_length=512, null=True, blank=True)
    profile = models.TextField(null=True, blank=True)
    picture = models.TextField(null=True, blank=True)
    email = models.CharField(max_length=512)
    email_verified = models.IntegerField(null=True,default=0)
    gender = models.CharField(max_length=32, null=True, blank=True)

    created_at = models.DateTimeField(null=True,auto_now_add=True)
    updated_at = models.DateTimeField(null=True,auto_now=True)
    is_deleted = models.IntegerField(null=True,default=0)

    def __str__(self) -> str:
        return str(self.email)

class Challenge(models.Model):
    class Meta():
        db_table = "challenges"

    id = models.BigAutoField(primary_key=True)    
    wallet = models.CharField(max_length=42)
    chain_id = models.CharField(max_length=16, null=True)
    nonce = models.CharField(max_length=64, unique=True)
    hash = models.CharField(max_length=128)
    expired_at = models.DateTimeField(null=True)
    is_verified = models.IntegerField(null=True, default=0)
    verified_at = models.DateTimeField(null=True)    
    signature = models.CharField(max_length=132, null=True)

    created_at = models.DateTimeField(null=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, auto_now=True)
    is_deleted = models.IntegerField(null=True, default=0)

    def __str__(self) -> str:
        return str(self.hash)
    
class AccountSecret(models.Model):
    class Meta():
        db_table = "account_secrets"

    id = models.BigAutoField(primary_key=True)
    account = models.ForeignKey(Account, on_delete=models.DO_NOTHING)
    api_key = models.CharField(max_length=64, unique=True)
    expired_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(null=True,auto_now_add=True)
    updated_at = models.DateTimeField(null=True,auto_now=True)
    is_deleted = models.IntegerField(null=True,default=0)

    def __str__(self) -> str:
        return str(self.hash)
    
class ChainConfig(models.Model):
    class Meta():
        db_table = "chain_config"

    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=256)
    chain_id = models.CharField(max_length=16, unique=True)
    rpc = models.CharField(max_length=512)    
    created_at = models.DateTimeField(null=True,auto_now_add=True)
    updated_at = models.DateTimeField(null=True,auto_now=True)
    is_deleted = models.IntegerField(null=True,default=0)

    def __str__(self) -> str:
        return str(self.name)
    