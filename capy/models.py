# capy/models.py
from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser

# Custom user model that extends the AbstractUser class 
class CustomUser(AbstractUser):
    # Sobrescrever o email para ser único e obrigatório
    email = models.EmailField(unique=True)
    profile_image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    email_confirmed = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
 
    def __str__(self):
        return self.email
    
class Item(models.Model):
    # Usar settings.AUTH_USER_MODEL que usei anteriormente
    # para referenciar o modelo de usuário personalizado
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='items')
    title = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    is_public = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title