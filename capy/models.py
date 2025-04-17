# capy/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings


# Criação do modelo de usuário personalizado do prório DRF!
class CustomUser(AbstractUser):
    # Sobrescrever o email para ser único e obrigatório
    email = models.EmailField(unique=True)
    profile_image = models.ImageField(
        upload_to='profile_pics/', null=True, blank=True
    )
    email_confirmed = models.BooleanField(default=False)
    confirmation_token = models.UUIDField(
        null=True,  # permite valor nulo no banco
        blank=True,  # permite campo em branco em forms/admin
        editable=False  # não deve ser editável diretamente no admin
    )
    token_created_at = models.DateTimeField(
        null=True,  # Permite valor nulo
        blank=True,  # Permite campo em branco
        editable=False  # Não editável
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email


class Item(models.Model):
    # Usar settings.AUTH_USER_MODEL para referenciar o modelo de usuário
    # Lembrar!(Boa prática): usar o settings.AUTH_USER_MODEL para referenciar
    # o modelo de usuário
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='items'
    )
    title = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    # se o item é público ou privado(requisito!)
    is_public = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # opcional pra debugging
    def __str__(self) -> str:
        return str(self.title)
