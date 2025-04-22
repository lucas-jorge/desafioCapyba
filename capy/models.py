# capy/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings


# Creation of the custom user model from DRF itself!
class CustomUser(AbstractUser):
    # Override email to be unique and required
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
    # Use settings.AUTH_USER_MODEL to reference the user model
    # Remember!(Good practice): use settings.AUTH_USER_MODEL to reference
    # the user model
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='items'
    )
    title = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    # if the item is public or private (requirement!)
    is_public = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # optional for debugging
    def __str__(self) -> str:
        return str(self.title)
