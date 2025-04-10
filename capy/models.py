# capy/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser

# Custom user model that extends the AbstractUser class 
class CustomUser(AbstractUser):
    # Overwrite the email field to make it unique
    email = models.EmailField(unique=True)
    profile_image = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    email_confirmed = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

# Override the default user manager to use email as the unique identifier
    def __str__(self):
        return self.email