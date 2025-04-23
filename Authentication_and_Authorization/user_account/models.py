from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

# CustomUser Manager Model
class CustomUserManager(BaseUserManager):
    def create_user(self, first_name, last_name, username, email, password=None, **extra_fields):
        if not first_name or not last_name or not username or not email or not password:
            return ValueError("This field cannot be blank")
        user = self.model(first_name=first_name, last_name=last_name, username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, first_name, last_name, username, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Is Staff must be set to True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must be set to True")

        return self.create_user(first_name, last_name, username, email, password, **extra_fields)

# Custom User Model
class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=30, null=False, blank=False)
    last_name = models.CharField(max_length=30, null=False, blank=False)
    username = models.CharField(max_length=15, null=False, blank=False, unique=True)
    email = models.EmailField(null=False, blank=False, unique=True)   
    is_active = models.BooleanField(default=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'username']
    objects = CustomUserManager()

    def __str__(self):
        return self.username
    
    def save(self, *args, **kwargs):
        # Capitalizing the first and last name
        self.first_name = self.first_name.capitalize()
        self.last_name = self.last_name.capitalize()
        
        # Converting username and email to lowercase
        self.username = self.username.lower()
        self.email = self.email.lower()

        # Saving the instance with any extra arguments passed
        super().save(*args, **kwargs)

# Temporary User Model
class TempUser(models.Model):
    first_name = models.CharField(max_length=30, null=False, blank=False)
    last_name = models.CharField(max_length=30, null=False, blank=False)
    username = models.CharField(max_length=15, null=False, blank=False, unique=True)
    email = models.EmailField(null=False, blank=False, unique=True)
    password = models.CharField(max_length=200, null=False, blank=False)