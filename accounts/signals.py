from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import User
from .services import issue_certificate_for_user


@receiver(post_save, sender=User)
def create_user_certificate(sender, instance, created, **kwargs):
    if not created:
        return

    if instance.role != User.Role.ADMIN:
        return

    issue_certificate_for_user(instance)
