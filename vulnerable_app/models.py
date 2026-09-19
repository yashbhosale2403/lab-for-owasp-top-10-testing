from django.contrib.auth.models import User
from django.db import models


class Order(models.Model):
    """A private record belonging to one user -- used to demonstrate IDOR:
    /orders/<id>/ (vulnerable) lets anyone view any order, while
    /orders/<id>/safe/ correctly checks ownership."""

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="orders")
    item_name = models.CharField(max_length=200)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    note = models.CharField(max_length=200, blank=True)

    def __str__(self) -> str:
        return f"Order #{self.id} ({self.owner.username}): {self.item_name}"


class Profile(models.Model):
    """A per-user profile with a privilege field -- used to demonstrate mass
    assignment: /profile/update/ (vulnerable) blindly applies every field in
    the request body to this model, so a client can set role="admin" even
    though the form only means to expose "bio"."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    bio = models.CharField(max_length=200, blank=True)
    role = models.CharField(max_length=20, default="user")

    def __str__(self) -> str:
        return f"Profile({self.user.username}, role={self.role})"
